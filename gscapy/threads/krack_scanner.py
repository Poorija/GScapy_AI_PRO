import logging
import time
from threading import Event

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL

class KrackScanThread(QThread):
    vulnerability_detected = pyqtSignal(str, str) # bssid, client_mac

    def __init__(self, iface, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.stop_event = Event()
        self.eapol_db = {} # { (bssid, client_mac): { replay_counter: count } }

    def _packet_handler(self, pkt):
        if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
            return

        # Check if frame is going from AP to client (To DS=0, From DS=1)
        if pkt.FCfield & 0x3 != 1:
            return

        try:
            # Key Information field is a good indicator for Message 3
            key_info = pkt[EAPOL].key_info
            # Message 3: Pairwise, Install, Ack, MIC
            # Install = bit 6 (0x40), Ack = bit 7 (0x80), MIC = bit 8 (0x100)
            is_msg3 = (key_info & 0x1c0) == 0x1c0

            if is_msg3:
                bssid = pkt.addr2
                client_mac = pkt.addr1
                replay_counter = pkt[EAPOL].replay_counter

                key = (bssid, client_mac)

                if key not in self.eapol_db:
                    self.eapol_db[key] = {}

                if replay_counter not in self.eapol_db[key]:
                    self.eapol_db[key][replay_counter] = 1
                else:
                    # If we see the same replay counter again, it's a retransmission
                    self.eapol_db[key][replay_counter] += 1
                    if self.eapol_db[key][replay_counter] == 2:
                        logging.info(f"KRACK vulnerability detected! BSSID: {bssid}, Client: {client_mac}")
                        self.vulnerability_detected.emit(bssid, client_mac)
                        # Reset counter to avoid flooding with signals for the same retransmission
                        self.eapol_db[key][replay_counter] = 0

        except (IndexError, AttributeError) as e:
            logging.debug(f"Error processing EAPOL packet for KRACK scan: {e}")

    def run(self):
        logging.info(f"KRACK scanner started on interface {self.iface}")
        while not self.stop_event.is_set():
            try:
                sniff(iface=self.iface, prn=self._packet_handler, filter="ether proto 0x888e", timeout=1)
            except Exception as e:
                logging.error(f"Error in KRACK sniffer loop: {e}", exc_info=True)
                time.sleep(1)

    def stop(self):
        self.stop_event.set()
