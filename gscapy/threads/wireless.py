import logging
import time
import os
import sys
import subprocess
from threading import Event
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff, wrpcap
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


class AircrackThread(QThread):
    """A thread to run the aircrack-ng process and emit its output."""
    output_received = pyqtSignal(str)
    finished_signal = pyqtSignal(int)

    def __init__(self, pcap_file, wordlist, parent=None, threads=1):
        super().__init__(parent)
        self.pcap_file = pcap_file
        self.wordlist = wordlist
        self.threads = threads
        self.process = None

    def run(self):
        command = ["aircrack-ng", "-w", self.wordlist, "-p", str(self.threads), self.pcap_file]
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in iter(self.process.stdout.readline, ''):
                self.output_received.emit(line.strip())
            self.process.stdout.close()
            return_code = self.process.wait()
            self.finished_signal.emit(return_code)
        except FileNotFoundError:
            self.output_received.emit("ERROR: 'aircrack-ng' command not found. Please ensure it is installed and in your system's PATH.")
            self.finished_signal.emit(-1)
        except Exception as e:
            self.output_received.emit(f"An unexpected error occurred: {e}")
            self.finished_signal.emit(-1)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait()
            logging.info("Aircrack-ng process terminated.")

class ChannelHopperThread(QThread):
    """A thread to automatically hop Wi-Fi channels on Linux for scanning."""
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.stop_event = Event()
    def run(self):
        if sys.platform != "linux":
            logging.warning("Channel hopping is only supported on Linux.")
            return
        logging.info(f"Channel hopper started for interface {self.iface}")
        channels = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10]
        while not self.stop_event.is_set():
            for ch in channels:
                if self.stop_event.is_set(): break
                try:
                    os.system(f"iwconfig {self.iface} channel {ch}")
                    time.sleep(0.5)
                except Exception as e:
                    logging.error(f"Failed to hop channel: {e}")
                    break
        logging.info("Channel hopper stopped.")
    def stop(self): self.stop_event.set()

class HandshakeSnifferThread(QThread):
    """A specialized thread to capture WPA 4-way handshakes."""
    handshake_captured = pyqtSignal(str, str) # BSSID, file_path
    log_message = pyqtSignal(str)

    def __init__(self, iface, bssid, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.bssid = bssid
        self.packets = []
        self.stop_event = Event()

    def run(self):
        self.log_message.emit(f"Starting handshake capture for BSSID: {self.bssid} on {self.iface}")
        try:
            sniff(iface=self.iface, prn=self._packet_handler, stop_filter=lambda p: self.stop_event.is_set(), filter="ether proto 0x888e")
        except Exception as e:
            self.log_message.emit(f"Handshake sniffer error: {e}")
        self.log_message.emit("Handshake sniffer stopped.")

    def _packet_handler(self, pkt):
        self.packets.append(pkt)
        # Simple check: once we have >= 4 EAPOL packets, save and stop.
        # A more robust implementation would check the actual handshake sequence.
        if len(self.packets) >= 4:
            self.log_message.emit("Potential handshake captured (4 EAPOL packets). Saving to file.")
            file_path = f"handshake_{self.bssid.replace(':', '')}.pcap"
            wrpcap(file_path, self.packets)
            self.handshake_captured.emit(self.bssid, file_path)
            self.stop()

    def stop(self):
        self.stop_event.set()
