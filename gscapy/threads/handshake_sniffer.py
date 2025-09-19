from threading import Event
from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import sniff, wrpcap

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
