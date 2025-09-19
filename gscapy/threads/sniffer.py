import logging
import queue
from threading import Event
from multiprocessing import Process, Queue

from PyQt6.QtCore import QThread, pyqtSignal

# This will cause an error if not handled carefully, as scapy is a large import.
# It's better to import it inside the process where it's needed.
# from scapy.all import sniff, bytes

def sniffer_process_target(queue, iface, bpf_filter):
    """
    This function runs in a separate process. It sniffs packets and puts them
    into a multiprocessing.Queue. This completely isolates the blocking
    sniff() call from the main GUI application.
    """
    # Import scapy here to avoid issues with multiprocessing on some platforms.
    from scapy.all import sniff, bytes

    try:
        # The packet handler now simply puts the raw packet into the queue
        def packet_handler(packet):
            queue.put(bytes(packet))

        # We don't need a stop_filter anymore, as the process will be terminated directly.
        sniff(prn=packet_handler, iface=iface, filter=bpf_filter, store=False)
    except Exception as e:
        logging.error(f"Critical error in sniffer process: {e}", exc_info=True)


class SnifferThread(QThread):
    """
    This QThread does not sniff itself. Instead, it manages a separate
    multiprocessing.Process for sniffing to prevent the GUI from freezing.
    It communicates with the main thread exclusively via thread-safe Qt signals
    that carry raw bytes, not complex objects.
    """
    packet_bytes_received = pyqtSignal(bytes)

    def __init__(self, iface, bpf_filter, parent=None):
        super().__init__(parent)
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.process = None
        self.queue = None
        self.stop_event = Event()

    def run(self):
        self.queue = Queue()
        self.process = Process(
            target=sniffer_process_target,
            args=(self.queue, self.iface, self.bpf_filter)
        )
        self.process.start()
        logging.info(f"Sniffer process started with PID: {self.process.pid}")

        while not self.stop_event.is_set():
            try:
                # Use a timeout on the queue to remain responsive
                pkt_bytes = self.queue.get(timeout=0.5)
                # Emit the raw bytes. Reconstruction will happen in the main thread.
                self.packet_bytes_received.emit(pkt_bytes)
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error in SnifferThread queue loop: {e}")

        logging.info("SnifferThread manager loop stopped.")


    def stop(self):
        logging.info("Stopping sniffer manager thread and process...")
        self.stop_event.set()
        if self.process and self.process.is_alive():
            logging.info(f"Terminating sniffer process {self.process.pid}...")
            self.process.terminate()
            self.process.join(timeout=2) # Wait for the process to terminate
            if self.process.is_alive():
                logging.warning(f"Sniffer process {self.process.pid} did not terminate gracefully, killing.")
                self.process.kill()
            logging.info("Sniffer process stopped.")
