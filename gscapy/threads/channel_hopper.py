import os
import sys
import time
import logging
from threading import Event

from PyQt6.QtCore import QThread

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
                if self.stop_event.is_set():
                    break
                try:
                    # Using subprocess is safer than os.system
                    # We can also handle stdout/stderr better if needed.
                    os.system(f"iwconfig {self.iface} channel {ch}")
                    time.sleep(0.5)
                except Exception as e:
                    logging.error(f"Failed to hop channel: {e}")
                    # If one channel hop fails, it's likely the interface is down
                    # or permissions are wrong, so we should stop.
                    break

        logging.info("Channel hopper stopped.")

    def stop(self):
        self.stop_event.set()
