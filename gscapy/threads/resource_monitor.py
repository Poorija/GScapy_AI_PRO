import time
import logging
from threading import Event

import psutil
from PyQt6.QtCore import QThread, pyqtSignal

try:
    import GPUtil
except ImportError:
    GPUtil = None
    logging.warning("Optional GPU monitoring dependency not found. Please run 'pip install gputil'")


class ResourceMonitorThread(QThread):
    """A thread that monitors and emits system resource usage statistics."""
    stats_updated = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.stop_event = Event()
        self.is_paused = False
        self.interval = 1 # default interval

    def run(self):
        """The main loop for monitoring resources."""
        psutil.cpu_percent() # Initial call to prevent first reading from being 0.0
        last_disk_io = psutil.disk_io_counters()
        last_net_io = psutil.net_io_counters()

        while not self.stop_event.is_set():
            if self.is_paused:
                time.sleep(1)
                continue

            time.sleep(self.interval)

            if self.stop_event.is_set():
                break

            cpu_percent = psutil.cpu_percent()
            ram_percent = psutil.virtual_memory().percent

            # GPU Stats
            gpu_percent = 0
            if GPUtil:
                try:
                    gpus = GPUtil.getGPUs()
                    if gpus:
                        gpu = gpus[0] # Use the first GPU
                        gpu_percent = gpu.load * 100
                except Exception as e:
                    logging.debug(f"Could not retrieve GPU stats: {e}")


            disk_io = psutil.disk_io_counters()
            read_mb_s = (disk_io.read_bytes - last_disk_io.read_bytes) / (1024**2) / self.interval
            write_mb_s = (disk_io.write_bytes - last_disk_io.write_bytes) / (1024**2) / self.interval
            last_disk_io = disk_io

            net_io = psutil.net_io_counters()
            sent_kb_s = (net_io.bytes_sent - last_net_io.bytes_sent) / 1024 / self.interval
            recv_kb_s = (net_io.bytes_recv - last_net_io.bytes_recv) / 1024 / self.interval
            last_net_io = net_io

            stats = {
                "cpu_percent": cpu_percent,
                "ram_percent": ram_percent,
                "gpu_percent": gpu_percent,
                "disk_str": f"{read_mb_s:.2f}/{write_mb_s:.2f} MB/s",
                "net_str": f"{sent_kb_s:.2f}/{recv_kb_s:.2f} KB/s"
            }
            self.stats_updated.emit(stats)

    def set_interval(self, interval):
        self.interval = interval
        self.is_paused = False

    def pause(self):
        self.is_paused = True

    def stop(self):
        self.stop_event.set()
