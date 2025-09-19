import logging
import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

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
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
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
