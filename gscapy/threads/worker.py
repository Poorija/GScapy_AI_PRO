from PyQt6.QtCore import QThread

class WorkerThread(QThread):
    """A generic QThread to run any function in the background."""
    def __init__(self, target, args=()):
        super().__init__()
        self.target = target
        self.args = args

    def run(self):
        """Executes the target function with its arguments."""
        try:
            self.target(*self.args)
        except Exception as e:
            # It's good practice to log exceptions that happen in threads.
            # We'll need to figure out a proper logging strategy for modules later.
            print(f"Error in worker thread: {e}")
