import numpy as np
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt

try:
    import pyqtgraph as pg
    PYQTGRAPH_AVAILABLE = True
except ImportError:
    PYQTGRAPH_AVAILABLE = False
    pg = None

if PYQTGRAPH_AVAILABLE:
    class ResourceGraph(pg.PlotWidget):
        """A custom PlotWidget for displaying a scrolling resource graph."""
        def __init__(self, parent=None, title="", color='c', text_color=(221, 221, 221)):
            super().__init__(parent)
            self.setMouseEnabled(x=False, y=False)
            self.setMenuEnabled(False)
            self.getPlotItem().hideAxis('bottom')
            self.getPlotItem().hideAxis('left')
            self.setBackground(background=(40, 44, 52)) # Default to dark theme background
            self.setRange(yRange=(0, 100), padding=0)

            self.data = np.zeros(60) # 60 data points for a 1-minute history at 1s refresh
            self.curve = self.plot(self.data, pen=pg.mkPen(color, width=2))

            self.text = pg.TextItem(text="", color=text_color, anchor=(0.5, 0.5))
            self.text.setPos(30, 50) # Position it in the middle of the graph
            self.addItem(self.text)

        def update_data(self, new_value):
            """Shifts the data and adds a new value to the end."""
            self.data[:-1] = self.data[1:]
            self.data[-1] = new_value
            self.curve.setData(self.data)
            self.text.setText(f"{new_value:.0f}%")
else:
    # If pyqtgraph is not available, create a dummy widget to avoid crashing.
    class ResourceGraph(QWidget):
        def __init__(self, parent=None, title="", color='c', text_color=(221, 221, 221)):
            super().__init__(parent)
            layout = QVBoxLayout(self)
            label = QLabel("Graphs disabled\n(pyqtgraph not installed)")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setStyleSheet("color: #888;")
            layout.addWidget(label)
            self.setMinimumHeight(60)
            # Make the placeholder visible
            self.setStyleSheet("background-color: #2d313a; border: 1px solid #444;")

        def update_data(self, new_value):
            """Dummy method, does nothing."""
            pass
