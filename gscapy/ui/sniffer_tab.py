import os
import time
import logging
from threading import Lock

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QHeaderView, QFrame, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QSplitter, QTextBrowser,
    QTreeWidgetItem, QFileDialog, QMessageBox
)
from PyQt6.QtGui import QIcon, QFont
from PyQt6.QtCore import QTimer, Qt

# Scapy and other backend imports
from scapy.all import hexdump, Ether, IP, ARP, rdpcap, wrpcap

# Relative imports from our new structure
from ..threads.sniffer import SnifferThread

# Constants will be moved later, for now, define it here
COMMON_FILTERS = [
    "", "tcp", "udp", "arp", "icmp",
    "port 80", "port 443", "udp port 53", "tcp port 22",
    "host 8.8.8.8", "net 192.168.1.0/24", "vlan"
]

class SnifferTab(QWidget):
    """A widget that contains all the UI and logic for the packet sniffer tab."""
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.icons_dir = self.main_window.icons_dir

        # --- Attributes moved from GScapy.__init__ ---
        self.packets_data = []
        self.sniffer_thread = None
        self.sniffer_packet_buffer = []
        self.sniffer_buffer_lock = Lock()

        self._init_ui()

        # --- Timer setup moved from GScapy.__init__ ---
        self.sniffer_ui_update_timer = QTimer(self)
        self.sniffer_ui_update_timer.timeout.connect(self._update_sniffer_display)
        self.sniffer_ui_update_timer.start(500) # Update every 500ms

    def _init_ui(self):
        """Initializes the user interface of the sniffer tab."""
        layout = QVBoxLayout(self)

        # Create the results widget first
        self.packet_list_widget = QTreeWidget()
        self.packet_list_widget.setColumnCount(6)
        self.packet_list_widget.setHeaderLabels(["No.", "Time", "Source", "Destination", "Protocol", "Length"])
        header = self.packet_list_widget.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)

        # --- Control Panel ---
        control_panel = QFrame()
        control_panel.setObjectName("controlPanel")
        control_panel.setStyleSheet("#controlPanel { border: 1px solid #444; border-radius: 8px; }")
        control_layout = QHBoxLayout(control_panel)
        control_layout.setContentsMargins(10, 10, 10, 10)
        control_layout.setSpacing(10)

        self.start_sniff_btn = QPushButton(QIcon(os.path.join(self.icons_dir, "search.svg")), " Start Sniffing")
        self.stop_sniff_btn = QPushButton(QIcon(os.path.join(self.icons_dir, "square.svg")), " Stop Sniffing")
        self.stop_sniff_btn.setEnabled(False)
        self.clear_sniff_btn = QPushButton("Clear")
        export_btn = self.main_window._create_export_button(self.packet_list_widget)

        control_layout.addWidget(self.start_sniff_btn)
        control_layout.addWidget(self.stop_sniff_btn)
        control_layout.addWidget(self.clear_sniff_btn)
        control_layout.addWidget(export_btn)
        control_layout.addStretch(1)

        control_layout.addWidget(QLabel("BPF Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp and port 80")
        control_layout.addWidget(self.filter_input, 2)

        control_layout.addWidget(QLabel("Common:"))
        self.common_filter_combo = QComboBox()
        self.common_filter_combo.addItems(COMMON_FILTERS)
        self.common_filter_combo.textActivated.connect(self.filter_input.setText)
        control_layout.addWidget(self.common_filter_combo)
        layout.addWidget(control_panel)

        # Main splitter for top (list) and bottom (details)
        main_splitter = QSplitter(self)
        main_splitter.setOrientation(Qt.Orientation.Vertical)
        main_splitter.addWidget(self.packet_list_widget)

        # Bottom splitter for details tree and hex view
        bottom_splitter = QSplitter(main_splitter)
        bottom_splitter.setOrientation(Qt.Orientation.Vertical)

        self.packet_details_tree = QTreeWidget()
        self.packet_details_tree.setHeaderLabels(["Field", "Value"])
        details_header = self.packet_details_tree.header()
        details_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        details_header.setStretchLastSection(True)
        bottom_splitter.addWidget(self.packet_details_tree)

        self.packet_hex_view = QTextBrowser()
        self.packet_hex_view.setReadOnly(True)
        self.packet_hex_view.setFont(QFont("Courier New", 10))
        bottom_splitter.addWidget(self.packet_hex_view)

        bottom_splitter.setSizes([200, 100])

        main_splitter.addWidget(bottom_splitter)
        main_splitter.setSizes([400, 300])
        layout.addWidget(main_splitter)

        # --- Connect Signals ---
        self.start_sniff_btn.clicked.connect(self.start_sniffing)
        self.stop_sniff_btn.clicked.connect(self.stop_sniffing)
        self.clear_sniff_btn.clicked.connect(self.clear_sniffer_display)
        self.packet_list_widget.currentItemChanged.connect(self.display_packet_details)

    # --- Methods moved from GScapy ---
    def start_sniffing(self):
        """Starts the packet sniffer thread."""
        self.start_sniff_btn.setEnabled(False)
        self.stop_sniff_btn.setEnabled(True)
        self.clear_sniffer_display()
        iface = self.main_window.get_selected_iface()
        bpf_filter = self.filter_input.text()
        self.sniffer_thread = SnifferThread(iface=iface, bpf_filter=bpf_filter, parent=self)
        self.sniffer_thread.packet_bytes_received.connect(self._handle_packet_bytes)
        self.sniffer_thread.finished.connect(self._on_sniffer_finished)
        self.sniffer_thread.start()
        self.main_window.status_bar.showMessage(f"Sniffing on interface: {iface or 'default'}...")

    def _handle_packet_bytes(self, pkt_bytes):
        """Reconstructs a packet from bytes and adds it to a buffer for batch updating."""
        try:
            packet = Ether(pkt_bytes)
            with self.sniffer_buffer_lock:
                self.sniffer_packet_buffer.append(packet)
        except Exception as e:
            logging.error(f"Failed to reconstruct or buffer packet: {e}")

    def stop_sniffing(self):
        """Signals the packet sniffer thread to stop."""
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.stop_sniff_btn.setEnabled(False)
            self.main_window.status_bar.showMessage("Stopping sniffer...")
            self.sniffer_thread.stop()

    def _on_sniffer_finished(self):
        """Handles cleanup after the sniffer thread has terminated."""
        self.start_sniff_btn.setEnabled(True)
        self.stop_sniff_btn.setEnabled(False)
        self.main_window.status_bar.showMessage("Sniffing stopped.")
        self.sniffer_thread = None

    def _update_sniffer_display(self):
        """Periodically called by a timer to batch-update the sniffer GUI."""
        with self.sniffer_buffer_lock:
            if not self.sniffer_packet_buffer:
                return
            packets_to_add = self.sniffer_packet_buffer
            self.sniffer_packet_buffer = []

        items_to_add = []
        for packet in packets_to_add:
            self.packets_data.append(packet)
            n = len(self.packets_data)
            try:
                pt = f"{time.strftime('%H:%M:%S', time.localtime(packet.time))}.{int(packet.time * 1000) % 1000}"
                src = packet[IP].src if packet.haslayer(IP) else (packet[ARP].psrc if packet.haslayer(ARP) else "N/A")
                dst = packet[IP].dst if packet.haslayer(IP) else (packet[ARP].pdst if packet.haslayer(ARP) else "N/A")
                proto = packet.summary().split('/')[1].strip() if '/' in packet.summary() else "N/A"
                length = len(packet)
                item_data = [str(n), pt, src, dst, proto, str(length)]
            except Exception:
                item_data = [str(n), "Parse Error", "N/A", "N/A", "N/A", "N/A"]

            items_to_add.append(QTreeWidgetItem(item_data))

        self.packet_list_widget.addTopLevelItems(items_to_add)
        self.packet_list_widget.scrollToBottom()

    def display_packet_details(self, current_item, previous_item):
        """Displays the selected packet's details in the tree and hex views."""
        self.packet_details_tree.clear()
        self.packet_hex_view.clear()
        if not current_item:
            return
        try:
            packet_index = int(current_item.text(0)) - 1
            if not (0 <= packet_index < len(self.packets_data)):
                return
            packet = self.packets_data[packet_index]
            self.packet_hex_view.setText(hexdump(packet, dump=True))
            layer_counts = {}
            current_layer = packet
            while current_layer:
                layer_name_raw = current_layer.name
                if layer_name_raw in layer_counts:
                    layer_counts[layer_name_raw] += 1
                    layer_name = f"{layer_name_raw} #{layer_counts[layer_name_raw]}"
                else:
                    layer_counts[layer_name_raw] = 1
                    layer_name = layer_name_raw
                layer_item = QTreeWidgetItem([layer_name])
                self.packet_details_tree.addTopLevelItem(layer_item)
                for field in current_layer.fields_desc:
                    field_name = field.name
                    try:
                        val = current_layer.getfieldval(field_name)
                        display_value = field.i2repr(current_layer, val)
                    except Exception as e:
                        logging.warning(f"Could not display field '{field_name}': {e}")
                        display_value = "Error reading value"
                    field_item = QTreeWidgetItem([field_name, display_value])
                    layer_item.addChild(field_item)
                layer_item.setExpanded(True)
                current_layer = current_layer.payload
            self.packet_details_tree.resizeColumnToContents(0)
        except (ValueError, IndexError):
            self.packet_details_tree.addTopLevelItem(QTreeWidgetItem(["Error displaying packet details."]))
        except Exception as e:
            logging.error(f"Unexpected error in display_packet_details: {e}", exc_info=True)
            self.packet_details_tree.addTopLevelItem(QTreeWidgetItem([f"Error: {e}"]))

    def clear_sniffer_display(self):
        self.packet_list_widget.clear()
        self.packet_details_tree.clear()
        self.packet_hex_view.clear()
        self.packets_data.clear()
        logging.info("Sniffer display cleared.")

    def save_packets(self):
        """Saves captured packets to a pcap file."""
        if not self.packets_data:
            QMessageBox.information(self, "Info", "There are no packets to save.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Packets", "", "Pcap Files (*.pcap *.pcapng);;All Files (*)", options=QFileDialog.Option.DontUseNativeDialog)
        if file_path:
            try:
                wrpcap(file_path, self.packets_data)
                self.main_window.status_bar.showMessage(f"Saved {len(self.packets_data)} packets to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save packets: {e}")

    def load_packets(self):
        """Loads packets from a pcap file into the sniffer view."""
        if self.packets_data and QMessageBox.question(self, "Confirm", "Clear captured packets?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.No:
            return
        self.clear_sniffer_display()
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Packets", "", "Pcap Files (*.pcap *.pcapng);;All Files (*)", options=QFileDialog.Option.DontUseNativeDialog)
        if file_path:
            try:
                loaded_packets = rdpcap(file_path)
                # Use the batch update mechanism to add loaded packets
                with self.sniffer_buffer_lock:
                    self.sniffer_packet_buffer.extend(loaded_packets)
                self.main_window.status_bar.showMessage(f"Loaded {len(loaded_packets)} packets from {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load packets: {e}")
