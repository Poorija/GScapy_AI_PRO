import os
import copy
import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QComboBox, QPushButton,
    QListWidget, QPlainTextEdit, QScrollArea, QLabel, QLineEdit, QFrame,
    QTreeWidget, QMenu, QMessageBox, QApplication
)
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt

# Scapy and other backend imports
from scapy.all import *

# Relative imports from our new structure
from ..threads.worker import WorkerThread

# Constants will be moved later, for now, define it here
AVAILABLE_PROTOCOLS = {"Ethernet": Ether, "ARP": ARP, "IP": IP, "IPv6": IPv6, "TCP": TCP, "UDP": UDP, "ICMP": ICMP, "DNS": DNS, "Raw": Raw}
PACKET_TEMPLATES = {
    "ICMP Ping (google.com)": [IP(dst="8.8.8.8"), ICMP()],
    "DNS Query (google.com)": [IP(dst="8.8.8.8"), UDP(dport=53), DNS(rd=1, qd=DNSQR(qname="google.com"))],
    "TCP SYN (localhost:80)": [IP(dst="127.0.0.1"), TCP(dport=80, flags="S")],
    "ARP Request (who-has 192.168.1.1)": [Ether(dst="ff:ff:ff:ff:ff:ff"), ARP(pdst="192.168.1.1")],
    "NTP Query (pool.ntp.org)": [IP(dst="pool.ntp.org"), UDP(sport=123, dport=123), NTP()],
    "SNMP GetRequest (public)": [IP(dst="127.0.0.1"), UDP(), SNMP(community="public", PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID('1.3.6.1.2.1.1.1.0'))]))]
}

class CrafterTab(QWidget):
    """A widget that contains all the UI and logic for the packet crafter tab."""
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window

        # --- Attributes moved from GScapy.__init__ ---
        self.packet_layers = []
        self.current_field_widgets = []
        self.tcp_flag_vars = {}

        self._init_ui()

    def _init_ui(self):
        """Initializes the user interface of the crafter tab."""
        main_layout = QVBoxLayout(self)
        top_splitter = QSplitter(self)
        top_splitter.setOrientation(Qt.Orientation.Horizontal)
        main_layout.addWidget(top_splitter)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        top_splitter.addWidget(left_panel)

        controls_layout = QHBoxLayout()
        self.proto_to_add = QComboBox()
        self.proto_to_add.addItems(AVAILABLE_PROTOCOLS.keys())
        add_btn = QPushButton("Add")
        remove_btn = QPushButton("Remove")
        controls_layout.addWidget(self.proto_to_add)
        controls_layout.addWidget(add_btn)
        controls_layout.addWidget(remove_btn)
        left_layout.addLayout(controls_layout)

        layer_actions_layout = QHBoxLayout()
        fuzz_btn = QPushButton("Fuzz/Unfuzz Selected Layer")
        templates_btn = QPushButton("Templates")
        layer_actions_layout.addWidget(fuzz_btn)
        layer_actions_layout.addWidget(templates_btn)
        left_layout.addLayout(layer_actions_layout)

        self.layer_list_widget = QListWidget()
        left_layout.addWidget(self.layer_list_widget)
        left_layout.addWidget(QLabel("Packet Summary:"))
        self.crafter_summary = QPlainTextEdit()
        self.crafter_summary.setReadOnly(True)
        left_layout.addWidget(self.crafter_summary)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.addWidget(QLabel("Layer Fields"))
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.fields_widget = QWidget()
        self.fields_layout = QVBoxLayout(self.fields_widget)
        self.scroll_area.setWidget(self.fields_widget)
        right_layout.addWidget(self.scroll_area)
        top_splitter.addWidget(right_panel)
        top_splitter.setSizes([300, 400])

        send_frame = QFrame()
        send_frame.setFrameShape(QFrame.Shape.StyledPanel)
        main_layout.addWidget(send_frame)
        send_layout = QVBoxLayout(send_frame)
        send_controls_layout = QHBoxLayout()
        send_controls_layout.addWidget(QLabel("Count:"))
        self.send_count_edit = QLineEdit("1")
        send_controls_layout.addWidget(self.send_count_edit)
        send_controls_layout.addWidget(QLabel("Interval:"))
        self.send_interval_edit = QLineEdit("0.1")
        send_controls_layout.addWidget(self.send_interval_edit)
        self.send_btn = QPushButton("Send Packet(s)")
        self.send_cancel_btn = QPushButton("Cancel")
        self.send_cancel_btn.setEnabled(False)
        send_controls_layout.addWidget(self.send_btn)
        send_controls_layout.addWidget(self.send_cancel_btn)
        send_layout.addLayout(send_controls_layout)
        self.send_results_widget = QTreeWidget()
        self.send_results_widget.setColumnCount(3)
        self.send_results_widget.setHeaderLabels(["No.", "Sent", "Received"])
        send_layout.addWidget(self.send_results_widget)
        send_layout.addWidget(self.main_window._create_export_button(self.send_results_widget))

        # --- Connect Signals ---
        add_btn.clicked.connect(self.crafter_add_layer)
        remove_btn.clicked.connect(self.crafter_remove_layer)
        self.layer_list_widget.currentRowChanged.connect(self.crafter_display_layer_fields)

        templates_menu = QMenu(self)
        for name in PACKET_TEMPLATES.keys():
            action = QAction(name, self)
            action.triggered.connect(lambda checked, n=name: self.crafter_load_template(n))
            templates_menu.addAction(action)
        templates_btn.setMenu(templates_menu)

        self.send_btn.clicked.connect(self.crafter_send_packet)
        self.send_cancel_btn.clicked.connect(self.main_window.cancel_tool)
        fuzz_btn.clicked.connect(self.crafter_toggle_fuzz_layer)

    def build_packet(self):
        """Builds a Scapy packet from the current layer list and field widgets."""
        if not self.packet_layers:
            return None

        focused_widget = QApplication.instance().focusWidget()
        if focused_widget:
            focused_widget.clearFocus()

        layers_to_build = copy.deepcopy(self.packet_layers)
        if not layers_to_build:
            return None

        packet = layers_to_build[0]
        for layer_instance in layers_to_build[1:]:
            packet /= layer_instance

        for i, layer in enumerate(packet.layers()):
            for widget in self.current_field_widgets:
                if widget.property("layer_index") == i:
                    field_name = widget.property("field_name")

                    if isinstance(layer, TCP) and field_name == 'flags':
                        flags = ""
                        for flag, var in self.tcp_flag_vars.items():
                            if var.isChecked():
                                flags += flag[0]
                        setattr(layer, field_name, flags)
                        continue

                    value = ""
                    if isinstance(widget, QLineEdit):
                        value = widget.text()
                    elif isinstance(widget, QComboBox):
                        value = widget.currentText()

                    if value:
                        try:
                            evaluated_value = eval(value, {'__builtins__': {}}, scapy.all.__dict__)
                            setattr(layer, field_name, evaluated_value)
                        except (NameError, SyntaxError, TypeError):
                            setattr(layer, field_name, value)
                        except Exception as e:
                            logging.warning(f"Could not set field {field_name} on layer {layer.name} to value '{value}': {e}")
        return packet

    def crafter_update_summary(self):
        """Updates the packet summary text edit."""
        packet = self.build_packet()
        if packet:
            try:
                summary = packet.show(dump=True)
                self.crafter_summary.setPlainText(summary)
            except Exception as e:
                self.crafter_summary.setPlainText(f"Error displaying summary: {e}")
                logging.error(f"Error generating packet summary: {e}", exc_info=True)
        else:
            self.crafter_summary.clear()

    def crafter_add_layer(self):
        """Adds a new protocol layer to the packet."""
        proto_name = self.proto_to_add.currentText()
        if proto_name in AVAILABLE_PROTOCOLS:
            layer_class = AVAILABLE_PROTOCOLS[proto_name]
            self.packet_layers.append(layer_class())
            self.layer_list_widget.addItem(proto_name)
            self.layer_list_widget.setCurrentRow(self.layer_list_widget.count() - 1)
            self.crafter_update_summary()

    def crafter_remove_layer(self):
        """Removes the selected protocol layer from the packet."""
        current_row = self.layer_list_widget.currentRow()
        if current_row >= 0:
            self.layer_list_widget.takeItem(current_row)
            del self.packet_layers[current_row]
            self.crafter_update_summary()

    def crafter_display_layer_fields(self, row):
        """Displays the fields for the currently selected layer."""
        for widget in self.current_field_widgets:
            widget.deleteLater()
        self.current_field_widgets = []
        self.tcp_flag_vars = {}

        if row < 0 or row >= len(self.packet_layers):
            return

        layer = self.packet_layers[row]
        for field in layer.fields_desc:
            field_name = field.name
            default_value = layer.get_field(field_name).i2repr(layer, getattr(layer, field_name))

            if isinstance(layer, TCP) and field_name == 'flags':
                widget = self._create_tcp_flags_widget(default_value)
                widget.setProperty("layer_index", row)
                widget.setProperty("field_name", field_name)
                self.fields_layout.addWidget(widget)
                self.current_field_widgets.append(widget)
                continue

            field_layout = QHBoxLayout()
            field_layout.addWidget(QLabel(f"{field_name}:"))

            # Use ComboBox for fields with predefined values
            if hasattr(field, 'enum') and field.enum:
                edit_widget = QComboBox()
                # Add a blank default option
                edit_widget.addItem("")
                for val, name in field.enum.items():
                    edit_widget.addItem(f"{name} ({val})", val)
                # Try to set the current value
                edit_widget.setCurrentText(default_value)
            else:
                edit_widget = QLineEdit(str(default_value))

            edit_widget.setProperty("layer_index", row)
            edit_widget.setProperty("field_name", field_name)
            edit_widget.editingFinished.connect(self.crafter_update_summary)
            if isinstance(edit_widget, QComboBox):
                edit_widget.currentTextChanged.connect(self.crafter_update_summary)

            field_layout.addWidget(edit_widget)
            self.fields_layout.addLayout(field_layout)
            self.current_field_widgets.append(edit_widget)

        self.fields_layout.addStretch()

    def _create_tcp_flags_widget(self, current_flags):
        """Creates a widget with checkboxes for TCP flags."""
        flags_box = QFrame()
        flags_box.setFrameShape(QFrame.Shape.StyledPanel)
        flags_layout = QHBoxLayout(flags_box)
        flags = {"FIN": "F", "SYN": "S", "RST": "R", "PSH": "P", "ACK": "A", "URG": "U", "ECE": "E", "CWR": "C"}
        for name, flag_char in flags.items():
            checkbox = QCheckBox(name)
            checkbox.setChecked(flag_char in current_flags)
            checkbox.stateChanged.connect(self.crafter_update_summary)
            self.tcp_flag_vars[name] = checkbox
            flags_layout.addWidget(checkbox)
        return flags_box

    def crafter_load_template(self, template_name):
        """Loads a packet template into the crafter."""
        if template_name in PACKET_TEMPLATES:
            self.packet_layers = copy.deepcopy(PACKET_TEMPLATES[template_name])
            self.layer_list_widget.clear()
            for layer in self.packet_layers:
                self.layer_list_widget.addItem(layer.name)
            self.layer_list_widget.setCurrentRow(0)
            self.crafter_update_summary()

    def crafter_toggle_fuzz_layer(self):
        """Toggles the fuzz() function on the selected layer."""
        row = self.layer_list_widget.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Warning", "Please select a layer to fuzz.")
            return

        layer_item = self.layer_list_widget.item(row)
        layer_instance = self.packet_layers[row]

        # Check if the layer is already fuzzed
        if "fuzz" in layer_item.text():
            # Unfuzz: Re-create the original layer instance
            original_class = type(layer_instance.underlayer)
            self.packet_layers[row] = original_class()
            layer_item.setText(original_class.name)
        else:
            # Fuzz: Wrap the current layer instance in fuzz()
            self.packet_layers[row] = fuzz(layer_instance)
            layer_item.setText(f"fuzz({layer_instance.name})")

        self.crafter_display_layer_fields(row)
        self.crafter_update_summary()

    def crafter_send_packet(self):
        """Builds the packet from the crafter and sends it."""
        if self.main_window.is_tool_running:
            QMessageBox.warning(self, "Busy", "Another tool is already running.")
            return

        packet = self.build_packet()
        if not packet:
            QMessageBox.critical(self, "Error", "Could not build packet. Check fields for errors.")
            return

        try:
            count = int(self.send_count_edit.text())
            interval = float(self.send_interval_edit.text())
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid count or interval.")
            return

        self.main_window.is_tool_running = True
        self.send_btn.setEnabled(False)
        self.send_cancel_btn.setEnabled(True)
        self.main_window.tool_stop_event.clear()

        send_func = sendp if packet.haslayer(Ether) else send

        def send_thread():
            q = self.main_window.tool_results_queue
            iface = self.main_window.get_selected_iface()
            try:
                # Note: srloop doesn't have a stop_event. We'd need to implement a custom loop
                # for cancellable sending. For now, it will run to completion.
                ans, unans = srloop(packet, count=count, inter=interval, timeout=2, iface=iface)
                q.put(('send_results', ans, unans))
            except Exception as e:
                logging.error("Exception in send thread", exc_info=True)
                q.put(('error', "Send Error", str(e)))
            finally:
                q.put(('tool_finished', 'sender'))

        # The WorkerThread needs to be handled by the main window to be tracked
        self.main_window.worker = WorkerThread(send_thread)
        self.main_window.active_threads.append(self.main_window.worker)
        self.main_window.worker.start()
