import copy
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QSplitter, QHBoxLayout, QComboBox, QPushButton,
    QListWidget, QPlainTextEdit, QLabel, QScrollArea, QFrame, QLineEdit,
    QTreeWidget, QMenu, QCheckBox
)
from PyQt6.QtGui import QAction
from ..utils.constants import AVAILABLE_PROTOCOLS, PACKET_TEMPLATES
from ..threads.workers import WorkerThread
from scapy.all import fuzz

class CrafterTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.packet_layers = []
        self.current_field_widgets = []
        self.tcp_flag_vars = {}

        main_layout = QVBoxLayout(self)
        top_splitter = QSplitter(self)
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
        layer_actions_layout.addWidget(fuzz_btn)
        templates_btn = QPushButton("Templates")
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

    def crafter_add_layer(self):
        proto_name = self.proto_to_add.currentText()
        if proto_name in AVAILABLE_PROTOCOLS:
            self.packet_layers.append(AVAILABLE_PROTOCOLS[proto_name]())
            self.crafter_rebuild_layer_list()
            self.layer_list_widget.setCurrentRow(len(self.packet_layers) - 1)

    def crafter_remove_layer(self):
        if (row := self.layer_list_widget.currentRow()) >= 0:
            del self.packet_layers[row]
            self.crafter_rebuild_layer_list()
            self.crafter_clear_fields_display()

    def crafter_toggle_fuzz_layer(self):
        row = self.layer_list_widget.currentRow()
        if row < 0:
            return
        layer = self.packet_layers[row]
        if hasattr(layer, 'obj'):
            self.packet_layers[row] = layer.obj
        else:
            self.packet_layers[row] = fuzz(layer)
        self.crafter_rebuild_layer_list()
        self.layer_list_widget.setCurrentRow(row)

    def crafter_rebuild_layer_list(self):
        self.layer_list_widget.clear()
        for i, layer in enumerate(self.packet_layers):
            if hasattr(layer, 'obj'):
                self.layer_list_widget.addItem(f"{i}: Fuzzed({layer.obj.name})")
            else:
                self.layer_list_widget.addItem(f"{i}: {layer.name}")
        self.crafter_update_packet_summary()

    def crafter_load_template(self, name):
        self.packet_layers = [copy.deepcopy(l) for l in PACKET_TEMPLATES[name]]
        self.crafter_rebuild_layer_list()
        if self.packet_layers:
            self.layer_list_widget.setCurrentRow(0)

    def crafter_clear_fields_display(self):
        for widget in self.current_field_widgets:
            widget.deleteLater()
        self.current_field_widgets = []

    def crafter_display_layer_fields(self, row):
        self.crafter_clear_fields_display()
        if not (0 <= row < len(self.packet_layers)):
            return
        layer = self.packet_layers[row]
        if hasattr(layer, 'obj'):
            self.scroll_area.setEnabled(False)
            label = QLabel("Fields are not editable for fuzzed layers.")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.fields_layout.addWidget(label)
            self.current_field_widgets.append(label)
            return
        self.scroll_area.setEnabled(True)
        from scapy.layers.inet import TCP
        for field in layer.fields_desc:
            container = QWidget()
            hbox = QHBoxLayout(container)
            hbox.setContentsMargins(0, 0, 0, 0)
            hbox.addWidget(QLabel(f"{field.name}:"))
            if isinstance(layer, TCP) and field.name == "flags":
                flags_widget = QWidget()
                flags_layout = QHBoxLayout(flags_widget)
                self.tcp_flag_vars = {}
                for flag in "FSRPAUEC":
                    var = QCheckBox(flag)
                    self.tcp_flag_vars[flag] = var
                    if flag in str(layer.flags):
                        var.setChecked(True)
                    var.stateChanged.connect(lambda state, l=layer: self.crafter_update_tcp_flags(l))
                    flags_layout.addWidget(var)
                hbox.addWidget(flags_widget)
            else:
                le = QLineEdit(str(getattr(layer, field.name, '')))
                le.editingFinished.connect(lambda l=layer, f=field.name, w=le: self.crafter_update_field(l, f, w.text()))
                hbox.addWidget(le)
            self.fields_layout.addWidget(container)
            self.current_field_widgets.append(container)

    def crafter_update_tcp_flags(self, layer):
        layer.flags = "".join([f for f, v in self.tcp_flag_vars.items() if v.isChecked()])
        self.crafter_update_packet_summary()

    def crafter_update_field(self, layer, field_name, text):
        try:
            setattr(layer, field_name, text)
        except:
            pass
        self.crafter_update_packet_summary()

    def build_packet(self):
        if not self.packet_layers:
            return None
        layers = []
        for l in self.packet_layers:
            if hasattr(l, 'obj'):
                layers.append(l)
            else:
                layers.append(copy.deepcopy(l))
        if not layers:
            return None
        pkt = layers[0]
        for i in range(1, len(layers)):
            pkt /= layers[i]
        return pkt

    def crafter_update_packet_summary(self):
        try:
            pkt = self.build_packet()
            summary = pkt.summary() if pkt else "No layers."
        except Exception as e:
            summary = f"Error: {e}"
        self.crafter_summary.setPlainText(summary)

    def crafter_send_packet(self):
        if not self.packet_layers:
            return
        try:
            count, interval = int(self.send_count_edit.text()), float(self.send_interval_edit.text())
        except ValueError:
            return
        self.send_results_widget.clear()
        self.send_btn.setEnabled(False)
        self.send_cancel_btn.setEnabled(True)
        self.main_window.tool_stop_event.clear()
        self.main_window.worker = WorkerThread(self.main_window._send_thread, args=(self.main_window, count, interval))
        self.main_window.worker.start()
