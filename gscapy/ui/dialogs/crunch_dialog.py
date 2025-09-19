from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QHBoxLayout, QFileDialog
)

class CrunchDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Crunch Wordlist Generator")
        layout = QVBoxLayout(self)
        form_layout = QFormLayout()

        self.min_len = QLineEdit("8")
        self.max_len = QLineEdit("8")
        self.charset = QLineEdit("abcdefghijklmnopqrstuvwxyz0123456789")
        self.output_file = QLineEdit()
        self.output_file.setReadOnly(True)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_output)

        form_layout.addRow("Min Length:", self.min_len)
        form_layout.addRow("Max Length:", self.max_len)
        form_layout.addRow("Character Set:", self.charset)

        output_layout = QHBoxLayout()
        output_layout.addWidget(self.output_file)
        output_layout.addWidget(browse_btn)
        form_layout.addRow("Output File:", output_layout)

        layout.addLayout(form_layout)

        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.accept)
        layout.addWidget(self.generate_button)

    def browse_output(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Wordlist", "", "Text Files (*.txt)", options=QFileDialog.Option.DontUseNativeDialog)
        if file_path:
            self.output_file.setText(file_path)

    def get_values(self):
        return {
            "min": self.min_len.text(),
            "max": self.max_len.text(),
            "charset": self.charset.text(),
            "outfile": self.output_file.text()
        }
