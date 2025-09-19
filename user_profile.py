import sys
import io
from PyQt6.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFormLayout, QMessageBox, QGroupBox, QFileDialog
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap
import database
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class UserProfileDialog(QDialog):
    """A dialog for viewing and editing user profile information."""
    def __init__(self, user_id, parent=None):
        super().__init__(parent)
        self.user_id = user_id
        self.setWindowTitle("User Profile")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.new_avatar_data = None
        self.original_email = ""

        main_layout = QVBoxLayout(self)

        # --- Avatar Section ---
        avatar_box = QGroupBox("Profile Picture")
        avatar_layout = QVBoxLayout(avatar_box)
        avatar_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.avatar_label = QLabel("No Avatar")
        self.avatar_label.setFixedSize(128, 128)
        self.avatar_label.setStyleSheet("border: 1px solid #888; border-radius: 64px;")
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar_layout.addWidget(self.avatar_label)

        change_avatar_btn = QPushButton("Change Avatar")
        change_avatar_btn.clicked.connect(self.change_avatar)
        avatar_layout.addWidget(change_avatar_btn)
        main_layout.addWidget(avatar_box)

        # --- Details Section ---
        details_box = QGroupBox("User Details")
        form_layout = QFormLayout(details_box)

        self.username_edit = QLineEdit()
        self.username_edit.setReadOnly(True)
        self.email_edit = QLineEdit()

        form_layout.addRow("Username:", self.username_edit)
        form_layout.addRow("Email:", self.email_edit)
        main_layout.addWidget(details_box)

        # --- Password Section ---
        password_box = QGroupBox("Change Password")
        password_layout = QFormLayout(password_box)
        self.new_pass_edit = QLineEdit()
        self.new_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_pass_edit.setPlaceholderText("Leave blank to keep current password")
        self.confirm_pass_edit = QLineEdit()
        self.confirm_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addRow("New Password:", self.new_pass_edit)
        password_layout.addRow("Confirm New Password:", self.confirm_pass_edit)
        main_layout.addWidget(password_box)

        # --- Action Buttons ---
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save Changes")
        self.save_btn.clicked.connect(self.save_changes)
        button_layout.addStretch()
        button_layout.addWidget(self.save_btn)
        main_layout.addLayout(button_layout)

        self.load_user_data()

    def load_user_data(self):
        """Loads user data from the database and populates the dialog."""
        user_data = database.get_user_by_id(self.user_id)
        if not user_data:
            QMessageBox.critical(self, "Error", "Could not load user data.")
            self.close()
            return

        self.username_edit.setText(user_data['username'])
        self.email_edit.setText(user_data['email'])
        self.original_email = user_data['email']

        avatar_data = user_data['avatar']
        if avatar_data:
            pixmap = QPixmap()
            pixmap.loadFromData(avatar_data)
            self.avatar_label.setPixmap(pixmap.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        else:
            self.avatar_label.setText("No Avatar")

    def change_avatar(self):
        """Opens a file dialog to select a new avatar image."""
        if not PIL_AVAILABLE:
            QMessageBox.critical(self, "Dependency Error", "The 'Pillow' library is required to change avatars. Please install it using 'pip install Pillow'.")
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Select Avatar", "", "Image Files (*.png *.jpg *.jpeg *.bmp)")
        if file_path:
            try:
                with Image.open(file_path) as img:
                    img.thumbnail((128, 128))
                    byte_array = io.BytesIO()
                    img.save(byte_array, format='PNG')
                    self.new_avatar_data = byte_array.getvalue()
                    pixmap = QPixmap()
                    pixmap.loadFromData(self.new_avatar_data)
                    self.avatar_label.setPixmap(pixmap)
            except Exception as e:
                QMessageBox.critical(self, "Image Error", f"Could not process image: {e}")

    def save_changes(self):
        """Saves all changed data to the database."""
        changes_made = False

        # --- Save Avatar ---
        if self.new_avatar_data:
            try:
                database.update_user_avatar(self.user_id, self.new_avatar_data)
                self.new_avatar_data = None
                changes_made = True
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to save avatar: {e}")
                return

        # --- Save Email ---
        new_email = self.email_edit.text().strip()
        if new_email != self.original_email:
            if not new_email:
                QMessageBox.warning(self, "Input Error", "Email cannot be empty.")
                return
            try:
                database.update_user_email(self.user_id, new_email)
                changes_made = True
            except ValueError as ve:
                QMessageBox.warning(self, "Input Error", str(ve))
                return
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to update email: {e}")
                return

        # --- Save Password ---
        new_password = self.new_pass_edit.text()
        confirm_password = self.confirm_pass_edit.text()
        if new_password:
            if len(new_password) < 8:
                QMessageBox.warning(self, "Input Error", "New password must be at least 8 characters long.")
                return
            if new_password != confirm_password:
                QMessageBox.warning(self, "Input Error", "Passwords do not match.")
                return
            try:
                database.update_user_password(self.user_id, new_password)
                changes_made = True
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to update password: {e}")
                return

        if changes_made:
            QMessageBox.information(self, "Success", "Profile updated successfully.")

        self.accept()

if __name__ == '__main__':
    print("This dialog cannot be run directly. It must be launched from the main application.")
