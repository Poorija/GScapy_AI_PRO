from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QPushButton, QHBoxLayout,
    QMessageBox, QInputDialog, QHeaderView
)
from PyQt6.QtCore import Qt
import database

class AdminPanelDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin Panel - User Management")
        self.setMinimumSize(700, 500)
        self.setLayout(QVBoxLayout())

        self._create_widgets()
        self._populate_users()

    def _create_widgets(self):
        # User list widget
        self.user_tree = QTreeWidget()
        self.user_tree.setColumnCount(5)
        self.user_tree.setHeaderLabels(["ID", "Username", "Email", "Is Admin?", "Is Active?"])
        self.user_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.layout().addWidget(self.user_tree)

        # Button layout
        button_layout = QHBoxLayout()
        self.toggle_active_btn = QPushButton("Enable/Disable User")
        self.reset_password_btn = QPushButton("Reset Password")
        self.refresh_btn = QPushButton("Refresh")

        self.toggle_active_btn.clicked.connect(self._toggle_user_active_status)
        self.reset_password_btn.clicked.connect(self._reset_user_password)
        self.refresh_btn.clicked.connect(self._populate_users)

        button_layout.addWidget(self.toggle_active_btn)
        button_layout.addWidget(self.reset_password_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.refresh_btn)
        self.layout().addLayout(button_layout)

    def _get_selected_user_id(self):
        """Helper to get the user ID from the selected item in the tree."""
        selected_items = self.user_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user from the list.")
            return None
        # User ID is in the first column (index 0)
        user_id = int(selected_items[0].text(0))
        return user_id

    def _populate_users(self):
        """Fetches all users from the database and populates the tree widget."""
        self.user_tree.clear()
        try:
            users = database.get_all_users()
            for user in users:
                item = QTreeWidgetItem([
                    str(user['id']),
                    user['username'],
                    user['email'],
                    "Yes" if user['is_admin'] else "No",
                    "Yes" if user['is_active'] else "No"
                ])
                if not user['is_active']:
                    font = item.font(0)
                    font.setItalic(True)
                    for i in range(self.user_tree.columnCount()):
                        item.setFont(i, font)
                        item.setForeground(i, Qt.GlobalColor.gray)

                self.user_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load users: {e}")

    def _toggle_user_active_status(self):
        selected_items = self.user_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user from the list.")
            return

        selected_item = selected_items[0]
        user_id = int(selected_item.text(0))
        username = selected_item.text(1)
        is_currently_active = selected_item.text(4) == "Yes"

        if username == 'admin':
            QMessageBox.warning(self, "Action Denied", "The default admin account cannot be disabled.")
            return

        new_status = not is_currently_active
        action_text = "disable" if is_currently_active else "enable"

        reply = QMessageBox.question(self, "Confirm Action", f"Are you sure you want to {action_text} the user '{username}'?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.set_user_active_status(user_id, new_status)
                QMessageBox.information(self, "Success", f"User '{username}' has been {action_text}d.")
                self._populate_users()
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to update user status: {e}")

    def _reset_user_password(self):
        user_id = self._get_selected_user_id()
        if user_id is None:
            return

        username = self.user_tree.selectedItems()[0].text(1)
        new_password, ok = QInputDialog.getText(self, "Reset Password", f"Enter new password for '{username}':", QLineEdit.EchoMode.Password)

        if ok and new_password:
            try:
                database.update_user_password(user_id, new_password)
                QMessageBox.information(self, "Success", f"Password for '{username}' has been reset.")
            except Exception as e:
                 QMessageBox.critical(self, "Database Error", f"Failed to reset password: {e}")
        else:
            QMessageBox.information(self, "Cancelled", "Password reset was cancelled.")
