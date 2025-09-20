from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QPushButton, QHBoxLayout,
    QMessageBox, QInputDialog, QHeaderView, QGroupBox, QFormLayout, QLineEdit,
    QSplitter, QWidget, QComboBox
)
from PyQt6.QtCore import Qt
import database

class AdminPanelDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin Panel - User Management")
        self.setMinimumSize(800, 600)
        self.main_layout = QVBoxLayout(self)
        self.original_username = ""
        self.original_email = ""

        self._create_widgets()
        self._populate_users()

    def _create_widgets(self):
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        self.user_tree = QTreeWidget()
        self.user_tree.setColumnCount(5)
        self.user_tree.setHeaderLabels(["ID", "Username", "Email", "Is Admin?", "Is Active?"])
        self.user_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.user_tree.currentItemChanged.connect(self._on_user_selected)
        main_splitter.addWidget(self.user_tree)

        bottom_pane = QWidget()
        bottom_layout = QHBoxLayout(bottom_pane)

        actions_box = QGroupBox("User Actions")
        actions_layout = QVBoxLayout(actions_box)
        self.toggle_active_btn = QPushButton("Enable/Disable User")
        self.reset_password_btn = QPushButton("Reset User Password")
        actions_layout.addWidget(self.toggle_active_btn)
        actions_layout.addWidget(self.reset_password_btn)
        actions_layout.addStretch()
        bottom_layout.addWidget(actions_box)

        profile_box = QGroupBox("Edit User Profile")
        profile_form = QFormLayout(profile_box)
        self.username_edit = QLineEdit()
        self.email_edit = QLineEdit()
        self.full_name_edit = QLineEdit()
        self.age_edit = QLineEdit()
        self.job_title_edit = QComboBox()
        self.job_title_edit.addItems(["Red Team", "Blue Team", "Purple Team", "IT Team", "Network Team", "Manager", "Other"])
        self.job_title_edit.setEditable(True)
        self.save_profile_btn = QPushButton("Save Profile Changes")

        profile_form.addRow("Username:", self.username_edit)
        profile_form.addRow("Email:", self.email_edit)
        profile_form.addRow("Full Name:", self.full_name_edit)
        profile_form.addRow("Age:", self.age_edit)
        profile_form.addRow("Job Title:", self.job_title_edit)
        profile_form.addRow(self.save_profile_btn)
        bottom_layout.addWidget(profile_box, 1)

        main_splitter.addWidget(bottom_pane)
        main_splitter.setSizes([400, 200])
        self.main_layout.addWidget(main_splitter)

        # --- History Section ---
        history_box = QGroupBox("User Activity Log")
        history_layout = QVBoxLayout(history_box)

        history_controls_layout = QHBoxLayout()
        history_controls_layout.addWidget(QLabel("View history for:"))
        self.history_user_combo = QComboBox()
        history_controls_layout.addWidget(self.history_user_combo)
        self.delete_log_btn = QPushButton("Delete Selected Log Entry")
        history_controls_layout.addWidget(self.delete_log_btn)
        history_controls_layout.addStretch()
        history_layout.addLayout(history_controls_layout)

        self.history_tree = QTreeWidget()
        self.history_tree.setColumnCount(3)
        self.history_tree.setHeaderLabels(["Date/Time", "Action", "Summary"])
        self.history_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.history_tree.header().setStretchLastSection(True)
        history_layout.addWidget(self.history_tree)

        self.main_layout.addWidget(history_box)
        # --- End History Section ---


        self.refresh_btn = QPushButton("Refresh User List")
        self.main_layout.addWidget(self.refresh_btn)

        self.toggle_active_btn.clicked.connect(self._toggle_user_active_status)
        self.reset_password_btn.clicked.connect(self._reset_user_password)
        self.save_profile_btn.clicked.connect(self._save_profile)
        self.refresh_btn.clicked.connect(self._populate_users)
        self.history_user_combo.currentIndexChanged.connect(self._on_history_user_changed)
        self.delete_log_btn.clicked.connect(self._delete_selected_log)

        self._set_editing_widgets_enabled(False)

    def _get_selected_user_id(self):
        selected_items = self.user_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a user from the list.")
            return None
        return int(selected_items[0].text(0))

    def _set_editing_widgets_enabled(self, enabled):
        self.toggle_active_btn.setEnabled(enabled)
        self.reset_password_btn.setEnabled(enabled)
        self.username_edit.setEnabled(enabled)
        self.email_edit.setEnabled(enabled)
        self.full_name_edit.setEnabled(enabled)
        self.age_edit.setEnabled(enabled)
        self.job_title_edit.setEnabled(enabled)
        self.save_profile_btn.setEnabled(enabled)

    def _clear_profile_fields(self):
        self.username_edit.clear()
        self.email_edit.clear()
        self.full_name_edit.clear()
        self.age_edit.clear()
        self.job_title_edit.setCurrentIndex(-1)
        self.job_title_edit.clearEditText()

    def _populate_users(self):
        self.user_tree.clear()
        self.history_user_combo.clear()
        self.history_tree.clear()
        self._clear_profile_fields()
        self._set_editing_widgets_enabled(False)
        try:
            users = database.get_all_users()
            self.history_user_combo.addItem("Select a user...", -1)
            for user in users:
                self.history_user_combo.addItem(user['username'], user['id'])
                item = QTreeWidgetItem([
                    str(user['id']),
                    user['username'],
                    user['email'],
                    "Yes" if user['is_admin'] else "No",
                    "Yes" if user['is_active'] else "No"
                ])
                item.setData(0, Qt.ItemDataRole.UserRole, dict(user))
                if not user['is_active']:
                    font = item.font(0)
                    font.setItalic(True)
                    for i in range(self.user_tree.columnCount()):
                        item.setFont(i, font)
                        item.setForeground(i, Qt.GlobalColor.gray)
                self.user_tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to load users: {e}")

    def _on_user_selected(self, current, previous):
        if not current:
            self._clear_profile_fields()
            self._set_editing_widgets_enabled(False)
            return

        self._set_editing_widgets_enabled(True)
        profile_data = current.data(0, Qt.ItemDataRole.UserRole)

        self.username_edit.setText(profile_data.get("username", ""))
        self.email_edit.setText(profile_data.get("email", ""))
        self.full_name_edit.setText(profile_data.get("full_name") or "")
        age = profile_data.get("age")
        self.age_edit.setText(str(age) if age is not None else "")
        self.job_title_edit.setCurrentText(profile_data.get("job_title") or "")

        self.original_username = profile_data.get("username", "")
        self.original_email = profile_data.get("email", "")

        if self.original_username == 'admin':
            self.toggle_active_btn.setEnabled(False)
            self.username_edit.setReadOnly(True)
        else:
            self.toggle_active_btn.setEnabled(True)
            self.username_edit.setReadOnly(False)

    def _save_profile(self):
        user_id = self._get_selected_user_id()
        if user_id is None: return

        try:
            # Handle username change
            new_username = self.username_edit.text().strip()
            if new_username != self.original_username:
                database.update_user_username_by_admin(user_id, new_username)

            # Handle email change
            new_email = self.email_edit.text().strip()
            if new_email != self.original_email:
                database.update_user_email_by_admin(user_id, new_email)

            # Handle other profile info
            full_name = self.full_name_edit.text()
            age = self.age_edit.text()
            job_title = self.job_title_edit.currentText()
            database.update_user_profile(user_id, full_name, age, job_title)

            QMessageBox.information(self, "Success", "User profile updated successfully.")
            self._populate_users()
        except ValueError as ve:
            QMessageBox.warning(self, "Input Error", str(ve))
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Failed to update profile: {e}")

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

    def _on_history_user_changed(self, index):
        """Loads and displays the activity log for the selected user."""
        self.history_tree.clear()
        user_id = self.history_user_combo.itemData(index)

        if user_id is None or user_id == -1:
            return

        try:
            history_records = database.get_history_for_user(user_id)
            for record in history_records:
                timestamp = record['timestamp']
                action = record['activity_type']
                details = record['details']
                full_data = record['full_data']
                log_id = record['id']

                main_item = QTreeWidgetItem([timestamp, action, details])
                main_item.setData(0, Qt.ItemDataRole.UserRole, log_id) # Store log ID
                self.history_tree.addTopLevelItem(main_item)

                if full_data:
                    try:
                        pretty_json = json.dumps(json.loads(full_data), indent=2)
                        child_item = QTreeWidgetItem(["Full Data:", pretty_json])
                        main_item.addChild(child_item)
                    except (json.JSONDecodeError, TypeError):
                        child_item = QTreeWidgetItem(["Raw Data:", full_data])
                        main_item.addChild(child_item)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"Could not load history for selected user: {e}")

    def _delete_selected_log(self):
        """Deletes the selected log entry from the database."""
        selected_items = self.history_tree.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a log entry to delete.")
            return

        log_item = selected_items[0]
        # Traverse up to the top-level item if a child is selected
        while log_item.parent():
            log_item = log_item.parent()

        log_id = log_item.data(0, Qt.ItemDataRole.UserRole)
        if log_id is None:
            QMessageBox.critical(self, "Error", "Could not identify the selected log entry.")
            return

        reply = QMessageBox.question(self, "Confirm Deletion", "Are you sure you want to permanently delete this log entry?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            try:
                database.delete_history_record(log_id)
                QMessageBox.information(self, "Success", "Log entry deleted.")
                # Refresh the view
                self._on_history_user_changed(self.history_user_combo.currentIndex())
            except Exception as e:
                QMessageBox.critical(self, "Database Error", f"Failed to delete log entry: {e}")
