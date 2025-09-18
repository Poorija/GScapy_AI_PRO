import sys
import random
from PyQt6.QtWidgets import (
    QApplication, QDialog, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QStackedWidget, QFormLayout, QMessageBox, QGroupBox, QComboBox
)
from PyQt6.QtCore import Qt
import database

# This list must be kept in sync with the one in database.py
SECURITY_QUESTIONS_LIST = [
    "What was your first pet's name?", "What is your mother's maiden name?",
    "What was the name of your elementary school?", "What city were you born in?",
    "What is your favorite book?", "What was the model of your first car?",
    "What is your favorite movie?", "What is your favorite food?",
    "What is the name of your best childhood friend?", "In what city did you meet your spouse/partner?",
    "What is your favorite sports team?", "What was your high school mascot?",
    "What is the name of the street you grew up on?", "What is your favorite color?",
    "What is your father's middle name?"
]

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("GScapy - Login")
        self.setModal(True)
        self.current_user = None

        main_layout = QVBoxLayout(self)
        self.stacked_widget = QStackedWidget()
        main_layout.addWidget(self.stacked_widget)

        self.login_page = self._create_login_page()
        self.register_page = self._create_register_page()

        self.stacked_widget.addWidget(self.login_page)
        self.stacked_widget.addWidget(self.register_page)

        self.setMinimumSize(450, 500)
        self.adjustSize()


    def _create_login_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        login_box = QGroupBox("User Login")
        form_layout = QFormLayout(login_box)

        self.login_username_edit = QLineEdit()
        self.login_password_edit = QLineEdit()
        self.login_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("Username:", self.login_username_edit)
        form_layout.addRow("Password:", self.login_password_edit)

        login_button = QPushButton("Login")
        login_button.clicked.connect(self._handle_login)
        form_layout.addRow(login_button)

        links_layout = QHBoxLayout()
        register_link = QLabel("<a href='#'>Register a new account</a>")
        register_link.linkActivated.connect(lambda: self.stacked_widget.setCurrentWidget(self.register_page))

        links_layout.addWidget(register_link)
        links_layout.addStretch()
        form_layout.addRow(links_layout)

        layout.addWidget(login_box)
        return page

    def _create_register_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        register_box = QGroupBox("Create New Account")
        form_layout = QFormLayout(register_box)

        self.reg_username_edit = QLineEdit()
        self.reg_email_edit = QLineEdit()
        self.reg_password_edit = QLineEdit()
        self.reg_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.reg_confirm_password_edit = QLineEdit()
        self.reg_confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form_layout.addRow("Username:", self.reg_username_edit)
        form_layout.addRow("Email:", self.reg_email_edit)
        form_layout.addRow("Password:", self.reg_password_edit)
        form_layout.addRow("Confirm Password:", self.reg_confirm_password_edit)

        # --- Security Questions ---
        self.security_questions_widgets = []
        questions_box = QGroupBox("Security Questions (Choose 3)")
        questions_layout = QFormLayout(questions_box)

        available_questions = list(enumerate(SECURITY_QUESTIONS_LIST))

        for i in range(3):
            q_combo = QComboBox()
            q_combo.addItems([q for _, q in available_questions])
            q_combo.setUserData([id for id, _ in available_questions])
            a_edit = QLineEdit()
            a_edit.setPlaceholderText(f"Answer for question {i+1}")
            questions_layout.addRow(f"Question {i+1}:", q_combo)
            questions_layout.addRow(f"Answer {i+1}:", a_edit)
            self.security_questions_widgets.append({'combo': q_combo, 'answer': a_edit})

        form_layout.addRow(questions_box)

        register_button = QPushButton("Register")
        register_button.clicked.connect(self._handle_register)
        form_layout.addRow(register_button)

        back_to_login_link = QLabel("<a href='#'>Back to Login</a>")
        back_to_login_link.linkActivated.connect(lambda: self.stacked_widget.setCurrentWidget(self.login_page))
        form_layout.addRow(back_to_login_link)

        layout.addWidget(register_box)
        return page

    def _handle_login(self):
        username = self.login_username_edit.text().strip()
        password = self.login_password_edit.text()

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Username and password are required.")
            return

        user = database.verify_user(username, password)
        if user:
            self.current_user = dict(user)
            QMessageBox.information(self, "Success", f"Welcome, {self.current_user['username']}!")
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password, or account is inactive.")

    def _handle_register(self):
        username = self.reg_username_edit.text().strip()
        email = self.reg_email_edit.text().strip()
        password = self.reg_password_edit.text()
        confirm_password = self.reg_confirm_password_edit.text()

        # --- Validation ---
        if not all([username, email, password, confirm_password]):
            QMessageBox.warning(self, "Input Error", "All fields are required.")
            return
        if password != confirm_password:
            QMessageBox.warning(self, "Input Error", "Passwords do not match.")
            return
        if database.check_username_or_email_exists(username, email):
            QMessageBox.warning(self, "Input Error", "Username or email already exists.")
            return

        # Security questions validation
        questions_with_answers = []
        selected_question_indices = set()
        for item in self.security_questions_widgets:
            q_index = item['combo'].currentIndex()
            answer = item['answer'].text().strip()
            if not answer:
                QMessageBox.warning(self, "Input Error", "All three security questions must be answered.")
                return
            if q_index in selected_question_indices:
                QMessageBox.warning(self, "Input Error", "Please select three different security questions.")
                return
            selected_question_indices.add(q_index)
            questions_with_answers.append((q_index, answer))

        # --- Database Interaction ---
        try:
            user_id = database.create_user(username, email, password)
            database.add_security_questions(user_id, questions_with_answers)
            QMessageBox.information(self, "Success", "Account created successfully! Please log in.")
            self.stacked_widget.setCurrentWidget(self.login_page)
        except Exception as e:
            QMessageBox.critical(self, "Database Error", f"An error occurred during registration: {e}")


    def closeEvent(self, event):
        if not self.current_user:
            sys.exit(0)
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    database.initialize_database()
    dialog = LoginDialog()
    if dialog.exec() == QDialog.DialogCode.Accepted:
        print(f"Login successful for user: {dialog.current_user['username']}")
    else:
        print("Login dialog closed or failed.")
