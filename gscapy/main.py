import sys
import logging
from PyQt6.QtWidgets import QApplication, QMessageBox, QDialog
from qt_material import apply_stylesheet

# Imports from package
from .core import database
from .ui.login import LoginDialog

# Relative imports for the new structure
from .main_window import GScapy


def main():
    """Main function to launch the GScapy application."""
    try:
        database.initialize_database()
        # This check is now less critical as imports would fail earlier, but good practice.
        if 'scapy' not in sys.modules:
            raise ImportError("Scapy is not available.")

        app = QApplication(sys.argv)

        login_dialog = LoginDialog()

        # Define the custom stylesheet additions
        extra_qss = {
            'QGroupBox': {
                'border': '1px solid #444;',
                'border-radius': '8px',
                'margin-top': '10px',
            },
            'QGroupBox::title': {
                'subcontrol-origin': 'margin',
                'subcontrol-position': 'top left',
                'padding': '0 10px',
            },
            'QTabWidget::pane': {
                'border-top': '1px solid #444;',
                'margin-top': '-1px',
            },
            'QFrame': {
                'border-radius': '8px',
            },
            'QPushButton': {
                'border-radius': '8px',
            },
            'QLineEdit': {
                'border-radius': '8px',
            },
            'QComboBox': {
                'border-radius': '8px',
            },
            'QTextEdit': {
                'border-radius': '8px',
            },
            'QPlainTextEdit': {
                'border-radius': '8px',
            },
            'QListWidget': {
                'border-radius': '8px',
            },
            'QTreeWidget': {
                'border-radius': '8px',
            }
        }

        # Apply the default theme before showing the login dialog
        apply_stylesheet(app, theme=login_dialog.selected_theme, extra=extra_qss)

        if login_dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

        # Re-apply the theme in case the user changed it in the dialog.
        # This ensures the main window gets the final selected theme.
        apply_stylesheet(app, theme=login_dialog.selected_theme, extra=extra_qss)

        window = GScapy()
        window.current_user = login_dialog.current_user
        # Set window title with username
        if window.current_user and 'username' in window.current_user:
            window.setWindowTitle(f"Welcome, {window.current_user['username']} - GScapy + AI - The Modern Scapy Interface with AI")
        window._update_menu_bar() # Populate the menu now that we have a user
        window.show()
        sys.exit(app.exec())

    except ImportError as e:
        # This part handles cases where critical modules like Scapy are missing.
        app = QApplication(sys.argv)
        QMessageBox.critical(None, "Fatal Error", f"A required module is missing: {e}")
        logging.critical(f"A required module is missing: {e}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unhandled exception occurred in main: {e}", exc_info=True)
        app = QApplication(sys.argv)
        QMessageBox.critical(None, "Unhandled Exception", f"An unexpected error occurred:\n\n{e}")
        sys.exit(1)
