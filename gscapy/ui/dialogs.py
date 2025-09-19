import json
import csv
import logging
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QHBoxLayout,
    QFileDialog, QTreeWidget, QTreeWidgetItem, QLabel, QHeaderView
)
from PyQt6.QtCore import Qt

LXML_AVAILABLE = True
try:
    from lxml import etree
except ImportError:
    LXML_AVAILABLE = False

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

class SubdomainResultsDialog(QDialog):
    """A dialog to show a list of found subdomains with an export option."""
    def __init__(self, subdomains, domain, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Subdomain Scan Results for {domain}")
        self.setMinimumSize(500, 400)
        self.parent = parent # To access the export handler
        self.domain = domain # Store domain for context

        layout = QVBoxLayout(self)

        summary_label = QLabel(f"<b>Found {len(subdomains)} unique subdomains.</b>")
        layout.addWidget(summary_label)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(1)
        self.tree.setHeaderLabels(["Subdomain"])
        for sub in subdomains:
            self.tree.addTopLevelItem(QTreeWidgetItem([sub]))
        self.tree.resizeColumnToContents(0)
        layout.addWidget(self.tree)

        button_layout = QHBoxLayout()
        export_button = self.parent._create_export_button(self.tree)
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(lambda: self.parent._send_to_ai_analyst("subdomain", self.tree, self.domain))
        button_layout.addWidget(export_button)
        button_layout.addWidget(analyze_button)
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)

        layout.addLayout(button_layout)

class NmapSummaryDialog(QDialog):
    """A dialog to show a summary of Nmap scan results from XML."""
    def __init__(self, xml_data, target_context, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nmap Scan Summary")
        self.setMinimumSize(700, 500)
        self.xml_data = xml_data
        self.target_context = target_context
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Host / Details", "Port", "Service", "Version"])
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.tree.header().setStretchLastSection(False)
        layout.addWidget(self.tree)

        self.parse_and_populate(xml_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("nmap", self.xml_data, self.target_context)
            self.accept() # Close dialog after sending

    def parse_and_populate(self, xml_data):
        if not LXML_AVAILABLE:
            self.tree.addTopLevelItem(QTreeWidgetItem(["LXML library not installed."]))
            return
        if not xml_data:
            self.tree.addTopLevelItem(QTreeWidgetItem(["No XML data to parse."]))
            return

        try:
            parser = etree.XMLParser(recover=True, no_network=True, dtd_validation=False)
            root = etree.fromstring(xml_data.encode('utf-8'), parser=parser)

            for host in root.findall('host'):
                if host.find('status').get('state') != 'up':
                    continue

                address = host.find('address').get('addr')
                hostname_elem = host.find('hostnames/hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else ""

                host_text = f"{address} ({hostname})" if hostname else address
                host_item = QTreeWidgetItem([host_text])
                host_item.setExpanded(True)
                self.tree.addTopLevelItem(host_item)

                ports_elem = host.find('ports')
                if ports_elem is None:
                    continue

                for port in ports_elem.findall('port'):
                    if port.find('state').get('state') == 'open':
                        port_id = port.get('portid')
                        protocol = port.get('protocol')

                        service_elem = port.find('service')
                        service = service_elem.get('name', '') if service_elem is not None else ''
                        version_parts = []
                        if service_elem is not None:
                            if service_elem.get('product'): version_parts.append(service_elem.get('product'))
                            if service_elem.get('version'): version_parts.append(service_elem.get('version'))
                        version = " ".join(version_parts)

                        port_item = QTreeWidgetItem(["", f"{port_id}/{protocol}", service, version])
                        host_item.addChild(port_item)

        except Exception as e:
            logging.error(f"Failed to parse Nmap XML for summary: {e}", exc_info=True)
            self.tree.addTopLevelItem(QTreeWidgetItem(["Error parsing XML data."]))

class HttpxResultsDialog(QDialog):
    def __init__(self, json_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("httpx Probe Results")
        self.setMinimumSize(800, 500)
        self.json_data = json_data
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        # Define columns based on common httpx JSON output
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["URL", "Status Code", "Title", "Web Server", "Technologies"])
        layout.addWidget(self.tree)

        self.parse_and_populate(json_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            # The AI can analyze the raw JSON data
            self.parent.ai_assistant_tab.send_to_analyst("httpx", self.json_data, "httpx probe results")
            self.accept()

    def parse_and_populate(self, json_data):
        try:
            # httpx outputs JSON objects separated by newlines
            results = [json.loads(line) for line in json_data.strip().split('\n') if line]
            for res in results:
                url = res.get('url', '')
                status_code = str(res.get('status_code', ''))
                title = res.get('title', '')
                web_server = res.get('webserver', '')
                tech = ", ".join(res.get('tech', []))

                item = QTreeWidgetItem([url, status_code, title, web_server, tech])
                self.tree.addTopLevelItem(item)
        except json.JSONDecodeError:
            # Handle case where output is not JSON
            item = QTreeWidgetItem(["Error parsing JSON output. Displaying raw data in console."])
            self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing httpx JSON: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))

class DirsearchResultsDialog(QDialog):
    def __init__(self, json_data, target_context, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"dirsearch Results for {target_context}")
        self.setMinimumSize(800, 500)
        self.json_data = json_data
        self.target_context = target_context
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Path", "Status Code", "Content-Length", "Redirect"])
        layout.addWidget(self.tree)

        self.parse_and_populate(json_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("dirsearch", self.json_data, self.target_context)
            self.accept()

    def parse_and_populate(self, json_data):
        try:
            # dirsearch report is a dictionary where keys are hostnames
            results = json.loads(json_data)
            for host, findings in results.items():
                host_item = QTreeWidgetItem([f"Host: {host}"])
                self.tree.addTopLevelItem(host_item)
                host_item.setExpanded(True)
                for finding in findings:
                    path = finding.get('path', '')
                    status = str(finding.get('status', ''))
                    length = str(finding.get('content-length', ''))
                    redirect = finding.get('redirect', '')

                    child_item = QTreeWidgetItem([path, status, length, redirect])
                    host_item.addChild(child_item)
        except json.JSONDecodeError:
            item = QTreeWidgetItem(["Error parsing JSON output."])
            self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing dirsearch JSON: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))

class FfufResultsDialog(QDialog):
    def __init__(self, json_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ffuf Scan Results")
        self.setMinimumSize(800, 500)
        self.json_data = json_data
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["URL", "Status", "Length", "Words"])
        layout.addWidget(self.tree)

        self.parse_and_populate(json_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("ffuf", self.json_data, "ffuf scan results")
            self.accept()

    def parse_and_populate(self, json_data):
        try:
            results = json.loads(json_data).get('results', [])
            for res in results:
                url = res.get('url', '')
                status = str(res.get('status', ''))
                length = str(res.get('length', ''))
                words = str(res.get('words', ''))

                item = QTreeWidgetItem([url, status, length, words])
                self.tree.addTopLevelItem(item)
        except (json.JSONDecodeError, AttributeError):
            item = QTreeWidgetItem(["Error parsing JSON output."])
            self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing ffuf JSON: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))

class NucleiResultsDialog(QDialog):
    def __init__(self, json_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nuclei Scan Results")
        self.setMinimumSize(900, 600)
        self.json_data = json_data
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["Template ID", "Name", "Severity", "Host", "Matched At"])
        layout.addWidget(self.tree)

        self.parse_and_populate(json_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("nuclei", self.json_data, "Nuclei scan results")
            self.accept()

    def parse_and_populate(self, json_data):
        try:
            # Nuclei outputs JSON objects separated by newlines
            results = [json.loads(line) for line in json_data.strip().split('\n') if line]
            for res in results:
                template_id = res.get('template-id', '')
                name = res.get('info', {}).get('name', '')
                severity = res.get('info', {}).get('severity', '')
                host = res.get('host', '')
                matched_at = res.get('matched-at', '')

                item = QTreeWidgetItem([template_id, name, severity, host, matched_at])
                self.tree.addTopLevelItem(item)

                # Add extracted results as children for more detail
                if 'extracted-results' in res:
                    for i, extracted in enumerate(res['extracted-results']):
                        child_item = QTreeWidgetItem([f"  - Extracted {i+1}", str(extracted)])
                        item.addChild(child_item)

                item.setExpanded(True)

        except json.JSONDecodeError:
            item = QTreeWidgetItem(["Error parsing JSON output."])
            self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing Nuclei JSON: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))

class TruffleHogResultsDialog(QDialog):
    def __init__(self, json_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("TruffleHog Scan Results")
        self.setMinimumSize(900, 600)
        self.json_data = json_data
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Detector", "Decoder", "File", "Raw Secret"])
        layout.addWidget(self.tree)

        self.parse_and_populate(json_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("trufflehog", self.json_data, "TruffleHog scan results")
            self.accept()

    def parse_and_populate(self, json_data):
        try:
            # TruffleHog outputs JSON objects separated by newlines
            results = [json.loads(line) for line in json_data.strip().split('\n') if line]
            for res in results:
                detector = res.get('DetectorType', '')
                decoder = res.get('DecoderType', '')
                file = res.get('File', '')
                raw = res.get('Raw', '')

                item = QTreeWidgetItem([detector, decoder, file, raw])
                self.tree.addTopLevelItem(item)
        except json.JSONDecodeError:
            item = QTreeWidgetItem(["Error parsing JSON output."])
            self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing TruffleHog JSON: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))

class Enum4LinuxNGResultsDialog(QDialog):
    def __init__(self, json_data, target_context, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"enum4linux-ng Results for {target_context}")
        self.setMinimumSize(800, 600)
        self.json_data = json_data
        self.target_context = target_context
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["Finding", "Details"])
        layout.addWidget(self.tree)

        self.parse_and_populate(json_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("enum4linux-ng", self.json_data, self.target_context)
            self.accept()

    def parse_and_populate(self, json_data):
        try:
            results = json.loads(json_data)
            # The JSON is a list of dictionaries, each representing a finding
            for finding in results:
                method = finding.get('method', 'N/A')
                item = QTreeWidgetItem([method])
                self.tree.addTopLevelItem(item)

                # Add all other keys as children
                for key, value in finding.items():
                    if key != 'method':
                        child_item = QTreeWidgetItem([f"  {key}", str(value)])
                        item.addChild(child_item)
                item.setExpanded(True)
        except json.JSONDecodeError:
            item = QTreeWidgetItem(["Error parsing JSON output."])
            self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing enum4linux-ng JSON: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))

class DnsReconResultsDialog(QDialog):
    def __init__(self, json_data, target_context, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"dnsrecon Results for {target_context}")
        self.setMinimumSize(800, 600)
        self.json_data = json_data
        self.target_context = target_context
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Type", "Target", "Address", "Name"])
        layout.addWidget(self.tree)

        self.parse_and_populate(json_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("dnsrecon", self.json_data, self.target_context)
            self.accept()

    def parse_and_populate(self, json_data):
        try:
            results = json.loads(json_data)
            # The JSON is a list of dictionaries
            for res in results:
                rec_type = res.get('type', 'N/A')
                target = res.get('target', 'N/A')
                address = res.get('address', 'N/A')
                name = res.get('name', 'N/A')

                item = QTreeWidgetItem([rec_type, target, address, name])
                self.tree.addTopLevelItem(item)
        except json.JSONDecodeError:
            item = QTreeWidgetItem(["Error parsing JSON output."])
            self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing dnsrecon JSON: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))

class SherlockResultsDialog(QDialog):
    def __init__(self, csv_data, target_context, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Sherlock Results for {target_context}")
        self.setMinimumSize(800, 600)
        self.csv_data = csv_data
        self.target_context = target_context
        self.parent = parent

        layout = QVBoxLayout(self)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Username", "Service Name", "URL", "Status"])
        layout.addWidget(self.tree)

        self.parse_and_populate(csv_data)

        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

        button_layout = QHBoxLayout()
        analyze_button = QPushButton("Send to AI Analyst")
        analyze_button.clicked.connect(self.send_to_ai)
        button_layout.addWidget(analyze_button)

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        button_layout.addWidget(ok_button)
        layout.addLayout(button_layout)

    def send_to_ai(self):
        if self.parent:
            self.parent.ai_assistant_tab.send_to_analyst("sherlock", self.csv_data, self.target_context)
            self.accept()

    def parse_and_populate(self, csv_data):
        try:
            # Use Python's built-in csv module to parse the data
            reader = csv.reader(csv_data.strip().splitlines())
            header = next(reader) # Skip header row
            for row in reader:
                # Assuming standard sherlock csv format: username,name,url,status
                if len(row) >= 4:
                    item = QTreeWidgetItem(row)
                    self.tree.addTopLevelItem(item)
        except Exception as e:
            logging.error(f"Error parsing Sherlock CSV: {e}")
            self.tree.addTopLevelItem(QTreeWidgetItem([f"An unexpected error occurred: {e}"]))
