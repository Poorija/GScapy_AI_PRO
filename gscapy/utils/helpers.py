import re
import logging
import urllib.request
import random
from PyQt6.QtGui import QImage, QPixmap, QIcon

def create_themed_icon(icon_path, color_str):
    """Loads an SVG, intelligently replaces its color, and returns a QIcon."""
    try:
        with open(icon_path, 'r', encoding='utf-8') as f:
            svg_data = f.read()

        # First, try to replace a stroke color in a style block (for paper-airplane.svg)
        themed_svg_data, count = re.subn(r'stroke:#[0-9a-fA-F]{6}', f'stroke:{color_str}', svg_data)

        # If no stroke was found in a style, fall back to injecting a fill attribute (for gear.svg)
        if count == 0 and '<svg' in themed_svg_data:
            themed_svg_data = themed_svg_data.replace('<svg', f'<svg fill="{color_str}"')

        image = QImage.fromData(themed_svg_data.encode('utf-8'))
        pixmap = QPixmap.fromImage(image)
        return QIcon(pixmap)
    except Exception as e:
        logging.warning(f"Could not create themed icon for {icon_path}: {e}")
        return QIcon(icon_path) # Fallback to original icon

def get_vendor(mac_address):
    """Retrieves the vendor for a given MAC address from an online API."""
    if not mac_address or mac_address == "N/A":
        return "N/A"
    try:
        # Use a timeout to prevent the application from hanging on network issues
        with urllib.request.urlopen(f"https://api.macvendors.com/{mac_address}", timeout=3) as url:
            data = url.read().decode()
            return data
    except Exception as e:
        logging.warning(f"Could not retrieve vendor for MAC {mac_address}: {e}")
        return "Unknown Vendor"

def _get_random_ip():
    """Generates a random, non-private IP address."""
    while True:
        ip = ".".join(str(random.randint(1, 223)) for _ in range(4))
        if not (ip.startswith('10.') or ip.startswith('192.168.') or (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31)):
             return ip
