"""Zentrale Konstanten, Pfade, Port-Profile und Standardwerte für ShodanCheck."""

import copy

APP_NAME = "ShodanCheck"
APP_VERSION = "2.0.0"

# --- Dateien & Cache-Verzeichnisse ---
CONFIG_FILE = "shodancheck_config.json"
SESSION_FILE = "shodancheck_session.json"
HISTORY_FILE = "shodancheck_history.json"
FAVORITES_FILE = "shodancheck_favorites.json"
GEOIP_CACHE_FILE = "geoip_cache.json"
SCREENSHOT_CACHE_DIR = "screenshots_cache"

# --- Ports & Scan-Profile ---
DEFAULT_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

PORT_PRESETS = {
    "Web Standard (80, 443, 8080, 8443)": [80, 443, 8080, 8443],
    "Dashboards & Web-UIs (9 Ports)": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
    "Erweitert inkl. SSH/RTSP/VNC": [22, 80, 443, 554, 3000, 3389, 5000, 5900, 8000, 8080, 8443, 8888, 9000],
    "Nur HTTP / HTTPS (80, 443)": [80, 443],
}

# --- Kuratierte Suchvorlagen ---
DORK_TEMPLATES = {
    "— Vorlage wählen —": "",
    "Web-Dashboards (200 OK)": 'http.status:200 "Dashboard"',
    "Grafana Instanzen": 'http.title:"Grafana"',
    "Proxmox VE Web-UI": 'http.title:"Proxmox Virtual Environment"',
    "Netzwerk-Kameras / Streams": 'title:"webcam" OR title:"IP Camera" port:80,8080',
    "NAS / Storage Login": 'http.title:"DiskStation" OR http.title:"QNAP"',
    "Open Directory Listings": 'http.title:"Index of /"',
    "Deutschland (DE) Webserver": 'country:"DE" port:80,443,8080,8443',
}

# --- Standard-Konfiguration (kompatibel mit ServiceConfigDialog & MainWindow) ---
DEFAULT_CONFIG = {
    "services": {
        "shodan": {"enabled": True, "api_key": "", "api_secret": ""},
        "censys": {"enabled": False, "api_key": "", "api_secret": ""},
        "fofa": {"enabled": False, "api_key": "", "api_secret": ""},
        "zoomeye": {"enabled": False, "api_key": "", "api_secret": ""},
        "criminalip": {"enabled": False, "api_key": "", "api_secret": ""},
        "hunterhow": {"enabled": False, "api_key": "", "api_secret": ""},
        "binaryedge": {"enabled": False, "api_key": "", "api_secret": ""},
        "demo": {"enabled": False, "api_key": "", "api_secret": ""},
    },
    "geoip": {
        "city_mmdb_path": "",
        "asn_mmdb_path": "",
        "ptr_enabled": True,
        "timeout_sec": 4,
    },
    "screenshot": {
        "page_wait_ms": 12000,
        "hard_timeout_sec": 35,
        "window_size": "1280,800",
    },
    "proxy_url": "",
    "default_ports": "80, 443, 8080, 8443",
    "url_suffix": "",
    "concurrency": 250,
    "timeout_sec": 3.5,
    "auto_geoip": False,
    "page_size": 100,
    "max_results_per_service": 100,
}

# --- Einheitliche Felder für jeden Tabellen-Eintrag ---
ITEM_SCHEMA_DEFAULTS = {
    "ip": "",
    "port": 80,
    "status": "OFFLINE",
    "checked": False,
    "favorite": False,
    "visited": False,
    "country_code": "",
    "country_name": "",
    "city": "",
    "asn": "",
    "asn_org": "",
    "ptr": "",
    "info": "",
    "url": "",
    "screenshot_path": "",
    "response_info": "",
    "http_code": 0,
    "tls_info": "",
    "headers_raw": "",
    "banner_raw": "",
}


def get_default_config() -> dict:
    """Gibt eine tiefe Kopie der Standard-Konfiguration zurück."""
    return copy.deepcopy(DEFAULT_CONFIG)