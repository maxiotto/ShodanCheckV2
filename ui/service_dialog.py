import os
import copy
import inspect
import importlib.util
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QTabWidget,
    QWidget,
    QListWidget,
    QListWidgetItem,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QSpinBox,
    QComboBox,
    QFrame,
    QFileDialog,
    QSplitter,
)

from ui.theme import COLORS

try:
    from scanner.screenshotter import find_browser_executable
except Exception:
    def find_browser_executable():
        return None


FALLBACK_ENGINES = {
    "shodan": {
        "name": "Shodan",
        "description": "Klassische Internet-Suchmaschine für offene Ports, Banner und Dienste.",
        "requires_key": True,
        "requires_secret": False,
        "key_label": "Shodan API-Key",
    },
    "censys": {
        "name": "Censys",
        "description": "Host- und Zertifikats-Suchmaschine (API ID + API Secret).",
        "requires_key": True,
        "requires_secret": True,
        "key_label": "Censys API ID",
        "secret_label": "Censys API Secret",
    },
    "fofa": {
        "name": "FOFA",
        "description": "Cyberspace-Asset-Suchmaschine (E-Mail + API-Key).",
        "requires_key": True,
        "requires_secret": True,
        "key_label": "FOFA API-Key",
        "secret_label": "FOFA Account-E-Mail",
    },
    "zoomeye": {
        "name": "ZoomEye",
        "description": "Globale Host- und Web-Komponenten-Suche.",
        "requires_key": True,
        "requires_secret": False,
        "key_label": "ZoomEye API-Key",
    },
    "criminalip": {
        "name": "Criminal IP",
        "description": "CTI- und Asset-Suchmaschine mit Banner- und Schwachstellenfiltern.",
        "requires_key": True,
        "requires_secret": False,
        "key_label": "Criminal IP API-Key",
    },
    "hunterhow": {
        "name": "Hunter.how",
        "description": "Internet-Asset-Suchmaschine für IP-, Port- und Header-Abfragen.",
        "requires_key": True,
        "requires_secret": False,
        "key_label": "Hunter.how API-Key",
    },
    "binaryedge": {
        "name": "BinaryEdge",
        "description": "Verteilte Internet-Scanning-Plattform für Dienst-Banner.",
        "requires_key": True,
        "requires_secret": False,
        "key_label": "BinaryEdge API-Key",
    },
    "demo": {
        "name": "Demo / Offline-Test",
        "description": "Lokaler Testmodus ohne API-Key zum Prüfen von Scanner, GeoIP und Vorschau.",
        "requires_key": False,
        "requires_secret": False,
        "key_label": "Kein Key erforderlich",
    },
}


def _extract_engine_meta(engine_id: str, engine_obj) -> dict:
    """Liest Metadaten flexibel aus einer Provider-Instanz oder einem Dictionary."""
    base = dict(FALLBACK_ENGINES.get(engine_id, {}))
    if isinstance(engine_obj, dict):
        base.update(engine_obj)
    elif engine_obj is not None:
        for attr in ("name", "description", "requires_key", "requires_secret", "key_label", "secret_label"):
            if hasattr(engine_obj, attr):
                base[attr] = getattr(engine_obj, attr)
    base.setdefault("name", engine_id.capitalize())
    base.setdefault("description", "Suchdienst-Anbindung für ShodanCheck.")
    base.setdefault("requires_key", True)
    base.setdefault("requires_secret", False)
    base.setdefault("key_label", "API-Key")
    base.setdefault("secret_label", "API-Secret / Zusatzfeld")
    return base


class ConnectionTestWorker(QThread):
    """Führt den API-Key-Verbindungstest asynchron im Hintergrund aus."""

    test_finished = Signal(bool, str)

    def __init__(self, engine_obj, api_key: str, api_secret: str = "", proxy_url: str = ""):
        super().__init__()
        self.engine_obj = engine_obj
        self.api_key = api_key
        self.api_secret = api_secret
        self.proxy_url = proxy_url

    def run(self):
        if self.engine_obj is None or not hasattr(self.engine_obj, "test_connection"):
            if not self.api_key.strip():
                self.test_finished.emit(False, "Bitte zuerst einen API-Key eingeben.")
            else:
                self.test_finished.emit(True, "Syntax geprüft (Provider-Testmethode wird beim Scan aktiv).")
            return

        try:
            fn = self.engine_obj.test_connection
            sig = inspect.signature(fn)
            params = sig.parameters
            kwargs = {}
            if "api_key" in params:
                kwargs["api_key"] = self.api_key.strip()
            if "api_secret" in params:
                kwargs["api_secret"] = self.api_secret.strip()
            if "proxy_url" in params:
                kwargs["proxy_url"] = self.proxy_url.strip()

            if kwargs:
                result = fn(**kwargs)
            else:
                result = fn(self.api_key.strip())

            if isinstance(result, tuple) and len(result) >= 2:
                self.test_finished.emit(bool(result[0]), str(result[1]))
            else:
                self.test_finished.emit(bool(result), "Verbindung erfolgreich getestet.")
        except Exception as exc:
            self.test_finished.emit(False, f"Verbindungsfehler: {exc}")


class ServiceConfigDialog(QDialog):
    """Konfigurationsdialog für Suchdienste, API-Keys, MaxMind-.mmdb & Vorschau-Engine."""

    def __init__(self, config: dict, engines: dict | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚙️ Dienste, API-Keys & Anreicherung konfigurieren")
        self.resize(860, 560)

        self._config = copy.deepcopy(config or {})
        self._services_cfg: dict = self._config.setdefault("services", {})
        self._geoip_cfg: dict = self._config.setdefault("geoip", {})
        self._shot_cfg: dict = self._config.setdefault("screenshot", {})

        self._engines = engines if engines else dict(FALLBACK_ENGINES)
        self._engine_ids = list(self._engines.keys())
        self._current_engine_id: str | None = None
        self._test_worker: ConnectionTestWorker | None = None

        self._build_ui()
        self._populate_service_list()
        self._load_geoip_and_shot_settings()

        if self._engine_ids:
            self.list_services.setCurrentRow(0)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_services_tab(), "🔍 Suchdienste && API-Keys")
        self.tabs.addTab(self._build_enrichment_tab(), "🌍 GeoIP (.mmdb) && Vorschau-Engine")
        root.addWidget(self.tabs, 1)

        footer = QHBoxLayout()
        footer.addStretch()

        btn_cancel = QPushButton("Abbrechen")
        btn_cancel.clicked.connect(self.reject)
        footer.addWidget(btn_cancel)

        btn_save = QPushButton("💾 Speichern && Übernehmen")
        btn_save.setObjectName("PrimaryBtn")
        btn_save.clicked.connect(self._on_save_clicked)
        footer.addWidget(btn_save)

        root.addLayout(footer)

    def _build_services_tab(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        hint = QLabel(
            "Aktiviere einen oder mehrere Suchdienste. Im Universal-Modus fragt ShodanCheck "
            "alle aktivierten Dienste parallel ab und führt doppelte IP:Port-Treffer automatisch zusammen."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {COLORS['text_muted']};")
        lay.addWidget(hint)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.list_services = QListWidget()
        self.list_services.setMinimumWidth(230)
        self.list_services.currentRowChanged.connect(self._on_service_selected)
        splitter.addWidget(self.list_services)

        right_card = QFrame()
        right_card.setObjectName("CardFrame")
        r_lay = QVBoxLayout(right_card)
        r_lay.setContentsMargins(14, 14, 14, 14)
        r_lay.setSpacing(10)

        self.lbl_srv_title = QLabel("<b>Suchdienst</b>")
        self.lbl_srv_title.setStyleSheet("font-size: 15px;")
        r_lay.addWidget(self.lbl_srv_title)

        self.lbl_srv_desc = QLabel("")
        self.lbl_srv_desc.setWordWrap(True)
        self.lbl_srv_desc.setStyleSheet(f"color: {COLORS['text_secondary']};")
        r_lay.addWidget(self.lbl_srv_desc)

        self.chk_srv_enabled = QCheckBox("Diesen Suchdienst aktivieren")
        self.chk_srv_enabled.toggled.connect(self._on_field_edited)
        r_lay.addWidget(self.chk_srv_enabled)

        form = QGridLayout()
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(8)

        self.lbl_key = QLabel("API-Key:")
        self.inp_key = QLineEdit()
        self.inp_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_key.setPlaceholderText("API-Key einfügen...")
        self.inp_key.textChanged.connect(self._on_field_edited)

        self.btn_toggle_key = QPushButton("👁")
        self.btn_toggle_key.setObjectName("IconBtn")
        self.btn_toggle_key.setFixedSize(32, 28)
        self.btn_toggle_key.setCheckable(True)
        self.btn_toggle_key.setToolTip("Klartext ein-/ausblenden")
        self.btn_toggle_key.toggled.connect(self._toggle_key_visibility)

        form.addWidget(self.lbl_key, 0, 0)
        form.addWidget(self.inp_key, 0, 1)
        form.addWidget(self.btn_toggle_key, 0, 2)

        self.lbl_secret = QLabel("API-Secret:")
        self.inp_secret = QLineEdit()
        self.inp_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_secret.setPlaceholderText("Optionales Zusatzfeld / Secret...")
        self.inp_secret.textChanged.connect(self._on_field_edited)

        form.addWidget(self.lbl_secret, 1, 0)
        form.addWidget(self.inp_secret, 1, 1, 1, 2)

        form.setColumnStretch(1, 1)
        r_lay.addLayout(form)

        test_row = QHBoxLayout()
        self.btn_test_srv = QPushButton("🔌 Verbindung && Key testen")
        self.btn_test_srv.clicked.connect(self._on_test_service_clicked)
        test_row.addWidget(self.btn_test_srv)
        test_row.addStretch()
        r_lay.addLayout(test_row)

        self.lbl_test_result = QLabel("")
        self.lbl_test_result.setWordWrap(True)
        self.lbl_test_result.setStyleSheet(f"color: {COLORS['text_muted']};")
        r_lay.addWidget(self.lbl_test_result)

        r_lay.addStretch(1)
        splitter.addWidget(right_card)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        lay.addWidget(splitter, 1)
        return page

    def _build_enrichment_tab(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(12)

        # --- Karte 1: GeoIP, ASN & Reverse-DNS ---
        geo_card = QFrame()
        geo_card.setObjectName("CardFrame")
        g_lay = QVBoxLayout(geo_card)
        g_lay.setContentsMargins(12, 12, 12, 12)
        g_lay.setSpacing(8)

        g_lay.addWidget(QLabel("<b>🌍 GeoIP-, ASN- & Reverse-DNS-Anreicherung</b>"))

        geo_desc = QLabel(
            "Optional kannst du lokale MaxMind-Datenbanken (.mmdb) hinterlegen. "
            "Ohne lokale Datei oder bei fehlenden Einträgen nutzt ShodanCheck automatisch "
            "die key-freie Online-Abfrage mit dauerhaftem lokalem Cache (geoip_cache.json)."
        )
        geo_desc.setWordWrap(True)
        geo_desc.setStyleSheet(f"color: {COLORS['text_secondary']};")
        g_lay.addWidget(geo_desc)

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)

        grid.addWidget(QLabel("GeoLite2-City.mmdb:"), 0, 0)
        self.inp_mmdb_city = QLineEdit()
        self.inp_mmdb_city.setPlaceholderText("Optional: Pfad zu GeoLite2-City.mmdb (Land & Stadt)")
        self.inp_mmdb_city.textChanged.connect(self._update_mmdb_status)
        grid.addWidget(self.inp_mmdb_city, 0, 1)

        btn_city = QPushButton("📂 Durchsuchen...")
        btn_city.clicked.connect(lambda: self._browse_mmdb(self.inp_mmdb_city))
        grid.addWidget(btn_city, 0, 2)

        btn_city_clr = QPushButton("✕")
        btn_city_clr.setObjectName("IconBtn")
        btn_city_clr.setFixedSize(28, 28)
        btn_city_clr.clicked.connect(self.inp_mmdb_city.clear)
        grid.addWidget(btn_city_clr, 0, 3)

        grid.addWidget(QLabel("GeoLite2-ASN.mmdb:"), 1, 0)
        self.inp_mmdb_asn = QLineEdit()
        self.inp_mmdb_asn.setPlaceholderText("Optional: Pfad zu GeoLite2-ASN.mmdb (AS-Nummer & Provider)")
        self.inp_mmdb_asn.textChanged.connect(self._update_mmdb_status)
        grid.addWidget(self.inp_mmdb_asn, 1, 1)

        btn_asn = QPushButton("📂 Durchsuchen...")
        btn_asn.clicked.connect(lambda: self._browse_mmdb(self.inp_mmdb_asn))
        grid.addWidget(btn_asn, 1, 2)

        btn_asn_clr = QPushButton("✕")
        btn_asn_clr.setObjectName("IconBtn")
        btn_asn_clr.setFixedSize(28, 28)
        btn_asn_clr.clicked.connect(self.inp_mmdb_asn.clear)
        grid.addWidget(btn_asn_clr, 1, 3)

        grid.setColumnStretch(1, 1)
        g_lay.addLayout(grid)

        opt_row = QHBoxLayout()
        self.chk_ptr_enabled = QCheckBox("Reverse-DNS (PTR) Hostname abrufen")
        self.chk_ptr_enabled.setChecked(True)
        opt_row.addWidget(self.chk_ptr_enabled)

        opt_row.addStretch()
        opt_row.addWidget(QLabel("Abfrage-Timeout (Sek.):"))
        self.spin_geo_timeout = QSpinBox()
        self.spin_geo_timeout.setRange(2, 20)
        self.spin_geo_timeout.setValue(4)
        opt_row.addWidget(self.spin_geo_timeout)
        g_lay.addLayout(opt_row)

        self.lbl_mmdb_status = QLabel("")
        self.lbl_mmdb_status.setWordWrap(True)
        g_lay.addWidget(self.lbl_mmdb_status)

        lay.addWidget(geo_card)

        # --- Karte 2: Headless-Screenshots ---
        shot_card = QFrame()
        shot_card.setObjectName("CardFrame")
        s_lay = QVBoxLayout(shot_card)
        s_lay.setContentsMargins(12, 12, 12, 12)
        s_lay.setSpacing(8)

        s_lay.addWidget(QLabel("<b>📸 Headless-Vorschau (Edge / Chrome)</b>"))

        self.lbl_browser_status = QLabel("")
        self.lbl_browser_status.setWordWrap(True)
        s_lay.addWidget(self.lbl_browser_status)

        s_grid = QGridLayout()
        s_grid.setHorizontalSpacing(10)
        s_grid.setVerticalSpacing(6)

        s_grid.addWidget(QLabel("Wartezeit nach Seitenaufbau (ms):"), 0, 0)
        self.spin_wait_ms = QSpinBox()
        self.spin_wait_ms.setRange(3000, 30000)
        self.spin_wait_ms.setSingleStep(1000)
        self.spin_wait_ms.setValue(12000)
        self.spin_wait_ms.setToolTip("Zeitbudget für verzögerte JavaScript-Oberflächen nach dem Laden der Gegenseite.")
        s_grid.addWidget(self.spin_wait_ms, 0, 1)

        s_grid.addWidget(QLabel("Maximales Gesamt-Timeout (Sek.):"), 0, 2)
        self.spin_hard_timeout = QSpinBox()
        self.spin_hard_timeout.setRange(10, 90)
        self.spin_hard_timeout.setValue(35)
        s_grid.addWidget(self.spin_hard_timeout, 0, 3)

        s_grid.addWidget(QLabel("Browser-Auflösung:"), 1, 0)
        self.cmb_resolution = QComboBox()
        self.cmb_resolution.addItems(["1280,800", "1366,768", "1920,1080"])
        s_grid.addWidget(self.cmb_resolution, 1, 1)

        s_grid.setColumnStretch(4, 1)
        s_lay.addLayout(s_grid)

        lay.addWidget(shot_card)
        lay.addStretch(1)
        return page

    def _populate_service_list(self):
        self.list_services.clear()
        for eid in self._engine_ids:
            meta = _extract_engine_meta(eid, self._engines.get(eid))
            srv_state = self._services_cfg.setdefault(eid, {})
            if eid == "shodan" and "enabled" not in srv_state:
                srv_state["enabled"] = True
            item = QListWidgetItem(self._format_service_row(eid, meta, srv_state))
            item.setData(Qt.ItemDataRole.UserRole, eid)
            self.list_services.addItem(item)

    def _format_service_row(self, eid: str, meta: dict, srv_state: dict) -> str:
        enabled = bool(srv_state.get("enabled", False))
        has_key = bool((srv_state.get("api_key") or "").strip())
        status_icon = "✅" if enabled else "⚪"
        key_icon = " 🔑" if has_key else ("" if not meta.get("requires_key", True) else " ⚠️")
        return f"{status_icon} {meta['name']}{key_icon}"

    def _on_service_selected(self, row: int):
        if row < 0 or row >= len(self._engine_ids):
            return
        eid = self._engine_ids[row]
        self._current_engine_id = eid
        meta = _extract_engine_meta(eid, self._engines.get(eid))
        srv_state = self._services_cfg.setdefault(eid, {})

        self.lbl_srv_title.setText(f"<b>{meta['name']}</b>")
        self.lbl_srv_desc.setText(meta["description"])

        self.chk_srv_enabled.blockSignals(True)
        self.inp_key.blockSignals(True)
        self.inp_secret.blockSignals(True)

        self.chk_srv_enabled.setChecked(bool(srv_state.get("enabled", False)))
        self.lbl_key.setText(f"{meta['key_label']}:")
        self.inp_key.setText(srv_state.get("api_key", ""))
        self.inp_key.setEnabled(bool(meta.get("requires_key", True)))

        show_secret = bool(meta.get("requires_secret", False))
        self.lbl_secret.setVisible(show_secret)
        self.inp_secret.setVisible(show_secret)
        self.lbl_secret.setText(f"{meta['secret_label']}:")
        self.inp_secret.setText(srv_state.get("api_secret", ""))

        self.chk_srv_enabled.blockSignals(False)
        self.inp_key.blockSignals(False)
        self.inp_secret.blockSignals(False)

        self.lbl_test_result.setText("")

    def _on_field_edited(self):
        if not self._current_engine_id:
            return
        eid = self._current_engine_id
        srv_state = self._services_cfg.setdefault(eid, {})
        srv_state["enabled"] = self.chk_srv_enabled.isChecked()
        srv_state["api_key"] = self.inp_key.text().strip()
        srv_state["api_secret"] = self.inp_secret.text().strip()

        row = self.list_services.currentRow()
        if 0 <= row < self.list_services.count():
            meta = _extract_engine_meta(eid, self._engines.get(eid))
            self.list_services.item(row).setText(self._format_service_row(eid, meta, srv_state))

    def _toggle_key_visibility(self, checked: bool):
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self.inp_key.setEchoMode(mode)
        self.inp_secret.setEchoMode(mode)

    def _on_test_service_clicked(self):
        if not self._current_engine_id:
            return
        eid = self._current_engine_id
        engine_obj = self._engines.get(eid)
        if isinstance(engine_obj, dict):
            engine_obj = None

        self.btn_test_srv.setEnabled(False)
        self.lbl_test_result.setStyleSheet(f"color: {COLORS['cyan']};")
        self.lbl_test_result.setText("⏳ Prüfe Verbindung und API-Schlüssel...")

        proxy_url = self._config.get("proxy_url", "")
        self._test_worker = ConnectionTestWorker(
            engine_obj=engine_obj,
            api_key=self.inp_key.text().strip(),
            api_secret=self.inp_secret.text().strip(),
            proxy_url=proxy_url,
        )
        self._test_worker.test_finished.connect(self._on_test_finished)
        self._test_worker.start()

    def _on_test_finished(self, ok: bool, message: str):
        self.btn_test_srv.setEnabled(True)
        color = COLORS["ok"] if ok else COLORS["err"]
        prefix = "✅ " if ok else "❌ "
        self.lbl_test_result.setStyleSheet(f"color: {color}; font-weight: bold;")
        self.lbl_test_result.setText(f"{prefix}{message}")

    def _load_geoip_and_shot_settings(self):
        self.inp_mmdb_city.setText(self._geoip_cfg.get("city_mmdb_path", ""))
        self.inp_mmdb_asn.setText(self._geoip_cfg.get("asn_mmdb_path", ""))
        self.chk_ptr_enabled.setChecked(bool(self._geoip_cfg.get("ptr_enabled", True)))
        self.spin_geo_timeout.setValue(int(self._geoip_cfg.get("timeout_sec", 4)))

        self.spin_wait_ms.setValue(int(self._shot_cfg.get("page_wait_ms", 12000)))
        self.spin_hard_timeout.setValue(int(self._shot_cfg.get("hard_timeout_sec", 35)))
        res = str(self._shot_cfg.get("window_size", "1280,800"))
        idx = self.cmb_resolution.findText(res)
        if idx >= 0:
            self.cmb_resolution.setCurrentIndex(idx)

        self._update_mmdb_status()

        browser = find_browser_executable()
        if browser:
            self.lbl_browser_status.setStyleSheet(f"color: {COLORS['ok']};")
            self.lbl_browser_status.setText(f"✅ Gefundener Headless-Browser: {browser}")
        else:
            self.lbl_browser_status.setStyleSheet(f"color: {COLORS['warn']};")
            self.lbl_browser_status.setText(
                "⚠️ Kein Microsoft Edge oder Google Chrome im Standardpfad erkannt. "
                "Bitte Edge oder Chrome installieren, um Live-Vorschauen zu nutzen."
            )

    def _browse_mmdb(self, target_edit: QLineEdit):
        start_dir = os.path.dirname(target_edit.text().strip()) if target_edit.text().strip() else os.getcwd()
        path, _ = QFileDialog.getOpenFileName(
            self,
            "MaxMind GeoLite2 Datenbank auswählen",
            start_dir,
            "MaxMind Datenbank (*.mmdb);;Alle Dateien (*.*)",
        )
        if path:
            target_edit.setText(path)

    def _update_mmdb_status(self):
        has_reader = (
            importlib.util.find_spec("maxminddb") is not None
            or importlib.util.find_spec("geoip2") is not None
        )
        city_path = self.inp_mmdb_city.text().strip()
        asn_path = self.inp_mmdb_asn.text().strip()

        if not city_path and not asn_path:
            self.lbl_mmdb_status.setStyleSheet(f"color: {COLORS['text_muted']};")
            self.lbl_mmdb_status.setText("ℹ️ Keine lokale .mmdb gewählt – Online-Abfrage mit lokalem Cache aktiv.")
            return

        if not has_reader:
            self.lbl_mmdb_status.setStyleSheet(f"color: {COLORS['warn']};")
            self.lbl_mmdb_status.setText(
                "⚠️ Für lokale .mmdb-Dateien bitte 'pip install maxminddb' ausführen. "
                "Bis dahin greift automatisch der Online-Fallback."
            )
            return

        missing = [p for p in (city_path, asn_path) if p and not os.path.isfile(p)]
        if missing:
            self.lbl_mmdb_status.setStyleSheet(f"color: {COLORS['err']};")
            self.lbl_mmdb_status.setText(f"❌ Datei nicht gefunden: {missing[0]}")
        else:
            self.lbl_mmdb_status.setStyleSheet(f"color: {COLORS['ok']};")
            self.lbl_mmdb_status.setText("✅ Lokale MaxMind-Datenbank(en) bereit (Offline-Lookup + Online-Fallback).")

    def _on_save_clicked(self):
        self._geoip_cfg["city_mmdb_path"] = self.inp_mmdb_city.text().strip()
        self._geoip_cfg["asn_mmdb_path"] = self.inp_mmdb_asn.text().strip()
        self._geoip_cfg["ptr_enabled"] = self.chk_ptr_enabled.isChecked()
        self._geoip_cfg["timeout_sec"] = int(self.spin_geo_timeout.value())

        self._shot_cfg["page_wait_ms"] = int(self.spin_wait_ms.value())
        self._shot_cfg["hard_timeout_sec"] = int(self.spin_hard_timeout.value())
        self._shot_cfg["window_size"] = self.cmb_resolution.currentText()

        self.accept()

    def get_updated_config(self) -> dict:
        return self._config