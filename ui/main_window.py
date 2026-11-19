import os
import csv
import html
import json
import urllib.parse
import webbrowser

from PySide6.QtCore import Qt, QPoint, QModelIndex, QTimer
from PySide6.QtGui import QAction, QKeySequence, QShortcut, QGuiApplication
from PySide6.QtWidgets import (
    QMainWindow,
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QCheckBox,
    QSpinBox,
    QTableView,
    QHeaderView,
    QAbstractItemView,
    QProgressBar,
    QFileDialog,
    QMessageBox,
    QFrame,
    QMenu,
    QSplitter,
)

from core.constants import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_PORTS,
    PORT_PRESETS,
    DORK_TEMPLATES,
    SCREENSHOT_CACHE_DIR,
)
from core.storage import (
    load_config,
    save_config,
    load_session,
    save_session,
    load_history,
    save_history,
    append_history,
    load_favorites,
    save_favorites,
    toggle_favorite_item,
    load_geoip_cache,
    normalize_item,
)
from providers.engines import get_all_engines
from scanner.net_utils import parse_ports, parse_targets_from_text, normalize_url_suffix
from scanner.async_scanner import ScanWorker
from scanner.enrichment import EnrichmentWorker
from scanner.screenshotter import (
    ScreenshotWorker,
    get_cache_stats,
    clear_screenshot_cache,
)
from ui.theme import COLORS
from ui.models import EndpointTableModel, EndpointFilterProxyModel, PaginatedProxyModel
from ui.inspector_panel import InspectorPanel
from ui.service_dialog import ServiceConfigDialog


def _make_vdivider() -> QFrame:
    div = QFrame()
    div.setObjectName("VDivider")
    return div


class MainWindow(QMainWindow):
    """Hauptfenster von ShodanCheck mit Multi-Engine-Suche, Merkliste, GeoIP & Live-Vorschau."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"🛡️ {APP_NAME} v{APP_VERSION} — Multi-Engine Endpoint & Infrastructure Validator")
        self.resize(1520, 920)
        self.setMinimumSize(1240, 720)

        self.config = load_config()
        self.engines = get_all_engines()
        self.favorites_map: dict[str, dict] = load_favorites()
        self.search_history: list[dict] = load_history()

        self.scan_worker: ScanWorker | None = None
        self.shot_worker: ScreenshotWorker | None = None
        self.enrich_worker: EnrichmentWorker | None = None

        self.view_mode = "results"  # "results" oder "favorites"
        self.table_page_index = 0
        self.table_page_size = int(self.config.get("page_size") or 100)
        self._updating_pager_ui = False
        self._last_warnings: list[str] = []

        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.timeout.connect(self._persist_session_now)

        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(lambda: self._apply_filters(reset_page=True))

        self._build_menu_bar()
        self._build_ui()
        self._setup_shortcuts()
        self._refresh_engine_selectors()
        self._refresh_history_combo()
        self._refresh_cache_button_label()
        self._restore_previous_session()

    # =========================================================================
    # MENÜLEISTE & TASTATURKÜRZEL
    # =========================================================================
    def _build_menu_bar(self):
        menubar = self.menuBar()

        srv_menu = menubar.addMenu("🌐 Dienste")
        act_cfg = QAction("⚙️ Dienste, API-Keys && GeoIP (.mmdb) konfigurieren...", self)
        act_cfg.triggered.connect(self._open_service_dialog)
        srv_menu.addAction(act_cfg)

        srv_menu.addSeparator()
        self.quick_engine_menu = srv_menu.addMenu("⚡ Suchdienst schnell wählen")

        file_menu = menubar.addMenu("📂 Datei && Export")
        act_imp = QAction("📂 IP- / CIDR-Liste importieren (.txt/.csv)...", self)
        act_imp.triggered.connect(self._import_target_file)
        file_menu.addAction(act_imp)

        act_clip = QAction("📋 IP- / CIDR-Liste aus Zwischenablage scannen", self)
        act_clip.triggered.connect(self._import_from_clipboard)
        file_menu.addAction(act_clip)

        file_menu.addSeparator()
        for label, fmt in [
            ("💾 Export: CSV-Tabelle (.csv)", "csv"),
            ("💾 Export: JSON-Daten (.json)", "json"),
            ("💾 Export: Nur IP:Port Liste (.txt)", "txt"),
            ("💾 Export: Klickbarer HTML-Report (.html)", "html"),
        ]:
            act = QAction(label, self)
            act.triggered.connect(lambda checked=False, f=fmt: self._export_results(f))
            file_menu.addAction(act)

        file_menu.addSeparator()
        act_exit = QAction("Beenden", self)
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        view_menu = menubar.addMenu("🖥️ Ansicht")
        act_v_res = QAction("📋 Suchergebnisse anzeigen", self)
        act_v_res.triggered.connect(lambda: self._switch_view("results"))
        view_menu.addAction(act_v_res)

        act_v_fav = QAction("⭐ Dauerhafte Merkliste anzeigen", self)
        act_v_fav.triggered.connect(lambda: self._switch_view("favorites"))
        view_menu.addAction(act_v_fav)

        view_menu.addSeparator()
        act_insp = QAction("◫ Detail-Inspektor ein-/ausblenden (Strg+I)", self)
        act_insp.triggered.connect(self._toggle_inspector)
        view_menu.addAction(act_insp)

        act_rib = QAction("▲ Steuerleiste ein-/ausklappen", self)
        act_rib.triggered.connect(self._toggle_ribbon)
        view_menu.addAction(act_rib)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+F"), self, activated=lambda: self.search_filter_edit.setFocus())
        QShortcut(QKeySequence("Ctrl+I"), self, activated=self._toggle_inspector)
        QShortcut(QKeySequence("Ctrl+C"), self.table_view, activated=self._shortcut_copy_selected)
        QShortcut(QKeySequence("Delete"), self.table_view, activated=lambda: self._delete_selected_rows(checked_only=False))
        QShortcut(QKeySequence("F"), self.table_view, activated=lambda: self._toggle_favorite_selected(checked_only=False))
        QShortcut(QKeySequence("Return"), self.table_view, activated=lambda: self._bulk_open_selected(checked_only=False))
        QShortcut(QKeySequence("Space"), self.table_view, activated=self._shortcut_toggle_check)
        QShortcut(QKeySequence("Alt+Left"), self, activated=self._prev_table_page)
        QShortcut(QKeySequence("Alt+Right"), self, activated=self._next_table_page)

    # =========================================================================
    # UI-AUFBAU
    # =========================================================================
    def _build_ui(self):
        central = QWidget(objectName="CentralWidget")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # --- 1. KOMPAKTER HEADER + VIEW-SWITCHER + RIBBON ---
        header_card = QFrame(objectName="HeaderCard")
        header_lay = QVBoxLayout(header_card)
        header_lay.setContentsMargins(16, 8, 16, 8)
        header_lay.setSpacing(8)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        title_lbl = QLabel(f"🛡️ {APP_NAME}")
        title_lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #f8fafc;")
        top_row.addWidget(title_lbl)
        top_row.addSpacing(8)

        self.view_results_btn = QPushButton("📋 Suchergebnisse (0)")
        self.view_results_btn.setCheckable(True)
        self.view_results_btn.setChecked(True)
        self.view_results_btn.clicked.connect(lambda: self._switch_view("results"))
        top_row.addWidget(self.view_results_btn)

        self.view_favorites_btn = QPushButton("⭐ Merkliste (0)")
        self.view_favorites_btn.setCheckable(True)
        self.view_favorites_btn.clicked.connect(lambda: self._switch_view("favorites"))
        top_row.addWidget(self.view_favorites_btn)

        top_row.addStretch()

        self.kpi_total = self._make_kpi_pill(top_row, "Gesamt", "0", COLORS["text_primary"])
        self.kpi_ok = self._make_kpi_pill(top_row, "Aktiv (OK)", "0", COLORS["ok"])
        self.kpi_visited = self._make_kpi_pill(top_row, "Angeschaut", "0 / 0", COLORS["accent_light"])
        self.kpi_closed = self._make_kpi_pill(top_row, "Offline", "0", COLORS["err"])

        self.toggle_ribbon_btn = QPushButton("▲")
        self.toggle_ribbon_btn.setObjectName("IconBtn")
        self.toggle_ribbon_btn.setFixedSize(30, 28)
        self.toggle_ribbon_btn.setToolTip("Obere Werkzeugleiste ein-/ausklappen")
        self.toggle_ribbon_btn.clicked.connect(self._toggle_ribbon)
        top_row.addWidget(self.toggle_ribbon_btn)

        header_lay.addLayout(top_row)

        self.ribbon_tabs = QTabWidget()
        self.ribbon_tabs.addTab(self._build_tab_search(), "🔍 Suche && Scan")
        self.ribbon_tabs.addTab(self._build_tab_import(), "📂 Import && Ziele")
        self.ribbon_tabs.addTab(self._build_tab_export_cache(), "💾 Export, Historie && Cache")
        self.ribbon_tabs.addTab(self._build_tab_settings(), "⚙️ Suffix, Proxy && Leistung")
        header_lay.addWidget(self.ribbon_tabs)

        root.addWidget(header_card)

        # --- 2. HAUPTBEREICH (FILTER + CHECKBOX-BULK-BAR + MASTER-DETAIL SPLITTER) ---
        body = QWidget()
        body_lay = QVBoxLayout(body)
        body_lay.setContentsMargins(16, 8, 16, 8)
        body_lay.setSpacing(6)

        # Filter- & Seitenleiste
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        self.only_ok_cb = QCheckBox("Nur OK")
        self.only_ok_cb.setToolTip("Nur erreichbare Dienste anzeigen")
        self.only_ok_cb.stateChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.only_ok_cb)

        self.only_unvisited_cb = QCheckBox("Ungelesen")
        self.only_unvisited_cb.setToolTip("Bereits besuchte Einträge ausblenden")
        self.only_unvisited_cb.stateChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.only_unvisited_cb)

        self.status_code_combo = QComboBox()
        self.status_code_combo.addItem("Status: Alle", "ALL")
        self.status_code_combo.addItem("2xx Erfolg (200/204)", "2XX")
        self.status_code_combo.addItem("3xx Weiterleitung", "3XX")
        self.status_code_combo.addItem("401/403 Login/Auth", "AUTH")
        self.status_code_combo.addItem("4xx/5xx Fehler", "ERR")
        self.status_code_combo.addItem("Nicht-HTTP / Banner", "BANNER")
        self.status_code_combo.addItem("📷 Mit Vorschau", "SHOT")
        self.status_code_combo.setMinimumWidth(155)
        self.status_code_combo.currentIndexChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.status_code_combo)

        self.geo_filter_edit = QLineEdit()
        self.geo_filter_edit.setPlaceholderText("🌍 Land / ASN (z.B. DE, hetzner)")
        self.geo_filter_edit.setMinimumWidth(185)
        self.geo_filter_edit.setMaximumWidth(230)
        self.geo_filter_edit.textChanged.connect(lambda: self.filter_timer.start(120))
        filter_row.addWidget(self.geo_filter_edit)

        self.search_filter_edit = QLineEdit()
        self.search_filter_edit.setPlaceholderText("🔎 Textfilter (Begriff oder -Ausschluss, z.B. grafana -404)...")
        self.search_filter_edit.setMinimumWidth(210)
        self.search_filter_edit.textChanged.connect(lambda: self.filter_timer.start(120))
        filter_row.addWidget(self.search_filter_edit, 1)

        # Seiten-Navigation
        pager_pill = QFrame(objectName="PagerPill")
        pager_lay = QHBoxLayout(pager_pill)
        pager_lay.setContentsMargins(6, 2, 6, 2)
        pager_lay.setSpacing(5)

        self.prev_tbl_page_btn = QPushButton("◀")
        self.prev_tbl_page_btn.setObjectName("IconBtn")
        self.prev_tbl_page_btn.setFixedSize(26, 24)
        self.prev_tbl_page_btn.setToolTip("Vorherige Seite (Alt+Pfeil links)")
        self.prev_tbl_page_btn.clicked.connect(self._prev_table_page)
        pager_lay.addWidget(self.prev_tbl_page_btn)

        self.tbl_page_spin = QSpinBox()
        self.tbl_page_spin.setRange(1, 1)
        self.tbl_page_spin.setValue(1)
        self.tbl_page_spin.setFixedWidth(54)
        self.tbl_page_spin.valueChanged.connect(self._on_page_spin_changed)
        pager_lay.addWidget(self.tbl_page_spin)

        self.tbl_total_pages_lbl = QLabel("/ 1")
        self.tbl_total_pages_lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: bold;")
        pager_lay.addWidget(self.tbl_total_pages_lbl)

        self.next_tbl_page_btn = QPushButton("▶")
        self.next_tbl_page_btn.setObjectName("IconBtn")
        self.next_tbl_page_btn.setFixedSize(26, 24)
        self.next_tbl_page_btn.setToolTip("Nächste Seite (Alt+Pfeil rechts)")
        self.next_tbl_page_btn.clicked.connect(self._next_table_page)
        pager_lay.addWidget(self.next_tbl_page_btn)

        self.page_size_combo = QComboBox()
        self.page_size_combo.addItem("100 / S.", 100)
        self.page_size_combo.addItem("250 / S.", 250)
        self.page_size_combo.addItem("500 / S.", 500)
        self.page_size_combo.addItem("Alle", 0)
        ps_idx = self.page_size_combo.findData(self.table_page_size)
        if ps_idx >= 0:
            self.page_size_combo.setCurrentIndex(ps_idx)
        self.page_size_combo.setFixedWidth(84)
        self.page_size_combo.currentIndexChanged.connect(self._on_page_size_changed)
        pager_lay.addWidget(self.page_size_combo)

        filter_row.addWidget(pager_pill)

        self.visible_count_lbl = QLabel("0 / 0")
        self.visible_count_lbl.setStyleSheet(f"color: {COLORS['text_muted']}; font-weight: bold;")
        filter_row.addWidget(self.visible_count_lbl)

        self.select_visible_btn = QPushButton("☑️ Seite")
        self.select_visible_btn.setToolTip("Alle Einträge der aktuellen Seite per Checkbox markieren")
        self.select_visible_btn.clicked.connect(self._select_all_visible)
        filter_row.addWidget(self.select_visible_btn)

        self.toggle_inspector_btn = QPushButton("◫ Details")
        self.toggle_inspector_btn.setCheckable(True)
        self.toggle_inspector_btn.setChecked(True)
        self.toggle_inspector_btn.setToolTip("Detail-Inspektor rechts ein-/ausblenden (Strg+I)")
        self.toggle_inspector_btn.clicked.connect(self._toggle_inspector)
        filter_row.addWidget(self.toggle_inspector_btn)

        body_lay.addLayout(filter_row)

        # Sammelaktions-Leiste: wird NUR eingeblendet, wenn mindestens eine Checkbox aktiv ist
        self.bulk_bar = QFrame(objectName="BulkBar")
        self.bulk_bar.setVisible(False)
        bulk_lay = QHBoxLayout(self.bulk_bar)
        bulk_lay.setContentsMargins(10, 5, 10, 5)
        bulk_lay.setSpacing(6)

        self.bulk_count_lbl = QLabel("0 markiert:")
        self.bulk_count_lbl.setStyleSheet(f"color: {COLORS['accent_light']}; font-weight: bold;")
        bulk_lay.addWidget(self.bulk_count_lbl)
        bulk_lay.addSpacing(4)

        self.bulk_fav_btn = QPushButton("⭐ Merkliste")
        self.bulk_fav_btn.setToolTip("Markierte Einträge in dauerhafte Merkliste aufnehmen / entfernen")
        self.bulk_fav_btn.clicked.connect(lambda: self._toggle_favorite_selected(checked_only=True))
        bulk_lay.addWidget(self.bulk_fav_btn)

        self.bulk_shot_btn = QPushButton("📸 Screenshots")
        self.bulk_shot_btn.setToolTip("Live-Vorschauen für markierte aktive Web-Ziele erstellen")
        self.bulk_shot_btn.clicked.connect(lambda: self._bulk_capture_screenshots(checked_only=True))
        bulk_lay.addWidget(self.bulk_shot_btn)

        self.bulk_geo_btn = QPushButton("🌍 GeoIP / PTR")
        self.bulk_geo_btn.setToolTip("Reverse-DNS, ASN & Standort für markierte Ziele abrufen")
        self.bulk_geo_btn.clicked.connect(lambda: self._bulk_enrich_selected(checked_only=True))
        bulk_lay.addWidget(self.bulk_geo_btn)

        self.bulk_read_btn = QPushButton("✓ Angeschaut", objectName="PrimaryBtn")
        self.bulk_read_btn.clicked.connect(lambda: self._bulk_set_visited(True))
        bulk_lay.addWidget(self.bulk_read_btn)

        self.bulk_unread_btn = QPushButton("↺ Ungelesen")
        self.bulk_unread_btn.clicked.connect(lambda: self._bulk_set_visited(False))
        bulk_lay.addWidget(self.bulk_unread_btn)

        self.bulk_open_btn = QPushButton("🌐 Öffnen", objectName="SuccessBtn")
        self.bulk_open_btn.clicked.connect(lambda: self._bulk_open_selected(checked_only=True))
        bulk_lay.addWidget(self.bulk_open_btn)

        self.bulk_del_btn = QPushButton("🗑️ Entfernen")
        self.bulk_del_btn.clicked.connect(lambda: self._delete_selected_rows(checked_only=True))
        bulk_lay.addWidget(self.bulk_del_btn)

        bulk_lay.addStretch()

        self.bulk_clear_btn = QPushButton("✖ Auswahl aufheben")
        self.bulk_clear_btn.clicked.connect(self._clear_all_selection)
        bulk_lay.addWidget(self.bulk_clear_btn)

        body_lay.addWidget(self.bulk_bar)

        # --- 3. MASTER-DETAIL SPLITTER ---
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.results_model = EndpointTableModel(on_check_changed=self._update_bulk_controls)
        self.favorites_model = EndpointTableModel(on_check_changed=self._update_bulk_controls)

        self.proxy_model = EndpointFilterProxyModel()
        self.proxy_model.setSourceModel(self.results_model)

        self.page_proxy = PaginatedProxyModel()
        self.page_proxy.setSourceModel(self.proxy_model)

        self.table_view = QTableView()
        self.table_view.setModel(self.page_proxy)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSortingEnabled(True)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.verticalHeader().setDefaultSectionSize(28)
        self.table_view.setShowGrid(True)
        self.table_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self._show_table_context_menu)
        self.table_view.clicked.connect(self._on_table_clicked)
        self.table_view.doubleClicked.connect(self._on_table_double_clicked)
        self.table_view.selectionModel().selectionChanged.connect(self._on_selection_or_row_changed)

        hdr = self.table_view.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table_view.setColumnWidth(0, 32)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table_view.setColumnWidth(1, 32)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.table_view.setColumnWidth(2, 128)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self.table_view.setColumnWidth(3, 58)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        self.table_view.setColumnWidth(4, 118)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.table_view.setColumnWidth(5, 165)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        self.table_view.setColumnWidth(6, 200)
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)

        self.main_splitter.addWidget(self.table_view)

        # Rechter 3-Tab-Detail-Inspektor
        self.inspector_panel = InspectorPanel(cache_dir=SCREENSHOT_CACHE_DIR, parent=self)
        self.inspector_panel.screenshot_requested.connect(self._start_single_screenshot)
        self.inspector_panel.screenshot_cancel_requested.connect(self._cancel_screenshot_worker)
        self.inspector_panel.enrichment_requested.connect(self._start_single_enrichment)
        self.inspector_panel.open_url_requested.connect(self._open_url_and_mark_visited)
        self.inspector_panel.favorite_toggled.connect(self._on_inspector_fav_toggled)
        self.inspector_panel.close_requested.connect(self._toggle_inspector)

        self.main_splitter.addWidget(self.inspector_panel)
        self.main_splitter.setStretchFactor(0, 3)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setSizes([1060, 420])

        body_lay.addWidget(self.main_splitter, 1)
        root.addWidget(body, 1)

        # --- 4. STATUSLEISTE UNTEN ---
        footer = QFrame(objectName="FooterBar")
        footer_lay = QHBoxLayout(footer)
        footer_lay.setContentsMargins(16, 6, 16, 6)
        footer_lay.setSpacing(12)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(210)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        footer_lay.addWidget(self.progress_bar)

        self.status_lbl = QLabel("Bereit.")
        self.status_lbl.setStyleSheet(f"color: {COLORS['ok']}; font-weight: bold;")
        footer_lay.addWidget(self.status_lbl, 1)

        self.stop_btn = QPushButton("⏹ Abbrechen", objectName="DangerBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._cancel_all_workers)
        footer_lay.addWidget(self.stop_btn)

        root.addWidget(footer)

    def _build_tab_search(self) -> QWidget:
        w = QWidget(objectName="TabPage")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(10, 7, 10, 7)
        lay.setSpacing(8)

        self.engine_combo = QComboBox()
        self.engine_combo.setMinimumWidth(215)
        self.engine_combo.setToolTip("Einzelnen Suchdienst oder alle aktivierten Dienste im Universal-Modus abfragen")
        lay.addWidget(self.engine_combo)

        btn_srv = QPushButton("⚙️")
        btn_srv.setObjectName("IconBtn")
        btn_srv.setFixedSize(32, 28)
        btn_srv.setToolTip("Suchdienste, API-Keys & GeoIP (.mmdb) verwalten")
        btn_srv.clicked.connect(self._open_service_dialog)
        lay.addWidget(btn_srv)

        lay.addWidget(_make_vdivider())

        self.dork_combo = QComboBox()
        for label in DORK_TEMPLATES:
            self.dork_combo.addItem(label)
        self.dork_combo.setMinimumWidth(165)
        self.dork_combo.setToolTip("Vordefinierte Suchvorlage einfügen")
        self.dork_combo.currentIndexChanged.connect(self._on_dork_selected)
        lay.addWidget(self.dork_combo)

        self.query_edit = QLineEdit()
        self.query_edit.setPlaceholderText('Suchanfrage eingeben (z. B. http.title:"Grafana" oder country:"DE")...')
        self.query_edit.setMinimumWidth(240)
        self.query_edit.returnPressed.connect(self._start_search)
        lay.addWidget(self.query_edit, 1)

        lay.addWidget(_make_vdivider())

        self.port_preset_combo = QComboBox()
        self.port_preset_combo.addItem("Port-Profil…", "")
        for label, plist in PORT_PRESETS.items():
            self.port_preset_combo.addItem(label, ", ".join(str(p) for p in plist))
        self.port_preset_combo.setMinimumWidth(150)
        self.port_preset_combo.currentIndexChanged.connect(self._on_port_preset_selected)
        lay.addWidget(self.port_preset_combo)

        lay.addWidget(QLabel("<b>Ports:</b>"))
        self.ports_edit = QLineEdit(str(self.config.get("default_ports") or "80, 443, 8080, 8443"))
        self.ports_edit.setMinimumWidth(145)
        self.ports_edit.setMaximumWidth(185)
        self.ports_edit.setToolTip("Fallback-Ports für Treffer ohne Port oder für IP-Listen (z. B. 80, 443, 8000-8005)")
        self.ports_edit.returnPressed.connect(self._start_search)
        lay.addWidget(self.ports_edit)

        self.search_btn = QPushButton("🔍 Suchen && Prüfen", objectName="PrimaryBtn")
        self.search_btn.clicked.connect(self._start_search)
        lay.addWidget(self.search_btn)

        return w

    def _build_tab_import(self) -> QWidget:
        w = QWidget(objectName="TabPage")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(10, 7, 10, 7)
        lay.setSpacing(10)

        self.import_btn = QPushButton("📂 Datei importieren (.txt / .csv)", objectName="PrimaryBtn")
        self.import_btn.clicked.connect(self._import_target_file)
        lay.addWidget(self.import_btn)

        self.clip_import_btn = QPushButton("📋 Zwischenablage scannen")
        self.clip_import_btn.clicked.connect(self._import_from_clipboard)
        lay.addWidget(self.clip_import_btn)

        lay.addWidget(_make_vdivider())

        self.rescan_btn = QPushButton("🔄 Aktuelle Liste neu prüfen (Rescan)", objectName="WarningBtn")
        self.rescan_btn.clicked.connect(self._start_rescan)
        lay.addWidget(self.rescan_btn)

        self.enrich_all_btn = QPushButton("🌍 Fehlende GeoIP / ASN / PTR laden")
        self.enrich_all_btn.setToolTip("Ermittelt Standort, ASN-Provider und Reverse-DNS für alle erreichbaren Treffer")
        self.enrich_all_btn.clicked.connect(self._enrich_all_missing_ok)
        lay.addWidget(self.enrich_all_btn)

        lay.addWidget(_make_vdivider())

        self.auto_geoip_cb = QCheckBox("🌍 Auto-GeoIP/PTR beim Scan")
        self.auto_geoip_cb.setChecked(bool(self.config.get("auto_geoip", False)))
        self.auto_geoip_cb.setToolTip("Reichert erreichbare Treffer bereits während des Scans automatisch mit GeoIP, ASN und PTR an")
        self.auto_geoip_cb.toggled.connect(self._on_perf_settings_changed)
        lay.addWidget(self.auto_geoip_cb)

        lay.addStretch()
        return w

    def _build_tab_export_cache(self) -> QWidget:
        w = QWidget(objectName="TabPage")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(10, 7, 10, 7)
        lay.setSpacing(8)

        self.export_scope_combo = QComboBox()
        self.export_scope_combo.addItem("Export: Gesamte Ansicht", "ALL")
        self.export_scope_combo.addItem("Export: Gefiltert / Auswahl", "FILTERED")
        self.export_scope_combo.setMinimumWidth(195)
        lay.addWidget(self.export_scope_combo)

        for label, fmt in [("CSV", "csv"), ("JSON", "json"), ("TXT", "txt"), ("HTML", "html")]:
            b = QPushButton(f"💾 {label}")
            b.clicked.connect(lambda checked=False, f=fmt: self._export_results(f))
            lay.addWidget(b)

        lay.addWidget(_make_vdivider())

        lay.addWidget(QLabel("<b>🕒 Historie:</b>"))
        self.history_combo = QComboBox()
        self.history_combo.setMinimumWidth(220)
        lay.addWidget(self.history_combo)

        btn_load_h = QPushButton("Laden")
        btn_load_h.clicked.connect(self._apply_selected_history)
        lay.addWidget(btn_load_h)

        btn_clr_h = QPushButton("🗑️")
        btn_clr_h.setObjectName("IconBtn")
        btn_clr_h.setFixedSize(30, 28)
        btn_clr_h.setToolTip("Suchhistorie leeren")
        btn_clr_h.clicked.connect(self._clear_history)
        lay.addWidget(btn_clr_h)

        lay.addStretch()
        lay.addWidget(_make_vdivider())

        self.clear_cache_btn = QPushButton("🧹 Cache (0 Bilder | 0.0 MB)")
        self.clear_cache_btn.setToolTip("Gespeicherte Vorschaubilder im Screenshot-Cache bereinigen")
        self.clear_cache_btn.clicked.connect(self._on_clear_screenshot_cache)
        lay.addWidget(self.clear_cache_btn)

        return w

    def _build_tab_settings(self) -> QWidget:
        w = QWidget(objectName="TabPage")
        lay = QHBoxLayout(w)
        lay.setContentsMargins(10, 7, 10, 7)
        lay.setSpacing(10)

        lay.addWidget(QLabel("<b>🔗 URL-Suffix:</b>"))
        self.suffix_edit = QLineEdit(str(self.config.get("url_suffix") or ""))
        self.suffix_edit.setPlaceholderText("z. B. /login oder /admin")
        self.suffix_edit.setMinimumWidth(165)
        self.suffix_edit.setMaximumWidth(210)
        self.suffix_edit.textChanged.connect(self._on_suffix_changed)
        lay.addWidget(self.suffix_edit)

        lay.addWidget(_make_vdivider())

        lay.addWidget(QLabel("<b>🛡️ Proxy:</b>"))
        self.proxy_edit = QLineEdit(str(self.config.get("proxy_url") or ""))
        self.proxy_edit.setPlaceholderText("http://127.0.0.1:8080 oder socks5://127.0.0.1:9050")
        self.proxy_edit.setMinimumWidth(240)
        self.proxy_edit.textChanged.connect(self._on_perf_settings_changed)
        lay.addWidget(self.proxy_edit, 1)

        lay.addWidget(_make_vdivider())

        lay.addWidget(QLabel("<b>⚡ Async:</b>"))
        self.concurrency_combo = QComboBox()
        self.concurrency_combo.addItems(["50", "100", "250", "500", "1000"])
        self.concurrency_combo.setCurrentText(str(self.config.get("concurrency") or 250))
        self.concurrency_combo.setFixedWidth(74)
        self.concurrency_combo.currentTextChanged.connect(self._on_perf_settings_changed)
        lay.addWidget(self.concurrency_combo)

        lay.addWidget(QLabel("<b>⏱️ Timeout (s):</b>"))
        self.timeout_combo = QComboBox()
        self.timeout_combo.addItems(["1.5", "2.0", "3.5", "5.0", "8.0"])
        self.timeout_combo.setCurrentText(str(self.config.get("timeout_sec") or 3.5))
        self.timeout_combo.setFixedWidth(68)
        self.timeout_combo.currentTextChanged.connect(self._on_perf_settings_changed)
        lay.addWidget(self.timeout_combo)

        lay.addWidget(QLabel("<b>Max/Dienst:</b>"))
        self.max_results_spin = QSpinBox()
        self.max_results_spin.setRange(10, 1000)
        self.max_results_spin.setSingleStep(50)
        self.max_results_spin.setValue(int(self.config.get("max_results_per_service") or 100))
        self.max_results_spin.setFixedWidth(74)
        self.max_results_spin.valueChanged.connect(self._on_perf_settings_changed)
        lay.addWidget(self.max_results_spin)

        btn_open_srv = QPushButton("⚙️ Dienste, API-Keys && .mmdb", objectName="PrimaryBtn")
        btn_open_srv.clicked.connect(self._open_service_dialog)
        lay.addWidget(btn_open_srv)

        return w

    def _make_kpi_pill(self, parent_layout: QHBoxLayout, label: str, value: str, color: str) -> QLabel:
        pill = QFrame(objectName="KpiPill")
        lay = QHBoxLayout(pill)
        lay.setContentsMargins(9, 3, 9, 3)
        lay.setSpacing(4)
        lbl_t = QLabel(f"{label}:")
        lbl_t.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px;")
        lbl_v = QLabel(value)
        lbl_v.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")
        lay.addWidget(lbl_t)
        lay.addWidget(lbl_v)
        parent_layout.addWidget(pill)
        return lbl_v

    # =========================================================================
    # KONFIGURATION, DIENSTE & SITZUNG
    # =========================================================================
    def _open_service_dialog(self):
        dlg = ServiceConfigDialog(config=self.config, engines=self.engines, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.config = dlg.get_updated_config()
            save_config(self.config)
            self._refresh_engine_selectors()
            self._set_status("Konfiguration für Dienste, GeoIP & Vorschau gespeichert.", COLORS["ok"])

    def _refresh_engine_selectors(self):
        current_id = self.engine_combo.currentData() or "__all__"
        services_cfg = self.config.get("services") or {}

        ready_count = 0
        for eid, eng in self.engines.items():
            s_cfg = services_cfg.get(eid) or {}
            if s_cfg.get("enabled") and (not eng.requires_key or (s_cfg.get("api_key") or "").strip()):
                ready_count += 1

        self.engine_combo.blockSignals(True)
        self.engine_combo.clear()
        self.engine_combo.addItem(f"🌐 Alle aktiven Dienste ({ready_count} bereit)", "__all__")

        self.quick_engine_menu.clear()
        act_all = QAction("🌐 Alle aktiven Dienste (Multi-Suche)", self.quick_engine_menu)
        act_all.triggered.connect(lambda: self._select_engine("__all__"))
        self.quick_engine_menu.addAction(act_all)
        self.quick_engine_menu.addSeparator()

        for eid, eng in self.engines.items():
            s_cfg = services_cfg.get(eid) or {}
            has_key = bool((s_cfg.get("api_key") or "").strip()) or not eng.requires_key
            badge = "✅" if (s_cfg.get("enabled") and has_key) else ("🔑" if has_key else "⚪")
            self.engine_combo.addItem(f"{badge} {eng.name}", eid)

            act = QAction(f"{badge} {eng.name}", self.quick_engine_menu)
            act.triggered.connect(lambda checked=False, target_id=eid: self._select_engine(target_id))
            self.quick_engine_menu.addAction(act)

        idx = self.engine_combo.findData(current_id)
        self.engine_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.engine_combo.blockSignals(False)

    def _select_engine(self, eid: str):
        idx = self.engine_combo.findData(eid)
        if idx >= 0:
            self.engine_combo.setCurrentIndex(idx)
            self.ribbon_tabs.setCurrentIndex(0)

    def _on_perf_settings_changed(self):
        self.config["proxy_url"] = self.proxy_edit.text().strip()
        self.config["concurrency"] = int(self.concurrency_combo.currentText())
        self.config["timeout_sec"] = float(self.timeout_combo.currentText())
        self.config["max_results_per_service"] = int(self.max_results_spin.value())
        self.config["auto_geoip"] = self.auto_geoip_cb.isChecked()
        save_config(self.config)

    def _restore_previous_session(self):
        fav_items = []
        for k, raw in self.favorites_map.items():
            norm = normalize_item(raw)
            norm["favorite"] = True
            norm["checked"] = False
            fav_items.append(norm)
        self.favorites_model.set_items(fav_items)

        sess = load_session()
        if sess.get("query"):
            self.query_edit.setText(sess["query"])
        if sess.get("ports"):
            self.ports_edit.setText(sess["ports"])
        if sess.get("suffix"):
            self.suffix_edit.blockSignals(True)
            self.suffix_edit.setText(sess["suffix"])
            self.suffix_edit.blockSignals(False)

        items = sess.get("items") or []
        for it in items:
            key = f"{it['ip']}:{it['port']}"
            it["favorite"] = key in self.favorites_map
            it["checked"] = False

        self.results_model.set_items(items)
        self.table_page_index = int(sess.get("page_index") or 0)

        self._update_view_buttons()
        self._apply_filters(reset_page=False)
        self._update_kpis()

        if items:
            self._set_status(
                f"Letzte Sitzung geladen ({len(items)} Treffer, {len(self.favorites_map)} Favoriten).",
                COLORS["accent_light"],
            )

    def _schedule_save_session(self):
        self.save_timer.start(600)

    def _persist_session_now(self):
        save_session(
            items=self.results_model.get_all_items(),
            query=self.query_edit.text().strip(),
            ports=self.ports_edit.text().strip(),
            suffix=self.suffix_edit.text().strip(),
            page_index=self.table_page_index,
        )

    def closeEvent(self, event):
        self._cancel_all_workers(wait_ms=1200)
        self.config["default_ports"] = self.ports_edit.text().strip()
        self.config["url_suffix"] = self.suffix_edit.text().strip()
        self.config["page_size"] = self.table_page_size
        save_config(self.config)
        self._persist_session_now()
        save_favorites(self.favorites_map)
        save_history(self.search_history)
        super().closeEvent(event)

    # =========================================================================
    # ANSICHTEN, SPLITTER & URL-SUFFIX
    # =========================================================================
    def _active_model(self) -> EndpointTableModel:
        return self.favorites_model if self.view_mode == "favorites" else self.results_model

    def _switch_view(self, mode: str):
        if mode not in ("results", "favorites"):
            return
        self.view_mode = mode
        self._update_view_buttons()
        self.proxy_model.setSourceModel(self._active_model())
        self._apply_filters(reset_page=True)
        self._update_kpis()
        self._update_inspector_selection()

    def _update_view_buttons(self):
        self.view_results_btn.setText(f"📋 Suchergebnisse ({self.results_model.rowCount()})")
        self.view_favorites_btn.setText(f"⭐ Merkliste ({len(self.favorites_map)})")
        self.view_results_btn.setChecked(self.view_mode == "results")
        self.view_favorites_btn.setChecked(self.view_mode == "favorites")

    def _toggle_ribbon(self):
        vis = not self.ribbon_tabs.isVisible()
        self.ribbon_tabs.setVisible(vis)
        self.toggle_ribbon_btn.setText("▲" if vis else "▼")

    def _toggle_inspector(self):
        vis = not self.inspector_panel.isVisible()
        self.inspector_panel.setVisible(vis)
        self.toggle_inspector_btn.setChecked(vis)

    def _on_dork_selected(self, idx: int):
        label = self.dork_combo.currentText()
        dork = DORK_TEMPLATES.get(label, "")
        if dork:
            self.query_edit.setText(dork)
        self.dork_combo.setCurrentIndex(0)

    def _on_port_preset_selected(self, idx: int):
        ports_str = self.port_preset_combo.currentData()
        if ports_str:
            self.ports_edit.setText(ports_str)
        self.port_preset_combo.setCurrentIndex(0)

    def _on_suffix_changed(self, text: str):
        clean_suffix = normalize_url_suffix(text)
        self.config["url_suffix"] = text.strip()

        for model in (self.results_model, self.favorites_model):
            changed_rows = []
            for idx, it in enumerate(model.get_all_items()):
                if it.get("status") == "OK" and it.get("url"):
                    parts = urllib.parse.urlsplit(it["url"])
                    new_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, clean_suffix, "", ""))
                    if it["url"] != new_url:
                        it["url"] = new_url
                        changed_rows.append(idx)
            if changed_rows:
                model.notify_rows_updated(changed_rows)

        self._update_inspector_selection()
        self._schedule_save_session()

    # =========================================================================
    # SCANNEN, IMPORT & RESCAN
    # =========================================================================
    def _set_busy_state(self, busy: bool):
        self.search_btn.setEnabled(not busy)
        self.rescan_btn.setEnabled(not busy)
        self.import_btn.setEnabled(not busy)
        self.clip_import_btn.setEnabled(not busy)
        self._update_stop_button_state()

    def _update_stop_button_state(self):
        any_running = bool(
            (self.scan_worker and self.scan_worker.isRunning())
            or (self.shot_worker and self.shot_worker.isRunning())
            or (self.enrich_worker and self.enrich_worker.isRunning())
        )
        self.stop_btn.setEnabled(any_running)

    def _cancel_all_workers(self, wait_ms: int = 0):
        for w in (self.scan_worker, self.shot_worker, self.enrich_worker):
            if w and w.isRunning() and hasattr(w, "request_cancel"):
                w.request_cancel()
        if wait_ms > 0:
            for w in (self.scan_worker, self.shot_worker, self.enrich_worker):
                if w and w.isRunning():
                    w.wait(wait_ms)
        self._set_status("Abbruch angefordert...", COLORS["warn"])

    def _start_search(self):
        if self.scan_worker and self.scan_worker.isRunning():
            return
        query = self.query_edit.text().strip()
        if not query:
            QMessageBox.information(self, "Suchanfrage fehlt", "Bitte gib einen Suchbegriff oder Dork ein.")
            self.query_edit.setFocus()
            return

        if self.view_mode != "results":
            self._switch_view("results")

        self.results_model.clear_all()
        self.inspector_panel.clear_view()
        self._update_view_buttons()
        self._update_kpis()
        self._apply_filters(reset_page=True)

        self._last_warnings.clear()
        self.progress_bar.setValue(0)
        self._set_busy_state(True)

        visited_keys = {
            f"{it['ip']}:{it['port']}"
            for it in self.favorites_map.values()
            if it.get("visited")
        }

        self.scan_worker = ScanWorker(
            mode="search",
            config=self.config,
            engines=self.engines,
            query=query,
            selected_engine_id=self.engine_combo.currentData() or "__all__",
            ports_text=self.ports_edit.text().strip(),
            favorite_keys=set(self.favorites_map.keys()),
            visited_keys=visited_keys,
            parent=self,
        )
        self.scan_worker.status_updated.connect(self._set_status)
        self.scan_worker.progress_updated.connect(self._on_scan_progress)
        self.scan_worker.batch_ready.connect(self._on_scan_batch_ready)
        self.scan_worker.search_summary.connect(self._on_search_summary)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.start()

    def _start_target_scan(self, targets: list[dict], history_label: str = ""):
        if self.scan_worker and self.scan_worker.isRunning():
            return
        if not targets:
            QMessageBox.information(self, "Keine gültigen Ziele", "Es wurden keine gültigen IP-Adressen erkannt.")
            return

        if self.view_mode != "results":
            self._switch_view("results")

        self.results_model.clear_all()
        self.inspector_panel.clear_view()
        self._update_view_buttons()
        self._update_kpis()
        self._apply_filters(reset_page=True)

        self._last_warnings.clear()
        self.progress_bar.setValue(0)
        self._set_busy_state(True)

        visited_keys = {
            f"{it['ip']}:{it['port']}"
            for it in self.favorites_map.values()
            if it.get("visited")
        }

        self.scan_worker = ScanWorker(
            mode="targets",
            config=self.config,
            engines=self.engines,
            query=history_label,
            ports_text=self.ports_edit.text().strip(),
            raw_targets=targets,
            favorite_keys=set(self.favorites_map.keys()),
            visited_keys=visited_keys,
            parent=self,
        )
        self.scan_worker.status_updated.connect(self._set_status)
        self.scan_worker.progress_updated.connect(self._on_scan_progress)
        self.scan_worker.batch_ready.connect(self._on_scan_batch_ready)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_worker.start()

    def _start_rescan(self):
        model = self._active_model()
        items = model.get_all_items()
        if not items:
            QMessageBox.information(self, "Keine Einträge", "Die aktuelle Liste ist leer.")
            return
        targets = [dict(it) for it in items]
        self._start_target_scan(targets, history_label="Rescan")

    def _import_target_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "IP- / CIDR-Liste importieren",
            "",
            "Text & CSV Dateien (*.txt *.csv *.lst);;Alle Dateien (*.*)",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()
        except Exception as exc:
            QMessageBox.critical(self, "Lesefehler", str(exc))
            return

        ports = parse_ports(self.ports_edit.text(), fallback=DEFAULT_PORTS)
        targets = parse_targets_from_text(raw, default_ports=ports, source_label=os.path.basename(path))
        self._start_target_scan(targets, history_label=f"Import: {os.path.basename(path)}")

    def _import_from_clipboard(self):
        raw = QGuiApplication.clipboard().text() or ""
        ports = parse_ports(self.ports_edit.text(), fallback=DEFAULT_PORTS)
        targets = parse_targets_from_text(raw, default_ports=ports, source_label="Zwischenablage")
        self._start_target_scan(targets, history_label="Zwischenablage")

    def _on_scan_progress(self, done: int, total: int):
        if total > 0:
            self.progress_bar.setValue(int((done / total) * 100))
            self._set_status(f"⚡ Prüfe Endpunkte: {done} / {total}...", COLORS["cyan"])

    def _on_search_summary(self, active_names: list[str], errors: list[str]):
        self._last_warnings = list(errors)
        if active_names:
            self.search_history = append_history(
                query=self.query_edit.text().strip(),
                ports=self.ports_edit.text().strip(),
                engines=", ".join(active_names),
                hit_count=0,
            )
            self._refresh_history_combo()

    def _on_scan_batch_ready(self, batch: list[dict]):
        self.results_model.append_items(batch)
        fav_changed = False
        for item in batch:
            key = f"{item['ip']}:{item['port']}"
            if key in self.favorites_map:
                merged = dict(self.favorites_map[key])
                for field in (
                    "status", "url", "http_code", "response_info", "tls_info",
                    "headers_raw", "banner_raw", "country_code", "country_name",
                    "city", "asn", "asn_org", "ptr",
                ):
                    if item.get(field):
                        merged[field] = item[field]
                merged["favorite"] = True
                self.favorites_map[key] = merged
                fav_changed = True

        if fav_changed:
            self.favorites_model.set_items(list(self.favorites_map.values()))

        self._update_view_buttons()
        self._update_kpis()
        self._update_pagination_ui()

    def _on_scan_finished(self, cancelled: bool, ok_count: int, total_count: int):
        self._set_busy_state(False)
        self.progress_bar.setValue(100 if total_count > 0 else 0)
        save_favorites(self.favorites_map)
        self._apply_filters(reset_page=False)
        self._update_kpis()
        self._schedule_save_session()

        warn_txt = f" | ⚠️ {self._last_warnings[0]}" if self._last_warnings else ""
        if cancelled:
            self._set_status(f"⏹ Abgebrochen ({ok_count} OK von {total_count} geprüften){warn_txt}", COLORS["warn"])
        elif total_count == 0 and self._last_warnings:
            self._set_status(f"❌ {self._last_warnings[0]}", COLORS["err"])
        else:
            self._set_status(
                f"✅ Fertig: {ok_count} erreichbar von {total_count} geprüften Zielen{warn_txt}",
                COLORS["warn"] if self._last_warnings else COLORS["ok"],
            )

    # =========================================================================
    # GEOIP / ASN / PTR ANREICHERUNG (ON-DEMAND & BATCH)
    # =========================================================================
    def _start_single_enrichment(self, item: dict):
        ip = (item.get("ip") or "").strip()
        if not ip:
            return
        self._start_enrichment_for_ips([ip], force_refresh=True)

    def _bulk_enrich_selected(self, checked_only: bool = True):
        rows = self._get_checked_source_rows() if checked_only else self._get_target_source_rows()
        if not rows:
            return
        model = self._active_model()
        ips = [model.get_item(r)["ip"] for r in rows]
        self._start_enrichment_for_ips(ips, force_refresh=False)

    def _enrich_all_missing_ok(self):
        model = self._active_model()
        ips = [
            it["ip"]
            for it in model.get_all_items()
            if it.get("status") == "OK" and not (it.get("country_code") and (it.get("asn") or it.get("ptr")))
        ]
        if not ips:
            self._set_status("Alle erreichbaren Einträge besitzen bereits GeoIP-/ASN-Daten.", COLORS["ok"])
            return
        self._start_enrichment_for_ips(ips, force_refresh=False)

    def _start_enrichment_for_ips(self, ips: list[str], force_refresh: bool = False):
        unique_ips = list(dict.fromkeys(ip.strip() for ip in ips if ip and ip.strip()))
        if not unique_ips:
            return
        if self.enrich_worker and self.enrich_worker.isRunning():
            return

        if len(unique_ips) > 1:
            self._set_status(f"🌍 Rufe GeoIP / ASN / PTR für {len(unique_ips)} IP(s) ab...", COLORS["cyan"])

        self.enrich_worker = EnrichmentWorker(
            ips=unique_ips,
            geoip_cfg=self.config.get("geoip") or {},
            proxy_url=(self.config.get("proxy_url") or "").strip(),
            force_refresh=force_refresh,
            parent=self,
        )
        self.enrich_worker.item_enriched.connect(self._on_ip_enriched)
        self.enrich_worker.batch_finished.connect(self._on_enrichment_finished)
        self.enrich_worker.start()
        self._update_stop_button_state()

    def _on_ip_enriched(self, ip: str, data: dict):
        if not data:
            return

        for model in (self.results_model, self.favorites_model):
            rows = model.find_rows_by_ip(ip)
            for r in rows:
                it = model.get_item(r)
                for field in ("country_code", "country_name", "city", "asn", "asn_org", "ptr"):
                    if data.get(field):
                        it[field] = data[field]
            if rows:
                model.notify_rows_updated(rows)

        for key, fav_it in self.favorites_map.items():
            if fav_it.get("ip") == ip:
                for field in ("country_code", "country_name", "city", "asn", "asn_org", "ptr"):
                    if data.get(field):
                        fav_it[field] = data[field]

        self._update_inspector_selection()

    def _on_enrichment_finished(self, count: int):
        self._update_stop_button_state()
        save_favorites(self.favorites_map)
        self._schedule_save_session()
        if count > 1:
            self._set_status(f"🌍 GeoIP / ASN / PTR für {count} IP(s) aktualisiert.", COLORS["ok"])

    # =========================================================================
    # HEADLESS-SCREENSHOTS (MANUELL & BATCH)
    # =========================================================================
    def _start_single_screenshot(self, item: dict):
        if not item or item.get("status") != "OK":
            return
        self._launch_screenshot_worker([dict(item)], is_single=True)

    def _bulk_capture_screenshots(self, checked_only: bool = True):
        model = self._active_model()
        rows = self._get_checked_source_rows() if checked_only else self._get_target_source_rows()
        targets = [
            dict(model.get_item(r))
            for r in rows
            if model.get_item(r).get("status") == "OK"
            and (model.get_item(r).get("url") or "").lower().startswith(("http://", "https://"))
        ]
        if not targets:
            QMessageBox.information(
                self,
                "Keine Web-Ziele markiert",
                "Bitte markiere mindestens einen erreichbaren (OK) HTTP/HTTPS-Eintrag.",
            )
            return
        self._launch_screenshot_worker(targets, is_single=False)

    def _launch_screenshot_worker(self, targets: list[dict], is_single: bool):
        if self.shot_worker and self.shot_worker.isRunning():
            QMessageBox.information(self, "Vorschau läuft", "Es läuft bereits eine Screenshot-Aufnahme.")
            return

        shot_cfg = self.config.get("screenshot") or {}
        if is_single:
            self.inspector_panel.set_screenshot_busy(
                True, "⏳ Warte auf vollständiges Laden der Gegenseite..."
            )
        else:
            self._set_status(f"📸 Erstelle Live-Vorschauen für {len(targets)} Ziele...", COLORS["cyan"])

        self.shot_worker = ScreenshotWorker(
            targets=targets,
            cache_dir=SCREENSHOT_CACHE_DIR,
            proxy_url=(self.config.get("proxy_url") or "").strip(),
            page_wait_ms=int(shot_cfg.get("page_wait_ms") or 12000),
            hard_timeout_sec=int(shot_cfg.get("hard_timeout_sec") or 35),
            max_workers=3,
        )
        self.shot_worker.progress_updated.connect(lambda msg: self._set_status(f"📸 {msg}", COLORS["cyan"]))
        self.shot_worker.screenshot_ready.connect(self._on_screenshot_ready)
        self.shot_worker.batch_finished.connect(self._on_screenshot_batch_finished)
        self.shot_worker.start()
        self._update_stop_button_state()

    def _cancel_screenshot_worker(self):
        if self.shot_worker and self.shot_worker.isRunning():
            self.shot_worker.request_cancel()
            self.inspector_panel.set_screenshot_busy(False, "Vorschau-Aufnahme abgebrochen.")
            self._set_status("Screenshot-Aufnahme abgebrochen.", COLORS["warn"])

    def _on_screenshot_ready(self, key: str, path: str, ok: bool, msg: str):
        if ok and path:
            for model in (self.results_model, self.favorites_model):
                row_idx = model.find_row_by_key(key)
                if row_idx >= 0:
                    model.get_item(row_idx)["screenshot_path"] = path
                    model.notify_rows_updated([row_idx])
            if key in self.favorites_map:
                self.favorites_map[key]["screenshot_path"] = path

        self.inspector_panel.set_screenshot_busy(False, msg)
        self._update_inspector_selection()
        self._refresh_cache_button_label()

    def _on_screenshot_batch_finished(self, ok_count: int, fail_count: int):
        self._update_stop_button_state()
        save_favorites(self.favorites_map)
        self._schedule_save_session()
        if (ok_count + fail_count) > 1:
            self._set_status(
                f"📸 Vorschauen abgeschlossen: {ok_count} erfolgreich, {fail_count} fehlgeschlagen.",
                COLORS["ok"] if ok_count > 0 else COLORS["warn"],
            )

    def _refresh_cache_button_label(self):
        count, total_bytes = get_cache_stats(SCREENSHOT_CACHE_DIR)
        mb = total_bytes / (1024 * 1024)
        self.clear_cache_btn.setText(f"🧹 Cache ({count} Bilder | {mb:.1f} MB)")

    def _on_clear_screenshot_cache(self):
        count, _ = get_cache_stats(SCREENSHOT_CACHE_DIR)
        if count == 0:
            self._set_status("Der Screenshot-Cache ist bereits leer.", COLORS["text_muted"])
            return
        reply = QMessageBox.question(
            self,
            "Screenshot-Cache leeren",
            f"Sollen alle {count} gespeicherten Vorschaubilder dauerhaft gelöscht werden?",
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        removed = clear_screenshot_cache(SCREENSHOT_CACHE_DIR)
        for model in (self.results_model, self.favorites_model):
            items = model.get_all_items()
            for it in items:
                it["screenshot_path"] = ""
            if items:
                model.notify_rows_updated(list(range(len(items))))

        for fav_it in self.favorites_map.values():
            fav_it["screenshot_path"] = ""
        save_favorites(self.favorites_map)

        self._refresh_cache_button_label()
        self._update_inspector_selection()
        self._schedule_save_session()
        self._set_status(f"🧹 {removed} Vorschaubilder aus dem Cache entfernt.", COLORS["ok"])

    # =========================================================================
    # FILTER, PAGINATION, INSPEKTOR & TABELLEN-AKTIONEN
    # =========================================================================
    def _map_view_to_source(self, view_index: QModelIndex) -> QModelIndex:
        if not view_index.isValid():
            return QModelIndex()
        filter_idx = self.page_proxy.mapToSource(view_index)
        if not filter_idx.isValid():
            return QModelIndex()
        return self.proxy_model.mapToSource(filter_idx)

    def _on_filter_changed(self):
        self._apply_filters(reset_page=True)

    def _apply_filters(self, reset_page: bool = False):
        if reset_page:
            self.table_page_index = 0
        self.proxy_model.set_filters(
            only_ok=self.only_ok_cb.isChecked(),
            only_unvisited=self.only_unvisited_cb.isChecked(),
            status_filter=self.status_code_combo.currentData() or "ALL",
            geo_filter=self.geo_filter_edit.text(),
            search_text=self.search_filter_edit.text(),
        )
        self._update_pagination_ui()
        self._update_bulk_controls()

    def _get_total_table_pages(self) -> int:
        filtered_total = self.proxy_model.rowCount()
        if filtered_total == 0 or self.table_page_size <= 0:
            return 1
        return max(1, (filtered_total + self.table_page_size - 1) // self.table_page_size)

    def _update_pagination_ui(self):
        total_pages = self._get_total_table_pages()
        if self.table_page_index >= total_pages:
            self.table_page_index = max(0, total_pages - 1)

        self.page_proxy.set_pagination(self.table_page_index, self.table_page_size)

        self._updating_pager_ui = True
        try:
            self.tbl_page_spin.setRange(1, total_pages)
            self.tbl_page_spin.setValue(self.table_page_index + 1)
            self.tbl_page_spin.setEnabled(total_pages > 1)
        finally:
            self._updating_pager_ui = False

        self.tbl_total_pages_lbl.setText(f"/ {total_pages}")
        self.prev_tbl_page_btn.setEnabled(self.table_page_index > 0)
        self.next_tbl_page_btn.setEnabled(self.table_page_index + 1 < total_pages)

        filtered_total = self.proxy_model.rowCount()
        all_total = self._active_model().rowCount()
        on_page = self.page_proxy.rowCount()

        if filtered_total == 0:
            self.visible_count_lbl.setText(f"0 / {all_total}")
        elif self.table_page_size <= 0 or total_pages == 1:
            self.visible_count_lbl.setText(f"{filtered_total} / {all_total}")
        else:
            start_num = self.table_page_index * self.table_page_size + 1
            end_num = start_num + on_page - 1
            self.visible_count_lbl.setText(f"{start_num}–{end_num} / {filtered_total}")

    def _prev_table_page(self):
        if self.table_page_index > 0:
            self.table_page_index -= 1
            self._update_pagination_ui()
            self.table_view.scrollToTop()

    def _next_table_page(self):
        if self.table_page_index + 1 < self._get_total_table_pages():
            self.table_page_index += 1
            self._update_pagination_ui()
            self.table_view.scrollToTop()

    def _on_page_spin_changed(self, value: int):
        if self._updating_pager_ui:
            return
        new_idx = max(0, min(value - 1, self._get_total_table_pages() - 1))
        if new_idx != self.table_page_index:
            self.table_page_index = new_idx
            self._update_pagination_ui()
            self.table_view.scrollToTop()

    def _on_page_size_changed(self):
        new_size = self.page_size_combo.currentData()
        if new_size is None:
            return
        self.table_page_size = int(new_size)
        self.table_page_index = 0
        self._update_pagination_ui()

    def _update_kpis(self):
        items = self._active_model().get_all_items()
        total = len(items)
        ok_count = sum(1 for r in items if r.get("status") == "OK")
        visited_count = sum(1 for r in items if r.get("status") == "OK" and r.get("visited"))
        closed_count = total - ok_count

        self.kpi_total.setText(str(total))
        self.kpi_ok.setText(str(ok_count))
        self.kpi_visited.setText(f"{visited_count} / {ok_count}")
        self.kpi_closed.setText(str(closed_count))

    def _get_checked_source_rows(self) -> list[int]:
        """Liefert ausschließlich per Checkbox markierte Zeilen-Indizes."""
        model = self._active_model()
        return [
            idx
            for idx, item in enumerate(model.get_all_items())
            if item.get("checked")
        ]

    def _get_target_source_rows(self) -> list[int]:
        """Liefert markierte Checkbox-Zeilen oder (falls keine angehakt) die hervorgehobenen Zeilen."""
        checked = self._get_checked_source_rows()
        if checked:
            return checked

        source_rows = set()
        if self.table_view.selectionModel():
            for view_idx in self.table_view.selectionModel().selectedRows():
                src_idx = self._map_view_to_source(view_idx)
                if src_idx.isValid():
                    source_rows.add(src_idx.row())
        return sorted(source_rows)

    def _on_selection_or_row_changed(self):
        # Normale Zeilenauswahl aktualisiert nur den Inspektor, ohne die Checkbox-Leiste einzublenden
        self._update_inspector_selection(auto_enrich=True)

    def _update_inspector_selection(self, auto_enrich: bool = False):
        cur_idx = self.table_view.currentIndex()
        src_idx = self._map_view_to_source(cur_idx)
        model = self._active_model()
        if not src_idx.isValid() or src_idx.row() >= model.rowCount():
            rows = self._get_target_source_rows()
            if not rows or rows[0] >= model.rowCount():
                self.inspector_panel.clear_view()
                return
            item = model.get_item(rows[0])
        else:
            item = model.get_item(src_idx.row())

        self.inspector_panel.set_item(item, SCREENSHOT_CACHE_DIR)

        if auto_enrich and not (item.get("ptr") or item.get("country_code") or item.get("asn")):
            cache = load_geoip_cache()
            ip = item.get("ip", "")
            if ip in cache:
                self._on_ip_enriched(ip, cache[ip])
            elif not (self.enrich_worker and self.enrich_worker.isRunning()):
                self._start_enrichment_for_ips([ip], force_refresh=False)

    def _update_bulk_controls(self):
        checked_rows = self._get_checked_source_rows()
        count = len(checked_rows)
        has_checked = count > 0

        self.bulk_bar.setVisible(has_checked)
        if has_checked:
            self.bulk_count_lbl.setText(f"{count} markiert:")

    def _select_all_visible(self):
        model = self._active_model()
        changed = []
        for view_row in range(self.page_proxy.rowCount()):
            src_idx = self._map_view_to_source(self.page_proxy.index(view_row, 0))
            if src_idx.isValid():
                r = src_idx.row()
                item = model.get_item(r)
                if not item.get("checked"):
                    item["checked"] = True
                    changed.append(r)
        if changed:
            model.notify_rows_updated(changed, [Qt.ItemDataRole.CheckStateRole, Qt.ItemDataRole.BackgroundRole])
        self._update_bulk_controls()

    def _clear_all_selection(self):
        model = self._active_model()
        changed = []
        for r, item in enumerate(model.get_all_items()):
            if item.get("checked"):
                item["checked"] = False
                changed.append(r)
        if changed:
            model.notify_rows_updated(changed, [Qt.ItemDataRole.CheckStateRole, Qt.ItemDataRole.BackgroundRole])
        self._update_bulk_controls()

    def _on_table_clicked(self, view_index: QModelIndex):
        if view_index.isValid() and view_index.column() == 1:
            src_idx = self._map_view_to_source(view_index)
            if src_idx.isValid():
                self._toggle_favorite_for_rows([src_idx.row()])

    def _on_table_double_clicked(self, view_index: QModelIndex):
        if view_index.column() in (0, 1):
            return
        src_idx = self._map_view_to_source(view_index)
        if not src_idx.isValid():
            return
        item = self._active_model().get_item(src_idx.row())
        if item.get("status") == "OK" and item.get("url"):
            self._open_specific_rows([src_idx.row()])

    def _on_inspector_fav_toggled(self, item: dict):
        key = f"{item['ip']}:{item['port']}"
        is_fav, self.favorites_map = toggle_favorite_item(self.favorites_map, item)
        for model in (self.results_model, self.favorites_model):
            r = model.find_row_by_key(key)
            if r >= 0:
                model.get_item(r)["favorite"] = is_fav
                model.notify_rows_updated([r])
        self.favorites_model.set_items(list(self.favorites_map.values()))
        self._update_view_buttons()
        self._update_inspector_selection()
        self._schedule_save_session()

    def _toggle_favorite_selected(self, checked_only: bool = True):
        rows = self._get_checked_source_rows() if checked_only else self._get_target_source_rows()
        if rows:
            self._toggle_favorite_for_rows(rows)

    def _toggle_favorite_for_rows(self, rows: list[int]):
        model = self._active_model()
        if not rows:
            return
        target_state = not bool(model.get_item(rows[0]).get("favorite"))

        for r in rows:
            item = model.get_item(r)
            key = f"{item['ip']}:{item['port']}"
            item["favorite"] = target_state
            if target_state:
                snap = normalize_item(item)
                snap["favorite"] = True
                snap["checked"] = False
                self.favorites_map[key] = snap
            else:
                self.favorites_map.pop(key, None)

        for idx, res_it in enumerate(self.results_model.get_all_items()):
            new_f = f"{res_it['ip']}:{res_it['port']}" in self.favorites_map
            if res_it.get("favorite") != new_f:
                res_it["favorite"] = new_f
                self.results_model.notify_rows_updated([idx])

        self.favorites_model.set_items(list(self.favorites_map.values()))
        save_favorites(self.favorites_map)
        self._update_view_buttons()
        self._apply_filters(reset_page=False)
        self._update_kpis()
        self._update_inspector_selection()
        self._schedule_save_session()

    def _delete_selected_rows(self, checked_only: bool = True):
        rows = self._get_checked_source_rows() if checked_only else self._get_target_source_rows()
        if not rows:
            return
        model = self._active_model()
        if self.view_mode == "favorites":
            for r in rows:
                it = model.get_item(r)
                self.favorites_map.pop(f"{it['ip']}:{it['port']}", None)
            save_favorites(self.favorites_map)
            for res_it in self.results_model.get_all_items():
                res_it["favorite"] = f"{res_it['ip']}:{res_it['port']}" in self.favorites_map
            if self.results_model.rowCount() > 0:
                self.results_model.notify_rows_updated(list(range(self.results_model.rowCount())))

        model.remove_rows(rows)
        self.table_view.clearSelection()
        self._update_view_buttons()
        self._apply_filters(reset_page=False)
        self._update_kpis()
        self._update_inspector_selection()
        self._schedule_save_session()

    # =========================================================================
    # KONTEXTMENÜ, BESUCHSSTATUS & HISTORIE
    # =========================================================================
    def _copy_to_clipboard(self, values: list[str], label: str):
        cleaned = [v for v in values if v and v != "—"]
        if not cleaned:
            return
        QGuiApplication.clipboard().setText("\n".join(cleaned))
        self._set_status(f"📋 {len(cleaned)}× {label} kopiert.", COLORS["cyan"])

    def _shortcut_copy_selected(self):
        rows = self._get_target_source_rows()
        if not rows:
            return
        model = self._active_model()
        items = [model.get_item(r) for r in rows]
        vals = [it["url"] if (it.get("status") == "OK" and it.get("url")) else f"{it['ip']}:{it['port']}" for it in items]
        self._copy_to_clipboard(vals, "Link / Ziel")

    def _shortcut_toggle_check(self):
        rows = self._get_target_source_rows()
        if not rows:
            return
        model = self._active_model()
        new_state = not bool(model.get_item(rows[0]).get("checked"))
        for r in rows:
            model.get_item(r)["checked"] = new_state
        model.notify_rows_updated(rows, [Qt.ItemDataRole.CheckStateRole, Qt.ItemDataRole.BackgroundRole])
        self._update_bulk_controls()

    def _show_table_context_menu(self, pos: QPoint):
        view_index = self.table_view.indexAt(pos)
        if not view_index.isValid():
            return

        sel_model = self.table_view.selectionModel()
        if sel_model and not sel_model.isRowSelected(view_index.row(), QModelIndex()):
            self.table_view.selectRow(view_index.row())

        rows = self._get_target_source_rows()
        if not rows:
            return

        model = self._active_model()
        items = [model.get_item(r) for r in rows]
        suffix = f" ({len(items)})" if len(items) > 1 else ""
        urls = [it["url"] for it in items if it.get("status") == "OK" and it.get("url")]

        menu = QMenu(self)
        act_ip = QAction(f"📋 IP kopieren{suffix}", menu)
        act_ip.triggered.connect(lambda: self._copy_to_clipboard([it["ip"] for it in items], "IP"))
        menu.addAction(act_ip)

        act_ipp = QAction(f"📋 IP:Port kopieren{suffix}", menu)
        act_ipp.triggered.connect(lambda: self._copy_to_clipboard([f"{it['ip']}:{it['port']}" for it in items], "IP:Port"))
        menu.addAction(act_ipp)

        act_url = QAction(f"🔗 Browser-Link kopieren{suffix}", menu)
        act_url.setEnabled(len(urls) > 0)
        act_url.triggered.connect(lambda: self._copy_to_clipboard(urls, "Browser-Link"))
        menu.addAction(act_url)

        menu.addSeparator()

        act_open = QAction(f"🌐 Im Browser öffnen{suffix}", menu)
        act_open.setEnabled(len(urls) > 0)
        act_open.triggered.connect(lambda: self._open_specific_rows(rows))
        menu.addAction(act_open)

        act_shot = QAction(f"📸 Vorschau(en) laden{suffix}", menu)
        act_shot.setEnabled(len(urls) > 0)
        act_shot.triggered.connect(lambda: self._bulk_capture_screenshots(checked_only=False))
        menu.addAction(act_shot)

        act_geo = QAction(f"🌍 GeoIP / ASN / PTR abrufen{suffix}", menu)
        act_geo.triggered.connect(lambda: self._bulk_enrich_selected(checked_only=False))
        menu.addAction(act_geo)

        menu.addSeparator()

        act_fav = QAction(f"⭐ Merkliste umschalten{suffix}", menu)
        act_fav.triggered.connect(lambda: self._toggle_favorite_for_rows(rows))
        menu.addAction(act_fav)

        act_read = QAction(f"✓ Als angeschaut markieren{suffix}", menu)
        act_read.triggered.connect(lambda: self._set_rows_visited(rows, True))
        menu.addAction(act_read)

        act_unread = QAction(f"↺ Als ungelesen markieren{suffix}", menu)
        act_unread.triggered.connect(lambda: self._set_rows_visited(rows, False))
        menu.addAction(act_unread)

        menu.addSeparator()
        act_del = QAction(f"🗑️ Aus Liste entfernen{suffix}", menu)
        act_del.triggered.connect(lambda: self._delete_selected_rows(checked_only=False))
        menu.addAction(act_del)

        menu.exec(self.table_view.viewport().mapToGlobal(pos))

    def _open_url_and_mark_visited(self, url: str):
        if not url:
            return
        webbrowser.open(url)
        model = self._active_model()
        matching = [idx for idx, it in enumerate(model.get_all_items()) if it.get("url") == url]
        if matching:
            self._set_rows_visited(matching, True)

    def _open_specific_rows(self, rows: list[int]):
        model = self._active_model()
        openable = [r for r in rows if model.get_item(r).get("status") == "OK" and model.get_item(r).get("url")]
        if not openable:
            return
        if len(openable) > 15:
            reply = QMessageBox.question(
                self,
                "Viele Tabs öffnen",
                f"Es sind {len(openable)} Links markiert. Alle im Browser öffnen?",
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        for r in openable:
            webbrowser.open(model.get_item(r)["url"])
        self._set_rows_visited(openable, True)

    def _bulk_open_selected(self, checked_only: bool = True):
        rows = self._get_checked_source_rows() if checked_only else self._get_target_source_rows()
        if rows:
            self._open_specific_rows(rows)

    def _bulk_set_visited(self, state: bool):
        rows = self._get_checked_source_rows()
        if rows:
            self._set_rows_visited(rows, state)

    def _set_rows_visited(self, rows: list[int], visited_state: bool):
        model = self._active_model()
        for r in rows:
            it = model.get_item(r)
            it["visited"] = visited_state
            it["checked"] = False
            key = f"{it['ip']}:{it['port']}"
            if key in self.favorites_map:
                self.favorites_map[key]["visited"] = visited_state

        model.notify_rows_updated(rows)
        save_favorites(self.favorites_map)
        self._update_kpis()
        self._apply_filters(reset_page=False)
        self._update_inspector_selection()
        self._schedule_save_session()

    def _refresh_history_combo(self):
        self.history_combo.clear()
        if not self.search_history:
            self.history_combo.addItem("Keine Suchen gespeichert", None)
            return
        for entry in self.search_history:
            q = entry.get("query", "")
            eng = entry.get("engines", "")
            self.history_combo.addItem(f"{q} ({eng})" if eng else q, entry)

    def _apply_selected_history(self):
        entry = self.history_combo.currentData()
        if not entry:
            return
        self.query_edit.setText(entry.get("query", ""))
        if entry.get("ports"):
            self.ports_edit.setText(entry["ports"])
        self.ribbon_tabs.setCurrentIndex(0)

    def _clear_history(self):
        self.search_history.clear()
        save_history(self.search_history)
        self._refresh_history_combo()

    def _set_status(self, text: str, color: str = "#f1f5f9"):
        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(f"color: {color}; font-weight: bold;")

    # =========================================================================
    # EXPORT (INKL. GEOIP, ASN, PTR & VORSCHAU-STATUS)
    # =========================================================================
    def _export_results(self, fmt: str):
        model = self._active_model()
        scope = self.export_scope_combo.currentData()

        if scope == "FILTERED":
            checked_rows = self._get_checked_source_rows()
            if checked_rows:
                items = [model.get_item(r) for r in checked_rows]
            else:
                items = [
                    model.get_item(self.proxy_model.mapToSource(self.proxy_model.index(r, 0)).row())
                    for r in range(self.proxy_model.rowCount())
                ]
        else:
            items = model.get_all_items()

        if not items:
            QMessageBox.information(self, "Keine Daten", "Es sind keine passenden Einträge zum Exportieren vorhanden.")
            return

        prefix = "merkliste" if self.view_mode == "favorites" else "shodancheck"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Ergebnisse exportieren",
            f"{prefix}_export.{fmt}",
            f"{fmt.upper()} Datei (*.{fmt})",
        )
        if not file_path:
            return

        fields = [
            "ip",
            "port",
            "status",
            "http_code",
            "country_code",
            "country_name",
            "city",
            "asn",
            "asn_org",
            "ptr",
            "favorite",
            "visited",
            "info",
            "url",
            "response_info",
            "tls_info",
            "screenshot_path",
        ]
        export_rows = [{k: r.get(k, "") for k in fields} for r in items]

        try:
            if fmt == "json":
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(export_rows, f, indent=2, ensure_ascii=False)
            elif fmt == "txt":
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(f"{r['ip']}:{r['port']}" for r in export_rows) + "\n")
            elif fmt == "html":
                rows_html = []
                for r in export_rows:
                    link_cell = (
                        f'<a href="{html.escape(r["url"])}" target="_blank">{html.escape(r["url"])}</a>'
                        if r["status"] == "OK" and r["url"]
                        else "—"
                    )
                    geo_cell = html.escape(
                        f"[{r['country_code']}] {r['asn']} {r['asn_org']}".strip()
                    )
                    cls = "ok" if r["status"] == "OK" else "closed"
                    rows_html.append(
                        f"<tr class='{cls}'><td>{html.escape(r['ip'])}</td><td>{r['port']}</td>"
                        f"<td>{r['status']}</td><td>{geo_cell}</td><td>{html.escape(r['ptr'])}</td>"
                        f"<td>{html.escape(r['info'])}</td><td>{link_cell}</td>"
                        f"<td>{html.escape(r['response_info'])}</td></tr>"
                    )
                doc = (
                    "<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'>"
                    "<title>ShodanCheck Report</title><style>"
                    "body{background:#0f1117;color:#f1f5f9;font-family:Segoe UI,sans-serif;padding:20px;}"
                    "table{width:100%;border-collapse:collapse;font-size:13px;}"
                    "th,td{padding:7px 9px;border:1px solid #282e3d;text-align:left;}"
                    "th{background:#1f232e;}tr.ok td:nth-child(3){color:#4ade80;font-weight:bold;}"
                    "tr.closed td:nth-child(3){color:#f87171;}a{color:#38bdf8;}</style></head><body>"
                    f"<h2>ShodanCheck Report ({len(export_rows)} Einträge)</h2>"
                    "<table><thead><tr><th>IP</th><th>Port</th><th>Status</th><th>Land / ASN</th>"
                    "<th>PTR</th><th>Quelle</th><th>Link</th><th>Server-Antwort</th></tr></thead>"
                    f"<tbody>{''.join(rows_html)}</tbody></table></body></html>"
                )
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(doc)
            else:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(export_rows)

            self._set_status(f"💾 Export ({len(export_rows)} Einträge) erfolgreich gespeichert!", COLORS["ok"])
        except Exception as exc:
            QMessageBox.critical(self, "Export-Fehler", str(exc))