import os
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPixmap, QGuiApplication, QTextDocument
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QTabWidget,
    QPlainTextEdit,
    QLineEdit,
    QScrollArea,
    QDialog,
    QSizePolicy,
)

from ui.theme import COLORS
from scanner.screenshotter import get_cached_screenshot, DEFAULT_CACHE_DIR


class ClickablePreviewLabel(QLabel):
    """Klickbares Vorschaubild zum Öffnen der Vollbild-Lightbox."""

    clicked = Signal()

    def __init__(self, text: str = ""):
        super().__init__(text)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWordWrap(True)
        self.setMinimumHeight(135)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._has_image = False

    def set_has_image(self, has_image: bool):
        self._has_image = has_image
        if has_image:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
            self.setToolTip("Klicken für Vollbild-Vorschau")
        else:
            self.setCursor(Qt.CursorShape.ArrowCursor)
            self.setToolTip("")

    def mouseReleaseEvent(self, event):
        if self._has_image and event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)


class ScreenshotLightboxDialog(QDialog):
    """Vergrößerte Vollbild-Ansicht für gespeicherte Seiten-Screenshots."""

    def __init__(self, image_path: str, title_text: str, url: str = "", parent=None):
        super().__init__(parent)
        self.image_path = image_path
        self.url = url
        self._fit_mode = True
        self._pixmap = QPixmap(image_path)

        self.setWindowTitle(f"Vorschau – {title_text}")
        self.resize(1120, 740)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        top_bar = QHBoxLayout()
        lbl_title = QLabel(f"<b>{title_text}</b>")
        if not self._pixmap.isNull():
            lbl_dim = QLabel(f"({self._pixmap.width()} × {self._pixmap.height()} px)")
            lbl_dim.setStyleSheet(f"color: {COLORS['text_muted']};")
        else:
            lbl_dim = QLabel("(Bild nicht lesbar)")
            lbl_dim.setStyleSheet(f"color: {COLORS['err']};")

        top_bar.addWidget(lbl_title)
        top_bar.addWidget(lbl_dim)
        top_bar.addStretch()

        self.btn_zoom = QPushButton("🔍 Originalgröße (100 %)")
        self.btn_zoom.clicked.connect(self._toggle_zoom)
        top_bar.addWidget(self.btn_zoom)

        if self.url:
            btn_open = QPushButton("🌐 Im Browser öffnen")
            btn_open.setObjectName("PrimaryBtn")
            btn_open.clicked.connect(self._open_external)
            top_bar.addWidget(btn_open)

        btn_close = QPushButton("Schließen")
        btn_close.clicked.connect(self.accept)
        top_bar.addWidget(btn_close)
        root.addLayout(top_bar)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.img_label = QLabel()
        self.img_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.img_label.setStyleSheet("background-color: #0b0d12; padding: 8px;")
        self.scroll.setWidget(self.img_label)
        root.addWidget(self.scroll, 1)

        self._render_pixmap()

    def _toggle_zoom(self):
        self._fit_mode = not self._fit_mode
        self.btn_zoom.setText("🔍 Originalgröße (100 %)" if self._fit_mode else "📐 An Fenster anpassen")
        self._render_pixmap()

    def _render_pixmap(self):
        if self._pixmap.isNull():
            self.img_label.setText("Screenshot-Datei konnte nicht geladen werden.")
            return
        if self._fit_mode:
            avail_w = max(400, self.scroll.viewport().width() - 24)
            avail_h = max(300, self.scroll.viewport().height() - 24)
            scaled = self._pixmap.scaled(
                avail_w,
                avail_h,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            self.img_label.setPixmap(scaled)
        else:
            self.img_label.setPixmap(self._pixmap)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._fit_mode:
            self._render_pixmap()

    def _open_external(self):
        if self.url:
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            QDesktopServices.openUrl(QUrl(self.url))


class InspectorPanel(QFrame):
    """Rechter 3-Tab-Detail-Inspektor für Vorschau, Host-Metadaten, Header/TLS und Banner."""

    screenshot_requested = Signal(dict)
    screenshot_cancel_requested = Signal()
    enrichment_requested = Signal(dict)
    open_url_requested = Signal(str)
    favorite_toggled = Signal(dict)
    close_requested = Signal()

    def __init__(self, cache_dir: str = DEFAULT_CACHE_DIR, parent=None):
        super().__init__(parent)
        self.setObjectName("InspectorPanel")
        self.setMinimumWidth(390)
        self._cache_dir = cache_dir
        self._current_item: dict | None = None
        self._current_pixmap: QPixmap | None = None
        self._current_image_path: str = ""
        self._is_busy = False

        self._build_ui()
        self.clear_view()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 8, 10, 10)
        root.setSpacing(8)

        # --- Kopfzeile ---
        header = QHBoxLayout()
        header.setSpacing(6)

        self.lbl_header_title = QLabel("<b>◫ Detail-Inspektor</b>")
        self.lbl_header_title.setStyleSheet("font-size: 14px;")
        header.addWidget(self.lbl_header_title)

        self.lbl_status_badge = QLabel("")
        self.lbl_status_badge.setStyleSheet(f"color: {COLORS['text_muted']}; font-weight: bold;")
        header.addWidget(self.lbl_status_badge)
        header.addStretch()

        self.btn_fav = QPushButton("☆")
        self.btn_fav.setObjectName("IconBtn")
        self.btn_fav.setFixedSize(30, 26)
        self.btn_fav.setToolTip("In Merkliste speichern / entfernen (Taste F)")
        self.btn_fav.clicked.connect(self._on_fav_clicked)
        header.addWidget(self.btn_fav)

        self.btn_close = QPushButton("✕")
        self.btn_close.setObjectName("IconBtn")
        self.btn_close.setFixedSize(30, 26)
        self.btn_close.setToolTip("Detail-Inspektor ausblenden (Strg+I)")
        self.btn_close.clicked.connect(self.close_requested.emit)
        header.addWidget(self.btn_close)

        root.addLayout(header)

        # --- 3 Unter-Tabs (&& verhindert Qt-Mnemonic-Unterstriche) ---
        self.tabs = QTabWidget()
        self.tabs.setObjectName("InspectorTabs")
        self.tabs.setUsesScrollButtons(False)

        self.tab_preview = self._build_preview_tab()
        self.tab_headers = self._build_headers_tab()
        self.tab_banner = self._build_banner_tab()

        self.tabs.addTab(self.tab_preview, "🖼️ Vorschau && Host")
        self.tabs.addTab(self.tab_headers, "🔒 Header && TLS")
        self.tabs.addTab(self.tab_banner, "📄 Banner / HTML")

        root.addWidget(self.tabs, 1)

    def _build_preview_tab(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(4, 6, 4, 4)
        page_layout.setSpacing(6)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        lay = QVBoxLayout(container)
        lay.setContentsMargins(2, 2, 4, 2)
        lay.setSpacing(8)

        # --- Screenshot-Vorschaubox ---
        preview_box = QFrame()
        preview_box.setObjectName("PreviewBox")
        p_lay = QVBoxLayout(preview_box)
        p_lay.setContentsMargins(8, 6, 8, 6)
        p_lay.setSpacing(6)

        self.lbl_preview = ClickablePreviewLabel("Wähle eine Zeile in der Tabelle aus.")
        self.lbl_preview.setStyleSheet(f"color: {COLORS['text_muted']};")
        self.lbl_preview.clicked.connect(self._open_lightbox)
        p_lay.addWidget(self.lbl_preview)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        self.btn_load_shot = QPushButton("📸 Vorschau laden")
        self.btn_load_shot.setObjectName("PrimaryBtn")
        self.btn_load_shot.clicked.connect(self._on_load_shot_clicked)
        btn_row.addWidget(self.btn_load_shot, 1)

        self.btn_cancel_shot = QPushButton("⏹ Abbruch")
        self.btn_cancel_shot.setObjectName("DangerBtn")
        self.btn_cancel_shot.setVisible(False)
        self.btn_cancel_shot.clicked.connect(self.screenshot_cancel_requested.emit)
        btn_row.addWidget(self.btn_cancel_shot)

        self.btn_zoom_shot = QPushButton("🔍 Vollbild")
        self.btn_zoom_shot.setEnabled(False)
        self.btn_zoom_shot.clicked.connect(self._open_lightbox)
        btn_row.addWidget(self.btn_zoom_shot)

        p_lay.addLayout(btn_row)

        self.lbl_shot_status = QLabel("Vorschau wird erst beim Klick auf 'Vorschau laden' erstellt.")
        self.lbl_shot_status.setWordWrap(True)
        self.lbl_shot_status.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 11px;")
        p_lay.addWidget(self.lbl_shot_status)

        lay.addWidget(preview_box)

        # --- Kompaktkarte: Ziel & Host-Metadaten ---
        meta_card = QFrame()
        meta_card.setObjectName("CardFrame")
        grid = QGridLayout(meta_card)
        grid.setContentsMargins(9, 8, 9, 8)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(5)

        self.val_endpoint = self._make_value_label("—", bold=True)
        self.val_url = self._make_value_label("—", color=COLORS["cyan"])
        self.val_response = self._make_value_label("—")
        self.val_ptr = self._make_value_label("—")
        self.val_asn = self._make_value_label("—")
        self.val_location = self._make_value_label("—")
        self.val_source = self._make_value_label("—")

        rows = [
            ("Ziel:", self.val_endpoint, lambda: self._copy_text(self.val_endpoint.text())),
            ("Link:", self.val_url, lambda: self._copy_text(self.val_url.text())),
            ("Antwort:", self.val_response, None),
            ("PTR / DNS:", self.val_ptr, lambda: self._copy_text(self.val_ptr.text())),
            ("ASN / Org:", self.val_asn, lambda: self._copy_text(self.val_asn.text())),
            ("Standort:", self.val_location, None),
            ("Quelle:", self.val_source, None),
        ]

        for row_idx, (caption, val_lbl, copy_cb) in enumerate(rows):
            cap = QLabel(caption)
            cap.setStyleSheet(f"color: {COLORS['text_muted']}; font-weight: bold; font-size: 12px;")
            cap.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            grid.addWidget(cap, row_idx, 0)
            grid.addWidget(val_lbl, row_idx, 1)

            if copy_cb is not None:
                btn_cp = QPushButton("📋")
                btn_cp.setObjectName("IconBtn")
                btn_cp.setFixedSize(26, 22)
                btn_cp.setToolTip("Wert kopieren")
                btn_cp.clicked.connect(copy_cb)
                grid.addWidget(btn_cp, row_idx, 2, Qt.AlignmentFlag.AlignTop)

        grid.setColumnStretch(1, 1)
        lay.addWidget(meta_card)

        # --- Aktionszeile unter Host-Karte ---
        host_actions = QHBoxLayout()
        host_actions.setSpacing(6)

        self.btn_refresh_geo = QPushButton("🌍 Host-Info aktualisieren")
        self.btn_refresh_geo.clicked.connect(self._on_refresh_geo_clicked)
        host_actions.addWidget(self.btn_refresh_geo, 1)

        self.btn_open_browser = QPushButton("🌐 Browser")
        self.btn_open_browser.clicked.connect(self._on_open_browser_clicked)
        host_actions.addWidget(self.btn_open_browser)

        lay.addLayout(host_actions)
        lay.addStretch(1)

        scroll.setWidget(container)
        page_layout.addWidget(scroll)
        return page

    def _build_headers_tab(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)

        tls_card = QFrame()
        tls_card.setObjectName("CardFrame")
        tls_lay = QVBoxLayout(tls_card)
        tls_lay.setContentsMargins(8, 8, 8, 8)
        tls_lay.setSpacing(4)

        lbl_tls_head = QLabel("<b>🔐 TLS- & Zertifikats-Details</b>")
        tls_lay.addWidget(lbl_tls_head)

        self.lbl_tls_details = QLabel("Keine TLS-Informationen vorhanden.")
        self.lbl_tls_details.setWordWrap(True)
        self.lbl_tls_details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_tls_details.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        tls_lay.addWidget(self.lbl_tls_details)

        lay.addWidget(tls_card)

        hdr_bar = QHBoxLayout()
        hdr_bar.addWidget(QLabel("<b>HTTP-Response-Header</b>"))
        hdr_bar.addStretch()
        btn_copy_hdr = QPushButton("📋 Kopieren")
        btn_copy_hdr.clicked.connect(lambda: self._copy_text(self.txt_headers.toPlainText()))
        hdr_bar.addWidget(btn_copy_hdr)
        lay.addLayout(hdr_bar)

        self.txt_headers = QPlainTextEdit()
        self.txt_headers.setReadOnly(True)
        self.txt_headers.setPlaceholderText("Keine HTTP-Header aufgezeichnet.")
        lay.addWidget(self.txt_headers, 1)

        return page

    def _build_banner_tab(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(6)
        self.inp_banner_search = QLineEdit()
        self.inp_banner_search.setPlaceholderText("Im Banner / HTML suchen...")
        self.inp_banner_search.returnPressed.connect(self._find_in_banner)
        top.addWidget(self.inp_banner_search, 1)

        btn_find = QPushButton("Suchen")
        btn_find.clicked.connect(self._find_in_banner)
        top.addWidget(btn_find)

        btn_copy = QPushButton("📋 Kopieren")
        btn_copy.clicked.connect(lambda: self._copy_text(self.txt_banner.toPlainText()))
        top.addWidget(btn_copy)

        lay.addLayout(top)

        self.txt_banner = QPlainTextEdit()
        self.txt_banner.setReadOnly(True)
        self.txt_banner.setPlaceholderText("Kein Banner oder HTML-Auszug vorhanden.")
        lay.addWidget(self.txt_banner, 1)

        return page

    def _make_value_label(self, text: str, bold: bool = False, color: str | None = None) -> QLabel:
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        styles = ["font-size: 12px;"]
        if bold:
            styles.append("font-weight: bold;")
        if color:
            styles.append(f"color: {color};")
        lbl.setStyleSheet(" ".join(styles))
        return lbl

    def clear_view(self):
        """Setzt den Inspektor in den leeren Ausgangszustand zurück."""
        self._current_item = None
        self._current_pixmap = None
        self._current_image_path = ""
        self._is_busy = False

        self.lbl_header_title.setText("<b>◫ Detail-Inspektor</b>")
        self.lbl_status_badge.setText("")
        self.btn_fav.setText("☆")
        self.btn_fav.setEnabled(False)

        self.lbl_preview.clear()
        self.lbl_preview.set_has_image(False)
        self.lbl_preview.setText("Wähle einen Treffer in der Tabelle aus.")
        self.btn_load_shot.setText("📸 Vorschau laden")
        self.btn_load_shot.setEnabled(False)
        self.btn_cancel_shot.setVisible(False)
        self.btn_zoom_shot.setEnabled(False)
        self.lbl_shot_status.setText("Vorschau wird erst beim Klick auf 'Vorschau laden' erstellt.")

        self.val_endpoint.setText("—")
        self.val_url.setText("—")
        self.val_response.setText("—")
        self.val_ptr.setText("—")
        self.val_asn.setText("—")
        self.val_location.setText("—")
        self.val_source.setText("—")

        self.btn_refresh_geo.setEnabled(False)
        self.btn_open_browser.setEnabled(False)

        self.lbl_tls_details.setText("Keine TLS-Informationen vorhanden.")
        self.txt_headers.clear()
        self.txt_banner.clear()

    def set_item(self, item: dict | None, cache_dir: str | None = None):
        """Befüllt alle drei Tabs mit den Daten des ausgewählten Eintrags."""
        if cache_dir:
            self._cache_dir = cache_dir
        if not item:
            self.clear_view()
            return

        self._current_item = item
        ip = item.get("ip", "")
        port = int(item.get("port") or 0)
        status = item.get("status", "")
        is_ok = status == "OK"
        url = (item.get("url") or "").strip()
        is_http = is_ok and url.lower().startswith(("http://", "https://"))

        self.lbl_header_title.setText(f"<b>◫ {ip}:{port}</b>")
        if item.get("visited"):
            self.lbl_status_badge.setText("✓ ANGESCHAUT")
            self.lbl_status_badge.setStyleSheet(f"color: {COLORS['accent_light']}; font-weight: bold;")
        elif is_ok:
            self.lbl_status_badge.setText("● OK")
            self.lbl_status_badge.setStyleSheet(f"color: {COLORS['ok']}; font-weight: bold;")
        else:
            self.lbl_status_badge.setText(f"● {status or 'OFFLINE'}")
            self.lbl_status_badge.setStyleSheet(f"color: {COLORS['err']}; font-weight: bold;")

        self.btn_fav.setEnabled(True)
        self.btn_fav.setText("★" if item.get("favorite") else "☆")

        # --- Tab 1: Host-Metadaten ---
        self.val_endpoint.setText(f"{ip}:{port}")
        self.val_url.setText(url if is_ok and url else "—")
        self.val_response.setText(item.get("response_info") or "—")
        self.val_source.setText(item.get("info") or "—")

        ptr = (item.get("ptr") or "").strip()
        self.val_ptr.setText(ptr if ptr else "Noch nicht abgerufen")

        asn = (item.get("asn") or "").strip()
        asn_org = (item.get("asn_org") or "").strip()
        asn_combined = f"{asn} {asn_org}".strip()
        self.val_asn.setText(asn_combined if asn_combined else "Noch nicht abgerufen")

        city = (item.get("city") or "").strip()
        country = (item.get("country_name") or item.get("country_code") or "").strip()
        cc = (item.get("country_code") or "").strip().upper()
        if city and country:
            loc_str = f"{city}, {country}" + (f" [{cc}]" if cc and cc not in country else "")
        elif country:
            loc_str = f"{country}" + (f" [{cc}]" if cc and cc not in country else "")
        else:
            loc_str = "—"
        self.val_location.setText(loc_str)

        self.btn_refresh_geo.setEnabled(True)
        self.btn_open_browser.setEnabled(is_http)

        # --- Tab 1: Screenshot-Zustand prüfen ---
        shot_path = item.get("screenshot_path") or ""
        if not shot_path or not os.path.isfile(shot_path):
            cached = get_cached_screenshot(ip, port, self._cache_dir)
            if cached:
                shot_path = cached
                item["screenshot_path"] = cached

        if shot_path and os.path.isfile(shot_path):
            self._apply_screenshot_pixmap(shot_path)
            self.btn_load_shot.setText("🔄 Neu laden")
            self.btn_load_shot.setEnabled(is_http and not self._is_busy)
            self.lbl_shot_status.setText("Vorschau aus Cache geladen. Klick auf Bild = Vollbild.")
        else:
            self._current_pixmap = None
            self._current_image_path = ""
            self.lbl_preview.clear()
            self.lbl_preview.set_has_image(False)
            self.btn_zoom_shot.setEnabled(False)
            self.btn_load_shot.setText("📸 Vorschau laden")
            if is_http:
                self.lbl_preview.setText("Keine Vorschau im Cache.\nKlicke auf '📸 Vorschau laden', um die Seite zu rendern.")
                self.btn_load_shot.setEnabled(not self._is_busy)
                self.lbl_shot_status.setText("Wartet erst auf vollständiges Laden der Gegenseite.")
            else:
                self.lbl_preview.setText("Vorschau nur für erreichbare HTTP/HTTPS-Dienste verfügbar.")
                self.btn_load_shot.setEnabled(False)
                self.lbl_shot_status.setText("Kein HTTP/HTTPS-Endpunkt.")

        # --- Tab 2: Header & TLS ---
        tls_text = (item.get("tls_info") or "").strip()
        self.lbl_tls_details.setText(tls_text if tls_text else "Keine TLS-/Zertifikatsdaten für diesen Port vorhanden.")

        headers_raw = (item.get("headers_raw") or "").strip()
        if not headers_raw and item.get("response_info"):
            headers_raw = f"Status / Antwort: {item.get('response_info')}"
        self.txt_headers.setPlainText(headers_raw)

        # --- Tab 3: Banner / HTML ---
        banner_raw = (item.get("banner_raw") or item.get("raw_banner") or "").strip()
        self.txt_banner.setPlainText(banner_raw)

    def update_item_fields(self, item: dict, cache_dir: str | None = None):
        """Aktualisiert die Anzeige, falls der Eintrag mit dem aktuell gewählten übereinstimmt."""
        if not self._current_item:
            return
        if (
            self._current_item.get("ip") == item.get("ip")
            and int(self._current_item.get("port") or 0) == int(item.get("port") or 0)
        ):
            self.set_item(item, cache_dir)

    def set_screenshot_busy(self, is_busy: bool, status_text: str = ""):
        """Schaltet Ladezustand während einer laufenden Screenshot-Aufnahme um."""
        self._is_busy = is_busy
        self.btn_cancel_shot.setVisible(is_busy)

        if self._current_item:
            url = (self._current_item.get("url") or "").strip().lower()
            is_http = self._current_item.get("status") == "OK" and url.startswith(("http://", "https://"))
            self.btn_load_shot.setEnabled(is_http and not is_busy)
        else:
            self.btn_load_shot.setEnabled(False)

        if status_text:
            self.lbl_shot_status.setText(status_text)

    def _apply_screenshot_pixmap(self, path: str):
        pm = QPixmap(path)
        if pm.isNull():
            self._current_pixmap = None
            self._current_image_path = ""
            self.lbl_preview.clear()
            self.lbl_preview.set_has_image(False)
            self.lbl_preview.setText("Vorschaubild konnte nicht dekodiert werden.")
            self.btn_zoom_shot.setEnabled(False)
            return

        self._current_pixmap = pm
        self._current_image_path = path
        self.lbl_preview.set_has_image(True)
        self.btn_zoom_shot.setEnabled(True)
        self._rescale_preview()

    def _rescale_preview(self):
        if not self._current_pixmap or self._current_pixmap.isNull():
            return
        target_w = max(240, self.lbl_preview.width() - 8)
        scaled = self._current_pixmap.scaled(
            target_w,
            180,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.lbl_preview.setPixmap(scaled)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._current_pixmap and not self._current_pixmap.isNull():
            self._rescale_preview()

    def _open_lightbox(self):
        if not self._current_image_path or not os.path.isfile(self._current_image_path):
            return
        title = ""
        url = ""
        if self._current_item:
            title = f"{self._current_item.get('ip')}:{self._current_item.get('port')}"
            url = self._current_item.get("url", "")
        dlg = ScreenshotLightboxDialog(self._current_image_path, title, url, self)
        dlg.exec()

    def _on_load_shot_clicked(self):
        if self._current_item:
            self.screenshot_requested.emit(self._current_item)

    def _on_refresh_geo_clicked(self):
        if self._current_item:
            self.enrichment_requested.emit(self._current_item)

    def _on_open_browser_clicked(self):
        if self._current_item and self._current_item.get("url"):
            self.open_url_requested.emit(self._current_item["url"])

    def _on_fav_clicked(self):
        if self._current_item:
            self.favorite_toggled.emit(self._current_item)

    def _copy_text(self, text: str):
        clean = (text or "").strip()
        if clean and clean != "—":
            QGuiApplication.clipboard().setText(clean)

    def _find_in_banner(self):
        query = self.inp_banner_search.text().strip()
        if not query:
            return
        found = self.txt_banner.find(query)
        if not found:
            cursor = self.txt_banner.textCursor()
            cursor.movePosition(cursor.MoveOperation.Start)
            self.txt_banner.setTextCursor(cursor)
            self.txt_banner.find(query, QTextDocument.FindFlag(0))