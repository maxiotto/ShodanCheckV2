from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PySide6.QtGui import QColor, QFont

from ui.theme import COLORS


def format_geo_asn_badge(item: dict) -> str:
    """Formatiert Land, ASN und Organisation kompakt für die Tabellenspalte."""
    cc = (item.get("country_code") or "").strip().upper()
    asn = (item.get("asn") or "").strip()
    org = (item.get("asn_org") or "").strip()

    left = f"[{cc}]" if cc else ""
    right = f"{asn} {org}".strip() if (asn or org) else ""
    combined = f"{left} {right}".strip()
    return combined if combined else "—"


class EndpointTableModel(QAbstractTableModel):
    """Virtualisiertes Tabellenmodell für Scan-Ergebnisse und Merkliste."""

    HEADERS = [
        "",
        "⭐",
        "IP-Adresse",
        "Port",
        "Status",
        "Land / ASN",
        "Info / Quelle",
        "Browser-Link",
        "Server-Antwort",
    ]

    def __init__(self, on_check_changed=None):
        super().__init__()
        self._items: list[dict] = []
        self._on_check_changed = on_check_changed

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._items)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None

    def flags(self, index: QModelIndex):
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            return base | Qt.ItemFlag.ItemIsUserCheckable
        return base

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        item = self._items[row]

        if role == Qt.ItemDataRole.CheckStateRole and col == 0:
            return Qt.CheckState.Checked if item.get("checked") else Qt.CheckState.Unchecked

        if role == Qt.ItemDataRole.TextAlignmentRole and col == 1:
            return int(Qt.AlignmentFlag.AlignCenter)

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return ""
            if col == 1:
                return "★" if item.get("favorite") else "☆"
            if col == 2:
                return item["ip"]
            if col == 3:
                return str(item["port"])
            if col == 4:
                return "✓ ANGESCHAUT" if item.get("visited") else f"● {item['status']}"
            if col == 5:
                return format_geo_asn_badge(item)
            if col == 6:
                return item.get("info") or "—"
            if col == 7:
                if item["status"] != "OK" or not item.get("url"):
                    return "—"
                has_shot = bool(item.get("screenshot_path"))
                return f"📷 {item['url']}" if has_shot else item["url"]
            if col == 8:
                return item.get("response_info") or "—"

        if role == Qt.ItemDataRole.UserRole:
            if col == 0:
                return 1 if item.get("checked") else 0
            if col == 1:
                return 1 if item.get("favorite") else 0
            if col == 2:
                try:
                    return tuple(int(p) for p in item["ip"].split("."))
                except Exception:
                    return (0, 0, 0, 0)
            if col == 3:
                return int(item["port"])
            if col == 4:
                return 2 if item.get("visited") else (1 if item["status"] == "OK" else 0)
            if col == 5:
                return format_geo_asn_badge(item).lower()
            if col == 6:
                return (item.get("info") or "").lower()
            if col == 7:
                return (item.get("url") or "").lower()
            if col == 8:
                return (item.get("response_info") or "").lower()

        if role == Qt.ItemDataRole.ForegroundRole:
            is_ok = item["status"] == "OK"
            if col == 1:
                return QColor(COLORS["warn"]) if item.get("favorite") else QColor("#475569")
            if item.get("visited"):
                if col == 4:
                    return QColor(COLORS["accent_light"])
                return QColor(COLORS["text_dim"])
            if col == 3:
                return QColor(COLORS["text_muted"])
            if col == 4:
                return QColor(COLORS["ok"]) if is_ok else QColor(COLORS["err"])
            if col == 5:
                return QColor(COLORS["text_secondary"]) if item.get("country_code") else QColor(COLORS["text_dim"])
            if col == 7 and is_ok:
                return QColor(COLORS["cyan"])
            if col == 8:
                if not is_ok:
                    return QColor(COLORS["text_dim"])
                code = int(item.get("http_code") or 0)
                if 200 <= code < 400:
                    return QColor(COLORS["ok"])
                if code in (401, 403):
                    return QColor(COLORS["warn"])
                if code >= 400 or "keine HTTP" in item.get("response_info", ""):
                    return QColor(COLORS["err"])
                return QColor("#93c5fd")
            return QColor(COLORS["text_primary"])

        if role == Qt.ItemDataRole.BackgroundRole:
            if item.get("checked"):
                return QColor(COLORS["row_selected"])
            if item.get("favorite"):
                return QColor(COLORS["row_favorite"])
            return None

        if role == Qt.ItemDataRole.FontRole:
            if col == 1:
                f = QFont()
                f.setPointSize(13)
                return f
            if col in (2, 4) or (col == 7 and item["status"] == "OK"):
                font = QFont()
                font.setBold(True)
                return font

        if role == Qt.ItemDataRole.ToolTipRole:
            if col == 1:
                return "Klick oder Taste 'F': In dauerhafter Merkliste speichern / entfernen"
            if col == 5:
                ptr = item.get("ptr") or "—"
                city = item.get("city") or ""
                country = item.get("country_name") or item.get("country_code") or "—"
                loc = f"{city}, {country}".strip(", ")
                return f"PTR: {ptr}\nStandort: {loc}\nASN: {item.get('asn', '—')} {item.get('asn_org', '')}".strip()
            if col == 7 and item["status"] == "OK":
                shot_hint = " (Vorschau im Cache vorhanden)" if item.get("screenshot_path") else ""
                return f"Doppelklick zum Öffnen im Browser: {item['url']}{shot_hint}"
            if col == 8:
                return item.get("response_info", "")
            if col == 6:
                return item.get("info", "")

        return None

    def setData(self, index: QModelIndex, value, role=Qt.ItemDataRole.EditRole) -> bool:
        if index.isValid() and index.column() == 0 and role == Qt.ItemDataRole.CheckStateRole:
            row = index.row()
            self._items[row]["checked"] = Qt.CheckState(value) == Qt.CheckState.Checked
            self.dataChanged.emit(
                self.index(row, 0),
                self.index(row, self.columnCount() - 1),
                [Qt.ItemDataRole.CheckStateRole, Qt.ItemDataRole.BackgroundRole],
            )
            if self._on_check_changed:
                self._on_check_changed()
            return True
        return False

    def get_item(self, row: int) -> dict:
        return self._items[row]

    def get_all_items(self) -> list[dict]:
        return self._items

    def find_rows_by_ip(self, ip: str) -> list[int]:
        """Liefert alle Zeilenindizes mit passender IP-Adresse."""
        return [idx for idx, it in enumerate(self._items) if it.get("ip") == ip]

    def find_row_by_key(self, key: str) -> int:
        """Liefert den Zeilenindex für 'ip:port' oder -1."""
        for idx, it in enumerate(self._items):
            if f"{it.get('ip')}:{it.get('port')}" == key:
                return idx
        return -1

    def clear_all(self):
        self.beginResetModel()
        self._items.clear()
        self.endResetModel()

    def set_items(self, items: list[dict]):
        self.beginResetModel()
        self._items = items
        self.endResetModel()

    def append_items(self, new_items: list[dict]):
        if not new_items:
            return
        start = len(self._items)
        end = start + len(new_items) - 1
        self.beginInsertRows(QModelIndex(), start, end)
        self._items.extend(new_items)
        self.endInsertRows()

    def remove_rows(self, rows: list[int]):
        if not rows:
            return
        remove_set = set(rows)
        self.beginResetModel()
        self._items = [it for idx, it in enumerate(self._items) if idx not in remove_set]
        self.endResetModel()

    def notify_rows_updated(self, rows: list[int], roles=None):
        if not rows or not self._items:
            return
        valid_rows = [r for r in rows if 0 <= r < len(self._items)]
        if not valid_rows:
            return
        min_r = min(valid_rows)
        max_r = max(valid_rows)
        self.dataChanged.emit(
            self.index(min_r, 0),
            self.index(max_r, self.columnCount() - 1),
            roles or [],
        )


class EndpointFilterProxyModel(QSortFilterProxyModel):
    """Filtert Zeilen nach Status, HTTP-Code, Land/ASN und Freitext inkl. Negativ-Tokens."""

    def __init__(self):
        super().__init__()
        self.only_ok = False
        self.only_unvisited = False
        self.status_filter = "ALL"  # ALL, 2XX, 3XX, AUTH, ERR, BANNER, SHOT
        self.geo_filter = ""
        self.search_text = ""
        self.setSortRole(Qt.ItemDataRole.UserRole)

    def set_filters(
        self,
        only_ok: bool = False,
        only_unvisited: bool = False,
        status_filter: str = "ALL",
        geo_filter: str = "",
        search_text: str = "",
    ):
        self.only_ok = only_ok
        self.only_unvisited = only_unvisited
        self.status_filter = status_filter or "ALL"
        self.geo_filter = (geo_filter or "").strip().lower()
        self.search_text = (search_text or "").strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model: EndpointTableModel = self.sourceModel()
        if model is None:
            return True
        item = model.get_item(source_row)

        if self.only_ok and item["status"] != "OK":
            return False
        if self.only_unvisited and item.get("visited"):
            return False

        code = int(item.get("http_code") or 0)
        if self.status_filter == "2XX" and not (200 <= code < 300):
            return False
        if self.status_filter == "3XX" and not (300 <= code < 400):
            return False
        if self.status_filter == "AUTH" and code not in (401, 403):
            return False
        if self.status_filter == "ERR" and code < 400:
            return False
        if self.status_filter == "BANNER" and not (item["status"] == "OK" and code == 0):
            return False
        if self.status_filter == "SHOT" and not item.get("screenshot_path"):
            return False

        if self.geo_filter:
            geo_haystack = " ".join([
                (item.get("country_code") or "").lower(),
                (item.get("country_name") or "").lower(),
                (item.get("city") or "").lower(),
                (item.get("asn") or "").lower(),
                (item.get("asn_org") or "").lower(),
                (item.get("ptr") or "").lower(),
            ])
            geo_tokens = [t.strip() for t in self.geo_filter.split(",") if t.strip()]
            positive_terms = [t for t in geo_tokens if not t.startswith("-")]
            negative_terms = [t[1:] for t in geo_tokens if t.startswith("-") and len(t) > 1]

            for neg in negative_terms:
                if neg in geo_haystack:
                    return False
            if positive_terms and not any(pos in geo_haystack for pos in positive_terms):
                return False

        if self.search_text:
            haystack = " ".join([
                item["ip"].lower(),
                str(item["port"]),
                (item.get("info") or "").lower(),
                (item.get("url") or "").lower(),
                (item.get("response_info") or "").lower(),
                (item.get("tls_info") or "").lower(),
                (item.get("ptr") or "").lower(),
                (item.get("country_code") or "").lower(),
                (item.get("country_name") or "").lower(),
                (item.get("asn") or "").lower(),
                (item.get("asn_org") or "").lower(),
            ])
            for tok in self.search_text.split():
                if tok.startswith("-") and len(tok) > 1:
                    if tok[1:] in haystack:
                        return False
                else:
                    if tok not in haystack:
                        return False
        return True


class PaginatedProxyModel(QSortFilterProxyModel):
    """Schneidet die gefilterten und sortierten Zeilen flackerfrei in Tabellenseiten."""

    def __init__(self):
        super().__init__()
        self.page_index = 0
        self.page_size = 100

    def set_pagination(self, page_index: int, page_size: int):
        self.page_index = max(0, page_index)
        self.page_size = max(0, page_size)
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        if self.page_size <= 0:
            return True
        start = self.page_index * self.page_size
        end = start + self.page_size
        return start <= source_row < end

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder):
        if self.sourceModel() is not None:
            self.sourceModel().sort(column, order)
            self.invalidateFilter()