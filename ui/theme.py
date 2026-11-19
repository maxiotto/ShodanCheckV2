"""Zentrales Dark-Theme-Stylesheet und Farbdefinitionen für ShodanCheck."""

COLORS = {
    "bg_root": "#0f1117",
    "bg_surface": "#181b23",
    "bg_elevated": "#1f232e",
    "bg_input": "#12151c",
    "border": "#282e3d",
    "border_strong": "#333b4d",
    "text_primary": "#f1f5f9",
    "text_secondary": "#cbd5e1",
    "text_muted": "#94a3b8",
    "text_dim": "#64748b",
    "accent": "#3b82f6",
    "accent_light": "#60a5fa",
    "cyan": "#38bdf8",
    "ok": "#4ade80",
    "warn": "#facc15",
    "err": "#f87171",
    "row_selected": "#1e293b",
    "row_favorite": "#1c1b15",
}

STYLESHEET = """
QMainWindow, QDialog, QWidget#CentralWidget {
    background-color: #0f1117;
    color: #f1f5f9;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QToolTip {
    background-color: #1f232e;
    color: #f1f5f9;
    border: 1px solid #3b82f6;
    padding: 5px 8px;
    border-radius: 5px;
}
QMenuBar {
    background-color: #12151c;
    color: #cbd5e1;
    border-bottom: 1px solid #282e3d;
    padding: 2px 10px;
    font-weight: bold;
}
QMenuBar::item {
    background-color: transparent;
    padding: 4px 12px;
    border-radius: 5px;
}
QMenuBar::item:selected {
    background-color: #252a37;
    color: #ffffff;
}
QLabel {
    color: #e2e8f0;
    background-color: transparent;
}
QCheckBox {
    color: #e2e8f0;
    background-color: transparent;
    spacing: 6px;
    font-weight: bold;
}
QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border-radius: 4px;
    border: 1px solid #475569;
    background-color: #12151c;
}
QCheckBox::indicator:hover {
    border: 1px solid #3b82f6;
}
QCheckBox::indicator:checked {
    background-color: #3b82f6;
    border: 1px solid #3b82f6;
}
QFrame#HeaderCard {
    background-color: #181b23;
    border-bottom: 1px solid #282e3d;
}
QFrame#BulkBar {
    background-color: #162033;
    border: 1px solid #2b4c7e;
    border-radius: 8px;
}
QFrame#PagerPill, QFrame#CardFrame, QFrame#InspectorPanel {
    background-color: #181b23;
    border: 1px solid #282e3d;
    border-radius: 8px;
}
QFrame#VDivider {
    background-color: #2e3546;
    min-width: 1px;
    max-width: 1px;
    margin-top: 2px;
    margin-bottom: 2px;
}
QFrame#PreviewBox {
    background-color: #12151c;
    border: 1px dashed #333b4d;
    border-radius: 8px;
}
QFrame#KpiPill {
    background-color: #1f232e;
    border: 1px solid #282e3d;
    border-radius: 7px;
}
QTabWidget::pane {
    background-color: #1f232e;
    border: 1px solid #282e3d;
    border-radius: 8px;
    top: -1px;
}
QTabWidget#InspectorTabs::pane {
    background-color: #151821;
    border: 1px solid #282e3d;
    border-radius: 7px;
    top: -1px;
}
QTabWidget > QWidget, QWidget#TabPage {
    background-color: transparent;
    color: #e2e8f0;
}
QTabBar::tab {
    background-color: #12151c;
    color: #94a3b8;
    padding: 6px 14px;
    margin-right: 4px;
    border-top-left-radius: 7px;
    border-top-right-radius: 7px;
    font-weight: bold;
}
QTabWidget#InspectorTabs QTabBar::tab {
    padding: 5px 8px;
    margin-right: 2px;
    font-size: 12px;
}
QTabBar::tab:selected {
    background-color: #3b82f6;
    color: #ffffff;
}
QTabBar::tab:hover:!selected {
    background-color: #1f232e;
    color: #f1f5f9;
}
QLineEdit, QComboBox, QSpinBox {
    background-color: #12151c;
    color: #f1f5f9;
    border: 1px solid #2e3546;
    border-radius: 6px;
    padding: 4px 8px;
    min-height: 22px;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #3b82f6;
}
QPlainTextEdit {
    background-color: #12151c;
    color: #cbd5e1;
    border: 1px solid #282e3d;
    border-radius: 6px;
    padding: 6px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
}
QComboBox QAbstractItemView {
    background-color: #181b23;
    color: #f1f5f9;
    selection-background-color: #3b82f6;
    border: 1px solid #2e3546;
}
QListWidget {
    background-color: #12151c;
    color: #f1f5f9;
    border: 1px solid #282e3d;
    border-radius: 8px;
    padding: 4px;
}
QListWidget::item {
    padding: 8px 10px;
    border-radius: 5px;
    margin-bottom: 2px;
}
QListWidget::item:selected {
    background-color: #1e3a8a;
    color: #ffffff;
    font-weight: bold;
}
QListWidget::item:hover:!selected {
    background-color: #1f232e;
}
QMenu {
    background-color: #181b23;
    color: #f1f5f9;
    border: 1px solid #2e3546;
    border-radius: 6px;
    padding: 5px;
}
QMenu::item {
    padding: 6px 24px 6px 12px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: #3b82f6;
    color: #ffffff;
}
QMenu::item:disabled {
    color: #475569;
    background-color: transparent;
}
QMenu::separator {
    height: 1px;
    background-color: #282e3d;
    margin: 4px 8px;
}
QPushButton {
    background-color: #252a37;
    color: #f1f5f9;
    border: 1px solid #333b4d;
    border-radius: 6px;
    padding: 5px 10px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #313849;
}
QPushButton:checked {
    background-color: #1e3a8a;
    border: 1px solid #3b82f6;
    color: #ffffff;
}
QPushButton#IconBtn {
    padding: 2px;
    min-width: 26px;
    font-size: 13px;
}
QPushButton:disabled,
QPushButton#PrimaryBtn:disabled,
QPushButton#SuccessBtn:disabled,
QPushButton#WarningBtn:disabled,
QPushButton#DangerBtn:disabled,
QPushButton#IconBtn:disabled {
    background-color: #181b23;
    color: #475569;
    border: 1px solid #222733;
}
QPushButton#PrimaryBtn {
    background-color: #3b82f6;
    border: none;
    color: #ffffff;
    padding: 5px 12px;
}
QPushButton#PrimaryBtn:hover {
    background-color: #2563eb;
}
QPushButton#SuccessBtn {
    background-color: #16a34a;
    border: none;
    color: #ffffff;
    padding: 5px 12px;
}
QPushButton#SuccessBtn:hover {
    background-color: #15803d;
}
QPushButton#WarningBtn {
    background-color: #d97706;
    border: none;
    color: #ffffff;
    padding: 5px 12px;
}
QPushButton#WarningBtn:hover {
    background-color: #b45309;
}
QPushButton#DangerBtn {
    background-color: #dc2626;
    border: none;
    color: #ffffff;
    padding: 5px 12px;
}
QPushButton#DangerBtn:hover {
    background-color: #991b1b;
}
QTableView {
    background-color: #151821;
    alternate-background-color: #191d27;
    color: #f1f5f9;
    gridline-color: #222734;
    border: 1px solid #282e3d;
    border-radius: 8px;
    selection-background-color: #1e3a8a;
    selection-color: #ffffff;
}
QTableView::item {
    padding: 3px 7px;
}
QHeaderView::section {
    background-color: #1f232e;
    color: #cbd5e1;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #282e3d;
    border-bottom: 1px solid #282e3d;
    font-weight: bold;
}
QHeaderView::section:hover {
    background-color: #282e3d;
}
QSplitter::handle {
    background-color: #282e3d;
    width: 3px;
}
QSplitter::handle:hover {
    background-color: #3b82f6;
}
QScrollArea {
    background-color: transparent;
    border: none;
}
QScrollBar:vertical {
    background-color: #12151c;
    width: 10px;
    margin: 0px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background-color: #2e3546;
    min-height: 24px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover {
    background-color: #475569;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}
QScrollBar:horizontal {
    background-color: #12151c;
    height: 10px;
    margin: 0px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background-color: #2e3546;
    min-width: 24px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal:hover {
    background-color: #475569;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
QProgressBar {
    background-color: #1f232e;
    border: 1px solid #282e3d;
    border-radius: 5px;
    text-align: center;
    height: 10px;
}
QProgressBar::chunk {
    background-color: #3b82f6;
    border-radius: 4px;
}
QFrame#FooterBar {
    background-color: #181b23;
    border-top: 1px solid #282e3d;
}
"""