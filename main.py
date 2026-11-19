"""Einstiegspunkt für ShodanCheck."""

import os
import sys

# Sicherstellen, dass das Projektverzeichnis im Suchpfad liegt
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

from core.constants import APP_NAME, APP_VERSION
import ui.theme as theme
from ui.main_window import MainWindow


def _apply_app_theme(app: QApplication):
    """Wendet das dunkle Stylesheet aus ui.theme unabhängig vom Export-Namen an."""
    app.setStyle("Fusion")
    if hasattr(theme, "apply_theme") and callable(theme.apply_theme):
        theme.apply_theme(app)
        return
    if hasattr(theme, "get_stylesheet") and callable(theme.get_stylesheet):
        app.setStyleSheet(theme.get_stylesheet())
        return
    for attr in ("DARK_STYLESHEET", "APP_STYLESHEET", "STYLESHEET"):
        qss = getattr(theme, attr, None)
        if isinstance(qss, str) and qss.strip():
            app.setStyleSheet(qss)
            return


def main():
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setFont(QFont("Segoe UI", 10))

    _apply_app_theme(app)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()