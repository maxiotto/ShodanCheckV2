import os
import re
import shutil
import tempfile
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtCore import QThread, Signal

DEFAULT_CACHE_DIR = "screenshots_cache"


def find_browser_executable() -> str | None:
    """Sucht nach einer installierten Microsoft Edge- oder Google Chrome-Binary."""
    for cmd in ("msedge", "msedge.exe", "chrome", "chrome.exe", "chromium"):
        found = shutil.which(cmd)
        if found and os.path.isfile(found):
            return found

    env_dirs = [
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        os.environ.get("LOCALAPPDATA", ""),
    ]
    rel_paths = [
        r"Microsoft\Edge\Application\msedge.exe",
        r"Google\Chrome\Application\chrome.exe",
        r"BraveSoftware\Brave-Browser\Application\brave.exe",
    ]
    for base in env_dirs:
        if not base:
            continue
        for rel in rel_paths:
            candidate = os.path.join(base, rel)
            if os.path.isfile(candidate):
                return candidate
    return None


def get_screenshot_filepath(ip: str, port: int, cache_dir: str = DEFAULT_CACHE_DIR) -> str:
    """Erzeugt den deterministischen Dateipfad für ein IP:Port-Ziel im Cache-Ordner."""
    os.makedirs(cache_dir, exist_ok=True)
    safe_ip = re.sub(r"[^0-9A-Za-z._-]", "_", ip.strip())
    return os.path.join(cache_dir, f"{safe_ip}_{int(port)}.png")


def get_cached_screenshot(ip: str, port: int, cache_dir: str = DEFAULT_CACHE_DIR) -> str | None:
    """Gibt den Pfad zu einem bereits gespeicherten Screenshot zurück, falls vorhanden."""
    path = get_screenshot_filepath(ip, port, cache_dir)
    if os.path.isfile(path) and os.path.getsize(path) > 512:
        return path
    return None


def get_cache_stats(cache_dir: str = DEFAULT_CACHE_DIR) -> tuple[int, int]:
    """Liefert (Anzahl Dateien, Gesamtgröße in Bytes) im Screenshot-Cache."""
    if not os.path.isdir(cache_dir):
        return 0, 0
    count = 0
    total_bytes = 0
    for name in os.listdir(cache_dir):
        full = os.path.join(cache_dir, name)
        if os.path.isfile(full) and name.lower().endswith(".png"):
            count += 1
            total_bytes += os.path.getsize(full)
    return count, total_bytes


def clear_screenshot_cache(cache_dir: str = DEFAULT_CACHE_DIR) -> int:
    """Löscht alle gespeicherten Vorschaubilder im Cache-Ordner."""
    if not os.path.isdir(cache_dir):
        return 0
    removed = 0
    for name in os.listdir(cache_dir):
        full = os.path.join(cache_dir, name)
        if os.path.isfile(full) and name.lower().endswith(".png"):
            try:
                os.remove(full)
                removed += 1
            except OSError:
                pass
    return removed


def capture_page_screenshot(
    url: str,
    ip: str,
    port: int,
    cache_dir: str = DEFAULT_CACHE_DIR,
    proxy_url: str = "",
    page_wait_ms: int = 12000,
    hard_timeout_sec: int = 35,
    window_size: str = "1280,800",
) -> tuple[bool, str, str]:
    """
    Erstellt einen Headless-Screenshot erst nach vollständigem Laden der Gegenseite.
    Nutzt ein isoliertes temporäres Browser-Profil, damit laufende Browser-Fenster
    nicht blockieren.
    """
    clean_url = (url or "").strip()
    if not clean_url.lower().startswith(("http://", "https://")):
        return False, "", "Vorschau nur für HTTP/HTTPS-Dienste verfügbar."

    browser_exe = find_browser_executable()
    if not browser_exe:
        return False, "", "Kein Microsoft Edge oder Google Chrome für Vorschau gefunden."

    out_path = get_screenshot_filepath(ip, port, cache_dir)
    temp_profile = tempfile.mkdtemp(prefix="shodancheck_shot_")

    cmd = [
        browser_exe,
        "--headless=new",
        f"--user-data-dir={temp_profile}",
        f"--window-size={window_size}",
        "--hide-scrollbars",
        "--ignore-certificate-errors",
        "--ignore-ssl-errors",
        "--allow-running-insecure-content",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-sync",
        "--disable-background-networking",
        "--no-first-run",
        "--no-default-browser-check",
        f"--virtual-time-budget={max(3000, int(page_wait_ms))}",
        f"--screenshot={out_path}",
    ]

    if proxy_url and proxy_url.strip():
        cmd.append(f"--proxy-server={proxy_url.strip()}")

    cmd.append(clean_url)

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=hard_timeout_sec,
            creationflags=creationflags,
        )
        if os.path.isfile(out_path) and os.path.getsize(out_path) > 512:
            return True, out_path, "Vorschau erfolgreich geladen."
        err_hint = (proc.stderr or b"").decode("utf-8", errors="ignore").strip()
        short_hint = err_hint.splitlines()[-1][:120] if err_hint else "Keine Bilddaten erzeugt"
        return False, "", f"Seite konnte nicht gerendert werden ({short_hint})."
    except subprocess.TimeoutExpired:
        if os.path.isfile(out_path) and os.path.getsize(out_path) > 512:
            return True, out_path, "Vorschau nach Zeitlimit gespeichert."
        return False, "", f"Zeitüberschreitung ({hard_timeout_sec}s): Gegenseite lädt zu langsam."
    except Exception as e:
        return False, "", f"Screenshot-Fehler: {e}"
    finally:
        shutil.rmtree(temp_profile, ignore_errors=True)


class ScreenshotWorker(QThread):
    """Hintergrund-Worker für Einzel- und Batch-Screenshots (max. 3 parallele Instanzen)."""

    progress_updated = Signal(str)
    screenshot_ready = Signal(str, str, bool, str)
    batch_finished = Signal(int, int)

    def __init__(
        self,
        targets: list[dict],
        cache_dir: str = DEFAULT_CACHE_DIR,
        proxy_url: str = "",
        page_wait_ms: int = 12000,
        hard_timeout_sec: int = 35,
        max_workers: int = 3,
    ):
        super().__init__()
        self.targets = targets
        self.cache_dir = cache_dir
        self.proxy_url = proxy_url
        self.page_wait_ms = page_wait_ms
        self.hard_timeout_sec = hard_timeout_sec
        self.max_workers = max(1, min(3, max_workers))
        self._cancel_requested = False

    def request_cancel(self):
        self._cancel_requested = True

    def run(self):
        total = len(self.targets)
        if total == 0:
            self.batch_finished.emit(0, 0)
            return

        ok_count = 0
        fail_count = 0
        done_count = 0

        if total == 1:
            t = self.targets[0]
            key = f"{t['ip']}:{t['port']}"
            self.progress_updated.emit(f"Lade Live-Vorschau für {key} (warte auf Seitenaufbau)...")
            ok, path, msg = capture_page_screenshot(
                url=t.get("url", ""),
                ip=t["ip"],
                port=int(t["port"]),
                cache_dir=self.cache_dir,
                proxy_url=self.proxy_url,
                page_wait_ms=self.page_wait_ms,
                hard_timeout_sec=self.hard_timeout_sec,
            )
            if ok:
                ok_count += 1
            else:
                fail_count += 1
            self.screenshot_ready.emit(key, path, ok, msg)
            self.batch_finished.emit(ok_count, fail_count)
            return

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {}
            for t in self.targets:
                if self._cancel_requested:
                    break
                fut = pool.submit(
                    capture_page_screenshot,
                    t.get("url", ""),
                    t["ip"],
                    int(t["port"]),
                    self.cache_dir,
                    self.proxy_url,
                    self.page_wait_ms,
                    self.hard_timeout_sec,
                )
                future_map[fut] = t

            for fut in as_completed(future_map):
                t = future_map[fut]
                key = f"{t['ip']}:{t['port']}"
                if self._cancel_requested:
                    continue
                try:
                    ok, path, msg = fut.result()
                except Exception as e:
                    ok, path, msg = False, "", f"Fehler: {e}"

                done_count += 1
                if ok:
                    ok_count += 1
                else:
                    fail_count += 1

                self.progress_updated.emit(f"Screenshots: {done_count} / {total} abgeschlossen...")
                self.screenshot_ready.emit(key, path, ok, msg)

        self.batch_finished.emit(ok_count, fail_count)