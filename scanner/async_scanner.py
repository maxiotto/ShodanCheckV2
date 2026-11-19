"""Asynchroner Hintergrund-Worker für Multi-Engine-Suche, Port-Probing und Auto-GeoIP."""

import time
import asyncio
from PySide6.QtCore import QThread, Signal

from core.constants import DEFAULT_PORTS, SCREENSHOT_CACHE_DIR
from core.storage import normalize_item, load_geoip_cache, save_geoip_cache
from providers.base import BaseSearchEngine, run_universal_search, merge_engine_hits
from scanner.net_utils import parse_ports, probe_endpoint
from ui.theme import COLORS


def _try_enrich_ip(ip: str, geoip_cfg: dict, cache: dict, proxy_url: str = "") -> dict:
    """Ruft die GeoIP/ASN/PTR-Anreicherung auf, sobald scanner/enrichment.py vorhanden ist."""
    try:
        from scanner.enrichment import enrich_ip_record
        return enrich_ip_record(ip=ip, geoip_cfg=geoip_cfg, cache=cache, proxy_url=proxy_url)
    except ImportError:
        return cache.get(ip, {})
    except Exception:
        return cache.get(ip, {})


class ScanWorker(QThread):
    """
    Hintergrund-Thread für:
      - mode='search': Suchmaschinen-Abfrage(n) + Live-Endpoint-Prüfung
      - mode='targets': Direkte Prüfung einer Ziel-Liste (Import, CIDR, Rescan)
    """

    status_updated = Signal(str, str)     # (Meldung, Hex-Farbe)
    progress_updated = Signal(int, int)   # (abgeschlossen, gesamt)
    batch_ready = Signal(list)            # list[dict] normalisierter Ergebnis-Zeilen
    search_summary = Signal(list, list)   # (aktive_dienstnamen, fehlermeldungen)
    scan_finished = Signal(bool, int, int)  # (abgebrochen, ok_anzahl, gesamt_anzahl)

    def __init__(
        self,
        mode: str,
        config: dict,
        engines: dict[str, BaseSearchEngine] | None = None,
        query: str = "",
        selected_engine_id: str = "__all__",
        ports_text: str = "",
        raw_targets: list[dict] | None = None,
        favorite_keys: set[str] | None = None,
        visited_keys: set[str] | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.mode = mode
        self.config = config or {}
        self.engines = engines or {}
        self.query = (query or "").strip()
        self.selected_engine_id = selected_engine_id or "__all__"
        self.ports_text = ports_text
        self.raw_targets = list(raw_targets or [])
        self.favorite_keys = set(favorite_keys or set())
        self.visited_keys = set(visited_keys or set())

        self._cancel_requested = False
        self._geoip_cache: dict[str, dict] = {}
        self._geoip_dirty = False

    def request_cancel(self):
        """Signalisiert dem laufenden Scan einen sauberen Abbruch."""
        self._cancel_requested = True

    def _expand_and_dedupe_targets(self, hits: list[dict], target_ports: list[int]) -> list[dict]:
        """
        Expandiert Treffer ohne konkreten Port (port <= 0) auf die gewählten Ziel-Ports
        und dedupliziert identische (ip, port)-Paare.
        """
        expanded: list[dict] = []
        seen: set[tuple[str, int]] = set()

        for h in hits:
            ip = (h.get("ip") or "").strip()
            if not ip:
                continue
            raw_port = int(h.get("port") or 0)
            ports_for_hit = [raw_port] if raw_port > 0 else target_ports

            for p in ports_for_hit:
                key = (ip, int(p))
                if key in seen:
                    continue
                seen.add(key)
                clone = dict(h)
                clone["ip"] = ip
                clone["port"] = int(p)
                expanded.append(clone)

        return expanded

    def _collect_search_targets(self, target_ports: list[int]) -> list[dict]:
        """Fragt einen einzelnen Suchdienst oder alle aktivierten Dienste ab."""
        proxy_url = (self.config.get("proxy_url") or "").strip()
        max_per_srv = int(self.config.get("max_results_per_service") or 100)

        if self.selected_engine_id == "__all__":
            self.status_updated.emit(
                "🔍 Frage alle aktivierten Suchdienste parallel ab...",
                COLORS["cyan"],
            )
            hits, active_names, errors = run_universal_search(
                query=self.query,
                config=self.config,
                engines=self.engines,
                progress_cb=lambda msg: self.status_updated.emit(f"🔍 {msg}", COLORS["cyan"]),
            )
            self.search_summary.emit(active_names, errors)
            return self._expand_and_dedupe_targets(hits, target_ports)

        engine = self.engines.get(self.selected_engine_id)
        if engine is None:
            self.search_summary.emit([], [f"Unbekannter Suchdienst: {self.selected_engine_id}"])
            return []

        s_cfg = (self.config.get("services") or {}).get(self.selected_engine_id) or {}
        api_key = (s_cfg.get("api_key") or "").strip()
        api_secret = (s_cfg.get("api_secret") or "").strip()

        if engine.requires_key and not api_key:
            self.search_summary.emit(
                [engine.name],
                [f"{engine.name}: Kein API-Key hinterlegt. Bitte unter '⚙️ Dienste' eintragen."],
            )
            return []

        self.status_updated.emit(f"🔍 Suche über {engine.name}...", COLORS["cyan"])
        try:
            raw_hits = engine.search(
                query=self.query,
                api_key=api_key,
                api_secret=api_secret,
                max_results=max_per_srv,
                proxy_url=proxy_url,
            )
            merged = merge_engine_hits(raw_hits)
            self.search_summary.emit([engine.name], [])
            return self._expand_and_dedupe_targets(merged, target_ports)
        except Exception as exc:
            self.search_summary.emit([engine.name], [f"{engine.name}: {exc}"])
            return []

    async def _probe_single_target(
        self,
        target: dict,
        semaphore: asyncio.Semaphore,
        timeout: float,
        proxy_url: str,
        url_suffix: str,
        auto_geoip: bool,
        geoip_cfg: dict,
    ) -> dict | None:
        """Prüft ein einzelnes Ziel unter Berücksichtigung des Concurrency-Semaphors."""
        if self._cancel_requested:
            return None

        async with semaphore:
            if self._cancel_requested:
                return None

            ip = target["ip"]
            port = int(target["port"])

            probe = await probe_endpoint(
                ip=ip,
                port=port,
                timeout=timeout,
                proxy_url=proxy_url,
                url_suffix=url_suffix,
            )

            item = normalize_item(target)
            item["status"] = probe["status"]
            item["url"] = probe["url"]
            item["http_code"] = probe["http_code"]
            item["response_info"] = probe["response_info"]

            if probe.get("tls_info"):
                item["tls_info"] = probe["tls_info"]
            if probe.get("headers_raw"):
                item["headers_raw"] = probe["headers_raw"]
            if probe.get("banner_raw"):
                item["banner_raw"] = probe["banner_raw"]

            key = f"{ip}:{port}"
            item["favorite"] = key in self.favorite_keys
            item["visited"] = key in self.visited_keys

            # Optionale Auto-GeoIP / ASN / PTR-Anreicherung für erreichbare Ziele
            if auto_geoip and item["status"] == "OK" and not self._cancel_requested:
                needs_enrichment = not (
                    item.get("country_code") and item.get("asn") and item.get("ptr")
                )
                if needs_enrichment:
                    loop = asyncio.get_running_loop()
                    cached_before = ip in self._geoip_cache
                    geo_data = await loop.run_in_executor(
                        None,
                        _try_enrich_ip,
                        ip,
                        geoip_cfg,
                        self._geoip_cache,
                        proxy_url,
                    )
                    if not cached_before and ip in self._geoip_cache:
                        self._geoip_dirty = True
                    for field in ("country_code", "country_name", "city", "asn", "asn_org", "ptr"):
                        if not item.get(field) and geo_data.get(field):
                            item[field] = geo_data[field]

            return normalize_item(item)

    async def _run_async_scan(self, targets: list[dict]) -> tuple[int, int]:
        """Führt alle Endpunkt-Checks asynchron aus und liefert laufend Ergebnis-Batches."""
        total = len(targets)
        concurrency = max(1, min(1000, int(self.config.get("concurrency") or 250)))
        timeout = float(self.config.get("timeout_sec") or 3.5)
        proxy_url = (self.config.get("proxy_url") or "").strip()
        url_suffix = (self.config.get("url_suffix") or "").strip()
        auto_geoip = bool(self.config.get("auto_geoip", False))
        geoip_cfg = dict(self.config.get("geoip") or {})

        if auto_geoip:
            self._geoip_cache = load_geoip_cache()

        semaphore = asyncio.Semaphore(concurrency)
        tasks = [
            asyncio.create_task(
                self._probe_single_target(
                    target=t,
                    semaphore=semaphore,
                    timeout=timeout,
                    proxy_url=proxy_url,
                    url_suffix=url_suffix,
                    auto_geoip=auto_geoip,
                    geoip_cfg=geoip_cfg,
                )
            )
            for t in targets
        ]

        completed = 0
        ok_count = 0
        batch: list[dict] = []
        last_flush = time.monotonic()

        try:
            for coro in asyncio.as_completed(tasks):
                if self._cancel_requested:
                    for pending in tasks:
                        if not pending.done():
                            pending.cancel()
                    break

                res = await coro
                if res is None:
                    continue

                completed += 1
                if res.get("status") == "OK":
                    ok_count += 1
                batch.append(res)

                now = time.monotonic()
                if len(batch) >= 25 or (now - last_flush) >= 0.35:
                    self.batch_ready.emit(list(batch))
                    batch.clear()
                    last_flush = now
                    self.progress_updated.emit(completed, total)
        finally:
            if batch:
                self.batch_ready.emit(list(batch))
                batch.clear()
            self.progress_updated.emit(completed, total)
            if self._geoip_dirty:
                save_geoip_cache(self._geoip_cache)

        return ok_count, completed

    def run(self):
        target_ports = parse_ports(self.ports_text, fallback=DEFAULT_PORTS)

        if self.mode == "search":
            targets = self._collect_search_targets(target_ports)
        else:
            targets = self._expand_and_dedupe_targets(self.raw_targets, target_ports)

        if self._cancel_requested:
            self.scan_finished.emit(True, 0, 0)
            return

        total = len(targets)
        if total == 0:
            self.status_updated.emit("Keine zu prüfenden Ziele gefunden.", COLORS["warn"])
            self.scan_finished.emit(False, 0, 0)
            return

        self.status_updated.emit(
            f"⚡ Prüfe {total} Endpunkt(e) parallel (Concurrency: {self.config.get('concurrency', 250)})...",
            COLORS["cyan"],
        )
        self.progress_updated.emit(0, total)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            ok_count, completed = loop.run_until_complete(self._run_async_scan(targets))
        finally:
            loop.close()

        self.scan_finished.emit(self._cancel_requested, ok_count, completed)