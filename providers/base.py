"""Gemeinsame Basis-Schnittstelle und Multi-Engine-Aggregator für Suchdienste."""

import ssl
import json
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed


def normalize_engine_hit(
    ip: str,
    port: int = 0,
    source: str = "",
    info: str = "",
    country_code: str = "",
    country_name: str = "",
    city: str = "",
    asn: str = "",
    asn_org: str = "",
    ptr: str = "",
    banner_raw: str = "",
    tls_info: str = "",
) -> dict:
    """Erzeugt ein einheitliches Roh-Treffer-Dictionary aus einer Suchmaschine."""
    clean_ip = (ip or "").strip()
    try:
        clean_port = int(port or 0)
    except (ValueError, TypeError):
        clean_port = 0

    asn_str = str(asn or "").strip()
    if asn_str and asn_str.isdigit():
        asn_str = f"AS{asn_str}"

    return {
        "ip": clean_ip,
        "port": clean_port,
        "sources": [source] if source else [],
        "info": (info or "").strip(),
        "country_code": (country_code or "").strip().upper(),
        "country_name": (country_name or "").strip(),
        "city": (city or "").strip(),
        "asn": asn_str,
        "asn_org": (asn_org or "").strip(),
        "ptr": (ptr or "").strip(),
        "banner_raw": (banner_raw or "").strip(),
        "tls_info": (tls_info or "").strip(),
    }


def merge_engine_hits(hits: list[dict]) -> list[dict]:
    """
    Führt doppelte Treffer (gleiche IP + Port) aus mehreren Suchdiensten zusammen,
    ohne bereits vorhandene GeoIP-, ASN-, PTR- oder Banner-Daten zu verlieren.
    """
    merged: dict[tuple[str, int], dict] = {}
    order: list[tuple[str, int]] = []

    for raw in hits:
        ip = (raw.get("ip") or "").strip()
        if not ip:
            continue
        port = int(raw.get("port") or 0)
        key = (ip, port)

        if key not in merged:
            entry = dict(raw)
            entry["sources"] = list(dict.fromkeys(raw.get("sources") or []))
            merged[key] = entry
            order.append(key)
            continue

        existing = merged[key]
        for src in raw.get("sources") or []:
            if src and src not in existing["sources"]:
                existing["sources"].append(src)

        new_info = (raw.get("info") or "").strip()
        if new_info and new_info not in existing.get("info", ""):
            existing["info"] = f"{existing['info']} | {new_info}".strip(" |")

        for field in ("country_code", "country_name", "city", "asn", "asn_org", "ptr", "tls_info"):
            if not existing.get(field) and raw.get(field):
                existing[field] = raw[field]

        if len(raw.get("banner_raw") or "") > len(existing.get("banner_raw") or ""):
            existing["banner_raw"] = raw["banner_raw"]

    result = []
    for key in order:
        item = merged[key]
        src_prefix = " + ".join(item.get("sources") or [])
        detail = item.get("info") or ""
        if src_prefix and not detail.startswith(src_prefix):
            item["info"] = f"{src_prefix}: {detail}".strip(": ")
        result.append(item)

    return result


class BaseSearchEngine(ABC):
    """Abstrakte Basisklasse für alle integrierten Internet-Asset-Suchmaschinen."""

    engine_id: str = ""
    name: str = ""
    description: str = ""
    requires_key: bool = True
    requires_secret: bool = False
    key_label: str = "API-Key"
    secret_label: str = "API-Secret"

    def _http_json(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        json_body: dict | None = None,
        proxy_url: str = "",
        timeout: int = 15,
    ) -> dict:
        """Führt einen HTTP/HTTPS-API-Aufruf inklusive optionalem Proxy aus."""
        req_headers = {
            "User-Agent": "ShodanCheck/2.0",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        body_bytes = None
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

        handlers = []
        if proxy_url and proxy_url.strip():
            p = proxy_url.strip()
            handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))

        ctx = ssl.create_default_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)

        try:
            with opener.open(req, timeout=timeout) as resp:
                raw_text = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw_text) if raw_text.strip() else {}
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8", errors="ignore")[:220]
            except Exception:
                pass
            if exc.code in (401, 403):
                raise RuntimeError(f"Zugriff verweigert (HTTP {exc.code}) – API-Key/Secret prüfen.") from exc
            if exc.code == 429:
                raise RuntimeError("Rate-Limit erreicht (HTTP 429) – bitte kurz warten.") from exc
            raise RuntimeError(f"HTTP {exc.code}: {err_body or exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Netzwerkfehler: {exc.reason}") from exc

    @abstractmethod
    def test_connection(
        self, api_key: str = "", api_secret: str = "", proxy_url: str = ""
    ) -> tuple[bool, str]:
        """Prüft die Gültigkeit der hinterlegten Zugangsdaten."""

    @abstractmethod
    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        """Führt eine Suchabfrage aus und liefert normalisierte Roh-Treffer."""


def run_universal_search(
    query: str,
    config: dict,
    engines: dict[str, BaseSearchEngine],
    progress_cb=None,
) -> tuple[list[dict], list[str], list[str]]:
    """
    Fragt alle aktivierten Suchdienste parallel ab.
    Rückgabe: (zusammengeführte_treffer, aktive_dienstnamen, fehlermeldungen)
    """
    services_cfg = config.get("services") or {}
    proxy_url = (config.get("proxy_url") or "").strip()
    max_per_srv = int(config.get("max_results_per_service") or 100)

    active_jobs = []
    for eid, engine in engines.items():
        s_cfg = services_cfg.get(eid) or {}
        if not s_cfg.get("enabled"):
            continue
        api_key = (s_cfg.get("api_key") or "").strip()
        api_secret = (s_cfg.get("api_secret") or "").strip()
        if engine.requires_key and not api_key:
            continue
        active_jobs.append((eid, engine, api_key, api_secret))

    if not active_jobs:
        return [], [], ["Kein aktiver Suchdienst mit gültigem API-Key konfiguriert."]

    all_hits: list[dict] = []
    active_names: list[str] = []
    errors: list[str] = []

    with ThreadPoolExecutor(max_workers=min(6, len(active_jobs))) as pool:
        future_map = {}
        for eid, engine, api_key, api_secret in active_jobs:
            active_names.append(engine.name)
            if progress_cb:
                progress_cb(f"Frage {engine.name} ab...")
            fut = pool.submit(
                engine.search,
                query=query,
                api_key=api_key,
                api_secret=api_secret,
                max_results=max_per_srv,
                proxy_url=proxy_url,
            )
            future_map[fut] = engine.name

        for fut in as_completed(future_map):
            srv_name = future_map[fut]
            try:
                srv_hits = fut.result() or []
                all_hits.extend(srv_hits)
                if progress_cb:
                    progress_cb(f"{srv_name}: {len(srv_hits)} Roh-Treffer erhalten.")
            except Exception as exc:
                errors.append(f"{srv_name}: {exc}")

    return merge_engine_hits(all_hits), active_names, errors