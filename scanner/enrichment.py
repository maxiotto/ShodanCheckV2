"""GeoIP-, ASN- und Reverse-DNS-Anreicherung (MaxMind .mmdb + Online-Fallback + Cache)."""

import os
import ssl
import json
import socket
import ipaddress
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from PySide6.QtCore import QThread, Signal
from core.storage import load_geoip_cache, save_geoip_cache

_CACHE_LOCK = threading.Lock()


def _lookup_ptr(ip: str, timeout_sec: float = 3.0) -> str:
    """Ermittelt den Reverse-DNS-Namen (PTR) mit striktem Timeout ohne globalen Socket-Lock."""
    def _resolve():
        host, _, _ = socket.gethostbyaddr(ip)
        return (host or "").strip().rstrip(".")

    pool = ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(_resolve)
    try:
        return fut.result(timeout=max(1.0, float(timeout_sec)))
    except (FuturesTimeoutError, Exception):
        return ""
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _lookup_mmdb(ip: str, city_mmdb_path: str, asn_mmdb_path: str) -> dict:
    """Liest Land, Stadt und ASN aus lokalen MaxMind-.mmdb-Dateien (via maxminddb oder geoip2)."""
    result = {
        "country_code": "",
        "country_name": "",
        "city": "",
        "asn": "",
        "asn_org": "",
    }

    city_path = (city_mmdb_path or "").strip()
    asn_path = (asn_mmdb_path or "").strip()
    if not city_path and not asn_path:
        return result

    # Variante 1: maxminddb (schnell & direkt auf Roh-Records)
    try:
        import maxminddb

        if city_path and os.path.isfile(city_path):
            with maxminddb.open_database(city_path) as reader:
                rec = reader.get(ip) or {}
                country = rec.get("country") or rec.get("registered_country") or {}
                c_names = country.get("names") or {}
                city_obj = rec.get("city") or {}
                city_names = city_obj.get("names") or {}
                result["country_code"] = str(country.get("iso_code") or "").upper()
                result["country_name"] = str(c_names.get("de") or c_names.get("en") or "")
                result["city"] = str(city_names.get("de") or city_names.get("en") or "")

        if asn_path and os.path.isfile(asn_path):
            with maxminddb.open_database(asn_path) as reader:
                rec = reader.get(ip) or {}
                asn_num = rec.get("autonomous_system_number")
                if asn_num:
                    result["asn"] = f"AS{asn_num}"
                result["asn_org"] = str(rec.get("autonomous_system_organization") or "")

        return result
    except ImportError:
        pass
    except Exception:
        pass

    # Variante 2: geoip2.database Fallback
    try:
        import geoip2.database

        if city_path and os.path.isfile(city_path):
            with geoip2.database.Reader(city_path) as reader:
                resp = reader.city(ip)
                result["country_code"] = str(resp.country.iso_code or "").upper()
                result["country_name"] = str(
                    resp.country.names.get("de") or resp.country.name or ""
                )
                result["city"] = str(
                    resp.city.names.get("de") or resp.city.name or ""
                )

        if asn_path and os.path.isfile(asn_path):
            with geoip2.database.Reader(asn_path) as reader:
                resp = reader.asn(ip)
                if resp.autonomous_system_number:
                    result["asn"] = f"AS{resp.autonomous_system_number}"
                result["asn_org"] = str(resp.autonomous_system_organization or "")
    except Exception:
        pass

    return result


def _http_get_json(url: str, timeout_sec: float = 4.0, proxy_url: str = "") -> dict:
    """Hilfsfunktion für key-freie GeoIP-JSON-Endpunkte inklusive Proxy-Unterstützung."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "ShodanCheck/2.0", "Accept": "application/json"},
    )
    handlers = []
    if proxy_url and proxy_url.strip():
        p = proxy_url.strip()
        handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))
    ctx = ssl.create_default_context()
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    opener = urllib.request.build_opener(*handlers)

    with opener.open(req, timeout=max(2.0, float(timeout_sec))) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw.strip() else {}


def _lookup_online_geoip(ip: str, timeout_sec: float = 4.0, proxy_url: str = "") -> dict:
    """Key-freie Online-Abfrage für Land, Stadt und ASN mit automatischem Endpunkt-Fallback."""
    # Primär: ipwho.is (HTTPS, strukturiertes ASN-Objekt)
    try:
        data = _http_get_json(f"https://ipwho.is/{ip}", timeout_sec=timeout_sec, proxy_url=proxy_url)
        if data.get("success") is True:
            conn = data.get("connection") or {}
            asn_num = conn.get("asn")
            asn_str = f"AS{asn_num}" if asn_num else ""
            org = str(conn.get("org") or conn.get("isp") or "").strip()
            return {
                "country_code": str(data.get("country_code") or "").upper(),
                "country_name": str(data.get("country") or "").strip(),
                "city": str(data.get("city") or "").strip(),
                "asn": asn_str,
                "asn_org": org,
            }
    except Exception:
        pass

    # Sekundär: ip-api.com (HTTP)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,as,org,isp"
        data = _http_get_json(url, timeout_sec=timeout_sec, proxy_url=proxy_url)
        if data.get("status") == "success":
            as_raw = str(data.get("as") or "").strip()
            asn_code = ""
            asn_org = str(data.get("org") or data.get("isp") or "").strip()
            if as_raw.upper().startswith("AS"):
                parts = as_raw.split(" ", 1)
                asn_code = parts[0].upper()
                if not asn_org and len(parts) > 1:
                    asn_org = parts[1].strip()
            return {
                "country_code": str(data.get("countryCode") or "").upper(),
                "country_name": str(data.get("country") or "").strip(),
                "city": str(data.get("city") or "").strip(),
                "asn": asn_code,
                "asn_org": asn_org,
            }
    except Exception:
        pass

    return {}


def enrich_ip_record(
    ip: str,
    geoip_cfg: dict | None = None,
    cache: dict[str, dict] | None = None,
    proxy_url: str = "",
    force_refresh: bool = False,
) -> dict:
    """
    Liefert angereicherte Host-Metadaten (PTR, Land, Stadt, ASN, Organisation) für eine IP.
    Nutzt zuerst den Cache, dann lokale MaxMind-.mmdb-Dateien und bei Bedarf Online-GeoIP.
    """
    clean_ip = (ip or "").strip()
    if not clean_ip:
        return {}

    cfg = geoip_cfg or {}
    timeout_sec = float(cfg.get("timeout_sec") or 4.0)
    ptr_enabled = bool(cfg.get("ptr_enabled", True))
    city_mmdb = str(cfg.get("city_mmdb_path") or "")
    asn_mmdb = str(cfg.get("asn_mmdb_path") or "")

    if cache is not None and not force_refresh:
        with _CACHE_LOCK:
            if clean_ip in cache and isinstance(cache[clean_ip], dict):
                return dict(cache[clean_ip])

    record = {
        "country_code": "",
        "country_name": "",
        "city": "",
        "asn": "",
        "asn_org": "",
        "ptr": "",
    }

    # 1) Reverse-DNS (PTR) auch für lokale Netze versuchen
    if ptr_enabled:
        record["ptr"] = _lookup_ptr(clean_ip, timeout_sec=min(timeout_sec, 3.0))

    # 2) Lokale/private Netze abfangen
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            record["country_code"] = "LAN"
            record["country_name"] = "Lokales / Privates Netz"
            record["asn_org"] = "Private IP"
            if cache is not None:
                with _CACHE_LOCK:
                    cache[clean_ip] = dict(record)
            return record
    except ValueError:
        return record

    # 3) Lokale MaxMind-.mmdb-Datenbanken abfragen
    mmdb_res = _lookup_mmdb(clean_ip, city_mmdb, asn_mmdb)
    for k, v in mmdb_res.items():
        if v:
            record[k] = v

    # 4) Fehlende GeoIP-/ASN-Felder per Online-Fallback ergänzen
    if not (record["country_code"] and (record["asn"] or record["asn_org"])):
        online_res = _lookup_online_geoip(clean_ip, timeout_sec=timeout_sec, proxy_url=proxy_url)
        for k, v in online_res.items():
            if not record.get(k) and v:
                record[k] = v

    if cache is not None:
        with _CACHE_LOCK:
            cache[clean_ip] = dict(record)

    return record


class EnrichmentWorker(QThread):
    """Hintergrund-Worker für On-Demand- und Batch-GeoIP/ASN/PTR-Abfragen."""

    item_enriched = Signal(str, dict)  # (ip, angereicherte_felder)
    batch_finished = Signal(int)       # (anzahl_aktualisierter_ips)

    def __init__(
        self,
        ips: list[str],
        geoip_cfg: dict | None = None,
        proxy_url: str = "",
        force_refresh: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self.ips = list(dict.fromkeys(ip.strip() for ip in (ips or []) if ip and ip.strip()))
        self.geoip_cfg = dict(geoip_cfg or {})
        self.proxy_url = (proxy_url or "").strip()
        self.force_refresh = force_refresh
        self._cancel_requested = False

    def request_cancel(self):
        self._cancel_requested = True

    def run(self):
        if not self.ips:
            self.batch_finished.emit(0)
            return

        cache = load_geoip_cache()
        dirty = False
        updated_count = 0

        for ip in self.ips:
            if self._cancel_requested:
                break

            existed_before = ip in cache
            data = enrich_ip_record(
                ip=ip,
                geoip_cfg=self.geoip_cfg,
                cache=cache,
                proxy_url=self.proxy_url,
                force_refresh=self.force_refresh,
            )
            if self.force_refresh or not existed_before:
                dirty = True

            updated_count += 1
            self.item_enriched.emit(ip, data)

        if dirty:
            save_geoip_cache(cache)

        self.batch_finished.emit(updated_count)