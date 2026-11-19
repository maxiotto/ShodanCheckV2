"""Atomare JSON-Persistenz für Konfiguration, Sitzung, Historie, Merkliste und Caches."""

import os
import re
import json
import copy
import tempfile
from datetime import datetime

from core.constants import (
    CONFIG_FILE,
    SESSION_FILE,
    HISTORY_FILE,
    FAVORITES_FILE,
    GEOIP_CACHE_FILE,
    SCREENSHOT_CACHE_DIR,
    ITEM_SCHEMA_DEFAULTS,
    get_default_config,
)


def _deep_merge(base: dict, override: dict) -> dict:
    """Führt gespeicherte Konfigurationswerte rekursiv mit Standardwerten zusammen."""
    result = copy.deepcopy(base)
    for key, val in (override or {}).items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = copy.deepcopy(val)
    return result


def load_json(path: str, default):
    """Lädt eine JSON-Datei fehlertolerant und liefert bei Fehlern `default`."""
    if not path or not os.path.isfile(path):
        return copy.deepcopy(default)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if data is not None else copy.deepcopy(default)
    except Exception:
        return copy.deepcopy(default)


def save_json(path: str, data) -> bool:
    """Speichert Daten atomar als UTF-8-JSON über eine temporäre Datei."""
    if not path:
        return False
    target_dir = os.path.dirname(os.path.abspath(path))
    os.makedirs(target_dir, exist_ok=True)
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp_sc_", suffix=".json", dir=target_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
        return True
    except Exception:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        return False


def _resolve_cached_screenshot_path(ip: str, port: int, current_path: str = "") -> str:
    """Prüft, ob ein Screenshot unter dem gespeicherten oder Standard-Cache-Pfad existiert."""
    if current_path and os.path.isfile(current_path) and os.path.getsize(current_path) > 512:
        return current_path
    safe_ip = re.sub(r"[^0-9A-Za-z._-]", "_", (ip or "").strip())
    candidate = os.path.join(SCREENSHOT_CACHE_DIR, f"{safe_ip}_{int(port)}.png")
    if os.path.isfile(candidate) and os.path.getsize(candidate) > 512:
        return candidate
    return ""


def normalize_item(raw: dict) -> dict:
    """Ergänzt fehlende Schema-Felder und prüft vorhandene Cache-Screenshots."""
    item = copy.deepcopy(ITEM_SCHEMA_DEFAULTS)
    if isinstance(raw, dict):
        item.update(raw)

    item["ip"] = str(item.get("ip") or "").strip()
    try:
        item["port"] = int(item.get("port") or 80)
    except (ValueError, TypeError):
        item["port"] = 80

    try:
        item["http_code"] = int(item.get("http_code") or 0)
    except (ValueError, TypeError):
        item["http_code"] = 0

    item["checked"] = bool(item.get("checked", False))
    item["favorite"] = bool(item.get("favorite", False))
    item["visited"] = bool(item.get("visited", False))
    item["screenshot_path"] = _resolve_cached_screenshot_path(
        item["ip"], item["port"], str(item.get("screenshot_path") or "")
    )
    return item


# --- Konfiguration ---
def load_config(path: str = CONFIG_FILE) -> dict:
    loaded = load_json(path, {})
    return _deep_merge(get_default_config(), loaded if isinstance(loaded, dict) else {})


def save_config(config: dict, path: str = CONFIG_FILE) -> bool:
    return save_json(path, config)


# --- Sitzung ---
def load_session(path: str = SESSION_FILE) -> dict:
    data = load_json(path, {})
    if not isinstance(data, dict):
        data = {}
    raw_items = data.get("items") or []
    items = [normalize_item(it) for it in raw_items if isinstance(it, dict) and it.get("ip")]
    return {
        "query": str(data.get("query") or ""),
        "ports": str(data.get("ports") or "80, 443, 8080, 8443"),
        "suffix": str(data.get("suffix") or ""),
        "page_index": int(data.get("page_index") or 0),
        "items": items,
    }


def save_session(
    items: list[dict],
    query: str = "",
    ports: str = "",
    suffix: str = "",
    page_index: int = 0,
    path: str = SESSION_FILE,
) -> bool:
    serializable = []
    for it in items:
        clean = normalize_item(it)
        clean["checked"] = False
        serializable.append(clean)

    payload = {
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "query": query,
        "ports": ports,
        "suffix": suffix,
        "page_index": max(0, int(page_index)),
        "items": serializable,
    }
    return save_json(path, payload)


# --- Suchhistorie ---
def load_history(path: str = HISTORY_FILE) -> list[dict]:
    data = load_json(path, [])
    return data if isinstance(data, list) else []


def save_history(history: list[dict], path: str = HISTORY_FILE) -> bool:
    return save_json(path, history[:150])


def append_history(
    query: str,
    ports: str = "",
    engines: str = "",
    hit_count: int = 0,
    path: str = HISTORY_FILE,
) -> list[dict]:
    q = (query or "").strip()
    if not q:
        return load_history(path)

    history = load_history(path)
    history = [h for h in history if h.get("query", "").strip() != q]
    history.insert(
        0,
        {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "query": q,
            "ports": ports.strip(),
            "engines": engines.strip(),
            "hits": int(hit_count),
        },
    )
    history = history[:100]
    save_history(history, path)
    return history


# --- Merkliste / Favoriten ---
def load_favorites(path: str = FAVORITES_FILE) -> dict[str, dict]:
    """Lädt Favoriten als Dictionary keyed by 'ip:port'."""
    data = load_json(path, {})
    result: dict[str, dict] = {}
    if isinstance(data, list):
        for raw in data:
            if isinstance(raw, dict) and raw.get("ip"):
                norm = normalize_item(raw)
                norm["favorite"] = True
                result[f"{norm['ip']}:{norm['port']}"] = norm
    elif isinstance(data, dict):
        for key, raw in data.items():
            if isinstance(raw, dict) and raw.get("ip"):
                norm = normalize_item(raw)
                norm["favorite"] = True
                result[f"{norm['ip']}:{norm['port']}"] = norm
    return result


def save_favorites(favorites: dict[str, dict], path: str = FAVORITES_FILE) -> bool:
    clean_map: dict[str, dict] = {}
    for key, raw in favorites.items():
        norm = normalize_item(raw)
        norm["favorite"] = True
        norm["checked"] = False
        clean_map[f"{norm['ip']}:{norm['port']}"] = norm
    return save_json(path, clean_map)


def toggle_favorite_item(
    favorites: dict[str, dict], item: dict, path: str = FAVORITES_FILE
) -> tuple[bool, dict[str, dict]]:
    """Schaltet den Favoriten-Status für ein Ziel um und speichert sofort."""
    key = f"{item['ip']}:{int(item['port'])}"
    if key in favorites:
        del favorites[key]
        item["favorite"] = False
        save_favorites(favorites, path)
        return False, favorites

    norm = normalize_item(item)
    norm["favorite"] = True
    item["favorite"] = True
    favorites[key] = norm
    save_favorites(favorites, path)
    return True, favorites


# --- GeoIP / ASN / PTR Cache ---
def load_geoip_cache(path: str = GEOIP_CACHE_FILE) -> dict[str, dict]:
    data = load_json(path, {})
    return data if isinstance(data, dict) else {}


def save_geoip_cache(cache: dict[str, dict], path: str = GEOIP_CACHE_FILE) -> bool:
    return save_json(path, cache)