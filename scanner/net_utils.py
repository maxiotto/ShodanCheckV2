"""Netzwerk-Hilfsfunktionen: Port-/Ziel-Parser, Proxy-Tunnel, TLS-Analyse & Dienst-Probing."""

import re
import ssl
import html
import base64
import socket
import struct
import asyncio
import ipaddress
import urllib.parse

from core.constants import DEFAULT_PORTS

HTTPS_PREFERRED_PORTS = {443, 8443, 9443, 4443, 10443, 2083, 2087, 2096}
MAX_CIDR_HOSTS = 4096


def parse_ports(port_text: str, fallback: list[int] | None = None) -> list[int]:
    """Parst Port-Angaben wie '80, 443, 8080-8085' in eine sortierte, eindeutige Liste."""
    default_list = list(fallback) if fallback else list(DEFAULT_PORTS)
    raw = (port_text or "").strip()
    if not raw:
        return default_list

    ports: set[int] = set()
    for token in re.split(r"[,;\s]+", raw):
        tok = token.strip()
        if not tok:
            continue
        if "-" in tok:
            parts = tok.split("-", 1)
            try:
                start_p = int(parts[0].strip())
                end_p = int(parts[1].strip())
                if start_p > end_p:
                    start_p, end_p = end_p, start_p
                start_p = max(1, start_p)
                end_p = min(65535, end_p)
                if (end_p - start_p) <= 2000:
                    ports.update(range(start_p, end_p + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(tok)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue

    return sorted(ports) if ports else default_list


def normalize_url_suffix(suffix: str) -> str:
    """Normiert einen optionalen URL-Pfad wie 'login' -> '/login'."""
    clean = (suffix or "").strip()
    if not clean:
        return ""
    return clean if clean.startswith("/") else f"/{clean}"


def is_valid_ip(value: str) -> bool:
    """Prüft, ob ein String eine gültige IPv4- oder IPv6-Adresse ist."""
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def parse_targets_from_text(
    raw_text: str,
    default_ports: list[int] | None = None,
    source_label: str = "Import",
) -> list[dict]:
    """
    Extrahiert Scan-Ziele aus freiem Text oder Dateien.
    Unterstützt: 'IP', 'IP:Port', 'http(s)://IP:Port/pfad', CIDR ('1.2.3.0/24')
    und einfache IP-Bereiche ('1.2.3.1-1.2.3.20').
    """
    ports_to_use = default_ports if default_ports else list(DEFAULT_PORTS)
    targets: list[dict] = []
    seen: set[tuple[str, int]] = set()

    def _add(ip_str: str, port_num: int, info_str: str):
        key = (ip_str, int(port_num))
        if key in seen:
            return
        seen.add(key)
        targets.append(
            {
                "ip": ip_str,
                "port": int(port_num),
                "sources": [source_label] if source_label else [],
                "info": info_str,
            }
        )

    for line in (raw_text or "").splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith(("#", "//", ";")):
            continue

        # 1) Vollständige URL (z. B. http://1.2.3.4:8080/admin)
        if cleaned.lower().startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(cleaned)
            host = (parsed.hostname or "").strip()
            if is_valid_ip(host):
                port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
                _add(host, port, f"{source_label}: {cleaned}")
            continue

        # 2) CIDR-Subnetz (z. B. 192.168.1.0/24)
        if "/" in cleaned and ":" not in cleaned:
            try:
                net = ipaddress.ip_network(cleaned, strict=False)
                hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
                for ip_obj in hosts[:MAX_CIDR_HOSTS]:
                    ip_s = str(ip_obj)
                    for p in ports_to_use:
                        _add(ip_s, p, f"{source_label} ({cleaned})")
                continue
            except ValueError:
                pass

        # 3) Einfacher IPv4-Bereich (z. B. 10.0.0.1-10.0.0.50)
        if "-" in cleaned and ":" not in cleaned:
            left, right = [x.strip() for x in cleaned.split("-", 1)]
            if is_valid_ip(left) and is_valid_ip(right):
                try:
                    start_ip = ipaddress.IPv4Address(left)
                    end_ip = ipaddress.IPv4Address(right)
                    if int(start_ip) > int(end_ip):
                        start_ip, end_ip = end_ip, start_ip
                    count = min(MAX_CIDR_HOSTS, int(end_ip) - int(start_ip) + 1)
                    for offset in range(count):
                        ip_s = str(ipaddress.IPv4Address(int(start_ip) + offset))
                        for p in ports_to_use:
                            _add(ip_s, p, f"{source_label} ({cleaned})")
                    continue
                except Exception:
                    pass

        # 4) IP:Port (oder [IPv6]:Port)
        m_ip_port = re.match(r"^\[?([0-9a-fA-F:.]+)\]?:(\d{1,5})(?:\s+(.*))?$", cleaned)
        if m_ip_port and is_valid_ip(m_ip_port.group(1)):
            ip_s = m_ip_port.group(1)
            port_n = int(m_ip_port.group(2))
            extra = (m_ip_port.group(3) or "").strip()
            if 1 <= port_n <= 65535:
                _add(ip_s, port_n, f"{source_label}: {extra}".strip(": "))
                continue

        # 5) Einzelne IP-Adresse (ggf. mit Kommentar dahinter)
        first_tok = re.split(r"[\s,;]+", cleaned, maxsplit=1)
        candidate_ip = first_tok[0].strip()
        extra_note = first_tok[1].strip() if len(first_tok) > 1 else ""
        if is_valid_ip(candidate_ip):
            info_txt = f"{source_label}: {extra_note}".strip(": ")
            for p in ports_to_use:
                _add(candidate_ip, p, info_txt)

    return targets


def create_unverified_ssl_context() -> ssl.SSLContext:
    """Erstellt einen fehlertoleranten TLS-Kontext für selbstsignierte Geräte-Zertifikate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def extract_tls_details(ssl_obj: ssl.SSLObject | None) -> str:
    """Extrahiert TLS-Version, Cipher, Common Name (CN) und SAN-Domains aus dem Handshake."""
    if ssl_obj is None:
        return ""

    parts: list[str] = []
    proto = ssl_obj.version() or ""
    cipher_info = ssl_obj.cipher()
    if proto:
        parts.append(f"Protokoll: {proto}")
    if cipher_info and len(cipher_info) >= 1:
        parts.append(f"Cipher: {cipher_info[0]}")

    der_bytes = b""
    try:
        der_bytes = ssl_obj.getpeercert(binary_form=True) or b""
    except Exception:
        der_bytes = b""

    if der_bytes:
        parsed_ok = False
        try:
            from cryptography import x509

            cert = x509.load_der_x509_certificate(der_bytes)
            cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attrs:
                parts.append(f"CN: {cn_attrs[0].value}")
            iss_attrs = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if iss_attrs:
                parts.append(f"Aussteller: {iss_attrs[0].value}")
            exp_dt = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            parts.append(f"Gültig bis: {exp_dt.strftime('%Y-%m-%d')}")
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                dns_names = san_ext.value.get_values_for_type(x509.DNSName)
                if dns_names:
                    preview_sans = ", ".join(dns_names[:8])
                    if len(dns_names) > 8:
                        preview_sans += f" (+{len(dns_names) - 8} weitere)"
                    parts.append(f"SANs: {preview_sans}")
            except Exception:
                pass
            parsed_ok = True
        except Exception:
            parsed_ok = False

        if not parsed_ok:
            # Leichtgewichtiger Fallback ohne Zusatzpakete: Domains aus DER-Zertifikat lesen
            domains = sorted(
                set(re.findall(rb"[a-zA-Z0-9*_-]+(?:\.[a-zA-Z0-9_-]+)+", der_bytes))
            )
            clean_domains = [
                d.decode("ascii", errors="ignore")
                for d in domains
                if not d.startswith(b"1.3.6.") and len(d) <= 80
            ][:6]
            if clean_domains:
                parts.append(f"Zertifikat-Domains: {', '.join(clean_domains)}")

    return " | ".join(parts)


def parse_proxy_url(proxy_url: str) -> dict | None:
    """Zerlegt eine Proxy-URL wie 'socks5://user:pass@127.0.0.1:9050' oder 'http://127.0.0.1:8080'."""
    raw = (proxy_url or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"http://{raw}"
    parsed = urllib.parse.urlparse(raw)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname
    if not host:
        return None
    default_port = 1080 if scheme.startswith("socks") else 8080
    port = parsed.port or default_port
    return {
        "scheme": scheme,
        "host": host,
        "port": int(port),
        "username": urllib.parse.unquote(parsed.username or ""),
        "password": urllib.parse.unquote(parsed.password or ""),
    }


async def _handshake_http_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    username: str = "",
    password: str = "",
):
    """Führt einen HTTP-CONNECT-Tunnel-Handshake über einen HTTP-Proxy aus."""
    host_header = f"[{target_host}]:{target_port}" if ":" in target_host else f"{target_host}:{target_port}"
    lines = [
        f"CONNECT {host_header} HTTP/1.1",
        f"Host: {host_header}",
        "Proxy-Connection: Keep-Alive",
    ]
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {token}")
    req_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    writer.write(req_bytes)
    await writer.drain()

    status_line = await reader.readline()
    if not status_line or b" 200 " not in status_line:
        raise ConnectionError(f"HTTP-Proxy CONNECT fehlgeschlagen: {status_line.decode('latin1', errors='ignore').strip()}")
    while True:
        hdr_line = await reader.readline()
        if not hdr_line or hdr_line in (b"\r\n", b"\n"):
            break


async def _handshake_socks5(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    username: str = "",
    password: str = "",
):
    """Führt einen vollständigen RFC-1928-SOCKS5-Handshake inklusive optionaler Auth aus."""
    use_auth = bool(username or password)
    if use_auth:
        writer.write(b"\x05\x02\x00\x02")
    else:
        writer.write(b"\x05\x01\x00")
    await writer.drain()

    greet = await reader.readexactly(2)
    if greet[0] != 0x05 or greet[1] == 0xFF:
        raise ConnectionError("SOCKS5-Proxy lehnt Authentifizierungsmethode ab.")

    if greet[1] == 0x02:
        u_bytes = username.encode("utf-8")[:255]
        p_bytes = password.encode("utf-8")[:255]
        auth_pkt = b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes
        writer.write(auth_pkt)
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        if auth_resp[1] != 0x00:
            raise ConnectionError("SOCKS5-Benutzername oder Passwort ungültig.")

    # Zieladresse kodieren (IPv4, IPv6 oder Domain)
    try:
        ip_obj = ipaddress.ip_address(target_host)
        if ip_obj.version == 4:
            addr_part = b"\x01" + ip_obj.packed
        else:
            addr_part = b"\x04" + ip_obj.packed
    except ValueError:
        h_bytes = target_host.encode("ascii", errors="ignore")[:255]
        addr_part = b"\x03" + bytes([len(h_bytes)]) + h_bytes

    req_pkt = b"\x05\x01\x00" + addr_part + struct.pack("!H", int(target_port))
    writer.write(req_pkt)
    await writer.drain()

    rep = await reader.readexactly(4)
    if rep[0] != 0x05 or rep[1] != 0x00:
        raise ConnectionError(f"SOCKS5-Verbindung abgelehnt (Code {rep[1]}).")

    atyp = rep[3]
    if atyp == 0x01:
        await reader.readexactly(6)
    elif atyp == 0x04:
        await reader.readexactly(18)
    elif atyp == 0x03:
        d_len = (await reader.readexactly(1))[0]
        await reader.readexactly(d_len + 2)


async def open_proxied_connection(
    target_host: str,
    target_port: int,
    timeout: float = 3.5,
    proxy_url: str = "",
    use_tls: bool = False,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Öffnet eine asynchrone TCP- oder TLS-Verbindung (direkt oder über HTTP/SOCKS5-Proxy)."""
    proxy_cfg = parse_proxy_url(proxy_url)
    ssl_ctx = create_unverified_ssl_context() if use_tls else None

    if not proxy_cfg:
        return await asyncio.wait_for(
            asyncio.open_connection(
                target_host,
                int(target_port),
                ssl=ssl_ctx,
                server_hostname=target_host if use_tls else None,
            ),
            timeout=timeout,
        )

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_cfg["host"], proxy_cfg["port"]),
        timeout=timeout,
    )
    try:
        if proxy_cfg["scheme"].startswith("socks"):
            await asyncio.wait_for(
                _handshake_socks5(
                    reader,
                    writer,
                    target_host,
                    int(target_port),
                    proxy_cfg["username"],
                    proxy_cfg["password"],
                ),
                timeout=timeout,
            )
        else:
            await asyncio.wait_for(
                _handshake_http_connect(
                    reader,
                    writer,
                    target_host,
                    int(target_port),
                    proxy_cfg["username"],
                    proxy_cfg["password"],
                ),
                timeout=timeout,
            )

        if use_tls and ssl_ctx is not None:
            await asyncio.wait_for(
                writer.start_tls(ssl_ctx, server_hostname=target_host),
                timeout=timeout,
            )

        return reader, writer
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise


def _extract_html_title(html_text: str) -> str:
    """Liest den <title>-Inhalt einer HTML-Antwort bereinigt aus."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = html.unescape(match.group(1))
    title = re.sub(r"\s+", " ", title).strip()
    return title[:120]


def _parse_http_response(raw_bytes: bytes) -> dict | None:
    """Zerlegt eine HTTP-Antwort in Statuscode, Header und Body. Liefert None, wenn kein HTTP."""
    if not raw_bytes.startswith(b"HTTP/"):
        return None

    sep_idx = raw_bytes.find(b"\r\n\r\n")
    sep_len = 4
    if sep_idx == -1:
        sep_idx = raw_bytes.find(b"\n\n")
        sep_len = 2

    if sep_idx != -1:
        head_bytes = raw_bytes[:sep_idx]
        body_bytes = raw_bytes[sep_idx + sep_len :]
    else:
        head_bytes = raw_bytes
        body_bytes = b""

    head_text = head_bytes.decode("latin1", errors="replace")
    lines = head_text.splitlines()
    if not lines:
        return None

    status_line = lines[0].strip()
    m_status = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$", status_line)
    if not m_status:
        return None

    code = int(m_status.group(1))
    reason = (m_status.group(2) or "").strip()

    headers_dict: dict[str, str] = {}
    for h_line in lines[1:]:
        if ":" in h_line:
            k, v = h_line.split(":", 1)
            headers_dict[k.strip().lower()] = v.strip()

    body_text = body_bytes.decode("utf-8", errors="replace")
    title = _extract_html_title(body_text)
    server_hdr = headers_dict.get("server", "")
    location_hdr = headers_dict.get("location", "")

    summary_parts = [f"{code} {reason}".strip()]
    if title:
        summary_parts.append(f"Titel: {title}")
    elif location_hdr:
        summary_parts.append(f"→ {location_hdr[:80]}")
    if server_hdr:
        summary_parts.append(f"Server: {server_hdr[:50]}")

    return {
        "http_code": code,
        "response_info": " | ".join(summary_parts),
        "headers_raw": head_text[:6000],
        "body_text": body_text[:6000],
    }


async def _single_probe(
    ip: str,
    port: int,
    use_tls: bool,
    timeout: float,
    proxy_url: str,
    suffix: str,
) -> dict:
    """Führt einen einzelnen Verbindungs- und Protokoll-Check auf ip:port aus."""
    reader = None
    writer = None
    try:
        reader, writer = await open_proxied_connection(
            target_host=ip,
            target_port=port,
            timeout=timeout,
            proxy_url=proxy_url,
            use_tls=use_tls,
        )

        tls_details = ""
        if use_tls:
            ssl_obj = writer.get_extra_info("ssl_object")
            tls_details = extract_tls_details(ssl_obj)

        path = suffix if suffix else "/"
        host_hdr = f"[{ip}]" if ":" in ip else ip
        if (use_tls and port != 443) or (not use_tls and port != 80):
            host_hdr = f"{host_hdr}:{port}"

        http_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShodanCheck/2.0\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")

        writer.write(http_req)
        await writer.drain()

        chunks: list[bytes] = []
        total_read = 0
        max_bytes = 24576
        while total_read < max_bytes:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=min(timeout, 2.5))
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total_read += len(chunk)
            # Wenn bereits ein Nicht-HTTP-Banner empfangen wurde, nicht unnötig lange warten
            if total_read == len(chunk) and not chunk.startswith(b"HTTP/"):
                break

        raw_resp = b"".join(chunks)
        scheme = "https" if use_tls else "http"
        default_port = 443 if use_tls else 80
        host_url = f"[{ip}]" if ":" in ip else ip
        port_part = "" if port == default_port else f":{port}"
        full_url = f"{scheme}://{host_url}{port_part}{suffix}"

        parsed_http = _parse_http_response(raw_resp)
        if parsed_http is not None:
            return {
                "reachable": True,
                "is_http": True,
                "url": full_url,
                "http_code": parsed_http["http_code"],
                "response_info": parsed_http["response_info"],
                "tls_info": tls_details,
                "headers_raw": parsed_http["headers_raw"],
                "banner_raw": parsed_http["body_text"] or parsed_http["headers_raw"],
                "raw_bytes": raw_resp,
            }

        # Port ist offen, liefert aber ein Nicht-HTTP-Banner (z. B. SSH, VNC, RTSP, FTP)
        banner_txt = raw_resp.decode("utf-8", errors="replace").strip()
        first_line = banner_txt.splitlines()[0][:110] if banner_txt else "Offener TCP-Port (kein HTTP-Banner)"
        return {
            "reachable": True,
            "is_http": False,
            "url": "",
            "http_code": 0,
            "response_info": f"Banner: {first_line}" if banner_txt else first_line,
            "tls_info": tls_details,
            "headers_raw": "",
            "banner_raw": banner_txt[:6000],
            "raw_bytes": raw_resp,
        }
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def probe_endpoint(
    ip: str,
    port: int,
    timeout: float = 3.5,
    proxy_url: str = "",
    url_suffix: str = "",
) -> dict:
    """
    Prüft einen einzelnen IP:Port-Endpunkt auf Erreichbarkeit, HTTP/HTTPS, TLS-Zertifikat
    und Banner. Erkennt automatisch HTTPS auf Nicht-Standard-Ports (z. B. 8080/8000).
    """
    clean_suffix = normalize_url_suffix(url_suffix)
    prefer_tls = int(port) in HTTPS_PREFERRED_PORTS

    try:
        res = await _single_probe(ip, int(port), prefer_tls, timeout, proxy_url, clean_suffix)

        # Falls HTTP auf einem Port wie 8080 oder 8000 einen HTTPS-Dienst trifft, automatisch auf HTTPS wechseln
        if not prefer_tls and res["reachable"]:
            resp_lower = (res.get("response_info") or "").lower()
            body_lower = (res.get("banner_raw") or "").lower()
            raw_b = res.get("raw_bytes") or b""
            looks_like_tls_mismatch = (
                (res.get("http_code") == 400 and ("https" in resp_lower or "https" in body_lower or "ssl" in body_lower))
                or raw_b.startswith(b"\x15\x03")
            )
            if looks_like_tls_mismatch:
                try:
                    https_res = await _single_probe(ip, int(port), True, timeout, proxy_url, clean_suffix)
                    if https_res["reachable"] and https_res["is_http"]:
                        res = https_res
                except Exception:
                    pass

        return {
            "status": "OK",
            "url": res["url"],
            "http_code": res["http_code"],
            "response_info": res["response_info"],
            "tls_info": res["tls_info"],
            "headers_raw": res["headers_raw"],
            "banner_raw": res["banner_raw"],
        }
    except Exception:
        return {
            "status": "OFFLINE",
            "url": "",
            "http_code": 0,
            "response_info": "Keine Verbindung / Timeout",
            "tls_info": "",
            "headers_raw": "",
            "banner_raw": "",
        }