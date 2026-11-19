"""Implementierung der 8 Suchdienst-Adapter für ShodanCheck."""

import base64
import urllib.parse
from datetime import datetime, timedelta

from providers.base import BaseSearchEngine, normalize_engine_hit


class ShodanEngine(BaseSearchEngine):
    engine_id = "shodan"
    name = "Shodan"
    description = "Klassische Internet-Suchmaschine für offene Ports, Banner und Dienste."
    requires_key = True
    requires_secret = False
    key_label = "Shodan API-Key"

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        if not api_key.strip():
            return False, "Bitte einen Shodan API-Key eingeben."
        url = f"https://api.shodan.io/api-info?key={urllib.parse.quote(api_key.strip())}"
        data = self._http_json(url, proxy_url=proxy_url)
        plan = data.get("plan", "unbekannt")
        q_credits = data.get("query_credits", 0)
        s_credits = data.get("scan_credits", 0)
        return True, f"Verbunden (Plan: {plan} | Query-Credits: {q_credits} | Scan-Credits: {s_credits})"

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        hits: list[dict] = []
        pages = max(1, (max_results + 99) // 100)
        for page in range(1, pages + 1):
            url = (
                f"https://api.shodan.io/shodan/host/search"
                f"?key={urllib.parse.quote(api_key.strip())}"
                f"&query={urllib.parse.quote(query.strip())}"
                f"&page={page}"
            )
            data = self._http_json(url, proxy_url=proxy_url)
            matches = data.get("matches") or []
            if not matches:
                break

            for m in matches:
                loc = m.get("location") or {}
                hostnames = m.get("hostnames") or []
                ssl_info = m.get("ssl") or {}
                cert_cn = ((ssl_info.get("cert") or {}).get("subject") or {}).get("CN", "")
                product = " ".join(
                    p for p in (str(m.get("product") or ""), str(m.get("version") or "")) if p
                ).strip()
                org = str(m.get("org") or m.get("isp") or "").strip()
                info_parts = [p for p in (product, org) if p]

                hits.append(
                    normalize_engine_hit(
                        ip=m.get("ip_str", ""),
                        port=m.get("port", 0),
                        source=self.name,
                        info=" | ".join(info_parts),
                        country_code=loc.get("country_code", ""),
                        country_name=loc.get("country_name", ""),
                        city=loc.get("city", ""),
                        asn=str(m.get("asn") or ""),
                        asn_org=org,
                        ptr=hostnames[0] if hostnames else "",
                        banner_raw=str(m.get("data") or "")[:4000],
                        tls_info=f"CN={cert_cn}" if cert_cn else "",
                    )
                )
                if len(hits) >= max_results:
                    return hits
        return hits


class CensysEngine(BaseSearchEngine):
    engine_id = "censys"
    name = "Censys"
    description = "Host- und Zertifikats-Suchmaschine (benötigt API ID + API Secret)."
    requires_key = True
    requires_secret = True
    key_label = "Censys API ID"
    secret_label = "Censys API Secret"

    def _auth_header(self, api_key: str, api_secret: str) -> dict:
        token = base64.b64encode(f"{api_key.strip()}:{api_secret.strip()}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        if not api_key.strip() or not api_secret.strip():
            return False, "Bitte Censys API ID und API Secret eingeben."
        data = self._http_json(
            "https://search.censys.io/api/v1/account",
            headers=self._auth_header(api_key, api_secret),
            proxy_url=proxy_url,
        )
        email = data.get("email", "Konto aktiv")
        quota = (data.get("quota") or {}).get("allowance", "?")
        return True, f"Verbunden ({email} | Kontingent: {quota})"

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        payload = {"q": query.strip(), "per_page": min(100, max(1, max_results))}
        data = self._http_json(
            "https://search.censys.io/api/v2/hosts/search",
            method="POST",
            headers=self._auth_header(api_key, api_secret),
            json_body=payload,
            proxy_url=proxy_url,
        )
        raw_hits = ((data.get("result") or {}).get("hits")) or []
        hits: list[dict] = []

        for h in raw_hits:
            ip = h.get("ip", "")
            loc = h.get("location") or {}
            as_info = h.get("autonomous_system") or {}
            rdns = ((h.get("dns") or {}).get("reverse_dns") or {}).get("names") or []
            services = h.get("services") or [{"port": 0, "service_name": ""}]

            for srv in services:
                svc_name = srv.get("extended_service_name") or srv.get("service_name") or ""
                as_name = as_info.get("name", "")
                hits.append(
                    normalize_engine_hit(
                        ip=ip,
                        port=srv.get("port", 0),
                        source=self.name,
                        info=" | ".join(p for p in (svc_name, as_name) if p),
                        country_code=loc.get("country_code", ""),
                        country_name=loc.get("country", ""),
                        city=loc.get("city", ""),
                        asn=str(as_info.get("asn") or ""),
                        asn_org=as_name,
                        ptr=rdns[0] if rdns else "",
                    )
                )
                if len(hits) >= max_results:
                    return hits
        return hits


class FofaEngine(BaseSearchEngine):
    engine_id = "fofa"
    name = "FOFA"
    description = "Cyberspace-Asset-Suchmaschine (benötigt API-Key + Account-E-Mail)."
    requires_key = True
    requires_secret = True
    key_label = "FOFA API-Key"
    secret_label = "FOFA Account-E-Mail"

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        if not api_key.strip() or not api_secret.strip():
            return False, "Bitte FOFA API-Key und Account-E-Mail eingeben."
        url = (
            f"https://fofa.info/api/v1/info/my"
            f"?email={urllib.parse.quote(api_secret.strip())}"
            f"&key={urllib.parse.quote(api_key.strip())}"
        )
        data = self._http_json(url, proxy_url=proxy_url)
        if data.get("error"):
            return False, f"FOFA-Fehler: {data.get('errmsg', 'Unbekannter Fehler')}"
        return True, f"Verbunden (Nutzer: {data.get('username', '?')} | F-Coins: {data.get('fcoin', 0)})"

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        q_b64 = base64.b64encode(query.strip().encode("utf-8")).decode("ascii")
        fields = "ip,port,title,server,country,country_name,city,as_number,as_organization,domain,banner"
        url = (
            f"https://fofa.info/api/v1/search/all"
            f"?email={urllib.parse.quote(api_secret.strip())}"
            f"&key={urllib.parse.quote(api_key.strip())}"
            f"&qbase64={urllib.parse.quote(q_b64)}"
            f"&size={min(100, max(1, max_results))}"
            f"&fields={fields}"
        )
        data = self._http_json(url, proxy_url=proxy_url)
        if data.get("error"):
            raise RuntimeError(data.get("errmsg", "FOFA-Abfrage fehlgeschlagen"))

        rows = data.get("results") or []
        hits: list[dict] = []
        for row in rows:
            if not isinstance(row, list) or len(row) < 2:
                continue
            padded = row + [""] * (11 - len(row))
            ip, port, title, server, cc, cname, city, asn, as_org, domain, banner = padded[:11]
            info = " | ".join(p for p in (str(title).strip(), str(server).strip()) if p)
            hits.append(
                normalize_engine_hit(
                    ip=str(ip),
                    port=int(port or 0),
                    source=self.name,
                    info=info,
                    country_code=str(cc),
                    country_name=str(cname),
                    city=str(city),
                    asn=str(asn),
                    asn_org=str(as_org),
                    ptr=str(domain),
                    banner_raw=str(banner)[:4000],
                )
            )
        return hits


class ZoomEyeEngine(BaseSearchEngine):
    engine_id = "zoomeye"
    name = "ZoomEye"
    description = "Globale Host- und Web-Komponenten-Suche."
    requires_key = True
    requires_secret = False
    key_label = "ZoomEye API-Key"

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        if not api_key.strip():
            return False, "Bitte einen ZoomEye API-Key eingeben."
        data = self._http_json(
            "https://api.zoomeye.org/resources-info",
            headers={"API-KEY": api_key.strip()},
            proxy_url=proxy_url,
        )
        plan = data.get("plan", "aktiv")
        rem = (data.get("resources") or {}).get("search", "?")
        return True, f"Verbunden (Plan: {plan} | Verbleibende Suchen: {rem})"

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        url = f"https://api.zoomeye.org/host/search?query={urllib.parse.quote(query.strip())}&page=1"
        data = self._http_json(url, headers={"API-KEY": api_key.strip()}, proxy_url=proxy_url)
        hits: list[dict] = []
        for m in data.get("matches") or []:
            pinfo = m.get("portinfo") or {}
            geo = m.get("geoinfo") or {}
            country = geo.get("country") or {}
            city = geo.get("city") or {}
            c_names = country.get("names") or {}
            city_names = city.get("names") or {}
            title = pinfo.get("title")
            if isinstance(title, list):
                title = title[0] if title else ""
            info = " | ".join(p for p in (str(pinfo.get("service") or ""), str(title or "")) if p)
            hits.append(
                normalize_engine_hit(
                    ip=m.get("ip", ""),
                    port=pinfo.get("port", 0),
                    source=self.name,
                    info=info,
                    country_code=country.get("code", ""),
                    country_name=c_names.get("en", ""),
                    city=city_names.get("en", ""),
                    asn=str(geo.get("asn") or ""),
                    asn_org=str(geo.get("organization") or ""),
                    ptr=str(m.get("rdns") or ""),
                    banner_raw=str(pinfo.get("banner") or "")[:4000],
                )
            )
            if len(hits) >= max_results:
                break
        return hits


class CriminalIPEngine(BaseSearchEngine):
    engine_id = "criminalip"
    name = "Criminal IP"
    description = "CTI- und Asset-Suchmaschine mit Banner- und Schwachstellenfiltern."
    requires_key = True
    requires_secret = False
    key_label = "Criminal IP API-Key"

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        if not api_key.strip():
            return False, "Bitte einen Criminal IP API-Key eingeben."
        data = self._http_json(
            "https://api.criminalip.io/v1/user/me",
            headers={"x-api-key": api_key.strip()},
            proxy_url=proxy_url,
        )
        email = (data.get("data") or {}).get("email", "Konto verifiziert")
        return True, f"Verbunden ({email})"

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        url = f"https://api.criminalip.io/v1/banner/search?query={urllib.parse.quote(query.strip())}&offset=0"
        data = self._http_json(url, headers={"x-api-key": api_key.strip()}, proxy_url=proxy_url)
        rows = ((data.get("data") or {}).get("result")) or []
        hits: list[dict] = []
        for r in rows[:max_results]:
            app = " ".join(p for p in (str(r.get("app_name") or ""), str(r.get("app_version") or "")) if p).strip()
            hits.append(
                normalize_engine_hit(
                    ip=r.get("ip_address", ""),
                    port=r.get("open_port_no", 0),
                    source=self.name,
                    info=" | ".join(p for p in (app, str(r.get("as_name") or "")) if p),
                    country_code=str(r.get("country") or ""),
                    city=str(r.get("city") or ""),
                    asn=str(r.get("as_no") or ""),
                    asn_org=str(r.get("as_name") or ""),
                    ptr=str(r.get("hostname") or ""),
                    banner_raw=str(r.get("banner") or "")[:4000],
                )
            )
        return hits


class HunterHowEngine(BaseSearchEngine):
    engine_id = "hunterhow"
    name = "Hunter.how"
    description = "Internet-Asset-Suchmaschine für IP-, Port- und Header-Abfragen."
    requires_key = True
    requires_secret = False
    key_label = "Hunter.how API-Key"

    def _build_search_url(self, api_key: str, query: str, page_size: int) -> str:
        q_b64 = base64.urlsafe_b64encode(query.strip().encode("utf-8")).decode("ascii")
        end_dt = datetime.utcnow().strftime("%Y-%m-%d")
        start_dt = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")
        return (
            f"https://api.hunter.how/search"
            f"?api-key={urllib.parse.quote(api_key.strip())}"
            f"&query={urllib.parse.quote(q_b64)}"
            f"&page=1&page_size={min(100, max(1, page_size))}"
            f"&start_time={start_dt}&end_time={end_dt}"
        )

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        if not api_key.strip():
            return False, "Bitte einen Hunter.how API-Key eingeben."
        url = self._build_search_url(api_key, 'protocol=="http"', 1)
        data = self._http_json(url, proxy_url=proxy_url)
        if int(data.get("code", 200)) != 200:
            return False, f"Hunter.how-Antwort: {data.get('message', 'Fehler')}"
        return True, "Verbunden (Hunter.how API-Key gültig)"

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        url = self._build_search_url(api_key, query, max_results)
        data = self._http_json(url, proxy_url=proxy_url)
        rows = ((data.get("data") or {}).get("list")) or []
        hits: list[dict] = []
        for r in rows[:max_results]:
            info = " | ".join(p for p in (str(r.get("web_title") or ""), str(r.get("as_org") or "")) if p)
            hits.append(
                normalize_engine_hit(
                    ip=str(r.get("ip") or ""),
                    port=int(r.get("port") or 0),
                    source=self.name,
                    info=info,
                    country_code=str(r.get("country") or ""),
                    city=str(r.get("city") or ""),
                    asn=str(r.get("asn") or ""),
                    asn_org=str(r.get("as_org") or ""),
                    ptr=str(r.get("domain") or ""),
                    banner_raw=str(r.get("banner") or "")[:4000],
                )
            )
        return hits


class BinaryEdgeEngine(BaseSearchEngine):
    engine_id = "binaryedge"
    name = "BinaryEdge"
    description = "Verteilte Internet-Scanning-Plattform für Dienst-Banner."
    requires_key = True
    requires_secret = False
    key_label = "BinaryEdge API-Key"

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        if not api_key.strip():
            return False, "Bitte einen BinaryEdge API-Key eingeben."
        data = self._http_json(
            "https://api.binaryedge.io/v2/user/subscription",
            headers={"X-Key": api_key.strip()},
            proxy_url=proxy_url,
        )
        left = data.get("requests_left", "?")
        return True, f"Verbunden (Verbleibende Requests: {left})"

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        url = f"https://api.binaryedge.io/v2/query/search?query={urllib.parse.quote(query.strip())}&page=1"
        data = self._http_json(url, headers={"X-Key": api_key.strip()}, proxy_url=proxy_url)
        events = data.get("events") or []
        hits: list[dict] = []
        for ev in events[:max_results]:
            target = ev.get("target") or {}
            origin = ev.get("origin") or {}
            svc = ((ev.get("result") or {}).get("data") or {}).get("service") or {}
            hits.append(
                normalize_engine_hit(
                    ip=str(target.get("ip") or ""),
                    port=int(target.get("port") or 0),
                    source=self.name,
                    info=str(svc.get("name") or ""),
                    country_code=str(origin.get("country") or ""),
                    asn=str(origin.get("asn") or ""),
                    banner_raw=str(svc.get("banner") or "")[:4000],
                )
            )
        return hits


class DemoEngine(BaseSearchEngine):
    engine_id = "demo"
    name = "Demo / Offline-Test"
    description = "Lokaler Testmodus ohne API-Key zum Prüfen von Scanner, GeoIP und Vorschau."
    requires_key = False
    requires_secret = False
    key_label = "Kein Key erforderlich"

    def test_connection(self, api_key: str = "", api_secret: str = "", proxy_url: str = "") -> tuple[bool, str]:
        return True, "Demo-Modus bereit (kein API-Key erforderlich)."

    def search(
        self,
        query: str,
        api_key: str = "",
        api_secret: str = "",
        max_results: int = 100,
        proxy_url: str = "",
    ) -> list[dict]:
        samples = [
            ("1.1.1.1", 80, "Cloudflare HTTP Redirect", "US", "United States", "Los Angeles", "AS13335", "Cloudflare, Inc.", "one.one.one.one"),
            ("1.1.1.1", 443, "Cloudflare HTTPS", "US", "United States", "Los Angeles", "AS13335", "Cloudflare, Inc.", "one.one.one.one"),
            ("8.8.8.8", 443, "Google Public DNS HTTPS", "US", "United States", "Mountain View", "AS15169", "Google LLC", "dns.google"),
            ("9.9.9.9", 443, "Quad9 DNS HTTPS", "CH", "Switzerland", "Zurich", "AS19281", "Quad9", "dns9.quad9.net"),
            ("93.184.216.34", 80, "Example Domain HTTP", "US", "United States", "Norwell", "AS15133", "Edgecast Inc.", "example.com"),
        ]
        q_hint = (query or "Demo").strip()[:40]
        hits = []
        for ip, port, label, cc, cname, city, asn, org, ptr in samples[:max_results]:
            hits.append(
                normalize_engine_hit(
                    ip=ip,
                    port=port,
                    source=self.name,
                    info=f"{label} (Query: {q_hint})",
                    country_code=cc,
                    country_name=cname,
                    city=city,
                    asn=asn,
                    asn_org=org,
                    ptr=ptr,
                    banner_raw=f"Demo-Ziel für Abfrage '{q_hint}' -> {ip}:{port}",
                )
            )
        return hits


def get_all_engines() -> dict[str, BaseSearchEngine]:
    """Erstellt und liefert alle registrierten Suchdienst-Instanzen."""
    instances = [
        ShodanEngine(),
        CensysEngine(),
        FofaEngine(),
        ZoomEyeEngine(),
        CriminalIPEngine(),
        HunterHowEngine(),
        BinaryEdgeEngine(),
        DemoEngine(),
    ]
    return {eng.engine_id: eng for eng in instances}