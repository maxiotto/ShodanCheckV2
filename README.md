Da mir aktuell kein direktes Datei-Download-Tool zur Verfügung steht, findest du hier den vollständigen, sauberen Inhalt für deine `README.md` direkt zum Kopieren (über das Kopier-Symbol oben rechts im Codeblock) sowie den 1-Zeilen-Speicherbefehl für PowerShell.

### 1. Fertiger Inhalt der `README.md` (kopieren)

Klicke oben rechts im folgenden Codeblock auf das **Kopieren-Symbol**:

```markdown
# ??? ShodanCheck v2.0

**Multi-Engine Endpoint & Infrastructure Validator** — eine moderne Desktop-Anwendung (Python & PySide6) zum Abfragen mehrerer Cyberspace-Suchmaschinen, zum asynchronen Prüfen von IP-/CIDR-Listen sowie zur Live-Analyse von Web-Oberflächen, TLS-Zertifikaten und Dienst-Bannern.

---

## ? Hauptfunktionen

### ?? Multi-Engine-Suche & Ziel-Import
* **Universal- & Einzelsuche:** Unterstützt **Shodan**, **Censys**, **FOFA**, **ZoomEye**, **Criminal IP**, **Hunter.how**, **BinaryEdge** sowie einen **Offline-/Demo-Modus**.
* **Automatische Deduplizierung:** Führt Treffer aus mehreren Suchdiensten anhand von `IP:Port` zusammen und kombiniert die Quellenangaben.
* **Vorlagen & Port-Profile:** Enthält vordefinierte Dork-Templates, Port-Profile (Web, Remote-Access, Datenbanken, Kameras/ICS) und benutzerdefinierte Port-Bereiche (`80, 443, 8000-8010`).
* **Flexibler Ziel-Import:** Verarbeitet `.txt`/`.csv`-Dateien oder die Zwischenablage mit einzelnen IPs, `IP:Port`, kompletten URLs, **CIDR-Subnetzen** (`192.168.1.0/24`) und **IPv4-Bereichen** (`10.0.0.1-10.0.0.50`).

### ? Asynchroner Hochgeschwindigkeits-Scanner & Proxy-Tunneling
* **Hohe Parallelität:** Prüft hunderte Endpunkte gleichzeitig via `asyncio` und konfigurierbarem Semaphore-Limit (50 bis 1.000 gleichzeitige Verbindungen).
* **Intelligente Protokoll-Erkennung:** Erkennt HTTP/HTTPS (inklusive automatischem HTTPS-Fallback auf Sonderports wie `8080`/`8443`), liest Seitentitel aus und erfasst rohe TCP-Banner (SSH, VNC, RTSP, FTP usw.).
* **TLS- & Zertifikats-Inspektion:** Extrahiert Protokollversion, Cipher-Suite, Common Name (`CN`), Aussteller, Ablaufdatum und Subject Alternative Names (`SANs`).
* **HTTP- & SOCKS5-Proxy:** Vollständiger `HTTP CONNECT`- und RFC-1928-`SOCKS5`-Support (inklusive Authentifizierung) für Scanner, Such-APIs, GeoIP und Screenshots.

### ??? Arbeitsoberfläche, Detail-Inspektor & Live-Vorschau
* **3-Tab-Detail-Inspektor:**
  1. **Vorschau & Host:** On-Demand-Screenshots über Headless Microsoft Edge / Google Chrome inklusive Vollbild-Lightbox mit Zoom, sowie Ziel-URL, Server-Antwort, PTR, ASN und Standort.
  2. **Header & TLS:** Vollständige HTTP-Response-Header und Zertifikatsdetails.
  3. **Banner / HTML:** Durchsuchbarer Roh-Banner- und HTML-Quelltext-Viewer.
* **GeoIP, ASN & Reverse-DNS:** Unterstützt lokale **MaxMind-Datenbanken** (`GeoLite2-City.mmdb` & `GeoLite2-ASN.mmdb`) sowie einen key-freien Online-Fallback mit dauerhaftem lokalem Cache (`geoip_cache.json`).
* **Merkliste, Filter & Exporte:** Dauerhafte Favoriten-Verwaltung, Sitzungswiederherstellung, Suchhistorie, Echtzeit-Filter (inkl. Ausschlussbegriffen wie `-404`), Pagination und Export als **CSV**, **JSON**, **TXT (`IP:Port`)** oder **klickbarer HTML-Report**.

---

## ?? Projektstruktur

```text
SchodanCheckV2/
+-- main.py                     # Einstiegspunkt & High-DPI-/Theme-Initialisierung
+-- requirements.txt            # Python-Abhängigkeiten
+-- core/
¦   +-- constants.py            # Standard-Ports, Port-Profile, Dorks & Pfade
¦   +-- storage.py              # Konfiguration, Sitzung, Historie, Merkliste & GeoIP-Cache
+-- providers/
¦   +-- base.py                 # Basis-Interface & parallele Multi-Engine-Aggregation
¦   +-- engines.py              # API-Anbindungen (Shodan, Censys, FOFA, ZoomEye, ...)
+-- scanner/
¦   +-- net_utils.py            # Ziel-/Port-Parser, HTTP/SOCKS5-Tunnel, TLS & Probing
¦   +-- async_scanner.py        # Asynchroner QThread-Scan-Worker
¦   +-- enrichment.py           # MaxMind-.mmdb-, Online-GeoIP- & PTR-Anreicherung
¦   +-- screenshotter.py        # Headless-Browser-Screenshots & Cache-Verwaltung
+-- ui/
    +-- theme.py                # Zentrales Dark-Theme-Stylesheet
    +-- models.py               # Tabellen-, Filter- und Pagination-Models
    +-- inspector_panel.py      # Rechter 3-Tab-Inspektor & Vollbild-Lightbox
    +-- service_dialog.py       # Konfigurationsdialog für API-Keys, .mmdb & Browser
    +-- main_window.py          # Hauptfenster, Ribbon-Tabs, Filter & Exporte

```

---

## ?? Installation & Start

### Voraussetzungen

* **Python 3.10** oder neuer
* Optional für Live-Vorschauen: **Microsoft Edge** oder **Google Chrome**
* Optional für Offline-GeoIP: MaxMind `GeoLite2-City.mmdb` und/oder `GeoLite2-ASN.mmdb`

### Abhängigkeiten installieren & starten

```powershell
git clone [https://github.com/maxiotto/ShodanCheckV2.git](https://github.com/maxiotto/ShodanCheckV2.git)
cd ShodanCheckV2

pip install -r requirements.txt
python main.py

```

---

## ?? Konfiguration & Tastenkürzel

### Dienste & Datenbanken einrichten

1. Öffne in der Anwendung **?? Dienste ? ?? Dienste, API-Keys & GeoIP (.mmdb) konfigurieren...** (oder klicke auf `??` neben der Suchdienst-Auswahl).
2. Aktiviere die gewünschten Suchdienste, hinterlege deine API-Schlüssel und teste die Verbindung direkt über **?? Verbindung & Key testen**.
3. Hinterlege im zweiten Tab bei Bedarf lokale `.mmdb`-Dateien und passe Wartezeiten für Headless-Screenshots an.
4. Alle Einstellungen werden lokal in `shodancheck_config.json` gespeichert und sind über `.gitignore` vom Git-Upload ausgeschlossen.

### Nützliche Tastenkürzel

| Tastenkürzel | Aktion |
| --- | --- |
| `Strg + F` | Textfilter fokussieren |
| `Strg + I` | Detail-Inspektor ein-/ausblenden |
| `Leertaste` | Checkbox der markierten Zeile(n) umschalten |
| `F` | Markierte Zeile(n) zur Merkliste hinzufügen / entfernen |
| `Enter` / Doppelklick | Ausgewählte HTTP/HTTPS-Ziele im Browser öffnen |
| `Strg + C` | Link bzw. `IP:Port` in die Zwischenablage kopieren |
| `Entf` | Ausgewählte Zeile(n) aus der aktuellen Ansicht entfernen |
| `Alt + ?` / `Alt + ?` | Vorherige / nächste Tabellenseite |

---

## ?? Eigenständige Windows-EXE erstellen (PyInstaller)

```powershell
pip install pyinstaller

pyinstaller --noconfirm --onefile --windowed `
  --name "ShodanCheck" `
  --hidden-import "scanner.enrichment" `
  --collect-submodules "core" `
  --collect-submodules "providers" `
  --collect-submodules "scanner" `
  --collect-submodules "ui" `
  main.py

```

Die fertige ausführbare Datei liegt anschließend unter `dist\ShodanCheck.exe`.

---

## ?? Hinweis zur Nutzung

Dieses Werkzeug ist ausschließlich für autorisierte Sicherheitsanalysen, Bestandsaufnahmen eigener Netzwerke und administrative Infrastrukturprüfungen bestimmt. Bitte beachte die Nutzungsbedingungen der angebundenen Suchdienste sowie die geltenden gesetzlichen Bestimmungen.

```

---

### 2. Direkt aus der Zwischenablage speichern & auf GitHub hochladen

Nachdem du oben auf **Kopieren** geklickt hast, füge nichts direkt in PowerShell ein, sondern schreibe die Zwischenablage mit diesem kurzen Befehl sauber als UTF-8 in deine Datei:

```powershell
[IO.File]::WriteAllText("$PWD\README.md", (Get-Clipboard -Raw), [Text.UTF8Encoding]::new($false))

```

*Verifikation:* Mit `(Get-Content "$PWD\README.md").Count` erscheint `126` (alle Zeilen komplett vorhanden).

Anschließend lädst du die Datei auf GitHub hoch:

```powershell
git add README.md
git commit -m "Docs: Vollständige README.md"
git push -u origin main

```
