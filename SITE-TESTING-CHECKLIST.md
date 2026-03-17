# Checkliste: WireGuard-Site einrichten und Dienst freigeben

Schritt-für-Schritt-Anleitung zum Testen des kompletten Workflows – vom Anlegen
einer Site auf dem VPS bis zur erreichbaren HTTPS-Anwendung aus einem entfernten
Netzwerk.

---

## Voraussetzungen

### VPS (Hub)
- [ ] `nrp` installiert und lauffähig (`nrp --help`)
- [ ] NGINX und Certbot eingerichtet (`sudo nrp setup`)
- [ ] WireGuard installiert (`wg --version`)
      → Falls nicht: `sudo nrp setup --with-wireguard`
- [ ] UDP-Port **51820** in der Firewall des VPS **eingehend** erlaubt
      `ufw allow 51820/udp` oder entsprechende Regel im Hoster-Panel
- [ ] Öffentliche IP des VPS bekannt (z.B. `curl -s ifconfig.me`)
- [ ] Eine Domain (FQDN) die auf die VPS-IP zeigt (A-Record gesetzt)

### Site-Host (entferntes Netzwerk)
- [ ] Linux-System mit Root-Zugriff (Debian, Ubuntu oder Alpine)
- [ ] Ausgehender UDP-Traffic auf Port 51820 erlaubt (fast immer der Fall)
- [ ] Die freizugebende Anwendung läuft lokal und ist erreichbar
      (z.B. `curl http://localhost:3000`)

---

## Phase 1 – Site anlegen (auf dem VPS)

- [ ] **Site erstellen**
  ```bash
  nrp site create home --targets 4
  ```
  → Notiere: **Subnetz** und **Connector-IP** aus der Ausgabe

- [ ] **Site in der Liste sehen**
  ```bash
  nrp site list
  # Erwartete Ausgabe: "home" mit Status "pending"
  ```

- [ ] **Site-Details prüfen**
  ```bash
  nrp site show home
  # Public Key: "(ausstehend)" – das ist korrekt an dieser Stelle
  ```

---

## Phase 2 – Install-Script generieren (auf dem VPS)

- [ ] **Script erzeugen**
  ```bash
  nrp site install-script home > /tmp/install-home.sh
  ```

- [ ] **Script prüfen** – folgende Felder müssen korrekt befüllt sein:
  ```bash
  cat /tmp/install-home.sh
  ```
  - [ ] `Address = <connector_ip>/<prefix>` – IP aus Phase 1
  - [ ] `PublicKey = <hub_pubkey>` – darf **nicht** `<UNKNOWN>` sein
        → Falls `<UNKNOWN>`: `wg show wg0 public-key` prüfen; ggf. wg0 starten:
        `systemctl start wg-quick@wg0`
  - [ ] `Endpoint = <VPS_PUBLIC_IP>:51820` – **muss manuell ersetzt werden**
        ```bash
        VPS_IP=$(curl -s ifconfig.me)
        sed -i "s/<VPS_PUBLIC_IP>/$VPS_IP/" /tmp/install-home.sh
        ```

- [ ] **Script auf den Site-Host übertragen**
  ```bash
  scp /tmp/install-home.sh user@site-host:/tmp/
  ```

---

## Phase 3 – Tunnel auf dem Site-Host einrichten

> Diese Schritte werden auf dem **Site-Host** (entferntes Netzwerk) ausgeführt.

- [ ] **Script ausführen**
  ```bash
  sudo bash /tmp/install-home.sh
  ```

- [ ] **Ausgabe lesen** – am Ende steht der Public Key:
  ```
  Site public key: <KEY>
  Run on the VPS hub:
  nrp site set-pubkey home <KEY>
  ```
  → **Public Key notieren** (wird in Phase 4 benötigt)

- [ ] **Tunnel-Interface prüfen** (auf dem Site-Host)
  ```bash
  wg show
  # Interface wg-site-home muss erscheinen
  # "latest handshake" erscheint sobald der Hub den Key kennt
  ```

- [ ] **Connector-IP pingbar?** (auf dem Site-Host – optional, noch kein Handshake erwartet)
  ```bash
  ping -c 3 10.240.0.1   # Hub-IP (network+1 im Site-Subnetz)
  ```

---

## Phase 4 – Public Key registrieren (auf dem VPS)

- [ ] **Public Key eintragen**
  ```bash
  nrp site set-pubkey home <KEY_AUS_PHASE_3>
  ```

- [ ] **WireGuard-Handshake prüfen**
  ```bash
  wg show wg0
  # Der Peer (home) sollte "latest handshake" zeigen
  # Falls nicht nach 30s: Firewall UDP 51820 prüfen
  ```

- [ ] **Verbindung testen (Ping)**
  ```bash
  ping -c 3 10.240.0.2   # Connector-IP der Site
  # oder
  nrp site show home --live
  # Status sollte "online" sein
  ```

---

## Phase 5 – Anwendung freigeben (auf dem VPS)

> Die Anwendung läuft auf dem Site-Host und ist unter einer Tunnel-IP erreichbar.

- [ ] **Tunnel-IP der Anwendung ermitteln**
  Die Anwendung ist über die Connector-IP + Port erreichbar, sobald der Tunnel steht.
  Beispiel: Anwendung läuft auf `localhost:3000` am Site-Host → erreichbar als `10.240.0.2:3000`

- [ ] **Verbindung vom VPS zur Anwendung testen**
  ```bash
  curl http://10.240.0.2:3000
  # Muss eine Antwort liefern – sonst Firewall am Site-Host prüfen
  ```

- [ ] **Proxy-Host anlegen**
  ```bash
  nrp add app.example.com \
    --site home \
    --internal-ip 10.240.0.2 \
    --internal-port 3000 \
    --email admin@example.com
  ```
  → Certbot holt automatisch ein Let's Encrypt Zertifikat

- [ ] **NGINX-Konfiguration prüfen**
  ```bash
  nginx -t
  nrp list
  ```

---

## Phase 6 – Ergebnis verifizieren

- [ ] **HTTPS-Aufruf im Browser**: `https://app.example.com`
- [ ] **Gültiges Zertifikat** (kein Browser-Warning)
- [ ] **Anwendung antwortet** korrekt
- [ ] **Status-Übersicht**
  ```bash
  nrp site list        # Status "online"
  nrp site show home   # Alle Felder vollständig
  nrp status           # NGINX grün, Zertifikat gültig
  ```

---

## Häufige Probleme

| Problem | Ursache | Lösung |
|---|---|---|
| `PublicKey = <UNKNOWN>` im Script | `wg0` läuft nicht | `systemctl start wg-quick@wg0` |
| Kein WireGuard-Handshake | Firewall blockiert UDP 51820 | Eingehende Regel am VPS prüfen |
| `ping 10.240.0.2` schlägt fehl | IP-Forwarding deaktiviert | `sysctl net.ipv4.ip_forward=1` |
| `curl http://10.240.0.2:3000` schlägt fehl | Anwendung bindet nur `localhost` | Am Site-Host auf `0.0.0.0` binden oder Routing prüfen |
| Certbot schlägt fehl | Domain zeigt nicht auf VPS | A-Record prüfen (`dig app.example.com`) |
| Site-Status bleibt `pending` | `set-pubkey` noch nicht ausgeführt | Phase 4 wiederholen |
