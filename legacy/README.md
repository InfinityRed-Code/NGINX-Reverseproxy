# Legacy

Frühere Generationen von NRP, nur als Referenz. Sie werden nicht mehr weiterentwickelt.

| Verzeichnis | Inhalt |
|---|---|
| [`v1/`](v1) | Ursprüngliche Bash-Skripte (`management.sh`, `setup.sh`, `setup_for_remote_execution.sh`) |
| [`v2/`](v2) | Python-CLI für Debian-Hosts (`nrp add/remove/list`, certbot, wg-quick, Fail2Ban, Coraza-Build auf dem Host), zuletzt Version 3.2.0 |

Die aktuelle Fassung ist der Container mit REST-API im Repository-Root. Eine bestehende v2-Installation
lässt sich mit `nrp --offline import v2` übernehmen, siehe [README](../README.md#migration-von-v2).
Die Zuordnung der alten Befehle steht in [`rewrite.md`, Abschnitt 10.3](../rewrite.md#103-übersetzungstabelle).
