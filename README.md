# LinHawk

Timeline forense veloce e threat hunting con regole **Sigma** per i log **Linux** e dei
**web server**, ispirato a
[Hayabusa](https://github.com/Yamato-Security/hayabusa) di Yamato Security, che fa lo stesso per i
log EVTX di Windows.

LinHawk legge i log grezzi di un host (o di una cartella di evidenze raccolte), li normalizza in uno
schema comune, li confronta con regole Sigma (incluse quelle di correlazione v2) e produce una
timeline CSV/JSON con **solo le detection**, ordinata e classificata per livello di gravità e tattica
MITRE ATT&CK. Il formato è pronto per Timeline Explorer, LibreOffice, Elastic e Timesketch.

## Sorgenti supportate

| Sorgente | File tipici | Note |
|---|---|---|
| syslog / auth | `/var/log/auth.log`, `secure`, `syslog`, `messages`, `cron` | timestamp RFC3164 e RFC3339 / ISO (rsyslog ad alta precisione) |
| auditd | `/var/log/audit/audit.log` | formato raw ed enriched; record raggruppati per serial; argomenti hex decodificati |
| journald | export `journalctl -o json`, oppure file `*.journal` binari se è presente `journalctl` | |
| web server: access log | `access.log`, `*_access.log`, `/var/log/nginx/*`, `/var/log/httpd/*` | formati Apache/nginx `common`, `combined`, `vhost_combined` e JSON (`log_format ... escape=json`) |
| web server: error log | `error.log` di Apache 2.2/2.4 e di nginx | incluse le righe ModSecurity e PHP-FPM |
| log applicativi | `dracut.log`, `yum.log`, `dpkg.log`, `dnf.rpm.log`, `apt/history.log` (blocchi con Commandline e pacchetti), `apt/term.log`, `alternatives.log`, `cups/error_log`, `tuned/tuned.log`, `firewalld`, `cloud-init.log`, MariaDB/MySQL, Tomcat, BIND, … | parser generico: riconosce il formato di data dominante (ISO, `2015/10/13`, `Tue Oct 13 10:58:37 CEST 2015`, `13/Oct/2015:…`, `13-Oct-2015`, `Oct 13 10:58:37` senza host, `151013 10:58:37`, epoch), anche preceduto da una o due parole (`update-alternatives 2026-…`, `E [09/Nov/2026…]`, `Start-Date: …`); le righe senza data vengono unite all'evento precedente (stack trace) |
| accessi binari | `wtmp`, `btmp`, `utmp`, `lastlog` | login/logout/boot, login falliti, ultimo accesso per UID: restano anche se `secure`/`auth.log` sono stati cancellati |
| compressi | `.gz`, `.bz2`, `.xz` (`.zst` con `pip install zstandard`) | riconosciuti dai magic byte, non dall'estensione |

**Rotazione dei file.** Il nome del file non serve per riconoscere il formato:
`dracut.log-20151013`, `messages-20151013`, `secure.3`, `maillog-20151013` (compresso senza
estensione) vengono letti per contenuto. La data `dateext` nel nome (`-20151013`) serve invece a
ricavare l'**anno** dei log syslog che non lo riportano, in modo più affidabile della data di
modifica, che spesso cambia quando si copiano le evidenze.

**File saltati.** Alla fine viene riportato per quale motivo un file non ha prodotto eventi:
vuoto, binario di tipo noto (journal di systemd, `sa` di sysstat…), dmesg senza data reale,
orari senza data (anaconda), testo senza timestamp. Con `--skipped-report skipped.csv` si ottiene
l'elenco completo con la prima riga di ogni file, utile per aggiungere nuovi formati.

**Hostname automatico.** Se l'input è la `var/log` di un'immagine montata (es. `E:\immagine\var\log` o `/mnt/immagine/var/log`),
l'hostname per gli eventi che non lo riportano (auditd, wtmp, log applicativi) viene letto da
`etc/hostname` o `etc/sysconfig/network` dell'immagine; `-H` ha la precedenza.

Il formato di ogni file viene riconosciuto in automatico. Si può passare l'intera cartella
`/var/log` copiata dall'host.

### Normalizzazione (l'equivalente dei "details" di Hayabusa)

- **sshd, sudo, su, useradd/usermod/userdel, passwd, cron/crontab, systemd-logind, kernel/UFW**
  vengono estratti in campi strutturati: `EventType`, `User`, `TargetUser`, `SrcIP`, `SrcPort`,
  `AuthMethod`, `Command`, `Group`, `TargetUid`, ecc.
- **auditd → `process_creation`**: per ogni `execve` viene generato un evento sintetico con
  `Image`, `CommandLine`, `ParentImage` (ricavato dalla tabella pid→exe), `User`, `ProcessId`,
  `ParentProcessId` e `CurrentDirectory`. In questo modo funzionano le ~150 regole SigmaHQ
  `linux/process_creation`.
- **auditd → `file_event`**: i record `PATH nametype=CREATE` diventano eventi con `TargetFilename`.
- **access log → `category: webserver`**: i campi sono in stile W3C, come li usano le regole
  SigmaHQ (`c-ip`, `cs-method`, `cs-uri-stem`, `cs-uri-query`, `sc-status`, `sc-bytes`,
  `cs-referer`, `cs-user-agent`, `cs-host`), più alias leggibili (`SrcIP`, `Method`, `Status`,
  `UserAgent`, `VHost`) e `UriDecoded`, cioè l'URI decodificato due volte per far emergere le
  evasioni del tipo `%252e%252e`. `cs-uri-query` contiene l'URI completo (path + query string),
  perché le regole SigmaHQ generiche cercano lì anche il path traversal. Il prodotto
  (`apache`/`nginx`) si ricava dal percorso del file.
- **error log → `service: apache` / `service: nginx`**, più il servizio LinHawk `weberror`
  che li copre entrambi; le righe ModSecurity ricevono anche `service: modsecurity`.
- Ogni record auditd resta anche un evento a sé (`service: auditd`), arricchito con il contesto
  del suo gruppo (exe, comm, key, uid...), come si aspettano le regole SigmaHQ auditd.

## Installazione

### Eseguibile standalone (Windows, Linux, macOS), come Hayabusa

Dalla pagina **Releases** si scarica lo zip per la propria piattaforma:

| Zip | Piattaforma |
|---|---|
| `linhawk-<versione>-win-x64.zip` | Windows 10/11 x64 |
| `linhawk-<versione>-win-arm64.zip` | Windows su ARM |
| `linhawk-<versione>-lin-x64.zip` / `lin-aarch64.zip` | Linux (glibc 2.35+) |
| `linhawk-<versione>-mac-arm64.zip` | macOS Apple Silicon |

Ogni zip contiene `linhawk.exe` (oppure `linhawk`), che **non richiede Python**, e la cartella
`rules/sigma` con le regole SigmaHQ Linux e web. Le regole LinHawk sono già incorporate
nell'eseguibile. Uso su Windows, con i log copiati da un server Linux:

```powershell
.\linhawk.exe csv-timeline C:\Evidence\web01\var\log -o web01.csv -t Europe/Rome -H web01
.\linhawk.exe update-rules     # aggiorna le regole SigmaHQ (senza git: scarica lo zip via HTTPS)
```

Gli zip vengono prodotti dalla pipeline `.github/workflows/release.yml` (GitHub Actions con
PyInstaller su runner Windows, Linux e macOS nativi). Per pubblicarli basta creare un tag:
`git tag v0.2.0 && git push --tags`. Per compilare in locale:

```powershell
# Windows (PowerShell, Python 3.10+ installato da python.org)
powershell -ExecutionPolicy Bypass -File .\build-windows.ps1   # -> dist\linhawk.exe + zip
```
```bash
./build.sh                                                    # Linux / macOS -> dist/linhawk + zip
```

### Da sorgente (Python 3.10+)

```bash
pip install .                 # oppure: python -m linhawk.cli ...
linhawk update-rules          # regole SigmaHQ Linux + web (con git se disponibile, altrimenti zip)
```

Cartella delle regole scaricate: `~/.local/share/linhawk/sigma` su Linux e macOS,
`%LOCALAPPDATA%\linhawk\sigma` su Windows; si può cambiare con `LINHAWK_HOME`. Se esiste una
cartella `rules/` accanto all'eseguibile, viene caricata anch'essa (uso portabile, come in Hayabusa).

## Comandi (sul modello di Hayabusa)

```bash
# Timeline CSV di tutte le detection (regole incluse + SigmaHQ, se scaricate)
linhawk csv-timeline /evidence/web01/var/log -o web01.csv -t Europe/Rome -H web01

# Solo medium e superiori, in JSONL per Elastic / Timesketch / jq
linhawk json-timeline /evidence/web01 -L -m medium -o web01.jsonl

# Riepilogo dei logon riusciti e falliti per utente e origine (sshd + wtmp/btmp)
linhawk logon-summary /evidence/web01/var/log/auth.log*

# Conteggio degli eventi per host, canale, programma e tipo
linhawk metrics /evidence/web01

# Solo i log web di un server (access + error log, anche .gz ruotati)
linhawk csv-timeline /evidence/web01/var/log/nginx -H web01 -m medium -o web.csv

# Ricerca libera (parole chiave in OR, oppure tutte con -a; regex con -R)
linhawk search /evidence/web01 -k 198.51.100.7 -k wget
```

Opzioni utili:

| Opzione | Effetto |
|---|---|
| `-y/--year` | anno dei log RFC3164, che non lo riportano (di default: anno di mtime del file, con gestione del cambio d'anno) |
| `-t/--timezone` | fuso orario dei log senza offset e dell'output (`UTC`, `local`, `Europe/Rome`) |
| `-H/--hostname` | hostname da assegnare agli eventi che non ne hanno uno (auditd senza `node=`) |
| `--timeline-start` / `--timeline-end` | finestra temporale |
| `-T/--threads` | processi in parallelo, un file per processo (di default: tutti i core; `1` = sequenziale). Le correlazioni vengono calcolate dopo, su tutti i file insieme |
| `-p/--profile` | colonne dell'output: `minimal`, `standard` o `verbose` |
| `-r/--rules` | file o cartelle di regole aggiuntive o alternative (opzione ripetibile) |
| `--skipped-report` | CSV con i file saltati, il motivo e la prima riga |
| `--include-status` | carica anche le regole `deprecated` / `unsupported` |

## Regole

- `linhawk/rules/` (incluse nel pacchetto): regole proprie basate sui campi normalizzati. Coprono brute force e password
  spraying SSH (correlazioni), login riuscito dopo una serie di fallimenti (correlazione
  `temporal_ordered`), account con UID 0, aggiunta a gruppi privilegiati, reverse shell,
  download piped to shell, `ld.so.preload`, chiavi SSH, unit systemd, cancellazione di
  history e log, moduli kernel/rootkit. Per il web coprono SQL injection, path traversal e
  LFI (con una variante critical se la risposta è 200 con contenuto), command injection,
  Log4Shell, SSTI, XSS, web shell e script eseguiti dalle cartelle di upload, file sensibili
  esposti (`.env`, `.git/config`, dump SQL), scanner (un alert per client e tool invece di uno per
  richiesta), content discovery (≥100 risposte 404 in 5 minuti), brute force sui login web,
  errori PHP da funzioni pericolose e blocchi ModSecurity.
- `~/.local/share/linhawk/sigma` (o `$LINHAWK_HOME/sigma`): regole SigmaHQ Linux, `webserver_generic`, `web/product` (Apache, nginx) ed emerging threats
  Linux/web, scaricate con `update-rules` (licenza DRL 1.1).
  Le regole per altri prodotti vengono saltate; anche le categorie non ancora supportate
  (`network_connection`) vengono saltate, e il conteggio compare nel riepilogo finale.

Funzionalità Sigma supportate:

- modifier: `contains`, `startswith`, `endswith`, `all`, `re` (con `i`, `m`, `s`), `cidr`,
  `base64`, `base64offset`, `windash`, `exists`, `cased`, `gt/gte/lt/lte`, `fieldref`;
- wildcard `*` e `?` (anche con escape), valori `null` e `keywords`;
- condizioni con `and`, `or`, `not`, parentesi, `1 of`, `all of` e `them`;
- correlazioni v2: `event_count`, `value_count`, `temporal`, `temporal_ordered`, con `group-by`
  e `timespan`. Le regole base vengono soppresse se la correlazione ha `generate: false`.

## Configurazione di auditd consigliata

Per ottenere le detection `process_creation` e `file_event` servono regole auditd come queste:

```
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
-w /etc/ld.so.preload -p wa -k persist
-w /etc/systemd/system/ -p wa -k persist
-w /etc/cron.d/ -p wa -k persist
-w /root/.ssh/ -p wa -k persist
```

## Test

```bash
python tests/generate_samples.py   # rigenera lo scenario d'attacco di esempio
pytest -q
```

## Roadmap

- parallelismo anche dentro un singolo file molto grande (per chunk) e porting del motore in Rust;
- `network_connection` da auditd (`connect` + `SOCKADDR`) e da log di firewall e Zeek;
- altre sorgenti: log di proxy (squid, per le regole SigmaHQ `category: proxy`), Tomcat/IIS,
  journal di systemd letto nativamente (senza `journalctl`, anche su Windows), `.bash_history`,
  log dei container;
- firma del codice di `linhawk.exe` (Authenticode), per ridurre gli avvisi di SmartScreen/EDR;
- tuning dei livelli (`level-tuning`), exclude list, pivot keywords e report HTML come in Hayabusa;
- integrazione con Velociraptor per la raccolta delle evidenze.
