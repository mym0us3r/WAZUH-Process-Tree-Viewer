# WAZUH Process Tree Viewer (WPTV)

WPTV is an independent OpenSearch Dashboards UI Plugin and forensic backend that integrates with the Wazuh Dashboard without modifying its core source code.

WPTV transforms raw Windows Security Logs (Event ID 4688) and Sysmon telemetry into interactive, draggable process trees - enabling analysts to trace process lineages during Threat Hunting and Incident Response operations. Correlated with all 15 Sysmon detection EIDs and 23 critical Windows Audit Event IDs for hashes, network connections, loaded DLLs, dropped files, clipboard changes, registry modifications, pipe events, privilege escalation, persistence, and more.

> **Disclaimer:** WPTV is an independent open-source project developed as part of my contributions to the Wazuh community through the Wazuh Ambassador Program. While it is built to integrate with and enhance the Wazuh platform, it is not an official Wazuh product and is not maintained or endorsed by the Wazuh team. The name 'Wazuh' is used solely to describe compatibility with the platform.

---

> Version: 2.1
> Last Updated: 2026-08-05
> Wazuh Compatibility: 4.14.4
> OpenSearch Dashboards: 2.19.4
> Companion Sysmon ruleset (recommended): [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs)

![WPTV Main Dashboard](img/wptv2.png)

## Deployment Modes

WPTV supports two deployment modes:

- **Standalone** - direct browser access at `https://<YOUR_WAZUH_IP>:5443`
- **Integrated into Wazuh Dashboard** - native sidebar entry at `https://<YOUR_WAZUH_IP>/app/wptv` under Forensics

Both modes share the same backend and frontend. The OSD plugin embeds the standalone interface as an iframe within the Wazuh Dashboard.

## Project Architecture & File Structure

<p align="center">
  <img src="img/arq.svg" alt="Project Architecture" width="900">
</p>

WPTV consists of two independent components:

**WPTV Backend** (`process_tree_api/`)

- `server.py`: Flask entrypoint - routing, logging, CORS, CSP headers
- `logic.py`: Core backend - Indexer query, archive scan, `build_tree`, BFS numbering. Wazuh Indexer as primary (`search_after` pagination up to 100k events), `wazuh-archives-*` OpenSearch index as supplement (fast path for events without rules), `archives.json` file scan as fallback, `alerts.json` last resort
- `requirements.txt`: Python dependencies
- `wptv_example.env`: Environment variables template (copy to `wptv.env`)
- `wazuh-process-tree.service`: SystemD unit template
- `public/index.html`: Frontend - vis-network.js, LR layout, PDF export, dark mode
- `public/favicon.svg` / `public/favicon.ico`: Browser tab icon

**WPTV Dashboard Plugin** (`wptv_plugin/`)

- `opensearch_dashboards.json`: OSD plugin manifest
- `package.json`
- `install.sh`: Plugin installation script (copy, permissions, restart)
- `target/public/wptv.plugin.js`: Pre-built bundle (~2.5KB, no compilation required)
- `target/public/wptv.plugin.js.gz`: Compressed bundle

**Mode 1 - Standalone (direct browser access)**

```
Browser
  |
  +-- https://IP:5000  (direct, no nginx required)
        |
  Flask + Gunicorn Backend (:5000, TLS)
        |
        +----------------+----------------+
        |                                 |
  Wazuh Indexer                   archives.json
    (Primary)                   alerts.json (fallback)
```

**Mode 2 - Integrated into Wazuh Dashboard**

```
Browser
  |
  +-- https://IP:443 - https://IP/app/wptv (Wazuh Dashboard / OSD)
        |
        OpenSearch Dashboards Plugin (wptv.plugin.js)
        Sidebar: Forensics -> Wazuh Process Tree Viewer
        Route: /app/wptv
        |
        iframe (sandbox: allow-scripts, allow-same-origin,
                         allow-popups, allow-downloads)
        |
        https://IP:5443  (Nginx Reverse Proxy - TLS required)
        |
  Flask + Gunicorn Backend (:5000, TLS)
        |
        +----------------+----------------+
        |                                 |
  Wazuh Indexer                   archives.json
    (Primary)                   alerts.json (fallback)
```

> **Note:** In Mode 2, Nginx is required. The OSD plugin embeds WPTV via iframe - since OSD serves over HTTPS (:443), the iframe source must also be HTTPS to avoid mixed-content blocking. In Mode 1, you can access the backend directly at `:5000` without Nginx.

WPTV v2.1 deployed as a native OpenSearch Dashboards UI Plugin, accessible directly from the Wazuh Dashboard sidebar under Forensics.

![WPTV inside Wazuh Dashboard](img/wptv_osd.png)

## Companion Sysmon Ruleset

WPTV correlates Sysmon and Windows Audit data from three sources in priority order:

1. `wazuh-alerts-*` (Indexer, fast path) - events that triggered a Wazuh rule
2. `wazuh-archives-*` (OpenSearch archive index) - all events regardless of rule, requires `archives.enabled: true` in `filebeat.yml`
3. `/var/ossec/logs/archives/archives.json` (file scan fallback) - used when the archive index is not available

Events like EID 24 (Clipboard Change) or EID 4104 (PowerShell Script Block) appear in the 'Detection Events' panel even without a rule firing, as long as the event was ingested by Wazuh. This project was developed and validated against [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs), which also documents two ruleset bugs found during that validation (both present in the stock Wazuh 4.14.4 ruleset as well):

- A missing `-enc` abbreviation in the PowerShell Base64-encoded-command detection (rules `92057`/`92059`/`92071`), which prevented the most common real-world invocation from ever escalating past a low-severity generic rule.
- A missing end-of-string anchor in rule `92213` ('Executable file dropped in folder commonly used by malware'), which caused legitimate `.json` files to be misclassified as executables.

### Sysmon EventID coverage map

| EventID | What it is | Behavioral rules exist? | Correlated by WPTV? |
|---|---|---|---|
| 1 | Process Creation | Yes - multiple modules | **Yes** - hashes, ProcessGuid, integrity, product/company |
| 3 | Network Connection | Yes - suspicious outbound | **Yes** - drawn as network edges + Detections tab |
| 6 | Driver Load | Yes - BYOVD / EDR-killer | **Yes** - Alerts tab (rule + MITRE) |
| 7 | Image Load (DLL) | Yes - `vaultcli.dll` tiered | **Yes** - Detections tab |
| 8 | CreateRemoteThread | Yes - injection / lateral movement | **Yes** - Alerts tab (rule + MITRE) |
| 9 | Raw Access Read | Yes - credential access via disk | **Yes** - Alerts tab (rule + MITRE) |
| 10 | Process Access | Yes - LSASS / sensitive memory | **Yes** - Alerts tab (rule + MITRE) |
| 11 | File Create | Yes - suspicious file creation | **Yes** - Detections tab |
| 13 | Registry Value Set | Yes - persistence / defense evasion | **Yes** - Alerts tab (rule + MITRE) |
| 17 | Pipe Created | Yes - Cobalt Strike named pipe C2 | **Yes** - Alerts tab (rule + MITRE) |
| 18 | Pipe Connected | Yes - Cobalt Strike named pipe C2 | **Yes** - Alerts tab (rule + MITRE) |
| 20 | WmiEvent Consumer | Yes - WMI-based persistence | **Yes** - Alerts tab (rule + MITRE) |
| 24 | Clipboard Change | Yes - ClickFix (T1204.004) | **Yes** - Alerts tab (rule + MITRE) |
| 25 | Process Tampering | Yes - hollowing / herpaderping | **Yes** - Alerts tab (rule + MITRE) |
| 29 | File Executable Detected | Yes - new PE drop | **Yes** - Alerts tab (rule + MITRE) |
| 2, 4, 5 | FileCreateTime, service state, process terminate | Group-tagged only, no behavioral rules | No |

### Windows Audit Event ID coverage

Beyond Sysmon, WPTV surfaces the following critical Windows Security and System Event IDs when indexed by Wazuh. These require Windows audit policies to be enabled on the endpoint.

| Event ID | Description | Category |
|---|---|---|
| 1102 | Security log cleared | Audit tampering |
| 4104 | PowerShell script block logging | Fileless malware / obfuscation |
| 4616 | System time changed | Log tampering / evasion |
| 4624 | Successful logon | Lateral movement baseline |
| 4625 | Failed logon | Brute force / credential attack |
| 4648 | Explicit credential logon | Pass-the-Hash / RunAs |
| 4663 | Object access attempt | Data exfiltration |
| 4672 | Special privileges assigned | Privilege escalation |
| 4689 | Process terminated | Process lifecycle correlation |
| 4698 | Scheduled task created | T1053 persistence |
| 4702 | Scheduled task updated | Persistence evasion |
| 4719 | Audit policy changed | Defense evasion |
| 4720 | User account created | Backdoor account |
| 4726 | User account deleted | Covering tracks |
| 4728 | Member added to global group | Privilege escalation |
| 4732 | Member added to local group | Privilege escalation |
| 4740 | Account lockout | Brute force indicator |
| 4768 | Kerberos TGT requested | Kerberoasting / Golden Ticket |
| 4769 | Kerberos service ticket requested | Lateral movement |
| 4771 | Kerberos pre-auth failed | Credential attacks |
| 4776 | NTLM credential validation | Pass-the-Hash / NTLM relay |
| 4964 | Special groups assigned | Privileged group monitoring |
| 7045 | New service installed | T1543 persistence |

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for the full version history.

## Installation & Setup

### 1. Directory Structure

```bash
mkdir -p /usr/share/wazuh-dashboard/plugins/process_tree_api/public
cd /usr/share/wazuh-dashboard/plugins/process_tree_api
# copy server.py, logic.py, requirements.txt, wptv_example.env here
# copy index.html to public/
```

After a complete deployment:

```
process_tree_api/
├── logic.py
├── server.py
├── requirements.txt
├── wptv.env              (generated from wptv_example.env - never commit this)
├── public/
│   ├── index.html
│   ├── favicon.ico
│   └── favicon.svg
└── venv/
    └── bin/
        ├── gunicorn
        └── python3
```

### 2. Virtual Environment

Isolate dependencies to prevent system conflicts:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Critical Permissions

The service must be executed by the dashboard user:

```bash
chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/plugins/process_tree_api
chmod -R 755 /usr/share/wazuh-dashboard/plugins/process_tree_api
```

### 4. Log Directory

```bash
mkdir -p /var/log/wazuh-process-tree
chown wazuh-dashboard:wazuh-dashboard /var/log/wazuh-process-tree
```

### 5. Wazuh Indexer Credentials (recommended)

WPTV queries the Wazuh Indexer directly as its primary data source. Create a dedicated read-only service user (`wptv_svc`) with access to both `wazuh-alerts-*` and `wazuh-archives-*`:

```bash
# Create the role
curl -sk -X PUT "https://127.0.0.1:9200/_plugins/_security/api/roles/wptv_role" \
  -H "Content-Type: application/json" \
  -u "admin:<admin_password>" \
  -d '{
    "index_permissions": [{
      "index_patterns": ["wazuh-alerts-*", "wazuh-archives-*"],
      "allowed_actions": ["read", "indices:data/read/search"]
    }]
  }'

# Create the user
curl -sk -X PUT "https://127.0.0.1:9200/_plugins/_security/api/internalusers/wptv_svc" \
  -H "Content-Type: application/json" \
  -u "admin:<admin_password>" \
  -d '{"password": "<your_password>", "backend_roles": [], "attributes": {}}'

# Map role to user
curl -sk -X PUT "https://127.0.0.1:9200/_plugins/_security/api/rolesmapping/wptv_role" \
  -H "Content-Type: application/json" \
  -u "admin:<admin_password>" \
  -d '{"users": ["wptv_svc"]}'
```

> **Important:** Updating the role (`PUT wptv_role`) overwrites the document entirely - it does not merge. The role mapping (`wptv_role` -> `wptv_svc`) is a separate document and must be recreated if the role is updated. Always run the mapping command after any role update.

Then configure the credentials:

```bash
mkdir -p /etc/wazuh-process-tree/certs
cp /etc/wazuh-indexer/certs/root-ca.pem /etc/wazuh-process-tree/certs/
# Copy the example file and fill in your values
cp wptv_example.env /etc/wazuh-process-tree/wptv.env
nano /etc/wazuh-process-tree/wptv.env
chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-process-tree/wptv.env
chmod 600 /etc/wazuh-process-tree/wptv.env
```

`wptv_example.env` template:

```bash
# Primary data source - Wazuh Indexer (wazuh-alerts-*)
WPTV_INDEXER_URL=https://127.0.0.1:9200
WPTV_INDEXER_INDEX=wazuh-alerts-*
WPTV_INDEXER_USER=wptv_svc
WPTV_INDEXER_PASSWORD=<your_password>
WPTV_INDEXER_CA_CERT=/etc/wazuh-process-tree/certs/root-ca.pem

# Archive index supplement - wazuh-archives-* (optional, recommended)
# Surfaces events without Wazuh rules (e.g. EID 4104, EID 4689).
# Requires: archives.enabled: true in filebeat.yml + index pattern in OSD.
# Set to empty (WPTV_ARCHIVE_INDEX=) to disable and use the file scan fallback.
WPTV_ARCHIVE_INDEX=wazuh-archives-*
```

If `WPTV_INDEXER_URL` is not set, WPTV automatically falls back to scanning the local `alerts.json` log file at `/var/ossec/logs/alerts/alerts.json`.

> **How this works:** WPTV runs on the same machine as the Wazuh Manager. All agents - regardless of how many - forward their logs to that central server. Both the Wazuh Indexer and `alerts.json` contain events from all agents; WPTV filters by Agent ID, Host, or IP at query time. No connection to individual endpoints is required.

### 6. Enabling the Archive Index (optional, recommended)

To enable `wazuh-archives-*` as a supplement data source:

**On the Wazuh server**, edit `/etc/filebeat/modules.d/wazuh.yml` and set `archives.enabled: true`, then restart Filebeat:

```bash
systemctl restart filebeat
```

**In the Wazuh Dashboard**, create the index pattern:
- Dashboards Management > Index Patterns > Create index pattern
- Pattern: `wazuh-archives-*`
- Time field: `timestamp`

### 7. TLS Certificate for Nginx Proxy

The OSD plugin embeds WPTV via iframe. The browser requires a trusted certificate for programmatic `fetch()` calls from within the iframe.

```bash
# Generate a self-signed certificate with SAN for your server IP
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /etc/wazuh-dashboard/certs/wptv-key.pem \
  -out    /etc/wazuh-dashboard/certs/wptv.pem \
  -days 3650 \
  -subj "/CN=<YOUR_IP>/O=WPTV" \
  -addext "subjectAltName=IP:<YOUR_IP>,IP:127.0.0.1"

chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs/wptv*.pem
chmod 400 /etc/wazuh-dashboard/certs/wptv-key.pem

# Import on each analyst Windows machine
certutil -addstore "Root" wptv.pem
# Then fully restart Chrome: taskkill /F /IM chrome.exe /T
```

> `wptv.pem` and `wptv-key.pem` are environment-specific (SAN bound to server IP) and are not distributed with the project.

### 8. Nginx Reverse Proxy

```bash
cat > /etc/nginx/sites-enabled/wptv << 'EOF'
server {
    listen 5443 ssl;
    ssl_certificate     /etc/wazuh-dashboard/certs/wptv.pem;
    ssl_certificate_key /etc/wazuh-dashboard/certs/wptv-key.pem;
    location / {
        proxy_pass https://127.0.0.1:5000;
        proxy_ssl_verify off;
    }
}
EOF
systemctl reload nginx
```

### 9. OSD Plugin Installation

```bash
sudo bash wptv_plugin/install.sh
```

The script copies the plugin, sets permissions, optionally compresses with Brotli, and restarts the dashboard. After ~30 seconds the sidebar entry appears under **Forensics - Wazuh Process Tree Viewer**.

> The bundle is pre-compiled. No Node.js, npm, or TypeScript compilation required.

### 10. Discover Link Base URL

Every node's 'Open in Wazuh Discover' link is built from a JavaScript constant, `WAZUH_DASHBOARD_BASE_URL`, in the **first lines** of the `<script>` block in `public/index.html`:

```js
const WAZUH_DASHBOARD_BASE_URL = `https://${window.location.hostname}`;
```

**How to check if you need to change it:**

1. Open WPTV in your browser and look at the navbar - it shows a live label: `Discover base URL: https://<detected-value>`.
2. Compare that value against the actual URL you use to log into your Wazuh Dashboard.
3. If they match - do nothing, it already works.
4. If they don't match, edit the constant directly:
   ```js
   const WAZUH_DASHBOARD_BASE_URL = 'https://your-actual-dashboard-host-or-fqdn';
   ```

## Service Management (SystemD)

Create the service file:

```bash
sudo nano /etc/systemd/system/wazuh-process-tree.service
```

```ini
[Unit]
Description=Wazuh Process Tree Viewer (WPTV)
After=network.target

[Service]
Type=simple
User=wazuh-dashboard
WorkingDirectory=/usr/share/wazuh-dashboard/plugins/process_tree_api
# Wazuh Indexer credentials (WPTV_INDEXER_*) - see wptv_example.env.
# Mode 600, owned by wazuh-dashboard, never committed to git.
EnvironmentFile=/etc/wazuh-process-tree/wptv.env
# Production WSGI server (gunicorn) with TLS.
# Certs reuse the Wazuh Dashboard certificate so the browser trusts HTTPS
# on port 5000 without an extra CA import - required when WPTV is embedded
# as an iframe inside the OSD plugin (mixed-content block otherwise).
ExecStart=/usr/share/wazuh-dashboard/plugins/process_tree_api/venv/bin/gunicorn \
  --workers 4 \
  --bind 0.0.0.0:5000 \
  --timeout 120 \
  --certfile /etc/wazuh-dashboard/certs/wazuh-dashboard.pem \
  --keyfile  /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem \
  server:app
# Delay before restart to avoid systemd start-limit-hit on rapid crash loops.
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Management Commands

```bash
sudo systemctl start wazuh-process-tree      # Start
sudo systemctl stop wazuh-process-tree       # Stop
sudo systemctl status wazuh-process-tree     # Check status
sudo systemctl enable wazuh-process-tree     # Enable on boot
tail -f /var/log/wazuh-process-tree/wptv.log # Real-time log
```

Live output from `journalctl -fu wazuh-process-tree` showing Indexer queries, archive index supplement, and tree build:

```
wptv: process-tree request: identity=009 range=1.0 event_id=(none)
wptv.logic: Indexer returned 6624 hits for 009 window 1.00h (pages: 2)
wptv.logic: fetch done in 1.10s: 6624 4688 events, 41 sysmon events (Indexer)
wptv.logic: archive index scan: 8563 hits, 2 pages, 7315 new detections (2731 pids) in 7.35s
wptv.logic: archive supplement (index): 2731 pids, 7315 new detections added
wptv.logic: build_tree done in 0.256s: 4112 nodes, 4094 edges
```

## Usage Guide

> Ensure **Audit Process Creation** is enabled on Windows targets to generate Event ID 4688, and that Sysmon is installed and forwarding to the Wazuh agent channel if you want the correlation features.

- Access via browser: `https://<YOUR_WAZUH_IP>:5443` (standalone) or `https://<YOUR_WAZUH_IP>/app/wptv` (OSD plugin)
- Enter **one** of: Agent ID, Host, or IP. Press **Enter** or click **ANALYZE**.
- Select the **Time Range** - presets from 5 minutes to 30 days, or a custom range (WPTV uses UTC comparison for forensic precision).
- Optionally add a **PROCESS FILTER** by process name (e.g. `chrome.exe`) to scope the graph.
- Optionally add an **EventID** (e.g. `1`, `3`, `24`, `4104`, `4688`) to show only trees containing nodes with that Event ID in their detections.

### EXPORT PDF

Click **EXPORT PDF** in the toolbar to generate a forensic report.
![Export PDF](img/export_pdf.png)

**Full Report** (no node selected):

- Page 1: Executive Summary and Acknowledgements
- Page 2: Summary table of all Parent Processes (name, user, host, child process count)
- Detail pages: one page per process tree with a full table of all nodes (Process, Parent, User, Host), including nodes hidden behind +MORE buttons

![Process List - services.exe](img/process_list.png)

- Last page: Top Parent Processes frequency pie chart with labeled slices and two-column legend

![Top Parent Processes Frequency Chart](img/tpp_freq.png)

**Branch Report** (node selected before clicking EXPORT PDF):

- Scoped to the selected process tree only
- Same structure as the Full Report but limited to that branch

Reports are generated entirely in the browser via jsPDF - no data leaves the machine.

The output filename follows the pattern `WPTV_<AgentID>_<TimeRange>_<Date>.pdf`.

### Graph Interactions

| Action | Result |
|--------|--------|
| Single click on a node | Opens detail panel; node turns blue (clears on next click or background click) |
| Double-click on a child node | Colors the entire subtree blue (lineage mark) |
| Double-click on a MORE node | Expands hidden children; double-click again to collapse |
| Double-click on Parent Process | Toggles SOLO drag mode (white border = solo; only the parent moves on drag) |
| Drag Parent Process (tree mode) | Moves the entire subtree (parent + all children) |
| Drag Parent Process (SOLO mode) | Moves only the parent node; children stay in place |
| Drag child/grandchild | Moves only that individual node freely |
| Right-click on any node | Context menu: 'Filter only: `<root name>`' to isolate that tree |
| <- SHOW ALL (toolbar) | Restores all trees after a right-click filter |
| Click on empty background | Resets blue selections; Parent Process stays red, children return to gray |
| Drag the divider bar | Resizes the detail panel width |
| Type EventID + ANALYZE | Shows only trees with at least one node matching that Event ID |

### Understanding the Graph

- **Red node** - Parent Process (always; never changes colour regardless of interaction)
- **Blue node** - currently selected node (single click) or lineage-marked subtree (double-click child)
- **Gray nodes** - unselected children/grandchild processes
- **Red circle labeled `+N MORE`** - N hidden child processes; double-click to expand / collapse
- **Green border node** - Ghost node: Sysmon or Windows Audit activity exists but no EID 4688 in the query window (process started before the window). Also created for long-running processes like PowerShell when EID 4104 detections exist within the window.
- **Gold border** - Sysmon telemetry correlated (EID 1, 7, or 11 - hashes, DLLs, or files)
- **Red border on gray node** - Wazuh detection rules fired for this process
- **Dashed green line** - Network connection (Sysmon EID 3)
- **Dashed orange line** - Cross-link (same process referenced in two different subtrees)
- **Blue diamond node** - External IP from EID 3 correlation; click for a direct Discover link

### Detail Panel Tabs

| Tab | Content |
|-----|---------|
| **Basic Properties** | Timestamp, executable path, PID, user, host, Wazuh rule info, direct Discover link |
| **Alerts** | Timeline of every Wazuh rule that fired for this process - level, description, MITRE tactic/technique, EID, timestamp. Badge turns red when detections exist. |
| **Detections** | Sysmon EID 1 (hashes, ProcessGuid, integrity), EID 7 (loaded DLLs), EID 11 (created files). Each section labeled with its source EID and a direct Discover link. |

## Screenshots

### EID 17/18 - Named Pipe C2 Detection (CRITICAL)

PowerShell creating known Cobalt Strike named pipes (`\\MSSE-1`, `\\postex_`, `\\status_`) detected via Sysmon EID 17 at level 12, MITRE T1071.001 - T1021.002.

![Named Pipe C2 Detection](img/c2_named_pipe.png)

---

### EID 24 - ClickFix (T1204.004) via Clipboard Change

Chrome.exe triggering 15 Sysmon EID 24 (Clipboard Change) detections in under 5 minutes - rule 92751 level 8.

![ClickFix Clipboard Detection](img/ps-clickfix.png)

---

### Post-Exploitation Reconnaissance

PowerShell spawning `net.exe`, `net1.exe`, `netstat.exe`, `whoami.exe`, `ipconfig.exe`, and `systeminfo.exe` in a 10-minute window.

![Post-Exploitation Reconnaissance](img/ps-netlocgroup.png)

---

### PowerShell Spawning PowerShell (T1059.001)

Multiple PowerShell child instances created by a parent PowerShell - rule 92027, Sysmon EID 1, MITRE T1059.001 level 4.

![PowerShell Spawned PowerShell](img/ps-spawned.png)

---

## Integrity Reference (v2.1 - 2026-08-05)

SHA256 hashes of the production files. Verify after any update:

```bash
sha256sum logic.py server.py public/index.html
sha256sum /usr/share/wazuh-dashboard/plugins/wptv/target/public/wptv.plugin.js*
```

| File | Location | SHA256 |
|------|----------|--------|
| `logic.py` | `process_tree_api/` | `74651e27826d964125d2f22c59fdd72890a9679ab2b03352a043259e4b91abdf` |
| `server.py` | `process_tree_api/` | `4682baf8fc58adce9f15e4bc4bad344891d00ef473703a5f9a166b47c4542b9b` |
| `index.html` | `process_tree_api/public/` | `66911ffda64b71e9077890e21e4601a3173951f513094f7ba593284453cfa11c` |
| `wptv.plugin.js` | `plugins/wptv/target/public/` | `7e58f27c9a1a56752db4c58c80bac191e856a374a67e28159d8a2b62e0595888` |
| `wptv.plugin.js.gz` | `plugins/wptv/target/public/` | `373722d0d9ff08d50fc9fe160996b18b56f65a571f315d6edaf606ce067d1ef5` |

> `wptv.pem` and `wptv-key.pem` are environment-specific and are not distributed with the project. See **Section 7 - TLS Certificate** above for generation instructions.

## WPTV Demo

![WPTV Demo](img/wptv_demo.gif)

## Special Thanks

Special thanks to the entire **Wazuh Community** for its continuous support and valuable feedback throughout the project's development.

The author would also like to express sincere gratitude to the Wazuh Ambassador Program team - Katia Bukovac, Raquel Presas Salguero, and Carolina Landa - for their encouragement, trust, and continued support.

Special thanks to Awwal Ishiaku for his support throughout the development process, and to William Weber for testing the project and providing valuable feedback.

Finally, sincere appreciation goes to Santiago Bassett, CEO of Wazuh, for his leadership, vision, and continued commitment to the growth of the Wazuh ecosystem, helping foster an environment where community-driven innovation can thrive.

This project reflects the collaborative spirit of the open-source community, where every suggestion, discussion, and contribution helps strengthen the ecosystem for everyone.

## Goal

This project is under active development and will continue to evolve. The destination is not the last stop, but a new point of departure.

## Contributors

[@AwwalQuan](https://github.com/AwwalQuan)

[Wazuh - The Open Source Security Platform (Unified XDR and SIEM)](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors%20program)

[Ambassadors Program | Wazuh](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program)

## License

Distributed under the MIT License. See [LICENSE](main/LICENSE) for more information.

Copyright (c) 2025-2026 m0us3r
