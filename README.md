# WAZUH Process Tree Viewer (WPTV)

WPTV is an independent OpenSearch Dashboards UI Plugin and forensic backend that integrates with the Wazuh Dashboard without modifying its core source code.

WPTV transforms raw Windows Security Logs (Event ID 4688) and Sysmon telemetry into interactive, draggable process trees - enabling analysts to trace process lineages during Threat Hunting and Incident Response operations. Correlated with all 15 Sysmon detection EIDs and 22 critical Windows Audit Event IDs for hashes, network connections, loaded DLLs, dropped files, clipboard changes, registry modifications, pipe events, privilege escalation, persistence, and more.

> **Disclaimer:** WPTV is an independent open-source project developed as part of my contributions to the Wazuh community through the Wazuh Ambassador Program. While it is built to integrate with and enhance the Wazuh platform, it is not an official Wazuh product and is not maintained or endorsed by the Wazuh team. The name "Wazuh" is used solely to describe compatibility with the platform.

--------------------------------
> Version: 2.1
> Last Updated: 2026-08-03
> Wazuh Compatibility: 4.14.4
> OpenSearch Dashboards: 2.19.4
> Companion Sysmon ruleset (recommended): [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs)

![WPTV Main Dashboard](img/wptv2.png)

## Deployment Modes

WPTV supports two deployment modes:

- **Mode 1 - Standalone (direct browser access)** - Direct HTTPS access to the backend at port 5000. No Nginx required. Ideal for isolated use, troubleshooting, or environments without the Wazuh Dashboard.
- **Mode 2 - Integrated into Wazuh Dashboard (OSD Plugin)** - The OSD plugin registers WPTV as a native sidebar entry. Nginx terminates external HTTPS on port 443 and routes the root path (`/`) to the Wazuh Dashboard at `127.0.0.1:5601` and `/wptv/` to the WPTV backend at `127.0.0.1:5000`. The iframe uses the same HTTPS origin, so WPTV inherits the Wazuh Dashboard certificate and no dedicated WPTV certificate needs to be imported on analyst workstations.


## Project Architecture & File Structure

<p align="center">
  <img src="img/architecture-wptv.png" alt="Project Architecture" width="900">
</p>

WPTV consists of two independent components:

**WPTV Backend** (`process_tree_api/`)
- `server.py`: Flask entrypoint - routing, logging, CORS, CSP headers
- `logic.py`: Core backend - Indexer query, archive scan, `build_tree`, BFS numbering. Wazuh Indexer as primary (`search_after` pagination up to 100k events), `wazuh-archives-*` supplement index for events without rules, filesystem fallback
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

**Mode 1 - Standalone (Direct Access)**

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

**Mode 2 - OSD Plugin (Integrated Mode - Unified Nginx Proxy)**

```
Browser
  |
  +-- https://IP:443 (Nginx Reverse Proxy - Path-based Routing)
        |-- /        --> Wazuh Dashboard (127.0.0.1:5601)
        |-- /wptv/   --> WPTV Backend (127.0.0.1:5000)
        |
        OpenSearch Dashboards Plugin (wptv.plugin.js)
        Sidebar: Forensics -> Wazuh Process Tree Viewer
        Route: /app/wptv
        |
        iframe (sandbox: allow-scripts, allow-same-origin,
                         allow-popups, allow-downloads)
```

> **Note:** In Mode 2, Nginx centralizes external HTTPS traffic on port 443 with path-based routing. The iframe uses the same HTTPS origin, eliminating mixed-content issues and secondary certificates.

WPTV v2.1 deployed as a native OpenSearch Dashboards UI Plugin, accessible directly from the Wazuh Dashboard sidebar under Forensics.

![WPTV inside Wazuh Dashboard](img/wptv_osd.png)

## Companion Sysmon Ruleset

WPTV correlates Sysmon data from two sources: `wazuh-alerts-*` (Indexer, fast path) for events that triggered a Wazuh rule, and `wazuh-archives-*` (or filesystem archives) for all events regardless of rule - including Sysmon telemetry captured but never escalated. Events like EID 24 (Clipboard Change) from any process appear in the Alerts tab even without a rule firing, as long as the event was ingested by Wazuh. This project was developed and validated against [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs), which also documents two ruleset bugs found during that validation (both present in the stock Wazuh 4.14.4 ruleset as well):

- A missing `-enc` abbreviation in the PowerShell Base64-encoded-command detection (rules `92057`/`92059`/`92071`), which prevented the most common real-world invocation from ever escalating past a low-severity generic rule.
- A missing end-of-string anchor in rule `92213` ("Executable file dropped in folder commonly used by malware"), which caused legitimate `.json` files to be misclassified as executables.

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

Beyond Sysmon, WPTV surfaces critical Windows Security and System Event IDs when indexed by Wazuh, handled transparently via `_normalize_pid()` to bridge hexadecimal and decimal PID formats.

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

WPTV queries the Wazuh Indexer directly as its primary data source. Create a dedicated read-only service user (`wptv_svc`) with access to `wazuh-alerts-*` and `wazuh-archives-*`:

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
WPTV_INDEXER_URL=https://127.0.0.1:9200
WPTV_INDEXER_INDEX=wazuh-alerts-*
WPTV_INDEXER_USER=wptv_svc
WPTV_INDEXER_PASSWORD=<your_password>
WPTV_INDEXER_CA_CERT=/etc/wazuh-process-tree/certs/root-ca.pem
WPTV_ARCHIVE_INDEX=wazuh-archives-*
```

--- 

### Nginx Reverse Proxy (Unified Configuration)

**Check whether Nginx is installed**

```
if ! command -v nginx >/dev/null 2>&1; then
    echo "Nginx is not installed. Installing..."
    apt update
    apt install -y nginx
else
    echo "Nginx is already installed."
fi
```

--- 

Nginx terminates external HTTPS on port 443 and routes paths uniformly:

```bash
cat > /etc/nginx/sites-available/wptv << 'EOF'
server {
    listen 443 ssl;
    server_name 192.168.1.10; # Adjust to your server IP or FQDN

    ssl_certificate     /etc/wazuh-dashboard/certs/wazuh-dashboard.pem;
    ssl_certificate_key /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem;

    location / {
        proxy_pass              https://127.0.0.1:5601;
        proxy_ssl_verify        off;
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_read_timeout      120s;
    }

    location /wptv/ {
        proxy_pass              https://127.0.0.1:5000/;
        proxy_ssl_verify        off;
        proxy_set_header        Host $host;
        proxy_set_header        X-Real-IP $remote_addr;
        proxy_read_timeout      120s;
    }
}
EOF
ln -s /etc/nginx/sites-available/wptv /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

### 7. Wazuh Dashboard Listener Hardening

Configure the Wazuh Dashboard to bind strictly to loopback (`127.0.0.1:5601`) in `/etc/wazuh-dashboard/opensearch_dashboards.yml`:
```yaml
server.port: 5601
server.host: "127.0.0.1"
```

### 8. OSD Plugin Installation

```bash
sudo bash wptv_plugin/install.sh
```

The script copies the plugin, sets permissions, optionally compresses with Brotli, and restarts the dashboard. After ~30 seconds the sidebar entry appears under **Forensics - Wazuh Process Tree Viewer**.

### 9. Discover Link Base URL

Every node's "Open in Wazuh Discover" link is built from a JavaScript constant, `WAZUH_DASHBOARD_BASE_URL`, in the **first lines** of the `<script>` block in `public/index.html`:

```js
const WAZUH_DASHBOARD_BASE_URL = `https://${window.location.hostname}`;
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
EnvironmentFile=/etc/wazuh-process-tree/wptv.env
ExecStart=/usr/share/wazuh-dashboard/plugins/process_tree_api/venv/bin/gunicorn \
  --workers 4 \
  --bind 0.0.0.0:5000 \
  --timeout 120 \
  --certfile /etc/wazuh-dashboard/certs/wazuh-dashboard.pem \
  --keyfile  /etc/wazuh-dashboard/certs/wazuh-dashboard-key.pem \
  server:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Service Logging

```
sudo mkdir -p /var/log/wazuh-process-tree
sudo touch /var/log/wazuh-process-tree/wptv.log
sudo chown -R wazuh-dashboard:wazuh-dashboard /var/log/wazuh-process-tree
sudo chmod 750 /var/log/wazuh-process-tree
sudo chmod 640 /var/log/wazuh-process-tree/wptv.log

```

### Management Commands
```
sudo systemctl start wazuh-process-tree      # Start
sudo systemctl stop wazuh-process-tree       # Stop
sudo systemctl status wazuh-process-tree     # Check status
sudo systemctl enable wazuh-process-tree     # Enable on boot
tail -f /var/log/wazuh-process-tree/wptv.log # Real-time log
```

## Usage Guide

- Access via browser: `https://<YOUR_WAZUH_IP>/app/wptv` (OSD plugin integrated mode)
- Enter **one** of: Agent ID, Host, or IP. Press **Enter** or click **ANALYZE**.
- Select the **Time Range** - presets from 5 minutes to 30 days, or a custom range.
- Optionally add a **PROCESS FILTER** by process name.
- Optionally add an **EventID** filter.

### EXPORT PDF
Click **EXPORT PDF** in the toolbar to generate a forensic report (Full Report or Branch Report) via jsPDF.

### Graph Interactions
- **Single click on a node**: Opens detail panel and highlights node.
- **Double-click on a child node**: Marks subtree lineage.
- **Double-click on a MORE node**: Expands/collapses hidden children.
- **Double-click on Parent Process**: Toggles SOLO drag mode.
- **Right-click on any node**: Isolate tree view (`Filter only: <root name>`).

## Screenshots
- EID 17/18 - Named Pipe C2 Detection (CRITICAL)
- EID 24 - ClickFix (T1204.004) via Clipboard Change
- Post-Exploitation Reconnaissance
- PowerShell Spawning PowerShell (T1059.001)

## Integrity Reference (v2.1 - 2026-08-03)

SHA256 hashes of production files:

| File | Location | SHA256 |
|------|----------|--------|
| `logic.py` | `process_tree_api/` | `c89ec61585ad08e5fb81f223d935b6d3b41eae1757a391600e949a4e6db4f53d` |
| `server.py` | `process_tree_api/` | `4682baf8fc58adce9f15e4bc4bad344891d00ef473703a5f9a166b47c4542b9b` |
| `index.html` | `process_tree_api/public/` | `de7e7b5a64967ea9d8c3c44ccb96f35d27a54db6ac07230bff2776952f1b03b7` |
| `wptv.plugin.js` | `plugins/wptv/target/public/` | `7e58f27c9a1a56752db4c58c80bac191e856a374a67e28159d8a2b62e0595888` |
| `wptv.plugin.js.gz` | `plugins/wptv/target/public/` | `373722d0d9ff08d50fc9fe160996b18b56f65a571f315d6edaf606ce067d1ef5` |

## Acknowledgements

A special thank you to the entire **Wazuh Community** for their ongoing support and valuable feedback throughout the project's development.

I would also like to express my sincere gratitude to the Wazuh Ambassador Program team:
Katia Bukovac, Raquel Presas Salguero, Carolina Landa, and Francis Jeremiah - for their encouragement, trust, review, and constant support during this project.

Special thanks to **Awwal Ishiaku** for his support throughout the development process, and to William   
Weber for testing the project and providing valuable feedback.  

Finally, a huge thank you to Santiago Bassett, CEO of Wazuh, for championing open source and building   
a space where community-driven innovation can truly thrive.  

This project reflects the **collaborative spirit of the open-source community**, where every suggestion,   
discussion, and contribution helps strengthen the ecosystem for everyone.

## License
Distributed under the MIT License. Copyright (c) 2025-2026 m0us3r.
