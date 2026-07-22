# WAZUH Process Tree Viewer (WPTV)

WAZUH Process Tree Viewer (WPTV) is a high-performance forensic visualization tool designed for the Wazuh ecosystem. It transforms raw Windows Security Logs (Event ID 4688) into interactive, draggable relationship graphs, enabling analysts to trace process lineages (Parent-Child) during Threat Hunting and Incident Response (IR) operations - now enriched with correlated Sysmon telemetry (EventID 1, 3, 7, 11) for hashes, network connections, loaded DLLs, and dropped files.

--------------------------------
> Version: 2.0
> Last Updated: 2026-07-22
> Wazuh Compatibility: 4.14.4 / 4.14.5
> OpenSearch Dashboards: 2.19.3
> Companion Sysmon ruleset (recommended): [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs)

![WPTV Main Dashboard](img/wazuh_process_tree_viewer.png)

## What's New in 2.0

- **Multi-mode agent lookup**: search by Agent ID, Hostname, or IP - mutually exclusive fields, only one is used per query.
- **Host matching against `data.win.system.computer`**, not `agent.name` - the latter goes stale when an endpoint is renamed without re-registering the agent.
- **Flexible time range**: presets from 5 minutes to 30 days, plus a fully custom start/end range.
- **Sysmon correlation**: each 4688-based node is enriched - never duplicated - with data from Sysmon EventID 1 (hashes, ProcessGuid, integrity level, product/company), EventID 3 (network connections, TCP/UDP only), EventID 7 (loaded DLLs), and EventID 11 (created files). Every enrichment section in the side panel is labeled with its source EventID.
- **PID/PPID shown exactly as logged** (raw hex, e.g. `0x235c`) - no decimal conversion. What is on screen matches the Wazuh Discover query one-for-one during triage. Hex-to-decimal conversion is used only internally, to bridge PID formats when correlating with Sysmon (whose own events report PID in decimal).
- **One-click Discover deep link** per node, using Lucene query syntax (confirmed empirically against KQL, which returned zero hits in production), pre-filled with the exact rule/event/PID for that process.
- **Spring/wave drag animation**: dragging a parent node makes its subtree follow with a cascading, depth-based easing effect instead of moving in rigid lockstep.
- **Custom zoom-to-fit**: computes the ideal scale from the actual node layout instead of relying on `vis-network`'s native `fit()`, which is capped at 1:1 and cannot zoom in on small/compact trees.

## Project Architecture & File Structure

1. `server.py`: Entrypoint. Flask server handling web routing (`/api/process-tree`, `/api/process-tree/expand`) and serving the frontend.
2. `logic.py`: Backend logic. Parses `alerts.json` (4688 and Sysmon EventID 1/3/7/11), handles UTC timezone normalization, and builds/enriches the process tree.
3. `public/index.html`: Frontend. Interactive UI powered by `vis-network.js`, radial layout, wave-drag animation, and Dark Mode support.
4. `requirements.txt`: Dependencies. Required Python libraries for the environment.
5. `wazuh-process-tree.service`: SystemD configuration template for background service management.
6. `public/favicon.svg` / `public/favicon.ico`: Browser tab icon and in-page navbar icon.

## Companion Sysmon Ruleset

WPTV's Sysmon correlation only surfaces data that Wazuh actually writes to `alerts.json` - if your Sysmon ruleset suppresses an event type at the source or never escalates it past level 0, WPTV has nothing to correlate. This project was developed and validated against [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs), which also documents two ruleset bugs found and fixed during that validation (both present in the stock Wazuh 4.14.4 ruleset as well):

- A missing `-enc` abbreviation in the PowerShell Base64-encoded-command detection (rules `92057`/`92059`/`92071`), which prevented the most common real-world invocation from ever escalating past a low-severity generic rule.
- A missing end-of-string anchor in rule `92213` ("Executable file dropped in folder commonly used by malware"), which caused legitimate `.json` files to be misclassified as executables.

### Sysmon EventID coverage map

The ruleset tags every Sysmon EventID 1-9 with a `sysmon_eventN` group (confirmed via `grep -rhoP 'sysmon_event([0-9]+)' *sysmon*`), but only some of them have actual behavioral detection rules built on top, and WPTV only correlates a subset of those into the graph:

| EventID | What it is | Behavioral rules exist? | Correlated by WPTV? |
|---|---|---|---|
| 1 | Process Creation | Yes - multiple modules (infrastructure routing, process/parent anomaly, native anchor chain) | **Yes** - hashes, ProcessGuid, integrity, product/company |
| 3 | Network Connection | Yes - suspicious outbound connection detection | **Yes** - drawn as network edges + Relations tab |
| 7 | Image Load (DLL) | Yes - `vaultcli.dll` tiered detection | **Yes** - Detections tab |
| 8 | CreateRemoteThread | Yes - cross-process injection / lateral movement | Not yet |
| 10 | Process Access | Yes - LSASS / sensitive process memory access | Not yet |
| 11 | File Create | Yes - suspicious file creation in high-risk paths | **Yes** - Detections tab |
| 13 | Registry Value Set | Yes - persistence / defense evasion | Not yet |
| 20 | WmiEvent (Consumer Activity) | Yes - WMI-based persistence | Not yet |
| 2, 4, 5, 6, 9 | FileCreateTime, service state change, process terminate, driver load, RawAccessRead | Group-tagged only, no behavioral rules in this ruleset | No |

EventID 8/10/13/20 having real behavioral rules but no WPTV correlation yet is a known gap, not an oversight - see Roadmap in the technical report.

## Technical Report

A full technical report documenting the development, the Sysmon correlation architecture, the adversarial simulation methodology used for validation, and the ruleset bugs above is available at `docs/WPTV_Relatorio_Tecnico_PT.docx` (Brazilian Portuguese).

## Changelog

See changelog for the full version history.

## Installation & Setup

## 1. Directory Structure
We recommend deploying the plugin within the Wazuh dashboard directory:
* mkdir -p /usr/share/wazuh-dashboard/plugins/process_tree_api
* cd /usr/share/wazuh-dashboard/plugins/process_tree_api
> Clone the repository files here <

## 2. Virtual Environment
Isolate dependencies to prevent system conflicts:
* python3 -m venv venv
* source venv/bin/activate
* pip install -r requirements.txt

## 3. Critical Permissions
The service must be able to read Wazuh logs and be executed by the dashboard user:
* chown -R wazuh-dashboard:wazuh-dashboard /usr/share/wazuh-dashboard/plugins/process_tree_api
* chmod -R 755 /usr/share/wazuh-dashboard/plugins/process_tree_api

## 4. Discover Link Base URL

Every node's "Open in Wazuh Discover" link is built from a JavaScript constant, `WAZUH_DASHBOARD_BASE_URL`, in the **first lines** of the `<script>` block in `public/index.html` - look for the `CONFIGURATION` banner comment, it's the very first thing in the file's script section, before any other code:

```js
const WAZUH_DASHBOARD_BASE_URL = `https://${window.location.hostname}`;
```

**Why this can't be fully automatic**: WPTV is a Flask app running on its own port (5000 by default); the Wazuh Dashboard is a separate application, usually on port 443 of the same machine - but not always. There is no reliable way for client-side JavaScript to discover the Dashboard's address on its own, so this constant exists as the one thing you may need to check after cloning.

**How to check if you need to change it:**
1. Open WPTV in your browser and look at the navbar - it shows a live label: `Discover base URL: https://<detected-value>`.
2. Compare that value against the actual URL you use to log into your Wazuh Dashboard.
3. If they match (the common case: WPTV reverse-proxied on the same host as the Dashboard, just a different port) - do nothing, it already works.
4. If they don't match (Dashboard on a different host/FQDN, or behind a load balancer with a different public name) - edit the constant directly:
   ```js
   const WAZUH_DASHBOARD_BASE_URL = 'https://your-actual-dashboard-host-or-fqdn';
   ```
   Save `public/index.html`, refresh the browser (no service restart needed, it's a static frontend file), and confirm the navbar label now shows the value you set.
5. Click any node's "Open in Wazuh Discover" link to do a final end-to-end check - it should land you on a Discover search already scoped to that process.

If your Dashboard has no valid HTTPS certificate for the hostname WPTV detects (e.g. you access it by IP but its certificate is issued for a different FQDN), the generated link may trigger a browser certificate warning even though the query itself is correct - that's a certificate/PKI concern on the Dashboard side, unrelated to WPTV.

## Service Management (SystemD)
To ensure WPTV starts automatically and remains highly available, use the provided SystemD configuration.
> Create the service file:
* sudo nano /etc/systemd/system/wazuh-process-tree.service

```
[Unit]
Description=Wazuh Process Tree Viewer (WPTV)
After=network.target

[Service]
Type=simple
User=wazuh-dashboard
WorkingDirectory=/usr/share/wazuh-dashboard/plugins/process_tree_api
# Production WSGI server (gunicorn) - not Flask's built-in dev server.
ExecStart=/usr/share/wazuh-dashboard/plugins/process_tree_api/venv/bin/gunicorn --workers 4 --bind 0.0.0.0:5000 --timeout 120 server:app
# Delay before restart, to avoid systemd's start-limit-hit failure on rapid crash loops
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`gunicorn` is included in `requirements.txt` and installed automatically inside the venv in step 2 above.

## Management Commands:
* (Start): `sudo systemctl start wazuh-process-tree`
* (Stop): `sudo systemctl stop wazuh-process-tree`
* (Check Status): `sudo systemctl status wazuh-process-tree`
* (Enable on Boot): `sudo systemctl enable wazuh-process-tree`

## Usage Guide
HEY! Ensure Audit Process Creation is enabled on Windows targets to generate Event ID 4688, and that Sysmon is installed and forwarding to the same channel if you want the correlation features.

* Access the tool via browser: `https://<YOUR_WAZUH_IP>:5000`
* Enter **one** of: Agent ID, Host, or IP (e.g. `?agent_id=009`, `?host=LABDESK`, or `?ip=192.168.1.3`).
* Select the Time Range - presets from 5 minutes to 30 days, or a custom range (WPTV uses UTC comparison for forensic precision).
* Click **Analyze Agent**.
* Click any node once to open the detail panel - Sysmon enrichment sections only appear when correlated data exists for that process.
* Click the Discover link in the panel to pivot directly into Wazuh Discover with the exact query for that event.

## WPTV Demo
![WPTV Demo](img/wptv_demo.gif)

Sped up ~6x from the original 102-second recording (real time from launch to the Discover pivot). Full-speed video: [`img/WPTV_-_demo.mp4`](img/WPTV_-_demo.mp4).

![Screenshot](img/wptv.png)

## Special Thanks

* I would like to extend my sincere gratitude to **AwwalQuan** for their invaluable support, guidance, and contributions during the development of this project. And also to the **Wazuh Community** for providing an amazing open-source platform for security research.

## Goal
* This project is in its initial version and will undergo updates until it matures. For now, we are making minor adjustments to reach our goal. But remember: the destination is not the last stop, but a new point of departure.

## Contributors:
[@AwwalQuan](https://github.com/AwwalQuan)

[@wazuh](https://github.com/wazuh)

## License
Distributed under the MIT License. See LICENSE for more information.
