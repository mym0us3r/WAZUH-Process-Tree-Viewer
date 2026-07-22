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

## Companion Sysmon Ruleset

WPTV's Sysmon correlation only surfaces data that Wazuh actually writes to `alerts.json` - if your Sysmon ruleset suppresses an event type at the source or never escalates it past level 0, WPTV has nothing to correlate. This project was developed and validated against [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs), which also documents two ruleset bugs found and fixed during that validation (both present in the stock Wazuh 4.14.4 ruleset as well):

- A missing `-enc` abbreviation in the PowerShell Base64-encoded-command detection (rules `92057`/`92059`/`92071`), which prevented the most common real-world invocation from ever escalating past a low-severity generic rule.
- A missing end-of-string anchor in rule `92213` ("Executable file dropped in folder commonly used by malware"), which caused legitimate `.json` files to be misclassified as executables.

## Technical Report

A full technical report documenting the development, the Sysmon correlation architecture, the adversarial simulation methodology used for validation, and the ruleset bugs above is available at `docs/WPTV_Relatorio_Tecnico_PT.docx` (Brazilian Portuguese).

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
`public/index.html` auto-detects the Wazuh Dashboard host from the page's own hostname (`window.location.hostname`), which works out of the box when WPTV is reverse-proxied on the same host as the Dashboard (just a different port). If your Dashboard runs on a different host than this plugin, edit the `WAZUH_DASHBOARD_BASE_URL` constant near the top of the `<script>` block directly.

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


## Special Thanks

* I would like to extend my sincere gratitude to **AwwalQuan** for their invaluable support, guidance, and contributions during the development of this project. And also to the **Wazuh Community** for providing an amazing open-source platform for security research.

## Goal
* This project is in its initial version and will undergo updates until it matures. For now, we are making minor adjustments to reach our goal. But remember: the destination is not the last stop, but a new point of departure.

## Contributors:
[@AwwalQuan](https://github.com/AwwalQuan)

[@wazuh](https://github.com/wazuh)

## License
Distributed under the MIT License. See LICENSE for more information.
