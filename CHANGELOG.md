# Changelog

## v2.1 - 2026-08-27

### UI / UX - Skin System

- **Dark / Light skin toggle** - moon/sun icon button in the top-right corner of the navbar. Preference persisted in `localStorage`. Switching is instantaneous, no page reload required.
- **Dark skin (default):** navbar and right panel at `#111827`, graph canvas white with a `3px solid #111827` right border for visual separation between canvas and panel.
- **Light skin:** navbar and right panel at `#00a0d1` (same blue as ANALYZE button), graph canvas white.
- **Graph canvas:** always white in both skins. The dark border on the canvas edge makes the separation readable without relying on background color contrast.
- **ANALYZE button:** color matches the active skin navbar - outlined `#00a0d1` in dark skin, filled `#00a0d1` in light skin.
- **Navbar:** restructured to `display:flex; justify-content:space-between` to accommodate the toggle button without breaking the existing GitHub / Discover URL row layout.
- **Navbar icon:** SVG glyph strokes follow the active skin - blue (`#00a0d1`) in dark, white in light.

### UI / UX - Process Category Icons

- Replaced the bare `?` glyph on unrecognized nodes with a **generic app-window icon** (rounded rect + header bar + 3 traffic-light dots + 2 content lines), drawn entirely via the HTML5 Canvas API. Every node now has a meaningful visual regardless of category.
- Expanded `PROCESS_CATEGORY_MAP` from 10 entries to approximately 70 common Windows processes across 10 categories. New entries cover: `winlogon.exe`, `userinit.exe`, `lsass.exe`, `logonui.exe`, `dwm.exe`, `ctfmon.exe`, `sihost.exe`, `svchost.exe`, `spoolsv.exe`, `dllhost.exe`, `audiodg.exe`, `trustedinstaller.exe`, `tiworker.exe`, `mssmpeng.exe`, `nissrv.exe`, `runtimebroker.exe`, `backgroundtaskhost.exe`, `searchindexer.exe`, `fontdrvhost.exe`, `taskhostw.exe`, `wusa.exe`, `dism.exe`, `regasm.exe`, `regedit.exe`, `ping.exe`, `tracert.exe`, `nslookup.exe`, `arp.exe`, `net1.exe`, `route.exe`, `netstat.exe`, `curl.exe`, `wget.exe`, `checknetisolation.exe`, `vpnbackgroundcontroller.exe`, `msedge.exe`, `chrome.exe`, `firefox.exe`, `bash.exe`, `wsl.exe`, `wt.exe`, `systeminfo.exe`, `hostname.exe`, `wfmdr.exe`, `ravbg64.exe`, `rtkngui64.exe`, `phonelink.exe`, and others.
- RMM category extended: `vpnbackgroundcontroller.exe` added.

### UI / UX - Parent Process Node

- **WPTV favicon icon** replaces the plain dot/question-mark circle for synthetic (unobserved / out-of-window) parent nodes. Uses `circularImage` vis-network shape with the WPTV SVG favicon encoded as a base64 data URI - no external image request.
- **Permanent label** rendered below the circle by vis-network: `Parent Process - PID 0x{pid}` on line one, `{process name}` on line two. Font color `#1e293b` (dark, readable on white canvas) set explicitly on the node to prevent inheritance of the global white font.
- **Hover tooltip** rebuilt with exact field order and content: `User`, `Host`, `Time`, `Parent Process`. Only fields with available data are shown - empty/null fields are omitted entirely. Time formatted as `YYYY-MM-DD HH:MM:SS` (space between date and time, no sub-second precision, no trailing `Z`).
- `RULE ID` removed from all node hover tooltips across the entire graph. It is already surfaced in the Basic Properties tab of the right panel. Removal is applied at `nodesForDataset` initialization (strips any `RULE ID:` line from `n.title` before the node enters the vis-network dataset), ensuring it does not appear on any node regardless of backend version.
- Tooltip data sourced from `n.meta` fields (preferred) with fallback to parsing the backend `n.title` string (`USER: x | HOST: y\nTIME: z`) when meta fields are null - covers both synthetic and observed root nodes.
- Same logic applied to the expand-path handler so nodes added via double-click expansion carry the same label and tooltip format.

### UI / UX - Detail Panel

- Right panel inline styles updated throughout for both skin variants: field table separators, badge pills, alert timeline cards, tab bar, comment input, and the "Open in Wazuh Discover" link.
- Detection event cards in the Detections tab: link color `#ffffff` with underline in dark skin, `#60a5fa` in light skin.
- Detection events header (`▲ DETECTION EVENTS (n)`) uses `rgba(255,255,255,0.85)` in dark skin, matching the rest of the panel text hierarchy.

### UI / UX - Edge Labels

- Edge label font color darkened from `#6b7280` to `#374151` for improved readability on the now-always-white canvas.

### AI Analyzer

- New **AI ANALYZE** button added to the navigation bar. Sends the resolved process tree and its correlated detections (the same Sysmon + Windows Audit Event IDs already covered by WPTV's correlation) to the Anthropic API using the **Claude Sonnet 4.6** model.
- New **AI Analysis** tab added to the process detail panel, after Basic Properties, Alerts, and Detections. Renders a 0-100 risk score with categorical label (e.g. `HIGH RISK`), model name and token consumption (input/output), a multi-paragraph narrative summary, a MITRE ATT&CK technique table with per-technique confidence, and prioritized remediation recommendations.
- **Language toggle** (`EN` / `PT-BR`) added to the AI Analysis tab, re-rendering the same analysis in both languages without an additional API call cost visible to the user.
- New environment variable `WPTV_ANTHROPIC_API_KEY` added to `wptv.env` / `wptv_example.env`. When unset, the AI ANALYZE button stays hidden and no other WPTV behavior is affected - the feature is fully optional and off by default.
- This is the only WPTV feature that sends data outside the local Wazuh environment; documented in `README.md` under "AI Analyzer" with a data-flow disclaimer.
- Validated end-to-end against a full RMM (ScreenConnect) adversarial abuse chain - initial elevated execution, UAC bypass (rule 92312), software hiding via registry (rule 92311), C2 beacon (rule 92111), mass reconnaissance (rule 92027 + EID 4104), and anti-forensics (rule 92561) - with AI ANALYZE correctly scoring the originating tree at 82/100 HIGH RISK and mapping it to six MITRE ATT&CK techniques.

### Documentation

- `README.md` rewritten to reflect v2.1: new UI Features section (Skin Toggle, Process Category Icons, Parent Process Node), new AI Analyzer section (button, AI Analysis tab, configuration, data-flow disclaimer), updated screenshots referencing `wptv_dark_blue.png`, `wptv_clear_blue.png`, `ai_analyze_full.png`, `ai_analysis_risk.png`, and `ai_analysis_mitre.png`, integrity SHA256 table updated, last updated date set to 2026-08-27.
- `CHANGELOG.md` updated with this entry.
- Companion write-up published: [Leveraging the Wazuh Ingestion Ecosystem for Advanced Threat Hunting](https://www.linkedin.com/pulse/leveraging-wazuh-ingestion-ecosystem-advanced-threat-rodrigues-bh9bf), documenting the three-tier ingestion method, the RMM abuse case study, and the AI Analyzer end to end.

---

### Development history (internal reference)

This version was developed across an extended working session covering the RMM adversarial simulation, five new Wazuh detection rules (92111, 92311, 92312, 92313, 92561), WPTV UI redesign (skin system, category icons, parent node improvements), the AI Analyzer integration (Claude Sonnet 4.6, `WPTV_ANTHROPIC_API_KEY`), and technical report generation (PT-BR, 15 pages with lab screenshots).

---

## v2.0 - 2026-07-22

### Search & Correlation

- Multi-mode agent lookup: Agent ID, Hostname, or IP (mutually exclusive).
- Host matching switched from `agent.name` to `data.win.system.computer` - the former goes stale after an endpoint rename without agent re-registration.
- Sysmon correlation added: EventID 1 (hashes, ProcessGuid, integrity, product/company), EventID 3 (network connections, TCP/UDP only), EventID 7 (loaded DLLs), EventID 11 (created files). Each 4688-based node is enriched, never duplicated. Every enrichment section in the side panel is labeled with its source EventID.
- PID/PPID now displayed exactly as logged (raw hex) instead of converted to decimal - matches the Wazuh Discover query one-for-one during triage. Hex-to-decimal conversion is used only internally, to bridge PID formats when correlating with Sysmon.
- Discover deep link generation fixed to use Lucene query syntax (KQL returned zero hits in production) and `data.win.system.computer` for host matching.

### UI / UX

- Fixed initial zoom: replaced `vis-network`'s native `fit()` (capped at 1:1, cannot zoom in) with a custom zoom-to-fit computed from the actual node layout.
- Subtree drag replaced with a spring/wave animation - depth-based easing instead of rigid lockstep movement.
- Removed all icons/emoji from the interface (title bar tree icon removed).
- Page title changed to "Threat Hunting & Incident Response" (spelled out) - not "DFIR", since DFIR does not cover the proactive-hunting use case this tool supports.
- Added a GitHub repository link directly under the title bar.

### Production Readiness

- Replaced Flask's built-in development server with `gunicorn` (4 workers, 120s timeout) as the WSGI server invoked by the systemd unit - removes the "development server" warning by actually no longer running one in production, rather than suppressing the log line.
- `WAZUH_DASHBOARD_BASE_URL` no longer hardcodes an IP; it auto-detects from `window.location.hostname`, so a fresh clone works out of the box when WPTV is reverse-proxied on the same host as the Dashboard.
- `requirements.txt` updated with `gunicorn==23.0.0`.
- `wazuh-process-tree.service` comments translated to English; `ExecStart` updated to invoke gunicorn instead of `python3 server.py` directly.

### Sysmon Ruleset (companion project)

- Migrated the validation environment from the stock Wazuh 4.14.4 Sysmon ruleset to [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs), on both the Wazuh Manager (rule files) and the endpoint (`sysmon-native.xml`).
- Found and fixed a missing `-enc` abbreviation in the PowerShell Base64-encoded-command detection (rules `92057`/`92059`/`92071`), present in both the stock ruleset and the rewrite.
- Found and documented (not yet fixed) a missing end-of-string anchor in rule `92213`, which misclassifies legitimate `.json` files as executables.
