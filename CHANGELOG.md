# Changelog

## v2.1 - 2026-07-26

### Search & Correlation

- **Sysmon EID coverage expanded from 4 to 15 event types**: previously only EIDs `{1, 3, 7, 11}` were correlated - all others were silently discarded even when they generated Wazuh alerts in the Indexer. Root cause: `ENRICHMENT_EVENT_IDS` was the only gate for any Sysmon processing. Added `SYSMON_ALL_DETECTION_EIDS` covering all 15 detection-capable EIDs from the Native Sysmon Rewrite ruleset; `sysmon_detections` collection now runs for every EID in this set, while the dedicated panel enrichment handlers (hashes, DLLs, files, connections) still run only for EIDs 1/3/7/11.
- **New EIDs now visible in the Alerts tab**: EID 6 (Driver Load / BYOVD), EID 8 (CreateRemoteThread / injection), EID 9 (Raw Access Read / credential access), EID 10 (Process Access / LSASS), EID 13 (Registry Value Set / persistence), EID 17/18 (Pipe Events / Cobalt Strike C2), EID 20 (WmiEvent Consumer / persistence), EID 24 (Clipboard Change / ClickFix T1204.004 - rule 92751), EID 25 (Process Tampering / hollowing), EID 29 (File Executable Detected / PE drop).
- **Wazuh Indexer as primary data source**: WPTV now queries the Wazuh Indexer (OpenSearch `wazuh-alerts-*`) directly instead of scanning `alerts.json`. Performance: 1.8 s for a 5-minute window vs. ~62 s with file scanning (34x faster). Activated when `WPTV_INDEXER_URL` is set in `wptv.env`; automatic fallback to file scan if the Indexer is unavailable. Credentials stored in `/etc/wazuh-process-tree/wptv.env` (mode 600, owned by `wazuh-dashboard`); TLS verified against the Indexer's root CA.
- **Log rotation bug fixed** (`_iter_log_paths`): when the Wazuh Manager restarts mid-day, `alerts.json` is rotated to `ossec-alerts-DD.json` and a new live file begins. The old code only checked the live file for the current day, making "Last 5 Hours" and "Last 5 Minutes" return 0 results whenever a restart had occurred. Fix: for the current day, both `alerts.json` (post-restart events) and `ossec-alerts-DD.json` (pre-restart events) are now checked.
- **Wazuh Indexer - read-only access**: dedicated `wptv_svc` user with role `wptv_reader` scoped to `wazuh-alerts-*`. Write attempts return 403 (confirmed).

### UI / UX

- **Alerts tab**: new tab in the side panel showing a timeline of every Wazuh detection rule that fired for the selected process - rule ID, level, description, MITRE tactic/technique, EventID source, and timestamp. Tab badge turns red and panel switches to this tab automatically when detections exist.
- **Creation-order numbering (BFS per subtree)**: each node now shows its creation-order number inside the circle. Parent Process is always #1 in its subtree; observed child processes receive #2, #3... in chronological order of creation. Numbering runs independently per connected component (each root starts at #1), so multiple independent process trees on the same graph each have their own sequence. Numbers are permanent: they survive double-click coloring, expand, and background clicks. Implementation: backend BFS assigns `meta.order` and sets the label; `reapplyLabels()` on the frontend normalises every label to `"N\nname"` after any dataset update.
- **Labels without PID**: node labels now show only the creation-order number and process name (e.g. `2\nchrome.exe`). PID remains visible in the Basic Properties tab of the side panel. `reapplyLabels()` also normalises nodes added via expand (which arrive from the backend with a PID in their label) to the same no-PID format.
- **Parent Process tooltip format**: changed from `"Parent process (outside queried range) - name"` to `"PARENT PROCESS - name - HOST - USER"`, using context extracted from the referencing child's 4688 event.
- **Uniform node sizes**: `shape: 'circle'` with `widthConstraint: { minimum: 70, maximum: 70 }` forces all nodes to the same diameter regardless of label length.
- **Resizable side panel**: a 5 px drag handle between the graph and the detail panel allows the analyst to adjust the split during an investigation.
- **Graph centering**: replaced `zoomToFitPositions()` with `network.once('afterDrawing', () => network.fit())`, which runs after the first render tick when node positions are finalised.
- **Double-click behaviour**: double-clicking a node now colors its entire subtree (descendants) blue. `reapplyLabels()` is called after coloring to prevent labels from reverting.
- **Background click**: clicking empty canvas restores all parent nodes to yellow, children to gray, and number labels to their correct format.
- **Detections tab placeholder**: updated to `"Sysmon Telemetry (EID 1 to 29): Correlated for this process in the queried window are shown under the Relations tab."`.
- **Status bar simplified**: `"Loaded in XXXms (XXX nodes)"`. Zero-node result now shows `"loaded in XXXms (0 processes found) — no EventID 4688 events in the selected time window. Try a wider range."`.
- **Removed**: `"Process not observed within the queried time range - no user/host/rule data available."` from the Basic Properties tab.

### Backend

- **`_win_basename()` static method**: replaces `os.path.basename()` which only splits on `/` on Linux, returning full Windows paths as-is. `_win_basename()` always splits on `\`.
- **`_parse_latest()` rewritten** with a two-pass approach: first pass accumulates all events per PID; second pass consolidates detections (de-duplicated by rule ID, sorted by level descending, generic process rules filtered). `_make_node()` and `_make_synthetic_parent()` now include `detections` and `badgeCounts` in `meta`.
- **`_make_synthetic_parent()`**: accepts `host` and `user` parameters from the child's 4688 event. Sets `meta.order = 1` directly so `reapplyLabels()` can restore the label even when the node is returned by `expand_node` (which does not run BFS).
- **`_time_delta_label()`**: computes human-readable elapsed time between parent and child spawn timestamps for edge labels (`622ms`, `4s`, `3m 30s`).
- **`_fetch_from_indexer()`**: new method. POST to `$WPTV_INDEXER_URL/wazuh-alerts-*/_search` with agent identity filter and time range. Returns raw alert documents in the same shape as `alerts.json` lines, so processing code is shared between both paths.
- **`expand_node()` timing**: `t0 = _time.monotonic()` was missing, causing `NameError: name 't0' is not defined` on every expand request. Fixed.

### Production & Observability

- **Structured logging**: `logging.getLogger('wptv')` and `logging.getLogger('wptv.logic')` with `RotatingFileHandler` at `/var/log/wazuh-process-tree/wptv.log` (5 MB, 5 backups). Logging level forced to `DEBUG` on the root logger before handlers are added, overriding gunicorn's pre-initialisation at `WARNING`.
- **Per-request log entries**: identity, time window with span, Indexer hit count, 4688/sysmon event split, tree build timing, node/edge counts, expand PID and result count.
- **systemd service**: `EnvironmentFile=/etc/wazuh-process-tree/wptv.env` added to inject Indexer credentials at start.

### Sysmon Ruleset (companion project)

- Migrated from Sysmon64.exe v15.21 (Sysinternals) to native Sysmon via DISM (schema 4.91). Confirmed via EID 16: SHA256 of applied config matched `sysmon-native.xml`.
- Added detection rule **92111** (level 10, MITRE T1571): Sysmon EID 3 from PowerShell to known C2 ports (4444/8080/8888/9001/31337). Validated end-to-end with `c2_beacon_simulation.ps1` against `beacon_listener.py` on Kali GNU/Linux 2026.1.

### Documentation

- Technical report updated: `docs/WPTV_Relatorio_Tecnico_PT.docx` (v2.1, Brazilian Portuguese).
- README updated to v2.1.
- CHANGELOG updated.

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

- Replaced Flask's built-in development server with `gunicorn` (4 workers, 120s timeout) as the WSGI server invoked by the systemd unit.
- `WAZUH_DASHBOARD_BASE_URL` no longer hardcodes an IP; it auto-detects from `window.location.hostname`.
- `requirements.txt` updated with `gunicorn==23.0.0`.
- `wazuh-process-tree.service` comments translated to English; `ExecStart` updated to invoke gunicorn directly.

### Sysmon Ruleset (companion project)

- Migrated the validation environment to [Native Sysmon Rewrite by m0us3r](https://github.com/mym0us3r/Unified-Sysmon-Configs).
- Found and fixed a missing `-enc` abbreviation in the PowerShell Base64-encoded-command detection (rules `92057`/`92059`/`92071`).
- Found and documented (not yet fixed) a missing end-of-string anchor in rule `92213`, which misclassifies legitimate `.json` files as executables.

### Documentation

- New technical report: `docs/WPTV_Relatorio_Tecnico_PT.docx` (Brazilian Portuguese).
- README rewritten; added "Companion Sysmon Ruleset" section and this changelog.
- Demo: linked `.mp4` replaced with embedded GIF (`img/wptv_demo.gif`, sped up ~6x).
