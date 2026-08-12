# Changelog
2026-08-12
## v2.1

### Data Sources

- **`wazuh-archives-*` index supplement**: implemented `_fetch_from_archive_index()` querying the OpenSearch archive index via `search_after` pagination (5000 hits/page, 20-page cap), reducing 7-day query time from ~91s (file scan) to ~7.35s. Falls back to file scan when unavailable.
- **Archive scan timeout guard**: added `ARCHIVE_SCAN_TIMEOUT = 90s` to the file scan fallback to stop oversized scans cleanly before hitting Gunicorn worker timeouts.
- **`search_after` pagination for primary Indexer**: replaced `size=10000` truncation with `search_after` cursor pagination (5000 hits/page, sort on `[@timestamp, _id]`, 100k event safety cap).
- **`wptv_example.env` updated**: added `WPTV_ARCHIVE_INDEX` documentation and prerequisites (`archives.enabled: true` in `filebeat.yml`).

### Detection Gate & PID Normalization

- **Windows Audit Event IDs & EID 4689**: added EID 4689 (Process Termination) and 22 critical Windows Security/System EIDs (total 23 Windows Audit EIDs) to `ALL_DETECTION_EIDS`.
- **`_normalize_pid()`**: added robust PID normalization across event schemas (handling decimal PIDs in Sysmon/EID 4104 and hex strings in Windows Audit events) across three independent code paths to prevent silent data loss.
- **Routing metadata**: detection entries now include `pidField`, `pidValue`, and `sourceIndex` for robust Discover navigation.

### Ghost Nodes & Filtering

- **Windows Audit ghost nodes & provider inference**: extended ghost node creation using provider-to-process inference (`Microsoft-Windows-PowerShell` -> `powershell.exe`) so pre-window sessions with EID 4104 detections have a visible node anchor.
- **Host population & PROCESS FILTER**: ghost node hosts are correctly extracted from detection entries, and `PROCESS FILTER` is fully enforced against ghost nodes.
- **EventID filter extended**: `build_tree()` now checks both `meta.detections` and `meta.sysmon_detections` buckets.

### UI / UX & OSD Plugin

- **Unified Nginx Proxy Architecture**: migrated from dedicated port 5443 to unified port 443 path-based routing (`/` -> Wazuh Dashboard on `127.0.0.1:5601`, `/wptv/` -> WPTV Gunicorn backend on `127.0.0.1:5000`), reusing the Wazuh Dashboard certificate (`wazuh-dashboard.pem`) and eliminating separate certificates or ports.
- **Native OSD Sidebar Entry**: registered WPTV as a native OSD UI Plugin (`Forensics - Wazuh Process Tree Viewer`, route `/app/wptv`) with pure DOM mounting.
- **LR mind-map layout & vis-network improvements**: Reingold-Tilford O(N) layout with `heightCache`, rectangular box nodes, fixed color scheme, `+MORE`/`-LESS` subtree pagination, right-click filtering, and dual-mode subtree dragging.
- **Forensic PDF Export**: jsPDF-powered report generation with Executive Summary, anti-overlap pie charts, and simplified process inventory tables (`Process | Parent | User | Host`).

### Bug Fixes

- Fixed `expand_node` returning `None` attribute error.
- Removed orphaned global scope code block causing `ReferenceError`.
- Added `allow-downloads` to OSD iframe sandbox for PDF export support.
- Cleaned up stale DOM element references on ANALYZE and fixed `network.once()` timing.
- Fixed MORE node graph origin coordinates and `computeLRTreeLayout` O(N²) memory/CPU bottleneck with `heightCache`.
- Resolved JavaScript scope initialization errors in Discover link builder.
