# Changelog

## v2.1

### Data Sources

- **`wazuh-archives-*` index supplement**: previously, the only supplement to `wazuh-alerts-*` was a sequential file scan of `archives.json` on disk. For 7-day windows this scan took ~91s and was still within the gunicorn timeout; for 30-day windows it exceeded 120s and killed the worker with SIGKILL. Implemented `_fetch_from_archive_index()` which queries the OpenSearch archive index via `search_after` pagination (5000 hits per page, 20-page cap). When `WPTV_ARCHIVE_INDEX` is set and the index exists, the file scan is skipped entirely. Same 7-day range now completes in ~7s. Falls back to the file scan when the index is unavailable.

- **Archive scan timeout guard**: added `ARCHIVE_SCAN_TIMEOUT = 90s` to the file scan fallback. Previously, an oversized scan would be killed by gunicorn mid-response with no log entry; now it stops cleanly, returns whatever was collected, and logs a warning pointing to the archive index as the long-term solution.

- **`search_after` pagination for the primary Indexer**: previously, `_fetch_from_indexer()` used `size=10000`, which is the OpenSearch default `max_result_window`. Any time window with more than 10,000 events was silently truncated. Replaced with `search_after` cursor pagination (5000 hits per page, sort on `[@timestamp, _id]`, 20-page safety cap / 100k events).

- **`wptv_example.env` updated**: `WPTV_ARCHIVE_INDEX` variable added. Documents prerequisites (filebeat `archives.enabled: true`, OSD index pattern `wazuh-archives-*`) and fallback behavior when left empty.

### Detection Gate

- **EID 4689 (Process Termination)**: was not in `WINDOWS_AUDIT_DETECTION_EIDS`. Process termination events were never fetched, never correlated, never surfaced. Added to the gate; correlates to existing tree nodes via PID.

- **Windows Audit Event IDs (first addition)**: prior to v2.1 the detection gate covered only the 15 Sysmon EIDs. Added 22 critical Windows Security/System EIDs: 1102, 4104, 4616, 4624, 4625, 4648, 4663, 4672, 4698, 4702, 4719, 4720, 4726, 4728, 4732, 4740, 4768, 4769, 4771, 4776, 4964, 7045. Combined with EID 4689 added above, the Windows Audit gate totals 23 EIDs.

- **`search_after` pagination**: see Data Sources section above.

### PID Normalization

- **Silent data loss on Windows Audit events**: Sysmon reports PIDs as decimal integers in `data.win.eventdata.processId`. Windows Audit events (EID 4104, 4689, etc.) report PIDs as hex strings in `data.win.eventdata.processId` for some events, and as decimal in `data.win.system.processID` for others - notably EID 4104, which has no `processId` in `eventdata` at all. The previous code called `ev.get('processId')` as the only PID source; for EID 4104 this returned `None` and the detection was silently discarded via `if not pid: continue`. Added `_normalize_pid()` to convert any hex or decimal PID to a consistent decimal string, and extended the PID extraction chain in three places (primary Indexer loop, `_fetch_from_archive_index()`, `_fetch_sysmon_from_archives()`) to fall back to `sys_f.get('processID')` when `eventdata` yields no PID.

- **Detection entries enriched with routing metadata**: previously, the frontend built every Discover link using hardcoded field names (`data.win.eventdata.processId`, always `wazuh-alerts-*`). This broke silently for EID 4104 (wrong field) and for archive-sourced events (wrong index). Added `pidField`, `pidValue`, and `sourceIndex` to every detection entry; the frontend uses these values directly.

### Ghost Nodes

- **Windows Audit ghost nodes**: ghost node creation previously required a process image path from Sysmon (`sysmon_images` or `process` enrichment). If no Sysmon image was available, the PID was skipped even when Windows Audit detections existed for it. A PowerShell session opened before the queried window would have EID 4104 detections inside the window but no EID 4688 and no Sysmon image - resulting in detections with no visible node to attach to. Added provider-to-process inference: `Microsoft-Windows-PowerShell` maps to `powershell.exe`, creating a ghost node with the 7-alert badge visible.

- **Ghost node host populated from detections**: `meta.host` for ghost nodes was hardcoded to `'N/A'` because there is no EID 4688 to extract a hostname from. The 'Open in Discover' link then generated `data.win.system.computer:"N/A"`, returning zero results. Now extracts the `computer` field from the node's own detection entries.

- **PROCESS FILTER applied to ghost nodes**: ghost nodes were added to the graph after the main `search_filter` pass over EID 4688 events. Filtering by 'powershell' would still surface chrome.exe ghost nodes because the filter never ran against them. Added `if search_filter and search_filter not in image.lower(): continue` inside the ghost node creation loop.

### UI / UX

- **'DETECTION EVENTS' label**: the detection panel header read 'SYSMON RULE DETECTIONS'. After Windows Audit events (EID 4104, 4689, etc.) were added to the detection gate, the label became inaccurate. Renamed to 'DETECTION EVENTS'.

- **EventID filter extended to `meta.sysmon_detections`**: the EventID filter in `build_tree()` checked only `meta.detections` - Wazuh rule alerts from EID 4688 events. Detections from the archive index (EID 4104, 4689, etc.) are stored in `meta.sysmon_detections` and were never matched, causing the filter to always return 'no matching nodes' for Windows Audit EIDs even when detections were correctly loaded. Both buckets are now checked.

- **Discover link - ghost nodes**: previously used the same `data.win.eventdata.newProcessName` query as observed child nodes. For ghost nodes this field is meaningless (no EID 4688 in window). Link now uses `data.win.system.processID:"<decimal_pid>"` with `wazuh-archives-*` as the index - matches the actual field structure of EID 4104 and similar events.

- **Discover link - observed child nodes**: the link included `rule.id:"67027" AND data.win.system.eventID:"4688" AND data.win.eventdata.newProcessId:"0x..."`. This locked the result to a single process-creation event. Simplified to `data.win.system.computer + data.win.eventdata.newProcessName` - returns all events related to that process and lets the analyst refine from there.

- **Discover link - detection entries**: per-detection 'Open in Discover' in the Detection Events panel previously hardcoded `data.win.eventdata.processId` for all event types and always used `wazuh-alerts-*`. Now uses `pidField:"pidValue"` from backend metadata and resolves the index to `d.sourceIndex` (e.g. `wazuh-archives-*` for archive-sourced detections).

- **LR tree layout (mind-map style)**: replaced the radial layout (`computeRadialTreeLayout`) with a left-to-right hierarchical layout (`computeLRTreeLayout`). Each independent subtree is positioned in a 3-column grid. Layout uses a memoised Reingold-Tilford algorithm (O(N) with `heightCache`) to handle graphs with 2000+ nodes without freezing the browser.

- **Rectangular box nodes**: `shape: 'circle'` replaced with `shape: 'box'`. Labels show process name and PID on separate lines. Node width capped at 280 px.

- **Fixed colour scheme**: colours are now permanent and never altered by mouse interactions. Parent Process: red (`#b91c1c`). Selected child/grandchild: blue (`#1d4ed8`). Unselected: gray (`#4b5563`).

- **+MORE / -LESS pagination**: parent nodes with more than 10 direct children collapse the excess behind a red `+N MORE` circle. Double-click to expand; double-click again to collapse. Grandchildren of hidden nodes are recursively hidden.

- **Right-click filter**: right-clicking any node shows 'Filter only: `<root name>`'. Hides all other trees and shows a `<- SHOW ALL` button to restore them.

- **Subtree drag - dual mode**: dragging a Parent Process (root node) moves the entire subtree by default. Double-clicking the root toggles SOLO MODE (white border) where drag moves only the root independently. Child and grandchild nodes always drag individually.

- **Ghost nodes (Sysmon-only processes)**: processes with Sysmon activity in the queried window but no EID 4688 appear as green-bordered nodes. Process born before the window but active within it is now visible instead of silently absent.

- **PROCESS FILTER / EventID filter error message**: when a filter returns zero results but events exist in the time window, the status bar now shows a specific message distinguishing 'no events in window' from 'filter matched nothing'.

- **EXPORT PDF - Executive Summary**: cover page replaced with Executive Summary + Acknowledgements text page. Canvas graph capture removed from cover.

- **EXPORT PDF - pie chart**: last page shows Top Parent Processes by frequency. Leader lines with anti-overlap sorting per side. Legend in two columns. Counts only root nodes.

- **EXPORT PDF - table columns**: tables now show `Process | Parent | User | Host`. PID, Command Line, and Alerts columns removed.

### OSD Plugin

- **Native sidebar entry**: WPTV registered as a native OSD UI Plugin (`Forensics - Wazuh Process Tree Viewer`, route `/app/wptv`). Pre-built JavaScript bundle (~2.5KB), DOM-only rendering - no TypeScript or npm build required. Nginx reverse proxy on port 5443 handles TLS for the iframe. `allow-downloads` added to iframe sandbox to enable PDF export from within the plugin.

### Bug Fixes

- **`expand_node` returning `None`**: `server.py` called `.get()` on the return value of `expand_node` without checking for `None` first, causing `AttributeError: 'NoneType' object has no attribute 'get'`. Added defensive guard: `if result is None: result = {'nodes': [], 'edges': [], 'stats': {'total': 0}}`.

- **Orphaned code block at global scope**: a stale copy of the old `generateFullReport` body was executing at page load outside any function, causing `ReferenceError: doc is not defined` that silently stopped drag/pan event handler registration. Block removed.

- **`allow-downloads` missing from iframe sandbox**: PDF export was silently blocked by the browser inside the OSD iframe. Fixed by adding `allow-downloads` to the sandbox attribute in `wptv.plugin.js`.

- **`TypeError: Cannot read properties of null` on ANALYZE**: elements removed from the HTML (Relations and Comments tabs) still had active `getElementById()` references in `loadTree()`, `showDetailPanel()`, and `showNetworkNodeInfo()`. All stale references removed.

- **`network.once()` before network creation**: `applyChildrenPagination()` was called before `new vis.Network()`, causing `Cannot read properties of null (reading 'once')`. Moved to after network creation and event registration.

- **MORE node at graph origin**: MORE nodes were added to `nodesDataset` without `x`/`y` coordinates; `vis.DataSet.add()` defaults to `(0, 0)`. Fixed by calling `network.getPosition(lastVisibleChildId)` after network creation and assigning those coordinates to the MORE node.

- **`computeLRTreeLayout` O(N²) freeze**: `subtreeH()` recomputed the height of every descendant for every ancestor without caching, causing O(N²) calls on large graphs (confirmed at 2051 nodes). Added `heightCache`; each node's height is now computed once.

- **Orphan nodes after MORE pagination**: `applyChildrenPagination` removed direct hidden children but not their descendants, leaving disconnected grandchildren. Fixed with `collectSubtree()` BFS that recursively collects all descendants before removal.

- **JavaScript scope errors in Discover link builder**: `discoverIndex` declared with `let` after its first assignment inside `buildDiscoverLink()`, causing `ReferenceError: Cannot access 'discoverIndex' before initialization`. `indexPattern` declared inside an `if` block but used outside it, causing `ReferenceError: indexPattern is not defined`. Both declarations moved before their usage scope.
