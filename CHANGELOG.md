# Changelog

## v2.1 - 2026-07-30

### UI / UX

- **LR tree layout (mind-map style)**: replaced the radial layout (`computeRadialTreeLayout`) with a left-to-right hierarchical layout (`computeLRTreeLayout`). Each independent subtree is positioned in a 3-column grid so multiple process trees spread across the screen instead of stacking vertically. Layout uses a memoised Reingold-Tilford algorithm (O(N) with `heightCache`) to handle graphs with 2000+ nodes without freezing the browser.
- **Rectangular box nodes**: `shape: 'circle'` replaced with `shape: 'box'`. Labels show process name and PID on separate lines. Node width capped at 280 px so long paths wrap cleanly.
- **Fixed colour scheme**: colours are now permanent and never altered by mouse interactions.
  - **Parent Process → red** (`#b91c1c`, white text) - immediately identifiable as the tree root at a glance, always.
  - **Selected child/grandchild → blue** (`#1d4ed8`, white text) - single click; cleared on next click or background click.
  - **Unselected children/grandchildren → gray** (`#4b5563`) - neutral baseline.
- **+MORE / -LESS pagination**: parent nodes with more than 10 direct children collapse the excess behind a red `+N MORE` circle. Double-click the MORE node to expand all hidden children (shown in place, anchored at the MORE node position); double-click again to collapse. Grandchildren of hidden nodes are recursively hidden so no orphan nodes are left floating on screen.
- **Right-click → Filter tree**: right-clicking any node shows a context menu with "Filter only: `<root name>`". All other trees are hidden and a **← SHOW ALL** button appears in the toolbar to restore them. Canvas native "Save image" context menu is suppressed.
- **← SHOW ALL toolbar button**: appears only when a tree is filtered; clicking it restores all process trees and hides the button.
- **ANALYZE button**: renamed from "ANALYZE AGENT". Enter key in any input field (Agent ID, Host, IP, Filter) also triggers analysis.
- **EXPORT ▾ dropdown**: replaces the single "EXPORT PNG" button. Options:
  - **Export PNG (HD)**: captures the graph at 3× resolution for use in documents and reports.
  - **Export PDF**: generates a PDF with a styled header and a full process inventory table (order, name, PID, user, command line, alert count).
- **Status bar (left-aligned)**: `PROCESSES: X | AGENT: 009 | UPDATED: HH:MM:SS  (Loaded in Xms - X nodes)`. "Loaded in" moved from the right side to inline with the process count.
- **Panel title**: static "WPTV — Process Details" header above the detail panel at all times.
- **Tabs reduced to 3**: side panel now shows only **Basic Properties**, **Alerts**, and **Detections**. Relations and Comments tabs removed.
- **Subtree drag — dual mode**:
  - **Parent Process (root node) drag**: moves the entire subtree (parent + all children + MORE node + expanded MORE children). Default mode.
  - **Double-click Parent Process → SOLO MODE**: border turns white to indicate mode; subsequent drag moves only the parent node independently, allowing the analyst to reposition it closer to or further from its subtree. Double-click again to return to tree-drag mode.
  - **Child/grandchild drag**: always moves only that individual node freely (no descendants follow), so nodes can be rearranged within the tree.
- **Ghost nodes** (Sysmon-only processes): processes that have Sysmon activity within the queried window but no EID 4688 (born before the window) appear as green-bordered nodes, making previously invisible processes visible.

### Bug Fixes

- **`TypeError: Cannot read properties of null`** on ANALYZE click: `detailConnections`, `detailRelations`, `relationsEmpty`, `commentsList`, `commentsEmpty`, `commentInput`, and `commentSubmitBtn` elements were removed from the HTML alongside their tabs but JavaScript references to them were left in `loadTree()`, `showDetailPanel()`, and `showNetworkNodeInfo()`. All `getElementById()` calls to removed elements now removed.
- **`network.once()` called before network creation**: `applyChildrenPagination()` was inserted before `network = new vis.Network(...)`, causing `Cannot read properties of null (reading 'once')`. Moved after network creation and event registration.
- **MORE node positioned at graph origin**: MORE nodes were added to `nodesDataset` without explicit `x`/`y` coordinates. `vis.DataSet.add()` without coordinates defaults to `(0, 0)`, so expanded children appeared at the graph origin instead of near the parent. Fixed by querying `network.getPosition(lastVisibleChildId)` after network creation and setting `x`/`y` on the MORE node accordingly.
- **`computeLRTreeLayout` O(N²) freeze**: `subtreeH()` recomputed the height of every descendant for every ancestor without caching, resulting in O(N²) recursive calls on large graphs (e.g. 2051 nodes). Added `heightCache` dictionary; each node's height is computed once and reused, reducing to O(N) total calls.
- **Orphan nodes after MORE pagination**: `applyChildrenPagination` removed direct hidden children but not their descendants, leaving grandchildren as disconnected nodes. Fixed with `collectSubtree()` BFS that recursively collects all descendants before removal.

### Documentation

- README updated to v2.1: removed "What's New" historical sections, updated Graph Interactions and Understanding the Graph tables, updated detail panel tab list.
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


