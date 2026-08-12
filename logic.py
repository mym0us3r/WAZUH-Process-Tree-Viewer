import json
import os
import gzip
import logging
import time as _time
from datetime import datetime, timedelta, timezone
import dateutil.parser

# ── Sysmon EID groupings ────────────────────────────────────────────────────
#
# ENRICHMENT_EVENT_IDS  (EID 1, 3, 7, 11)
#   Dedicated panel sections: EID 1 → hashes/integrity, EID 3 → network
#   connections, EID 7 → loaded DLLs, EID 11 → created files.
#
# SYSMON_ALL_DETECTION_EIDS  (EID 1, 3, 6, 7, 8, 9, 10, 11, 13, 17, 18, 20, 24, 25, 29)
#   Every Sysmon EID that carries a Wazuh detection rule. All of them
#   surface in the Alerts tab (rule ID, level, description, MITRE, Discover
#   link). EIDs not in ENRICHMENT_EVENT_IDS have no dedicated panel section
#   but their rule metadata is still fully collected.
#
# Source: Native Sysmon Rewrite by m0us3r (Unified-Sysmon-Configs)
#         https://github.com/mym0us3r/Unified-Sysmon-Configs
# ────────────────────────────────────────────────────────────────────────────
SYSMON_PROCESS_CREATE = '1'
SYSMON_IMAGE_LOAD     = '7'
SYSMON_FILE_CREATE    = '11'
SYSMON_NETWORK        = '3'

logger = logging.getLogger('wptv.logic')

ENRICHMENT_EVENT_IDS = (SYSMON_PROCESS_CREATE, SYSMON_IMAGE_LOAD, SYSMON_FILE_CREATE, SYSMON_NETWORK)

SYSMON_ALL_DETECTION_EIDS = frozenset({
    '1',  # EID  1  - Process Creation
    '3',  # EID  3  - Network Connection
    '6',  # EID  6  - Driver Load (BYOVD / EDR-killer)
    '7',  # EID  7  - Image Load (DLL hijack, vaultcli.dll)
    '8',  # EID  8  - CreateRemoteThread (injection)
    '9',  # EID  9  - Raw Access Read (credential access)
    '10', # EID 10  - Process Access (LSASS)
    '11', # EID 11  - File Create
    '13', # EID 13  - Registry Value Set (persistence)
    '17', # EID 17  - Pipe Created (Cobalt Strike C2)
    '18', # EID 18  - Pipe Connected
    '20', # EID 20  - WmiEvent Consumer (persistence)
    '24', # EID 24  - Clipboard Change (ClickFix T1204.004)
    '25', # EID 25  - Process Tampering (hollowing/herpaderping)
    '29', # EID 29  - File Executable Detected (new PE drop)
})

# ── Critical Windows Audit Event IDs ────────────────────────────────────────
# Standard Windows Security / System events that every SOC should monitor.
# When indexed by Wazuh, WPTV correlates them to the relevant process node
# and surfaces them in the Alerts tab alongside Sysmon detections.
# These require Windows audit policies to be enabled on the endpoint.
WINDOWS_AUDIT_DETECTION_EIDS = frozenset({
    '1102',  # Security log cleared (evidence tampering)
    '4104',  # PowerShell script block logging (fileless malware)
    '4616',  # System time changed (log tampering / evasion)
    '4624',  # Successful logon
    '4625',  # Failed logon (brute force / password spray)
    '4648',  # Explicit credential logon (lateral movement / Pass-the-Hash)
    '4663',  # Object access attempt (file / registry exfiltration)
    '4672',  # Special privileges assigned to new logon (privilege escalation)
    '4698',  # Scheduled task created (T1053 persistence)
    '4702',  # Scheduled task updated (persistence evasion)
    '4719',  # System audit policy changed (tampering)
    '4720',  # User account created (rogue / backdoor account)
    '4726',  # User account deleted (covering tracks)
    '4728',  # Member added to security-enabled global group (privilege escalation)
    '4732',  # Member added to security-enabled local group (privilege escalation)
    '4740',  # Account lockout (brute force indicator)
    '4768',  # Kerberos TGT requested (Kerberoasting / Golden Ticket)
    '4769',  # Kerberos service ticket requested (lateral movement)
    '4771',  # Kerberos pre-auth failed (credential attacks)
    '4689',  # Process Termination - correlates end-of-life to existing tree nodes
    '4776',  # NTLM credential validation (Pass-the-Hash / NTLM relay)
    '4964',  # Special groups assigned to new logon (privileged group monitoring)
    '7045',  # New service installed (T1543 persistence)
})

# Hard time budget for the archives.json file scan (fallback path).
# When the Wazuh archive index (wazuh-archives-*) is available this scan is
# never reached. When it IS reached (no archive index configured), large time
# windows (>14 days) can produce hundreds of thousands of lines in compressed
# .gz files, exceeding gunicorn's --timeout and triggering a SIGKILL.
# Stopping early is safer than losing the entire response — whatever was
# collected before the timeout is returned to the caller with a warning.
ARCHIVE_SCAN_TIMEOUT = 90  # seconds

# Combined gate: all EIDs that WPTV surfaces in the Alerts tab.
ALL_DETECTION_EIDS = SYSMON_ALL_DETECTION_EIDS | WINDOWS_AUDIT_DETECTION_EIDS

class ProcessTreeLogic:
    def __init__(self):
        self.log_path = "/var/ossec/logs/alerts/alerts.json"
        # Analyst notes stored as a flat JSON file - last-write-wins is
        # acceptable for an internal tool without concurrent write contention.
        self.comments_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'comments_store.json')

    def _resolve_range(self, hours_back=None, start=None, end=None):
        """
        Resolves the query window. If start/end (ISO 8601 strings, e.g. produced by
        JS Date.toISOString()) are provided, they take priority over hours_back.
        Returns (start_dt, end_dt) as timezone-aware UTC datetimes.
        """
        now_utc = datetime.now(timezone.utc)

        if start and end:
            start_dt = dateutil.parser.isoparse(start)
            end_dt = dateutil.parser.isoparse(end)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
            return start_dt, end_dt

        hours = float(hours_back) if hours_back is not None else 24.0
        return now_utc - timedelta(hours=hours), now_utc

    def _iter_log_paths(self, start_dt, end_dt):
        """
        Builds the list of log files to scan to cover the requested window.
        Covers both the current file (alerts.json, not yet rotated) and the
        daily rotated files under <base>/<year>/<Month>/ossec-alerts-<day>.json[.gz].

        IMPORTANT: for today's date, ALSO checks the rotated file in case Wazuh
        already rotated today's logs (e.g. after a manager restart mid-day).
        When this happens, the day's events are split between the rotated file
        (events before the restart) and the live alerts.json (events after), so
        BOTH must be read to cover the full day - including short windows like
        'Last 5 Minutes' that would otherwise miss older events from today.

        Example: on 2026-07-25, after a Wazuh restart, both
          /var/ossec/logs/alerts/2026/Jul/ossec-alerts-25.json  (pre-restart)
          /var/ossec/logs/alerts/alerts.json                     (post-restart)
        must be scanned. The original code only added alerts.json for today,
        silently missing every 4688 event created before the restart.
        """
        now = datetime.now(timezone.utc)
        base_dir = os.path.dirname(self.log_path)

        paths = []
        seen_dates = set()
        cursor = start_dt
        while cursor.date() <= end_dt.date():
            date_key = cursor.date()
            if date_key not in seen_dates:
                seen_dates.add(date_key)

                year  = cursor.strftime('%Y')
                month = cursor.strftime('%b')
                day   = cursor.strftime('%d')
                day_dir = os.path.join(base_dir, year, month)

                if date_key == now.date():
                    # Live file (events after last rotation)
                    if os.path.exists(self.log_path):
                        paths.append(self.log_path)
                    # Also check rotated file for TODAY - Wazuh may have already
                    # rotated mid-day (e.g. on manager restart), splitting today's
                    # events between the rotated file and the live alerts.json
                    for ext in ['.json', '.json.gz']:
                        rotated_today = os.path.join(day_dir, f"ossec-alerts-{day}{ext}")
                        if os.path.exists(rotated_today) and rotated_today not in paths:
                            paths.append(rotated_today)
                else:
                    gz_path    = os.path.join(day_dir, f"ossec-alerts-{day}.json.gz")
                    plain_path = os.path.join(day_dir, f"ossec-alerts-{day}.json")
                    if os.path.exists(gz_path):
                        paths.append(gz_path)
                    elif os.path.exists(plain_path):
                        paths.append(plain_path)

            cursor += timedelta(days=1)

        logger.debug("_iter_log_paths: %d file(s) for window %s->%s: %s",
                     len(paths), start_dt.date(), end_dt.date(), paths)
        return paths

    def _open_log(self, path):
        if path.endswith('.gz'):
            return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
        return open(path, 'r', encoding='utf-8', errors='replace')

    def _fetch_from_indexer(self, agent_id, host, ip, start_dt, end_dt):
        """
        Query the Wazuh Indexer (OpenSearch) for alert events in the given window.
        Returns a list of raw alert dicts (same shape as json.loads() on a line from
        alerts.json) so the caller doesn't need to know which source was used.

        Activated only when WPTV_INDEXER_URL env var is set. All other Indexer
        env vars (WPTV_INDEXER_USER/PASSWORD/CA_CERT/INDEX) must also be set for
        a successful connection; missing any of them raises an exception that causes
        fetch_events_and_enrichment to fall back to the file-based scan.

        The advantage over the file scan: the Indexer filters server-side by time
        and agent, returning only matching documents instead of making us read
        potentially tens of MB of today's live alerts.json.
        """
        import requests as _req

        url   = os.getenv('WPTV_INDEXER_URL', '').rstrip('/')
        index = os.getenv('WPTV_INDEXER_INDEX', 'wazuh-alerts-*')
        user  = os.getenv('WPTV_INDEXER_USER', '')
        pwd   = os.getenv('WPTV_INDEXER_PASSWORD', '')
        ca    = os.getenv('WPTV_INDEXER_CA_CERT', '')

        if not url:
            raise EnvironmentError("WPTV_INDEXER_URL not set - using file fallback")

        must = [{"range": {"timestamp": {
            "gte": start_dt.isoformat(),
            "lte": end_dt.isoformat()
        }}}]
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        elif host:
            must.append({"match_phrase": {"data.win.system.computer": host}})
        elif ip:
            must.append({"term": {"agent.ip": ip}})

        query = {
            "size": 10000,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"must": must}},
            "_source": True
        }

        resp = _req.post(
            f"{url}/{index}/_search",
            json=query,
            auth=(user, pwd) if user else None,
            verify=ca if ca else False,
            timeout=30
        )
        resp.raise_for_status()
        hits = resp.json().get('hits', {}).get('hits', [])
        logger.info("Indexer returned %d hits for %s window %.2fh",
                    len(hits), agent_id or host or ip,
                    (end_dt - start_dt).total_seconds() / 3600)
        # Each hit's _source is the raw alert document - same shape as alerts.json lines
        return [h['_source'] for h in hits]

    def _iter_archive_paths(self, start_dt, end_dt):
        """
        Yield archive log file paths covering the requested time window.
        Archives directory: /var/ossec/logs/archives/
        Pattern matches _iter_log_paths but for ossec-archive-DD files.
        """
        now      = datetime.now(timezone.utc)
        base_dir = '/var/ossec/logs/archives'
        live     = os.path.join(base_dir, 'archives.json')
        paths    = []
        seen     = set()

        cursor = start_dt
        while cursor.date() <= end_dt.date():
            dk = cursor.date()
            if dk not in seen:
                seen.add(dk)
                year  = cursor.strftime('%Y')
                month = cursor.strftime('%b')
                day   = cursor.strftime('%d')
                day_dir = os.path.join(base_dir, year, month)

                if dk == now.date():
                    if os.path.exists(live):
                        paths.append(live)
                    for ext in ['.json', '.json.gz']:
                        rot = os.path.join(day_dir, f'ossec-archive-{day}{ext}')
                        if os.path.exists(rot) and rot not in paths:
                            paths.append(rot)
                else:
                    for ext in ['.json', '.json.gz']:
                        rot = os.path.join(day_dir, f'ossec-archive-{day}{ext}')
                        if os.path.exists(rot):
                            paths.append(rot)
                            break
            cursor += timedelta(hours=1)

        return paths

    def _fetch_sysmon_from_archives(self, agent_id, host, ip, start_dt, end_dt, existing_enrichment):
        """
        Scan archives.json for ALL Sysmon events in ALL_DETECTION_EIDS —
        including events that did NOT trigger a Wazuh rule (not in alerts/).

        Performance strategy:
          1. Pre-filter each line by agent/host string before JSON decode
          2. Pre-filter each line by at least one target EID string
          3. Only JSON-decode lines that pass both checks
          4. Skip events outside the time window

        Returns a supplementary sysmon_detections dict {pid: [detection, ...]}
        containing ONLY events not already present in existing_enrichment.
        """
        if agent_id:
            pre_agent = f'"id":"{agent_id}"'
        elif host:
            pre_agent = host.lower()
        else:
            return {}

        # String patterns to pre-check before JSON decode
        target_eids_str = [f'"eventID":"{eid}"' for eid in ALL_DETECTION_EIDS]
        # Exclude 4688 — already covered completely by alerts/Indexer
        target_eids_str = [s for s in target_eids_str if '"eventID":"4688"' not in s]

        archive_paths = self._iter_archive_paths(start_dt, end_dt)
        if not archive_paths:
            return {}

        supplement = {}   # pid -> [detections not yet in existing_enrichment]
        lines_read = skipped = found = 0
        t0 = _time.monotonic()

        # Build a set of (ts, eventId) already in enrichment to avoid duplicates
        existing_keys = set()
        for pid_dets in existing_enrichment.get('sysmon_detections', {}).values():
            for d in pid_dets:
                existing_keys.add((d.get('time', ''), str(d.get('eventId', ''))))

        GENERIC_RULES = {'67027', '61612', '67020', '60012', '60010', '', 'N/A'}

        for path in archive_paths:
            try:
                opener = gzip.open if path.endswith('.gz') else open
                mode   = 'rt'
                with opener(path, mode, encoding='utf-8', errors='replace') as fh:
                    for raw in fh:
                        lines_read += 1
                        # Pre-filter 1: agent/host
                        if pre_agent not in raw and (not host or host not in raw):
                            skipped += 1
                            continue
                        # Pre-filter 2: any target EID
                        if not any(eid_s in raw for eid_s in target_eids_str):
                            skipped += 1
                            continue
                        try:
                            evt = json.loads(raw)
                        except (json.JSONDecodeError, ValueError):
                            continue

                        data_win = evt.get('data', {}).get('win', {})
                        sys_f    = data_win.get('system', {})
                        ev       = data_win.get('eventdata', {})
                        event_id = sys_f.get('eventID', '')

                        if event_id not in ALL_DETECTION_EIDS or event_id == '4688':
                            continue

                        # Agent filter
                        agent_d = evt.get('agent', {})
                        if agent_id and agent_d.get('id') != agent_id:
                            continue
                        if host and host.lower() not in sys_f.get('computer', '').lower():
                            continue

                        # Timestamp filter
                        ts_raw = evt.get('timestamp', '')
                        try:
                            ts = dateutil.parser.isoparse(ts_raw).replace(tzinfo=timezone.utc)
                            if not (start_dt <= ts <= end_dt):
                                continue
                        except Exception:
                            continue

                        _pid_ev2  = ev.get('processId') or ev.get('newProcessId') or ev.get('targetProcessId')
                        _pid_sys2 = sys_f.get('processID') if not _pid_ev2 else None
                        pid = self._normalize_pid(_pid_ev2 or _pid_sys2)
                        if not pid:
                            continue
                        _pid_field2 = ('data.win.system.processID'
                                       if _pid_sys2 and not _pid_ev2
                                       else 'data.win.eventdata.processId')
                        _pid_value2 = str(_pid_ev2 or _pid_sys2 or '')

                        ts_key = (ts_raw, str(event_id))
                        if ts_key in existing_keys:
                            continue   # already captured from alerts

                        # Build detection entry
                        rule_s = evt.get('rule', {})
                        rid    = rule_s.get('id', '')
                        entry  = {
                            'eventId':   event_id,
                            'ruleId':    rid if rid not in GENERIC_RULES else '',
                            'ruleLevel': int(rule_s.get('level') or 0),
                            'ruleDesc':  (rule_s.get('description', '')
                                          if rid not in GENERIC_RULES
                                          else f'EID {event_id} (archive)'),
                            'mitre':     rule_s.get('mitre', {}),
                            'providerName': sys_f.get('providerName', 'Microsoft-Windows-Sysmon'),
                            'time':      ts_raw,
                            'computer':  sys_f.get('computer', ''),
                            'image':     ev.get('image', ev.get('imageLoaded',
                                         ev.get('targetFilename', ''))),
                            'pidField':  _pid_field2,
                            'pidValue':  _pid_value2,
                            'sourceIndex': 'wazuh-archives-*',
                            'source':    'archive',
                        }
                        supplement.setdefault(pid, []).append(entry)
                        existing_keys.add(ts_key)
                        found += 1
            except Exception as exc:
                logger.warning('archive scan error on %s: %s', path, exc)

            # Hard timeout guard: stop before gunicorn's SIGKILL.
            # Large windows (>14 days) can push hundreds of .gz files into this
            # loop; ARCHIVE_SCAN_TIMEOUT gives the caller a partial result rather
            # than a worker crash. The archive index path (wazuh-archives-*) avoids
            # this entirely — enable it via WPTV_ARCHIVE_INDEX for long queries.
            if _time.monotonic() - t0 > ARCHIVE_SCAN_TIMEOUT:
                logger.warning(
                    'archive file scan timeout after %.0fs (processed %d/%d files) - '
                    'stopping early. Enable wazuh-archives-* index for full coverage '
                    'on large time windows.',
                    _time.monotonic() - t0, archive_paths.index(path) + 1, len(archive_paths))
                break

        elapsed = _time.monotonic() - t0
        logger.info('archive sysmon scan: %d lines, %d skipped, %d new events in %.2fs (files: %d)',
                    lines_read, skipped, found, elapsed, len(archive_paths))
        return supplement

    def _normalize_pid(self, pid_raw):
        """
        Normalize a PID value to a decimal string for consistent enrichment lookup.

        Sysmon events report PIDs as decimal integers ('18564').
        Windows Audit events report PIDs as hex strings ('0x4884').
        EID 4688 (newProcessId) is also hex.

        All of these must resolve to the same key so that _enrich() can find
        detections from ANY event type when looking up a tree node by its PID.
        Returns None when the input is empty or unparseable.
        """
        if not pid_raw:
            return None
        s = str(pid_raw).strip().lower()
        try:
            if s.startswith('0x'):
                return str(int(s, 16))
            return str(int(float(s)))   # handles '18564' and edge-case floats
        except (ValueError, TypeError):
            return s   # return as-is; caller will get a cache-miss, not a crash

    def _fetch_from_archive_index(self, agent_id, host, ip, start_dt, end_dt, existing_enrichment):
        """
        Query wazuh-archives-* (OpenSearch) for ALL_DETECTION_EIDS events that
        are NOT already captured in existing_enrichment (alerts already indexed).

        wazuh-archives-* contains EVERY event forwarded by Filebeat regardless
        of whether it triggered a Wazuh rule.  This is the fast path for events
        such as EID 4689 (Process Termination) and EID 4104 (PowerShell Script
        Block) that may not generate alerts but are still valuable for forensic
        correlation in the process tree.

        Prerequisites on the Wazuh server:
            filebeat.yml:  archives.enabled: true
            OSD:           Index pattern wazuh-archives-* created in
                           Dashboards Management > Index Patterns

        Enabled when WPTV_ARCHIVE_INDEX is set (default: wazuh-archives-*).
        Set WPTV_ARCHIVE_INDEX= (empty) to disable and force the file scan.
        """
        import requests as _req

        url        = os.getenv('WPTV_INDEXER_URL', '').rstrip('/')
        arc_index  = os.getenv('WPTV_ARCHIVE_INDEX', 'wazuh-archives-*').strip()
        user       = os.getenv('WPTV_INDEXER_USER', '')
        pwd        = os.getenv('WPTV_INDEXER_PASSWORD', '')
        ca         = os.getenv('WPTV_INDEXER_CA_CERT', '')

        if not url:
            raise EnvironmentError("WPTV_INDEXER_URL not set")
        if not arc_index:
            raise EnvironmentError("WPTV_ARCHIVE_INDEX explicitly disabled (empty)")

        # Deduplicate against events already found in wazuh-alerts-*
        existing_keys = set()
        for pid_dets in existing_enrichment.get('sysmon_detections', {}).values():
            for d in pid_dets:
                existing_keys.add((d.get('time', ''), str(d.get('eventId', ''))))

        # Query for ALL detection EIDs except 4688 (tree structure comes from alerts)
        arc_eids = list(ALL_DETECTION_EIDS - {'4688'})

        must = [
            {'range': {'timestamp': {
                'gte': start_dt.isoformat(),
                'lte': end_dt.isoformat()
            }}},
            {'terms': {'data.win.system.eventID': arc_eids}},
        ]
        if agent_id:
            must.append({'term': {'agent.id': agent_id}})
        elif host:
            must.append({'match_phrase': {'data.win.system.computer': host}})
        elif ip:
            must.append({'term': {'agent.ip': ip}})

        GENERIC_RULES = {'67027', '61612', '67020', '60012', '60010', '', 'N/A'}
        supplement   = {}
        total_hits   = 0
        page         = 0
        search_after = None
        t0           = _time.monotonic()

        while page < 20:   # safety cap: 20 × 5000 = 100k events
            query = {
                'size': 5000,
                'sort': [{'timestamp': {'order': 'asc'}}, {'_id': {'order': 'asc'}}],
                'query': {'bool': {'must': must}},
                '_source': True,
            }
            if search_after:
                query['search_after'] = search_after

            resp = _req.post(
                f"{url}/{arc_index}/_search",
                json=query,
                auth=(user, pwd) if user else None,
                verify=ca if ca else False,
                timeout=30
            )
            resp.raise_for_status()
            hits = resp.json().get('hits', {}).get('hits', [])
            if not hits:
                break

            page        += 1
            total_hits  += len(hits)

            for h in hits:
                doc      = h['_source']
                data_win = doc.get('data', {}).get('win', {})
                sys_f    = data_win.get('system', {})
                ev       = data_win.get('eventdata', {})
                event_id = sys_f.get('eventID', '')

                if event_id not in ALL_DETECTION_EIDS or event_id == '4688':
                    continue

                ts_raw = doc.get('timestamp', '')
                ts_key = (ts_raw, str(event_id))
                if ts_key in existing_keys:
                    continue

                # Track which field held the PID — needed to build a correct
                # Discover link later (field name differs by event type).
                _pid_ev  = ev.get('processId') or ev.get('newProcessId') or ev.get('targetProcessId')
                _pid_sys = sys_f.get('processID') if not _pid_ev else None
                pid = self._normalize_pid(_pid_ev or _pid_sys)
                if not pid:
                    continue
                _pid_field = ('data.win.system.processID'
                              if _pid_sys and not _pid_ev
                              else 'data.win.eventdata.processId')
                _pid_value = str(_pid_ev or _pid_sys or '')

                rule_s = doc.get('rule', {})
                rid    = rule_s.get('id', '')
                entry  = {
                    'eventId':      event_id,
                    'ruleId':       rid if rid not in GENERIC_RULES else '',
                    'ruleLevel':    int(rule_s.get('level') or 0),
                    'ruleDesc':     (rule_s.get('description', '')
                                    if rid not in GENERIC_RULES
                                    else f'EID {event_id} (archive index)'),
                    'mitre':        rule_s.get('mitre', {}),
                    'providerName': sys_f.get('providerName', 'Windows'),
                    'time':         ts_raw,
                    'computer':     sys_f.get('computer', ''),
                    'image':        ev.get('image',
                                    ev.get('processName',
                                    ev.get('imageLoaded',
                                    ev.get('targetFilename', '')))),
                    'pidField':     _pid_field,
                    'pidValue':     _pid_value,
                    'sourceIndex':  arc_index,
                    'source':       'archive_index',
                }
                supplement.setdefault(pid, []).append(entry)
                existing_keys.add(ts_key)

            if len(hits) < 5000:
                break   # last page
            search_after = hits[-1].get('sort')

        elapsed = _time.monotonic() - t0
        new_dets = sum(len(v) for v in supplement.values())
        logger.info(
            'archive index scan: %d hits, %d pages, %d new detections (%d pids) in %.2fs',
            total_hits, page, new_dets, len(supplement), elapsed)
        return supplement

    def fetch_events_and_enrichment(self, agent_id=None, hours_back=24, start=None, end=None, host=None, ip=None):
        """
        Combines what used to be two separate methods (fetch_events for 4688,
        fetch_sysmon_enrichment for Sysmon EventID 1/3/7/11) into a single
        pass over the log files. They previously each called
        _iter_log_paths() and read the exact same files independently - for a
        live (non-rotated) alerts.json, which can be tens of MB and covers
        every agent in the environment, reading and line-iterating it twice
        roughly doubled query time for no benefit, since both scans read
        identical bytes. This was the dominant cost behind slow queries even
        for narrow windows like "5 minutes, one host" - the time window only
        limits which *rotated* files get opened (see _iter_log_paths), not
        how much of the current live file must still be scanned line by line.

        Returns (events, enrichment) - same shapes fetch_events and
        fetch_sysmon_enrichment used to return individually.
        """
        t0 = _time.monotonic()
        events = []
        enrichment = {'process': {}, 'imageLoads': {}, 'fileCreates': {}, 'connections': {},
                      'sysmon_detections': {}, 'sysmon_images': {}}
        start_dt, end_dt = self._resolve_range(hours_back, start, end)
        logger.debug("fetch start: agent=%s host=%s ip=%s range=%s->%s",
                     agent_id, host, ip, start_dt, end_dt)

        # ── DIAGNOSTIC: log exact time window so we can verify filtering ────
        logger.info("TIME WINDOW: start=%s  end=%s  (span=%.2fh)",
                    start_dt.isoformat(), end_dt.isoformat(),
                    (end_dt - start_dt).total_seconds() / 3600)

        # ── Primary path: Wazuh Indexer (OpenSearch) ─────────────────────────
        if os.getenv('WPTV_INDEXER_URL'):
            try:
                raw_docs = self._fetch_from_indexer(agent_id, host, ip, start_dt, end_dt)
                for item in raw_docs:
                    data_win = item.get('data', {}).get('win', {})
                    sys_f = data_win.get('system', {})
                    agent = item.get('agent', {})
                    event_id = sys_f.get('eventID', '')
                    is_4688  = event_id == '4688'
                    is_sysmon = event_id in ALL_DETECTION_EIDS
                    if agent_id and agent.get('id') != agent_id:
                        continue
                    if host and host.lower() not in sys_f.get('computer', '').lower():
                        continue
                    ev = data_win.get('eventdata', {})
                    _pid_ev3  = ev.get('processId') or ev.get('newProcessId')
                    _pid_sys3 = sys_f.get('processID') if not _pid_ev3 else None
                    pid = _pid_ev3 or _pid_sys3
                    _pid_field3 = ('data.win.system.processID'
                                   if _pid_sys3 and not _pid_ev3
                                   else 'data.win.eventdata.processId')
                    _pid_value3 = str(_pid_ev3 or _pid_sys3 or '')
                    if is_4688:
                        events.append(item)
                    elif is_sysmon and pid:
                        # Store process image from ANY Sysmon event so we can
                        # create ghost nodes for processes without a 4688 in window
                        if ev.get('image') and pid not in enrichment['sysmon_images']:
                            enrichment['sysmon_images'][pid] = ev.get('image')
                        if event_id == SYSMON_PROCESS_CREATE:
                            enrichment['process'][pid] = {
                                'hashes': ev.get('hashes', 'N/A'),
                                'processGuid': ev.get('processGuid', 'N/A'),
                                'integrityLevel': ev.get('integrityLevel', 'N/A'),
                                'company': ev.get('company', 'N/A'),
                                'product': ev.get('product', 'N/A'),
                                'description': ev.get('description', 'N/A'),
                                # Extra fields for ghost node reconstruction
                                'image': ev.get('image', 'N/A'),
                                'parentProcessId': ev.get('parentProcessId', 'N/A'),
                                'user': ev.get('user', 'N/A'),
                                'commandLine': ev.get('commandLine', 'N/A'),
                                'utcTime': sys_f.get('systemTime', 'N/A'),
                            }
                        elif event_id == SYSMON_IMAGE_LOAD:
                            b = enrichment['imageLoads'].setdefault(pid, [])
                            if len(b) < 20: b.append(ev.get('imageLoaded', 'N/A'))
                        elif event_id == SYSMON_FILE_CREATE:
                            b = enrichment['fileCreates'].setdefault(pid, [])
                            if len(b) < 20: b.append(ev.get('targetFilename', 'N/A'))
                        elif event_id == SYSMON_NETWORK:
                            enrichment['connections'].setdefault(pid, []).append({
                                'sourceIp': ev.get('sourceIp', 'N/A'), 'sourcePort': ev.get('sourcePort', 'N/A'),
                                'destinationIp': ev.get('destinationIp', 'N/A'),
                                'destinationPort': ev.get('destinationPort', 'N/A'),
                                'protocol': ev.get('protocol', 'N/A'), 'time': sys_f.get('systemTime', 'N/A')})
                        rule_s = item.get('rule', {})
                        rid = rule_s.get('id', 'N/A')
                        GENERIC = {'67027', '61612', '67020', 'N/A'}
                        if rid not in GENERIC:
                            db = enrichment['sysmon_detections'].setdefault(pid, [])
                            if len(db) < 50:
                                db.append({'eventId': event_id, 'ruleId': rid,
                                    'ruleLevel': int(rule_s.get('level') or 0),
                                    'ruleDesc': rule_s.get('description', 'N/A'),
                                    'mitre': rule_s.get('mitre', {}),
                                    'providerName': sys_f.get('providerName', 'Microsoft-Windows-Sysmon'),
                                    'time': item.get('timestamp', 'N/A'),
                                    'computer': sys_f.get('computer', 'N/A'),
                                    'image': ev.get('image', ev.get('imageLoaded', ev.get('targetFilename', 'N/A'))),
                                    'pidField': _pid_field3,
                                    'pidValue': _pid_value3,
                                    'sourceIndex': os.getenv('WPTV_INDEXER_INDEX', 'wazuh-alerts-*'),
                                    'source': 'alerts'})
                elapsed = _time.monotonic() - t0
                logger.info("fetch done in %.2fs: %d 4688 events, %d sysmon events (Indexer)",
                            elapsed, len(events), sum(len(v) for v in enrichment.values()))

                # ── Supplement: events without Wazuh rules (archives) ────────
                # wazuh-alerts-* only has events that triggered a rule.
                # wazuh-archives-* has ALL events — essential for events like
                # EID 4689 (Process Termination) and EID 4104 (PowerShell Script
                # Block) that may not fire rules but are in ALL_DETECTION_EIDS.
                #
                # Priority:
                #   1. wazuh-archives-* OpenSearch index  (fast, requires
                #      filebeat archives.enabled: true + index pattern in OSD)
                #   2. archives.json filesystem scan       (slower fallback)
                archive_sup    = {}
                archive_source = 'none'
                arc_index_env  = os.getenv('WPTV_ARCHIVE_INDEX', 'wazuh-archives-*').strip()

                if arc_index_env:
                    # Fast path: OpenSearch archive index
                    try:
                        archive_sup    = self._fetch_from_archive_index(
                            agent_id, host, ip, start_dt, end_dt, enrichment)
                        archive_source = 'index'
                    except Exception as arc_e:
                        logger.info(
                            "archive index unavailable (%s) - falling back to file scan",
                            arc_e)
                        archive_sup    = self._fetch_sysmon_from_archives(
                            agent_id, host, ip, start_dt, end_dt, enrichment)
                        archive_source = 'file'
                else:
                    # WPTV_ARCHIVE_INDEX explicitly disabled: use file scan
                    archive_sup    = self._fetch_sysmon_from_archives(
                        agent_id, host, ip, start_dt, end_dt, enrichment)
                    archive_source = 'file'

                if archive_sup:
                    for pid, dets in archive_sup.items():
                        db = enrichment['sysmon_detections'].setdefault(pid, [])
                        db.extend(dets)
                    logger.info(
                        "archive supplement (%s): %d pids, %d new detections added",
                        archive_source,
                        len(archive_sup),
                        sum(len(v) for v in archive_sup.values()))

                return events, enrichment
            except Exception as e:
                logger.warning("Indexer unavailable (%s) - falling back to file scan", e)
                events.clear()
                for k in enrichment: enrichment[k].clear()

        # ── Fallback: file scan ───────────────────────────────────────────────
        pre_filter = None
        if agent_id:
            pre_filter = f'"id":"{agent_id}"'
        elif host:
            pre_filter = f'"computer":"{host}"'
        elif ip:
            pre_filter = f'"ip":"{ip}"'

        if not pre_filter:
            logger.error("fetch_events_and_enrichment called without agent_id, host or ip")
            return events, enrichment

        # Sysmon enrichment correlation only ever supported agent_id/host,
        # never ip - preserved as-is from the original fetch_sysmon_enrichment,
        # not a new restriction introduced by merging the two scans.
        enrichment_enabled = bool(agent_id or host)
        MAX_ITEMS_PER_PID = 20

        log_paths = self._iter_log_paths(start_dt, end_dt)
        logger.info("FILES TO SCAN: %d file(s): %s", len(log_paths), log_paths)

        for path in log_paths:
            try:
                lines_read = prefilter_pass = ts_pass = ts_fail = 0
                ts_sample_fail = []  # first few timestamps that fell OUTSIDE the window
                with self._open_log(path) as f:
                    for line in f:
                        lines_read += 1
                        if pre_filter not in line:
                            continue
                        prefilter_pass += 1

                        is_4688 = '4688' in line
                        is_sysmon = enrichment_enabled and any(f'"eventID":"{eid}"' in line for eid in ALL_DETECTION_EIDS)
                        if not is_4688 and not is_sysmon:
                            continue

                        try:
                            item = json.loads(line)
                            ts_str = item.get('timestamp')
                            if not ts_str: continue

                            event_time = dateutil.parser.isoparse(ts_str)
                            if event_time.tzinfo is None:
                                event_time = event_time.replace(tzinfo=timezone.utc)
                            if not (start_dt <= event_time <= end_dt):
                                ts_fail += 1
                                if len(ts_sample_fail) < 3:
                                    ts_sample_fail.append(ts_str)
                                continue
                            ts_pass += 1

                            data_win = item.get('data', {}).get('win', {})
                            sys = data_win.get('system', {})
                            agent = item.get('agent', {})

                            if agent_id and agent.get('id') != agent_id:
                                continue
                            if host and host.lower() not in sys.get('computer', '').lower():
                                continue

                            # ---- 4688 branch (process creation, builds the tree) ----
                            if is_4688:
                                if ip and ip not in agent.get('ip', ''):
                                    pass  # ip filter only excludes this event from `events`, not from the enrichment branch below
                                else:
                                    events.append(item)

                            # ---- Sysmon enrichment branch ----
                            if is_sysmon:
                                event_id = sys.get('eventID')
                                if event_id in ENRICHMENT_EVENT_IDS:
                                    ev = data_win.get('eventdata', {})

                                    ev_pid = ev.get('processId')
                                    # Store image for ghost node reconstruction (all Sysmon EIDs)
                                    if ev_pid and ev.get('image') and ev_pid not in enrichment['sysmon_images']:
                                        enrichment['sysmon_images'][ev_pid] = ev.get('image')

                                    if event_id == SYSMON_PROCESS_CREATE:
                                        pid = ev_pid
                                        if pid:
                                            enrichment['process'][pid] = {
                                                'hashes': ev.get('hashes', 'N/A'),
                                                'processGuid': ev.get('processGuid', 'N/A'),
                                                'integrityLevel': ev.get('integrityLevel', 'N/A'),
                                                'company': ev.get('company', 'N/A'),
                                                'product': ev.get('product', 'N/A'),
                                                'description': ev.get('description', 'N/A'),
                                                # Extra fields for ghost node reconstruction
                                                'image': ev.get('image', 'N/A'),
                                                'parentProcessId': ev.get('parentProcessId', 'N/A'),
                                                'user': ev.get('user', 'N/A'),
                                                'commandLine': ev.get('commandLine', 'N/A'),
                                                'utcTime': sys.get('systemTime', 'N/A'),
                                            }
                                    elif event_id == SYSMON_IMAGE_LOAD:
                                        pid = ev.get('processId')
                                        if pid:
                                            bucket = enrichment['imageLoads'].setdefault(pid, [])
                                            if len(bucket) < MAX_ITEMS_PER_PID:
                                                bucket.append(ev.get('imageLoaded', 'N/A'))
                                    elif event_id == SYSMON_FILE_CREATE:
                                        pid = ev.get('processId')
                                        if pid:
                                            bucket = enrichment['fileCreates'].setdefault(pid, [])
                                            if len(bucket) < MAX_ITEMS_PER_PID:
                                                bucket.append(ev.get('targetFilename', 'N/A'))
                                    elif event_id == SYSMON_NETWORK:
                                        pid = ev.get('processId')
                                        if pid:
                                            enrichment['connections'].setdefault(pid, []).append({
                                                'sourceIp': ev.get('sourceIp', 'N/A'),
                                                'sourcePort': ev.get('sourcePort', 'N/A'),
                                                'destinationIp': ev.get('destinationIp', 'N/A'),
                                                'destinationPort': ev.get('destinationPort', 'N/A'),
                                                'protocol': ev.get('protocol', 'N/A'),
                                                'time': sys.get('systemTime', 'N/A')
                                            })

                                    # For every Sysmon enrichment event (regardless of type),
                                    # also collect the Wazuh rule that fired so the Detections
                                    # tab can show rule.id, rule.description and a Discover link
                                    # for each correlated Sysmon event - not just the raw content.
                                    rule_s = item.get('rule', {})
                                    rule_id_s = rule_s.get('id', 'N/A')
                                    GENERIC = {'67027', '61612', '67020', 'N/A'}
                                    eid_pid = ev.get('processId')
                                    if eid_pid and rule_id_s not in GENERIC:
                                        det_bucket = enrichment['sysmon_detections'].setdefault(eid_pid, [])
                                        if len(det_bucket) < 50:  # cap per pid
                                            det_bucket.append({
                                                'eventId': event_id,
                                                'ruleId': rule_id_s,
                                                'ruleLevel': int(rule_s.get('level') or 0),
                                                'ruleDesc': rule_s.get('description', 'N/A'),
                                                'mitre': rule_s.get('mitre', {}),
                                                'providerName': sys.get('providerName', 'Microsoft-Windows-Sysmon'),
                                                'time': item.get('timestamp', 'N/A'),
                                                # extra context fields for Discover link
                                                'computer': sys.get('computer', 'N/A'),
                                                'image': ev.get('image', ev.get('imageLoaded', ev.get('targetFilename', 'N/A'))),
                                            })
                        except: continue
                logger.info("FILE %s: %d lines read, %d passed prefilter, "
                            "%d passed timestamp, %d rejected by timestamp%s",
                            path, lines_read, prefilter_pass, ts_pass, ts_fail,
                            f" (samples: {ts_sample_fail})" if ts_sample_fail else "")
            except Exception as e:
                logger.error(f"Error reading {path}: {e}")
                continue

        elapsed = _time.monotonic() - t0
        logger.info("fetch done in %.2fs: %d 4688 events, %d sysmon enrichment events",
                    elapsed, len(events),
                    sum(len(v) for v in enrichment.values()))
        return events, enrichment

    def fetch_events(self, agent_id=None, hours_back=24, start=None, end=None, host=None, ip=None):
        """
        agent_id, host and ip are alternative entry points to identify the target
        endpoint - at least one is required. Host is matched against
        data.win.system.computer (the hostname reported inside the Windows event
        itself), not agent.name - agent.name is Wazuh's cached registration name
        and goes stale if the endpoint is renamed without re-registering the agent.
        data.win.system.computer always reflects the actual current Windows hostname.

        Kept as a standalone method (on top of fetch_events_and_enrichment)
        only for any external/future caller that needs 4688 events without
        paying for the Sysmon enrichment pass at all.
        """
        events, _ = self.fetch_events_and_enrichment(agent_id=agent_id, hours_back=hours_back, start=start, end=end, host=host, ip=ip)
        return events

    def fetch_sysmon_enrichment(self, agent_id=None, hours_back=24, start=None, end=None, host=None):
        """
        Kept as a standalone method (on top of fetch_events_and_enrichment)
        for callers that only need Sysmon enrichment. server.py's hot path
        (the /api/process-tree and /api/process-tree/expand routes) calls
        fetch_events_and_enrichment() directly instead, to get both in one
        pass over the log files.
        """
        _, enrichment = self.fetch_events_and_enrichment(agent_id=agent_id, hours_back=hours_back, start=start, end=end, host=host)
        return enrichment

    def hex_to_dec(self, hex_val):
        """
        Used ONLY to bridge PID formats between two unrelated event sources
        (4688's hex PID vs Sysmon's decimal PID) when looking up enrichment
        data. Never used for the PID/PPID shown to the analyst - those stay
        exactly as logged, so what is on screen matches Discover one-for-one
        during triage.
        """
        if not hex_val: return None
        try: return str(int(str(hex_val), 16))
        except: return str(hex_val)

    @staticmethod
    def _win_basename(path):
        """
        Returns the filename portion of a Windows path (C:\\...\\exe) on any OS.
        os.path.basename() uses posixpath on Linux and only splits on '/', so
        'C:\\Windows\\System32\\cmd.exe' would be returned as-is instead of
        'cmd.exe'. This method always splits on '\\' regardless of the host OS.
        """
        if not path:
            return path
        return path.replace('/', '\\').rsplit('\\', 1)[-1]

    def _parse_latest(self, events):
        """
        Consolidates 4688 events into a dict {pid: latest_process_data}.
        Single parsing point, used by both build_tree and expand_node to avoid
        two diverging implementations of the same field extraction.

        Now accumulates ALL Wazuh rule detections for each PID (not just the
        last ruleId) so the frontend can display a proper alert timeline per
        process, similar to Elastic Security's Visual Event Analyzer which shows
        all rule matches per node. Detections are stored newest-first.
        """
        latest = {}
        # First pass: accumulate all events per pid
        all_events_per_pid = {}
        for item in events:
            data_win = item.get('data', {}).get('win', {})
            ev = data_win.get('eventdata', {})
            pid = (ev.get('newProcessId') or '').lower() or None
            if not pid: continue
            all_events_per_pid.setdefault(pid, []).append(item)

        # Second pass: build latest per pid + collect all detections
        for pid, pid_events in all_events_per_pid.items():
            # Sort by timestamp ascending to find the canonical (latest) event
            pid_events.sort(key=lambda x: x.get('timestamp', ''), reverse=False)
            canonical = pid_events[-1]  # most recent 4688 for this PID

            data_win = canonical.get('data', {}).get('win', {})
            ev = data_win.get('eventdata', {})
            sys_fields = data_win.get('system', {})
            rule = canonical.get('rule', {})

            full_path = ev.get('newProcessName', 'Unknown')
            parent_path = ev.get('parentProcessName', 'Unknown')

            # Accumulate all distinct rule detections for this PID across every
            # 4688 event (rare to have >1, but possible when a process is created
            # multiple times within the window with the same PID due to PID reuse).
            # ruleId='67027' is the generic "process created" rule - not an alert,
            # just the base correlation rule. We track it separately as base_rule
            # and filter it out of the detections list so the alert count shown
            # in the badge pill is meaningful (only real detection rules).
            GENERIC_PROCESS_RULES = {'67027', '61612', '67020', 'N/A'}
            detections = []
            base_rule_id = rule.get('id', 'N/A')
            base_rule_level = rule.get('level', 0)

            for e in pid_events:
                r = e.get('rule', {})
                rid = r.get('id', 'N/A')
                if rid not in GENERIC_PROCESS_RULES:
                    detections.append({
                        'ruleId': rid,
                        'ruleLevel': int(r.get('level') or 0),
                        'ruleDesc': r.get('description', 'N/A'),
                        'mitre': r.get('mitre', {}),
                        'time': e.get('timestamp', 'N/A'),
                        'eventId': e.get('data', {}).get('win', {}).get('system', {}).get('eventID', 'N/A')
                    })
            # Remove duplicates (same ruleId + same minute, keeps the first)
            seen_detections = set()
            unique_detections = []
            for d in sorted(detections, key=lambda x: x['ruleLevel'], reverse=True):
                key = d['ruleId']
                if key not in seen_detections:
                    seen_detections.add(key)
                    unique_detections.append(d)

            # PID/PPID kept as raw hex - see _make_node comment
            pid_hex = (ev.get('newProcessId') or '').lower() or None
            ppid_hex = (ev.get('processId') or '').lower() or None

            ir_metadata = {
                'subjectUser': ev.get('subjectUserName', 'N/A'),
                'targetUser': ev.get('targetUserName', 'N/A'),
                'computer': sys_fields.get('computer', 'N/A'),
                'eventId': sys_fields.get('eventID', 'N/A'),
                'systemTime': sys_fields.get('systemTime', 'N/A'),
                'ruleId': base_rule_id,
                'ruleLevel': int(base_rule_level) if str(base_rule_level).isdigit() else 0,
                'agentIp': canonical.get('agent', {}).get('ip', 'N/A')
            }

            latest[pid] = {
                'ts': canonical.get('timestamp'),
                'name': self._win_basename(full_path),
                'ppid': ppid_hex,
                'parent_path': parent_path,
                'full_path': full_path,
                'cmd': ev.get('commandLine', 'N/A'),
                'ir': ir_metadata,
                'detections': unique_detections,  # all distinct rule alerts for this PID
            }
        return latest

    def _enrich(self, pid, sysmon_enrichment):
        """Sysmon's PIDs are decimal; our node pid is the raw hex from 4688 - convert only for this lookup."""
        empty = {'connections': [], 'sysmonProcess': None, 'imageLoads': [], 'fileCreates': [],
                 'sysmon_detections': [], 'sysmon_image': None}
        if not sysmon_enrichment or not pid:
            return empty
        dec_pid = self.hex_to_dec(pid)
        return {
            'connections': sysmon_enrichment.get('connections', {}).get(dec_pid, []),
            'sysmonProcess': sysmon_enrichment.get('process', {}).get(dec_pid),
            'imageLoads': sysmon_enrichment.get('imageLoads', {}).get(dec_pid, []),
            'fileCreates': sysmon_enrichment.get('fileCreates', {}).get(dec_pid, []),
            'sysmon_detections': sysmon_enrichment.get('sysmon_detections', {}).get(dec_pid, []),
            'sysmon_image': sysmon_enrichment.get('sysmon_images', {}).get(dec_pid),
        }

    # ENRICHED_BORDER (gold, thicker) signals correlated Sysmon telemetry
    # on a node, independent of its fill color.
    PALETTE = {
        'observed_bg': '#2c6e8c', 'observed_border': '#1b4a5e',
        'highlight_bg': '#b8722c', 'highlight_border': '#7a4a17',
        'synthetic_bg': '#333f4d', 'synthetic_border': '#7c8a9c',
        'enriched_border': '#c9a227',
        'alert_border': '#ef4444',
        # Ghost nodes: processes active in Sysmon data but born before the
        # queried window (no EID 4688 in range). Distinct teal so analysts
        # can immediately see "this process has activity but no creation event".
        'ghost_bg': '#1a4a3a', 'ghost_border': '#2e8b57',
    }

    def _make_node(self, pid, d, highlight=False, sysmon_enrichment=None):
        tooltip = (f"USER: {d['ir']['subjectUser']} | HOST: {d['ir']['computer']}\n"
                   f"TIME: {d['ir']['systemTime']}\n"
                   f"RULE ID: {d['ir']['ruleId']}")
        enrichment = self._enrich(pid, sysmon_enrichment)
        detections = d.get('detections', [])
        has_enrichment = bool(enrichment['sysmonProcess'] or enrichment['connections'] or enrichment['imageLoads'] or enrichment['fileCreates'])
        has_alerts = bool(detections)
        bg, base_border = (self.PALETTE['highlight_bg'], self.PALETTE['highlight_border']) if highlight else (self.PALETTE['observed_bg'], self.PALETTE['observed_border'])
        border = self.PALETTE['enriched_border'] if has_enrichment else (self.PALETTE['alert_border'] if has_alerts else base_border)
        return {
            'id': f"P{pid}", 'label': f"{d['name']}\n({pid})", 'title': tooltip,
            'color': {'background': bg, 'border': border},
            'borderWidth': 4 if (has_enrichment or has_alerts) else 2,
            'font': {'color': '#ffffff'},
            'meta': {
                'observed': True,
                'pid': pid, 'ppid': d['ppid'], 'name': d['name'], 'fullPath': d['full_path'],
                'cmd': d['cmd'], 'user': d['ir']['subjectUser'], 'targetUser': d['ir']['targetUser'],
                'host': d['ir']['computer'], 'ip': d['ir']['agentIp'], 'time': d['ir']['systemTime'],
                'eventId': d['ir']['eventId'], 'ruleId': d['ir']['ruleId'],
                'ruleLevel': d['ir'].get('ruleLevel', 0),
                'ts': d.get('ts'),
                'detections': detections,
                'connections': enrichment['connections'],
                'sysmonProcess': enrichment['sysmonProcess'],
                'imageLoads': enrichment['imageLoads'],
                'fileCreates': enrichment['fileCreates'],
                'sysmon_detections': enrichment['sysmon_detections'],
                # Pre-computed counts used by the frontend to render badge pills
                # without re-iterating the arrays on every node draw
                'badgeCounts': {
                    'alerts': len(detections),
                    'connections': len(enrichment['connections']),
                    'files': len(enrichment['fileCreates']),
                    'libraries': len(enrichment['imageLoads']),
                }
            }
        }

    @staticmethod
    def _time_delta_label(parent_ts, child_ts):
        """
        Formats the elapsed time between a parent process spawn and a child
        process spawn as a human-readable edge label, matching Elastic's
        Visual Event Analyzer style ("622 milliseconds", "4 seconds", etc.).
        Returns an empty string if either timestamp is missing or unparseable
        - an edge without a label is still functionally correct.
        """
        if not parent_ts or not child_ts:
            return ''
        try:
            import dateutil.parser
            p = dateutil.parser.isoparse(parent_ts)
            c = dateutil.parser.isoparse(child_ts)
            delta_ms = int((c - p).total_seconds() * 1000)
            if delta_ms < 0:
                delta_ms = abs(delta_ms)
            if delta_ms < 1000:
                return f"{delta_ms}ms"
            if delta_ms < 60000:
                s = delta_ms / 1000
                return f"{s:.1f}s" if s != int(s) else f"{int(s)}s"
            m = int(delta_ms / 60000)
            s = int((delta_ms % 60000) / 1000)
            return f"{m}m {s}s" if s else f"{m}m"
        except Exception:
            return ''

    def _make_synthetic_parent(self, ppid, parent_path, note="Parent Process", sysmon_enrichment=None, host=None, user=None):
        parent_name = self._win_basename(parent_path) if parent_path and 'Unknown' not in parent_path else 'System/Service'
        enrichment = self._enrich(ppid, sysmon_enrichment)
        has_enrichment = bool(enrichment['sysmonProcess'] or enrichment['connections'] or enrichment['imageLoads'] or enrichment['fileCreates'])
        # Tooltip: "PARENT PROCESS - name [Host - User]" matching user's requested format
        host_info = ""
        if host and host != 'N/A':
            host_info = f" - {host}"
            if user and user != 'N/A':
                host_info += f" - {user}"
        tooltip = f"PARENT PROCESS - {parent_name}{host_info}"
        border = self.PALETTE['enriched_border'] if has_enrichment else self.PALETTE['synthetic_border']
        return {
            'id': f"P{ppid}", 'label': f"{parent_name}\n({ppid})",
            'color': {'background': self.PALETTE['synthetic_bg'], 'border': border},
            'borderWidth': 4 if has_enrichment else 2,
            'font': {'color': '#ffffff', 'size': 16},
            'title': tooltip,   # "PARENT PROCESS - name [Host - User]"
            'meta': {
                'observed': False,
                'order': 1,  # synthetic parents are always #1 in their component;
                             # set here so reapplyLabels() restores the label even
                             # when the node is returned by expand (which doesn't
                             # run BFS, so order would otherwise be undefined)
                'pid': ppid, 'ppid': None, 'name': parent_name, 'fullPath': parent_path or 'N/A',
                'cmd': None, 'user': None, 'targetUser': None, 'host': None, 'ip': None,
                'time': None, 'eventId': None, 'ruleId': None, 'ruleLevel': 0, 'ts': None,
                'detections': [],
                'connections': enrichment['connections'],
                'sysmonProcess': enrichment['sysmonProcess'],
                'imageLoads': enrichment['imageLoads'],
                'fileCreates': enrichment['fileCreates'],
                'sysmon_detections': enrichment.get('sysmon_detections', []),
                'badgeCounts': {
                    'alerts': 0,
                    'connections': len(enrichment['connections']),
                    'files': len(enrichment['fileCreates']),
                    'libraries': len(enrichment['imageLoads']),
                }
            }
        }

    def build_tree(self, events, search_filter="", sysmon_enrichment=None, event_id_filter=None):
        t0 = _time.monotonic()
        logger.debug("build_tree: %d events, filter=%r", len(events), search_filter or "(none)")
        search_filter = search_filter.lower()
        latest_all = self._parse_latest(events)

        if search_filter:
            latest = {pid: d for pid, d in latest_all.items() if search_filter in d['full_path'].lower()}
        else:
            latest = latest_all

        nodes_map, edges = {}, []
        NO_PARENT = ('0', '0x0')

        for pid, d in latest.items():
            nodes_map[f"P{pid}"] = self._make_node(pid, d, sysmon_enrichment=sysmon_enrichment)

            if d['ppid'] and d['ppid'] not in NO_PARENT:
                p_id = f"P{d['ppid']}"
                if p_id not in nodes_map:
                    parent_d = latest_all.get(d['ppid'])
                    if parent_d:
                        nodes_map[p_id] = self._make_node(d['ppid'], parent_d, sysmon_enrichment=sysmon_enrichment)
                    else:
                        # Pass child's host/user context so the synthetic parent
                        # tooltip can show "PARENT PROCESS - name [Host - User]"
                        nodes_map[p_id] = self._make_synthetic_parent(
                            d['ppid'], d['parent_path'],
                            host=d['ir'].get('computer', 'N/A'),
                            user=d['ir'].get('subjectUser', 'N/A'),
                            sysmon_enrichment=sysmon_enrichment
                        )
                edge_label = self._time_delta_label(
                    (nodes_map.get(p_id) or {}).get('meta', {}).get('ts'),
                    d.get('ts')
                )
                edges.append({'from': p_id, 'to': f"P{pid}", 'label': edge_label})

        # ── Per-component BFS numbering ───────────────────────────────────────
        # Each independent tree (connected component) has its OWN sequence
        # starting at #1. The root of EVERY component is #1, its first child
        # is #2, second child is #3, etc. Numbers repeat across components
        # (multiple roots are all #1, multiple first-children are all #2).
        # This matches the analyst's mental model: "the Parent Process is always
        # #1, the first process it spawned is #2, the second is #3..."
        from collections import deque

        bfs_children = {}
        for e in edges:
            if not nodes_map.get(e['to'], {}).get('meta', {}).get('isNetworkNode'):
                bfs_children.setdefault(e['from'], []).append(e['to'])

        has_incoming_bfs = {
            e['to'] for e in edges
            if not nodes_map.get(e['to'], {}).get('meta', {}).get('isNetworkNode')
        }
        roots_bfs = [
            nid for nid, n in nodes_map.items()
            if nid not in has_incoming_bfs and not n['meta'].get('isNetworkNode')
        ]

        visited_bfs = set()
        total_numbered = 0
        for root in roots_bfs:
            # Each root starts its own sequence at 1
            local_seq = 1
            local_queue = deque([root])
            while local_queue:
                nid = local_queue.popleft()
                if nid in visited_bfs:
                    continue
                visited_bfs.add(nid)
                n = nodes_map.get(nid)
                if not n or n['meta'].get('isNetworkNode'):
                    continue
                n['meta']['order'] = local_seq
                # Label format: number on top (inside the circle), then name and pid.
                # No "#" prefix - the number alone is clearer inside the circle shape.
                n['label'] = f"{local_seq}\n{n['meta']['name']}"
                local_seq += 1
                total_numbered += 1
                sorted_children = sorted(
                    bfs_children.get(nid, []),
                    key=lambda cid: nodes_map.get(cid, {}).get('meta', {}).get('ts') or ''
                )
                local_queue.extend(c for c in sorted_children if c not in visited_bfs)

        logger.debug("Per-component BFS done: %d components, %d nodes numbered",
                     len(roots_bfs), total_numbered)

        # ── Ghost nodes: Sysmon-active processes without a 4688 in the window ─
        # A process may have fired Sysmon rules (EID 3, 7, 24...) during the
        # queried window but its creation happened BEFORE the window - so there
        # is no EID 4688 to build a tree node from. Without this block, every
        # Invoke-WebRequest, clipboard-change, or DLL-load from a long-running
        # process is invisible in the WPTV even though the Indexer has the events.
        # Ghost nodes are green-bordered to signal "active here, born before range".
        if sysmon_enrichment:
            # Build the set of decimal PIDs already visible in nodes_map
            existing_dec_pids = set()
            for nid in nodes_map:
                if nid.startswith('P'):
                    try:
                        existing_dec_pids.add(str(int(nid[1:], 16)))
                    except (ValueError, TypeError):
                        pass

            # All decimal PIDs that appear in any Sysmon activity bucket
            sysmon_active_pids = set()
            for bucket in ('sysmon_detections', 'connections', 'imageLoads',
                           'fileCreates', 'sysmon_images'):
                sysmon_active_pids.update(sysmon_enrichment.get(bucket, {}).keys())

            ghost_count = 0
            for dec_pid in sysmon_active_pids - existing_dec_pids:
                # Get the process image path from Sysmon data
                image = (sysmon_enrichment.get('sysmon_images', {}).get(dec_pid) or
                         (sysmon_enrichment.get('process', {}).get(dec_pid) or {}).get('image'))
                if not image or image == 'N/A':
                    # No Sysmon image available — try to infer the process
                    # from Windows Audit detections (e.g. EID 4104 from
                    # Microsoft-Windows-PowerShell → powershell.exe).
                    # This allows ghost nodes for processes like PowerShell
                    # that were opened before the queried time window but
                    # have detections (script block logging, clipboard, etc.)
                    # inside it — covering the 'pecar pelo excesso' case.
                    _PROVIDER_PROC = {
                        'Microsoft-Windows-PowerShell':            'powershell.exe',
                        'Microsoft-Windows-PowerShell/Operational': 'powershell.exe',
                        'PowerShell':                               'powershell.exe',
                    }
                    _dets = sysmon_enrichment.get('sysmon_detections', {}).get(dec_pid, [])
                    _provider = next((d.get('providerName', '') for d in _dets), '')
                    _inferred = _PROVIDER_PROC.get(_provider)
                    if not _inferred:
                        continue
                    image = _inferred


                # Apply PROCESS FILTER to ghost nodes — without this,
                # a filter for 'powershell' would still show chrome.exe
                # ghost nodes because ghost nodes were added after the
                # main filter pass that operates on EID 4688 events.
                if search_filter and search_filter not in image.lower():
                    continue


                name = self._win_basename(image)

                # Extract host from sysmon_detections — ghost nodes have no
                # EID 4688 so meta.host would be 'N/A' without this, breaking
                # the Discover link (computer:"N/A" returns zero results).
                _ghost_dets = sysmon_enrichment.get('sysmon_detections', {}).get(dec_pid, [])
                _ghost_host = next(
                    (d.get('computer') for d in _ghost_dets
                     if d.get('computer') and d.get('computer') not in ('N/A', '')),
                    'N/A'
                )
                # Decimal PID for Discover link (system.processID stores decimal)
                _ghost_dec_pid = dec_pid

                try:
                    hex_pid = hex(int(dec_pid))
                except (ValueError, TypeError):
                    continue

                node_id = f"P{hex_pid}"
                if node_id in nodes_map:
                    continue

                # Parent info from Sysmon EID 1 if available
                sysmon_proc = sysmon_enrichment.get('process', {}).get(dec_pid) or {}
                parent_dec = sysmon_proc.get('parentProcessId', '')
                ppid_hex = None
                if parent_dec and str(parent_dec).isdigit():
                    ppid_hex = hex(int(parent_dec))

                enrichment_node = self._enrich(hex_pid, sysmon_enrichment)
                detections = sysmon_enrichment.get('sysmon_detections', {}).get(dec_pid, [])
                has_detections = bool(detections)

                nodes_map[node_id] = {
                    'id': node_id,
                    'label': name,   # BFS will prefix the order number
                    'color': {
                        'background': self.PALETTE['ghost_bg'],
                        'border': self.PALETTE['alert_border'] if has_detections
                                  else self.PALETTE['ghost_border']
                    },
                    'borderWidth': 4 if has_detections else 2,
                    'font': {'color': '#ffffff'},
                    'title': f'SYSMON ONLY - {name} (active in window, no EID 4688 in queried range)',
                    'meta': {
                        'observed': True,
                        'sysmon_only': True,   # frontend uses this to skip recolorRootsAndBranches
                        'pid': hex_pid,
                        'ppid': ppid_hex,
                        'name': name,
                        'fullPath': image,
                        'cmd': sysmon_proc.get('commandLine', 'N/A'),
                        'user': sysmon_proc.get('user', 'N/A'),
                        'targetUser': 'N/A',
                        'host': _ghost_host,
                        'ip': 'N/A',
                        'time': sysmon_proc.get('utcTime', 'N/A'),
                        'eventId': '1',
                        'ruleId': 'N/A',
                        'ruleLevel': 0,
                        'ts': sysmon_proc.get('utcTime'),
                        'detections': detections,
                        'connections': enrichment_node['connections'],
                        'sysmonProcess': enrichment_node['sysmonProcess'],
                        'imageLoads': enrichment_node['imageLoads'],
                        'fileCreates': enrichment_node['fileCreates'],
                        'sysmon_detections': enrichment_node['sysmon_detections'],
                        'badgeCounts': {
                            'alerts': len(detections),
                            'connections': len(enrichment_node['connections']),
                            'files': len(enrichment_node['fileCreates']),
                            'libraries': len(enrichment_node['imageLoads']),
                        }
                    }
                }

                # Connect to parent if the parent is already in the graph
                if ppid_hex:
                    parent_nid = f"P{ppid_hex}"
                    if parent_nid in nodes_map:
                        delta = self._time_delta_label(
                            (nodes_map[parent_nid].get('meta') or {}).get('ts'),
                            sysmon_proc.get('utcTime')
                        )
                        edges.append({'from': parent_nid, 'to': node_id, 'label': delta})

                ghost_count += 1

            if ghost_count:
                logger.info("build_tree: %d ghost node(s) created from Sysmon-only activity "
                            "(processes active in window but born before queried range)", ghost_count)

            # Re-run BFS numbering to include ghost nodes in the sequence
            if ghost_count:
                bfs_children_g = {}
                for e in edges:
                    if not nodes_map.get(e['to'], {}).get('meta', {}).get('isNetworkNode'):
                        bfs_children_g.setdefault(e['from'], []).append(e['to'])
                has_incoming_g = {e['to'] for e in edges
                                  if not nodes_map.get(e['to'], {}).get('meta', {}).get('isNetworkNode')}
                roots_g = [nid for nid in nodes_map
                           if nid not in has_incoming_g
                           and not nodes_map[nid].get('meta', {}).get('isNetworkNode')]
                visited_g = set()
                for root in roots_g:
                    local_seq = 1
                    q = deque([root])
                    while q:
                        nid = q.popleft()
                        if nid in visited_g: continue
                        visited_g.add(nid)
                        n = nodes_map.get(nid)
                        if not n or n.get('meta', {}).get('isNetworkNode'): continue
                        n['meta']['order'] = local_seq
                        n['label'] = f"{local_seq}\n{n['meta']['name']}"
                        local_seq += 1
                        q.extend(c for c in sorted(
                            bfs_children_g.get(nid, []),
                            key=lambda c: nodes_map.get(c, {}).get('meta', {}).get('ts') or '')
                            if c not in visited_g)

        elapsed_bt = _time.monotonic() - t0
        logger.info("build_tree done in %.3fs: %d nodes, %d edges",
                    elapsed_bt, len(nodes_map), len(edges))

        nodes_list = list(nodes_map.values())

        # ── Event ID filter ─────────────────────────────────────────────────
        # If the caller requests only trees containing a specific Event ID,
        # keep only the complete subtrees (root + all descendants) where at
        # least one node has that EID in its detections.  No existing tree
        # structure or detection logic is modified.
        if event_id_filter:
            eid_str = str(event_id_filter)

            if eid_str == '4688':
                # Every process node in WPTV originates from an EID 4688 event.
                # Filtering by 4688 means "show all processes" - no reduction needed.
                nodes_with_eid = {n['id'] for n in nodes_list
                                  if not n.get('meta', {}).get('sysmon_only', False)
                                  and not n.get('meta', {}).get('isNetworkNode', False)}

            elif eid_str == '1':
                # Sysmon EID 1 covers both Process-Create detections AND ghost nodes
                # (sysmon_only=True nodes that have EID 1 telemetry but no 4688 event).
                nodes_with_eid = {n['id'] for n in nodes_list
                                  if n.get('meta', {}).get('sysmon_only', False)
                                  or any(str(d.get('eventId', '')) == '1'
                                         for d in n.get('meta', {}).get('detections', []))}

            else:
                # All other EIDs: check both detection buckets.
                #
                # meta.detections        -> Wazuh rule alerts from EID 4688
                #                          events (populated by _parse_latest)
                # meta.sysmon_detections -> Sysmon + Windows Audit events from
                #                          Indexer and archive sources
                #                          (populated by _enrich). This is where
                #                          EID 4104, 4689 and other non-4688
                #                          events land after archive indexing.
                #
                # Checking only meta.detections was the reason EID 4104/4689
                # filters returned zero nodes even when the archive index had
                # correctly loaded those events into sysmon_detections.
                nodes_with_eid = {
                    n['id'] for n in nodes_list
                    if any(str(d.get('eventId', '')) == eid_str
                           for d in (
                               n.get('meta', {}).get('detections', []) +
                               n.get('meta', {}).get('sysmon_detections', [])
                           ))
                }
            if nodes_with_eid:
                # Build children map to traverse subtrees
                children_map = {}
                for e in edges:
                    children_map.setdefault(e['from'], []).append(e['to'])
                has_incoming = {e['to'] for e in edges}
                roots = [n['id'] for n in nodes_list if n['id'] not in has_incoming]

                def _subtree_has_eid(root_id):
                    q = [root_id]
                    while q:
                        nid = q.pop()
                        if nid in nodes_with_eid:
                            return True
                        q.extend(children_map.get(nid, []))
                    return False

                def _collect_subtree(root_id):
                    ids, q = set(), [root_id]
                    while q:
                        nid = q.pop()
                        ids.add(nid)
                        q.extend(children_map.get(nid, []))
                    return ids

                valid_ids = set()
                for r in roots:
                    if _subtree_has_eid(r):
                        valid_ids.update(_collect_subtree(r))

                nodes_list = [n for n in nodes_list if n['id'] in valid_ids]
                edges      = [e for e in edges if e['from'] in valid_ids and e['to'] in valid_ids]
                logger.info("event_id_filter=%s: kept %d nodes, %d edges",
                            eid_str, len(nodes_list), len(edges))
            else:
                # No node has the requested EID - return empty
                nodes_list, edges = [], []
                logger.info("event_id_filter=%s: no matching nodes", eid_str)

        return {
            'nodes': nodes_list, 'edges': edges,
            'stats': {
                'total':     len(latest),
                'total_raw': len(latest_all),   # raw count before search_filter, for UI feedback
                'last_update': datetime.now().strftime("%H:%M:%S")
            }
        }

    def expand_node(self, pid, hours_back=24, start=None, end=None, agent_id=None, host=None, ip=None, sysmon_enrichment=None, events=None):
        """
        Returns the direct parent and direct children (spawned processes) of a
        specific pid, for incremental expansion of the graph already rendered
        on the frontend (click on an existing node).

        `events` can be pre-fetched by the caller (server.py's /expand route
        fetches events + enrichment together via fetch_events_and_enrichment
        in a single pass and passes events in here) to avoid a second,
        independent scan of the same log files. Falls back to fetching them
        itself for any other caller that doesn't already have them.
        """
        t0 = _time.monotonic()
        logger.debug("expand_node: pid=%s", pid)
        if events is None:
            events = self.fetch_events(agent_id=agent_id, hours_back=hours_back, start=start, end=end, host=host, ip=ip)
        latest = self._parse_latest(events)

        target = latest.get(pid)
        if not target:
            return {'nodes': [], 'edges': [], 'stats': {'total': 0}}

        nodes_map = {f"P{pid}": self._make_node(pid, target, highlight=True, sysmon_enrichment=sysmon_enrichment)}
        edges = []
        NO_PARENT = ('0', '0x0')

        ppid = target['ppid']
        if ppid and ppid not in NO_PARENT:
            parent_d = latest.get(ppid)
            if parent_d:
                nodes_map[f"P{ppid}"] = self._make_node(ppid, parent_d, sysmon_enrichment=sysmon_enrichment)
            else:
                nodes_map[f"P{ppid}"] = self._make_synthetic_parent(
                    ppid, target['parent_path'], note="Parent process (outside queried range)",
                    sysmon_enrichment=sysmon_enrichment
                )
            edges.append({'from': f"P{ppid}", 'to': f"P{pid}"})

        for child_pid, d in latest.items():
            if d['ppid'] == pid:
                nodes_map[f"P{child_pid}"] = self._make_node(child_pid, d, sysmon_enrichment=sysmon_enrichment)
