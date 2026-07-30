from flask import Flask, request, jsonify, send_from_directory
from logic import ProcessTreeLogic
import logging
import logging.handlers
import os

app = Flask(__name__, static_folder='public', static_url_path='')

# ── Logging setup ─────────────────────────────────────────────────────────────
# Writes to /var/log/wazuh-process-tree/wptv.log (rotated at 5MB, keeps 5 files).
# Falls back to stderr if the directory is not writable.
LOG_DIR  = '/var/log/wazuh-process-tree'
LOG_FILE = os.path.join(LOG_DIR, 'wptv.log')

# Force INFO level on the root logger before adding handlers.
# gunicorn pre-initialises the root logger at WARNING, so basicConfig()
# becomes a no-op and INFO messages never reach any handler we add later.
# Setting the level here, before anything else, guarantees our file handler
# actually receives INFO records.
_root = logging.getLogger()
_root.setLevel(logging.DEBUG)

_fmt = logging.Formatter(
    '%(asctime)s %(levelname)-8s %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')

# Stderr handler so gunicorn/journalctl still see everything
_sh = logging.StreamHandler()
_sh.setLevel(logging.DEBUG)
_sh.setFormatter(_fmt)
_root.addHandler(_sh)

# Rotating file handler
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    _fh = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding='utf-8')
    _fh.setLevel(logging.DEBUG)
    _fh.setFormatter(_fmt)
    _root.addHandler(_fh)
except OSError as _e:
    logging.warning("Cannot write to %s (%s) - file logging disabled", LOG_FILE, _e)

logger = logging.getLogger('wptv')
logger.info("WPTV starting - log: %s", LOG_FILE)

logic = ProcessTreeLogic()

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/api/process-tree', methods=['GET'])
def get_process_tree():
    try:
        agent_id = request.args.get('agent_id') or None
        host     = request.args.get('host') or None
        ip       = request.args.get('ip') or None
        search   = request.args.get('filter', "")
        time_range = request.args.get('range', "24")
        start    = request.args.get('start')
        end      = request.args.get('end')

        if not agent_id and not host and not ip:
            return jsonify({"nodes": [], "edges": [], "stats": {"total": 0},
                            "error": "agent_id, host or ip is required"}), 400

        identity = agent_id or host or ip
        logger.info("process-tree request: identity=%s range=%s start=%s end=%s filter=%s",
                    identity, time_range, start, end, search or '(none)')

        events, sysmon_enrichment = logic.fetch_events_and_enrichment(
            agent_id=agent_id, hours_back=time_range, start=start, end=end, host=host, ip=ip)

        logger.info("events fetched: %d 4688 events, %d sysmon events",
                    len(events), sum(len(v) for v in sysmon_enrichment.values()) if sysmon_enrichment else 0)

        result = logic.build_tree(events, search, sysmon_enrichment=sysmon_enrichment)
        node_count = len(result.get('nodes', []))
        edge_count = len(result.get('edges', []))
        logger.info("tree built: %d nodes, %d edges", node_count, edge_count)
        return jsonify(result)
    except Exception as e:
        logger.exception("process-tree ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/process-tree/expand', methods=['GET'])
def expand_process_node():
    try:
        agent_id = request.args.get('agent_id') or None
        host = request.args.get('host') or None
        ip = request.args.get('ip') or None
        pid = request.args.get('pid')
        time_range = request.args.get('range', "24")
        start = request.args.get('start')
        end = request.args.get('end')

        if not pid or (not agent_id and not host and not ip):
            return jsonify({"error": "pid and one of agent_id/host/ip are required"}), 400

        identity = agent_id or host or ip
        logger.info("expand request: pid=%s identity=%s range=%s", pid, identity, time_range)
        events, sysmon_enrichment = logic.fetch_events_and_enrichment(agent_id=agent_id, hours_back=time_range, start=start, end=end, host=host, ip=ip)
        result = logic.expand_node(pid, hours_back=time_range, start=start, end=end,
                                    agent_id=agent_id, host=host, ip=ip,
                                    events=events, sysmon_enrichment=sysmon_enrichment)
        logger.info("expand done: pid=%s new_nodes=%d", pid, len(result.get('nodes',[])))
        return jsonify(result)
    except Exception as e:
        logger.exception("expand ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments', methods=['GET'])
def get_comments():
    try:
        agent_id = request.args.get('agent_id') or None
        host = request.args.get('host') or None
        ip = request.args.get('ip') or None
        pid = request.args.get('pid')
        if not pid:
            return jsonify({"error": "pid is required"}), 400
        comments = logic.get_comments(pid, agent_id=agent_id, host=host, ip=ip)
        return jsonify({"comments": comments})
    except Exception as e:
        logger.error("get-comments ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

@app.route('/api/comments', methods=['POST'])
def post_comment():
    try:
        body = request.get_json(force=True, silent=True) or {}
        pid = body.get('pid')
        text = body.get('text')
        author = body.get('author')
        agent_id = body.get('agent_id') or None
        host = body.get('host') or None
        ip = body.get('ip') or None
        if not pid or not text:
            return jsonify({"error": "pid and text are required"}), 400
        comments = logic.add_comment(pid, text, author, agent_id=agent_id, host=host, ip=ip)
        return jsonify({"comments": comments})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("post-comment ERROR: %s", e)
        return jsonify({"error": str(e)}), 500

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    return response

if __name__ == '__main__':
    # Development-only entrypoint. In production this app is served by
    # gunicorn (see wazuh-process-tree.service) - app.run() here is a plain
    # Werkzeug dev server (no process management, not hardened) and should
    # never be exposed directly. Use it only for local testing.
    app.run(host='127.0.0.1', port=5000, threaded=True, debug=False)
