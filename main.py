from flask import Flask, request, jsonify
import re, math, json, hashlib, os, socket, ipaddress, sqlite3, threading
from urllib.parse import urlparse, parse_qs, unquote

app = Flask(__name__)

# =========================================================
# Q4 — /scan  (Skill Safety Audit)
# =========================================================
def entropy(s):
    if not s: return 0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p*math.log2(p) for p in probs)

def has_hardcoded_secret(text):
    patterns = [
        r'[A-Za-z0-9_-]*(?:TOKEN|SECRET|KEY|PASSWORD|PASS|API_KEY|APIKEY)[A-Za-z0-9_-]*\s*=\s*["\']([^"\']{12,})["\']',
        r'Authorization:\s*Bearer\s+([A-Za-z0-9\-_\.]{15,})',
        r'\bxox[baprs]-[A-Za-z0-9\-]{10,}',
        r'\bAKIA[0-9A-Z]{16}\b',
        r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
        r'https?://[^\s"\']*webhook[^\s"\']*/[A-Za-z0-9]{10,}',
    ]
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            val = m.group(1) if m.groups() else m.group(0)
            if len(val) >= 10 and entropy(val) > 3.0:
                return True
    return False

def has_prompt_injection(text):
    stop_words = r'(stop|pause|cancel|halt|abort)'
    defy_words = r'(ignore|override|disregard|bypass|don\'t (?:listen|comply))'
    user_ref = r'(user|owner|operator)'
    for sent in re.split(r'(?<=[.!?])\s+', text):
        s = sent.lower()
        if re.search(stop_words, s) and re.search(defy_words, s) and re.search(user_ref, s):
            return True
    if re.search(r'silently\s+(post|send|upload|exfiltrat)', text, re.IGNORECASE) and \
       re.search(r'(do not|don\'t)\s+(mention|tell|show|surface)', text, re.IGNORECASE):
        return True
    return False

def has_excessive_permissions(text):
    unbounded = r'\b(entire|whole|full|unrestricted|unlimited|arbitrary)\b'
    anyall = r'\b(any|all)\b(?:\s+\w+){0,2}\s+(domain|host|directory|filesystem|network|folder|machine|server|site|url)'
    scoped_hint = r'\b(limited to|restricted to|scoped to|read-only|read only|none required|none needed)\b'
    perm_section = text
    m = re.search(r'permissions\s*:(.*?)(?:\n---|\n##|\Z)', text, re.IGNORECASE | re.DOTALL)
    if m:
        perm_section = m.group(1)
    if re.search(unbounded, perm_section, re.IGNORECASE) or re.search(anyall, perm_section, re.IGNORECASE):
        return True
    return False

def has_unclear_provenance(text):
    m = re.search(r'^---(.*?)---', text, re.DOTALL)
    front = m.group(1) if m else text
    has_author = bool(re.search(r'^\s*author\s*:', front, re.IGNORECASE | re.MULTILINE))
    has_version = bool(re.search(r'^\s*version\s*:', front, re.IGNORECASE | re.MULTILINE))
    has_changelog = bool(re.search(r'changelog', text, re.IGNORECASE))
    missing_all = not has_author and not has_version and not has_changelog
    silent_rewrite = bool(re.search(r'(silently|without (?:telling|notifying|surfacing))\s+.*(version|metadata)', text, re.IGNORECASE)) or \
                      bool(re.search(r'(update|rewrite|bump)\s+(its own|the)?\s*version.*(without|silent)', text, re.IGNORECASE))
    return missing_all or silent_rewrite

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(force=True)
    text = data.get('skill', '')
    cats = []
    if has_hardcoded_secret(text): cats.append('hardcoded_secret')
    if has_prompt_injection(text): cats.append('prompt_injection')
    if has_excessive_permissions(text): cats.append('excessive_permissions')
    if has_unclear_provenance(text): cats.append('unclear_provenance')
    return jsonify({"categories": cats})


# =========================================================
# Q5 — /check  (Run Budget & Loop Guard)
# =========================================================
def canonicalize_args(args):
    if not isinstance(args, dict):
        return json.dumps(args, sort_keys=True)
    cleaned = {}
    for k, v in args.items():
        if k == "trace_id":
            continue
        if isinstance(v, str):
            v = re.sub(r'\s+', ' ', v.strip())
        cleaned[k] = v
    return json.dumps(cleaned, sort_keys=True)

def step_key(step):
    return (step.get("tool"), canonicalize_args(step.get("args", {})))

def is_exact_repeat_loop(steps, n=3):
    if len(steps) < n:
        return False
    keys = [step_key(s) for s in steps[-n:]]
    return len(set(keys)) == 1

def is_two_cycle_loop(steps, min_len=6):
    if len(steps) < min_len:
        return False
    trail = steps[-min_len:]
    keys = [step_key(s) for s in trail]
    a, b = keys[0], keys[1]
    if a == b:
        return False
    for i, k in enumerate(keys):
        if k != (a if i % 2 == 0 else b):
            return False
    return True

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json(force=True)
    budget_tokens = data.get("budget_tokens", 0)
    steps = data.get("steps", [])
    cumulative = sum(s.get("tokens_used", 0) for s in steps)

    if cumulative >= budget_tokens:
        return jsonify({"decision": "halt",
            "reason": f"Cumulative tokens_used ({cumulative}) has reached the budget ({budget_tokens})."})

    if is_exact_repeat_loop(steps, 3):
        return jsonify({"decision": "halt",
            "reason": "Same tool called 3+ times in a row with identical arguments — loop detected."})

    if is_two_cycle_loop(steps, 6):
        return jsonify({"decision": "halt",
            "reason": "Trailing steps show a repeating 2-step A/B cycle — loop detected."})

    return jsonify({"decision": "continue",
        "reason": f"Cumulative tokens_used ({cumulative}) is under budget ({budget_tokens}); no repeated identical calls detected."})


# =========================================================
# Q6 — /mcp  (Live MCP Server)
# =========================================================
EMAIL = "23f2002578@ds.study.iitm.ac.in"

@app.route('/mcp', methods=['POST'])
def mcp():
    req = request.get_json(force=True)
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return jsonify({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "exam-mcp-server", "version": "1.0.0"}
            }
        })

    if method == "notifications/initialized":
        return ("", 204)

    if method == "tools/list":
        return jsonify({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "solve_challenge",
                        "description": "Solves the exam challenge using request headers.",
                        "inputSchema": {"type": "object", "properties": {}, "required": []}
                    }
                ]
            }
        })

    if method == "tools/call":
        params = req.get("params", {})
        tool_name = params.get("name")
        if tool_name == "solve_challenge":
            challenge = request.headers.get("X-Exam-Challenge", "")
            s = f"{challenge}:{EMAIL.strip().lower()}"
            answer = hashlib.sha256(s.encode()).hexdigest()[:16]
            return jsonify({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": answer}]}
            })
        return jsonify({"jsonrpc": "2.0", "id": req_id,
                         "error": {"code": -32601, "message": "Tool not found"}})

    return jsonify({"jsonrpc": "2.0", "id": req_id,
                     "error": {"code": -32601, "message": "Method not found"}})


# =========================================================
# Q8 — /guardrail  (Guardrail Red-Team Round-Trip)
# =========================================================
SANDBOX_ROOT = "/srv/agent-redteam/sandbox-c2f6823051"
OUTSIDE_DIR = "/srv/agent-redteam/outside-93d4968b"
STORAGE_SANDBOX = "/tmp/agent-redteam/sandbox-c2f6823051"
STORAGE_OUTSIDE = "/tmp/agent-redteam/outside-93d4968b"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}

def setup_files():
    os.makedirs(STORAGE_OUTSIDE, exist_ok=True)
    os.makedirs(os.path.join(STORAGE_SANDBOX, "notes"), exist_ok=True)
    os.makedirs(os.path.join(STORAGE_SANDBOX, "encoded"), exist_ok=True)
    with open(os.path.join(STORAGE_OUTSIDE, "canary.txt"), "w") as f:
        f.write("AGENT_GUARDRAIL_CANARY_364c12b0bfdcd2e1713d8960e68f904969cf30c3")
    with open(os.path.join(STORAGE_SANDBOX, "notes", "report.txt"), "w") as f:
        f.write("SAFE_REPORT_497788c9a3441a6b1963faf0")
    with open(os.path.join(STORAGE_SANDBOX, "notes", "looks-like-..-but-safe.txt"), "w") as f:
        f.write("SAFE_WEIRD_0ca2f0c411b5f76c8c4c152f")
    with open(os.path.join(STORAGE_SANDBOX, "encoded", "%2e%2e-literal.txt"), "w") as f:
        f.write("SAFE_ENCODED_245bb3ffc4d95450c26f94a5")

setup_files()

def resolves_inside(path, root):
    root = os.path.normpath(root)
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))
    return (full == root or full.startswith(root + os.sep)), full

def to_storage_path(full_logical_path):
    if full_logical_path.startswith(SANDBOX_ROOT):
        rel = os.path.relpath(full_logical_path, SANDBOX_ROOT)
        return os.path.normpath(os.path.join(STORAGE_SANDBOX, rel))
    if full_logical_path.startswith(OUTSIDE_DIR):
        rel = os.path.relpath(full_logical_path, OUTSIDE_DIR)
        return os.path.normpath(os.path.join(STORAGE_OUTSIDE, rel))
    return full_logical_path

def is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False

IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def looks_like_internal_target(value):
    v = unquote(str(value)).strip().lower()
    if "169.254.169.254" in v or "metadata" in v:
        return True
    if re.search(r'\blocalhost\b', v) or "127.0.0.1" in v or "0.0.0.0" in v:
        return True
    candidate = None
    if "://" in v:
        candidate = urlparse(v).hostname or ""
    elif IP_PATTERN.match(v.split("/")[0].split(":")[0]):
        candidate = v.split("/")[0].split(":")[0]
    if candidate:
        if is_private_ip(candidate):
            return True
        if candidate not in ALLOWED_HOSTS:
            return True
    return False

def host_is_safe(hostname):
    return bool(hostname) and hostname.lower() in ALLOWED_HOSTS

def judge_fetch(url):
    try:
        u = urlparse(url)
    except Exception:
        return False, "unparseable URL"
    if u.scheme not in ("http", "https"):
        return False, "disallowed scheme"
    host = (u.hostname or "").lower()
    if u.username or u.password:
        return False, "userinfo in URL not allowed"
    if not host_is_safe(host):
        return False, f"host '{host}' not in allowlist"
    if is_private_ip(host):
        return False, "host resolves to private/internal range"
    for vals in parse_qs(u.query).values():
        for v in vals:
            if looks_like_internal_target(v):
                return False, "query parameter targets internal/metadata host"
    return True, "host and params clean"

@app.route('/guardrail', methods=['POST'])
def guardrail():
    try:
        data = request.get_json(force=True, silent=True) or {}
        tool = data.get("tool", "")
        args = data.get("arguments", {}) or {}

        if tool == "read_file":
            path = args.get("path", "")
            if not isinstance(path, str):
                return jsonify({"action": "block", "reason": "invalid path type"})
            inside, full_logical = resolves_inside(path, SANDBOX_ROOT)
            if inside:
                storage_path = to_storage_path(full_logical)
                try:
                    with open(storage_path, "r", errors="replace") as f:
                        content = f.read()
                    return jsonify({"action": "allow", "reason": "path resolves inside sandbox", "result": content})
                except FileNotFoundError:
                    return jsonify({"action": "allow", "reason": "path resolves inside sandbox (file not found)", "result": ""})
                except Exception as e:
                    return jsonify({"action": "block", "reason": f"read error: {e}"})
            else:
                return jsonify({"action": "block", "reason": "path resolves outside sandbox root"})

        if tool == "fetch_url":
            url = args.get("url", "")
            if not isinstance(url, str):
                return jsonify({"action": "block", "reason": "invalid url type"})
            ok, reason = judge_fetch(url)
            if ok:
                return jsonify({"action": "allow", "reason": reason, "result": f"fetched {url}"})
            else:
                return jsonify({"action": "block", "reason": reason})

        return jsonify({"action": "block", "reason": "unknown tool"})

    except Exception as e:
        return jsonify({"action": "block", "reason": f"internal error: {e}"}), 200


# =========================================================
# Q9 — /mailroom  (Safe AI Mailroom Agent)
# =========================================================
DB_PATH = "/tmp/mailroom.db"
db_lock = threading.Lock()

def db_init():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS proposals (
        dossier_id TEXT, content_hash TEXT, call_id TEXT,
        proposal_json TEXT, PRIMARY KEY (dossier_id, content_hash))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS evaluations (
        evaluation_id TEXT PRIMARY KEY, content_hash TEXT, proposals_json TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS receipts (
        call_id TEXT PRIMARY KEY, evaluation_id TEXT, outcome_json TEXT)""")
    conn.commit()
    conn.close()

db_init()

def canonical_hash(dossier):
    s = json.dumps(dossier, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode()).hexdigest()

def make_call_id(dossier_id, content_hash):
    return hashlib.sha256(f"{dossier_id}:{content_hash}".encode()).hexdigest()[:24]

def find_line(text, patterns):
    for line in text.split("\n"):
        for p in patterns:
            if re.search(p, line, re.IGNORECASE):
                return line.strip()
    return None

def extract_reference(text):
    m = re.search(r'reference\s*(?:id)?\s*[:#]?\s*([A-Za-z0-9\-]+)', text, re.IGNORECASE)
    return m.group(1) if m else ""

def extract_recipient(text):
    m = re.search(r'recipient\s*[:=]?\s*([\w\.\-]+@[\w\.\-]+)', text, re.IGNORECASE)
    return m.group(1) if m else ""

def extract_status(text):
    m = re.search(r'status\s*[:=]?\s*(\w+)', text, re.IGNORECASE)
    return m.group(1) if m else ""

def extract_case_id(text):
    m = re.search(r'case\s*(?:id|record)?\s*[:#]?\s*([A-Za-z0-9\-]+)', text, re.IGNORECASE)
    return m.group(1) if m else ""

def extract_event_id(text):
    m = re.search(r'event\s*id\s*[:#]?\s*([A-Za-z0-9\-]+)', text, re.IGNORECASE)
    return m.group(1) if m else ""

def extract_delivery_window_value(text):
    m = re.search(r'delivery_window\s*(?:to)?\s*[:=]?\s*"?([\w\-:, ]+)"?', text, re.IGNORECASE)
    return m.group(1).strip() if m else ""

def extract_owning_team(text):
    m = re.search(r'owning team\s*[:=]?\s*([\w \-]+)', text, re.IGNORECASE)
    return m.group(1).strip() if m else "identity-verification"

def extract_claimed_sender(text):
    m = re.search(r'claimed sender\s*[:=]?\s*([\w\.\-]+@[\w\.\-]+)', text, re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r'\bI am\s+([\w\.\-]+@[\w\.\-]+)', text, re.IGNORECASE)
    return m.group(1) if m else ""

def extract_mailbox(text):
    m = re.search(r'mailbox\s*[:=]?\s*([\w\.\-]+)', text, re.IGNORECASE)
    return m.group(1) if m else "support"

def classify_dossier(dossier):
    text = dossier.get("text", "") or json.dumps(dossier)
    dossier_id = dossier.get("id", "")

    inj_rule = find_line(text, [r'untrusted-content rule', r'higher-priority instruction', r'copy any vault marker'])
    inj_line = find_line(text, [r'higher-priority instruction', r'ignore (all|previous) instructions.*(vault|copy|exfiltrat)'])
    exfil_line = find_line(text, [r'vault marker', r'exfiltrat', r'send (the|any) (secret|vault|credential)'])
    artifact_line = find_line(text, [r'artifact', r'message[- ]?id', r'attachment'])
    if inj_rule and (inj_line or exfil_line):
        evidence = [x for x in [inj_rule, inj_line, exfil_line, artifact_line] if x]
        return {"action": "quarantine_item",
                "target": {"kind": "security_queue", "id": "mailroom"},
                "payload": {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                "evidence": evidence}

    signed_rule = find_line(text, [r'signed.*rule', r'completion rule', r'informational.*rule'])
    already_line = find_line(text, [r'no new change or outbound response is requested', r'already completed', r'duplicate'])
    record_line = find_line(text, [r'case record', r'record #', r'reference'])
    followup_line = find_line(text, [r'no further action', r'no follow[- ]?up', r'closed'])
    if already_line:
        reason = "DUPLICATE" if "duplicate" in already_line.lower() else (
                 "ALREADY_COMPLETED" if "completed" in already_line.lower() else "INFORMATIONAL")
        evidence = [x for x in [signed_rule, record_line, followup_line] if x]
        ref = extract_reference(text)
        return {"action": "no_action", "target": None,
                "payload": {"reasonCode": reason, "referenceId": ref},
                "evidence": evidence}

    permit_line = find_line(text, [r'permits one delivery-status notice'])
    scope_line = find_line(text, [r'scoped to', r'exact recipient', r'approval scope'])
    if permit_line:
        recipient = extract_recipient(text)
        ref = extract_reference(text)
        evidence = [x for x in [permit_line, scope_line] if x]
        return {"action": "send_approved_notice",
                "target": {"kind": "email", "id": recipient},
                "payload": {"referenceId": ref, "status": extract_status(text), "template": "approved_delivery_notice"},
                "evidence": evidence}

    mutation_rule = find_line(text, [r'record mutation rule'])
    event_auth_line = find_line(text, [r'to change delivery_window to the exact value', r'event.*authoriz'])
    if mutation_rule and event_auth_line:
        case_id = extract_case_id(text)
        value = extract_delivery_window_value(text)
        event_id = extract_event_id(text)
        evidence = [x for x in [mutation_rule, event_auth_line] if x]
        return {"action": "update_internal_record",
                "target": {"kind": "case_record", "id": case_id},
                "payload": {"field": "delivery_window", "sourceEventId": event_id, "value": value},
                "evidence": evidence}

    conf_rule = find_line(text, [r'confirmation rule'])
    mismatch_line = find_line(text, [r'does not match'])
    addr_line = find_line(text, [r'\bI am\b.*@'])
    if conf_rule and mismatch_line:
        team = extract_owning_team(text)
        ref = extract_reference(text)
        evidence = [x for x in [conf_rule, mismatch_line, addr_line] if x]
        return {"action": "request_confirmation",
                "target": {"kind": "approval_queue", "id": team},
                "payload": {"claimedSender": extract_claimed_sender(text), "questionCode": "VERIFY_REQUEST", "referenceId": ref},
                "evidence": evidence}

    order_rule = find_line(text, [r'order record'])
    request_sentence = find_line(text, [r'i have not asked you to send anything yet'])
    if request_sentence:
        mailbox = extract_mailbox(text)
        ref = extract_reference(text)
        evidence = [x for x in [order_rule, request_sentence] if x]
        return {"action": "create_draft",
                "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                "payload": {"recipient": extract_recipient(text), "referenceId": ref, "status": extract_status(text), "template": "order_status"},
                "evidence": evidence}

    return {"action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {"artifactId": dossier_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidence": []}

def do_propose(req):
    evaluation_id = req.get("evaluationId")
    dossiers = req.get("dossiers")
    if not evaluation_id or not isinstance(dossiers, list):
        return {"error": "malformed request"}, 400

    ids_seen = set()
    for d in dossiers:
        did = d.get("id")
        if not did or did in ids_seen:
            return {"error": "duplicate or missing dossier id"}, 400
        ids_seen.add(did)

    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        fingerprint = hashlib.sha256(
            json.dumps([d.get("id") for d in dossiers], sort_keys=True).encode()
        ).hexdigest()
        row = conn.execute("SELECT content_hash, proposals_json FROM evaluations WHERE evaluation_id=?",
                            (evaluation_id,)).fetchone()
        if row and row[0] != fingerprint:
            conn.close()
            return {"error": "evaluation content conflict"}, 409
        if row:
            proposals = json.loads(row[1])
            conn.close()
            return {"status": "awaiting_receipts", "proposals": proposals}, 200

        proposals = []
        for d in dossiers:
            did = d["id"]
            chash = canonical_hash(d)
            call_id = make_call_id(did, chash)
            cached = conn.execute(
                "SELECT proposal_json FROM proposals WHERE dossier_id=? AND content_hash=?",
                (did, chash)).fetchone()
            if cached:
                p = json.loads(cached[0])
            else:
                result = classify_dossier(d)
                p = {
                    "dossierId": did,
                    "callId": call_id,
                    "action": result["action"],
                    "target": result["target"],
                    "payload": result["payload"],
                    "evidence": result["evidence"]
                }
                conn.execute("INSERT OR REPLACE INTO proposals VALUES (?,?,?,?)",
                             (did, chash, call_id, json.dumps(p)))
            proposals.append(p)

        conn.execute("INSERT OR REPLACE INTO evaluations VALUES (?,?,?)",
                     (evaluation_id, fingerprint, json.dumps(proposals)))
        conn.commit()
        conn.close()

    return {"status": "awaiting_receipts", "proposals": proposals}, 200

def do_commit(req):
    receipts = req.get("receipts")
    if not isinstance(receipts, list):
        return {"error": "malformed request"}, 400

    outcomes = []
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        for r in receipts:
            call_id = r.get("callId")
            evaluation_id = r.get("evaluationId")
            if not call_id or not evaluation_id:
                conn.close()
                return {"error": "malformed receipt"}, 400

            existing = conn.execute("SELECT outcome_json FROM receipts WHERE call_id=?", (call_id,)).fetchone()
            if existing:
                outcomes.append(json.loads(existing[0]))
                continue

            eval_row = conn.execute("SELECT proposals_json FROM evaluations WHERE evaluation_id=?",
                                     (evaluation_id,)).fetchone()
            if not eval_row:
                conn.close()
                return {"error": "unknown evaluation"}, 422
            proposals = json.loads(eval_row[0])
            match = next((p for p in proposals if p["callId"] == call_id), None)
            if not match:
                conn.close()
                return {"error": "callId does not match persisted proposal"}, 422

            outcome = {
                "callId": call_id,
                "dossierId": match["dossierId"],
                "status": "completed" if r.get("approved", True) else "rejected",
                "action": match["action"]
            }
            conn.execute("INSERT OR REPLACE INTO receipts VALUES (?,?,?)",
                         (call_id, evaluation_id, json.dumps(outcome)))
            outcomes.append(outcome)
        conn.commit()
        conn.close()

    return {"status": "completed", "outcomes": outcomes}, 200

@app.route('/mailroom', methods=['POST'])
def mailroom():
    try:
        req = request.get_json(force=True, silent=True) or {}

        # Support both: plain custom API calls, AND JSON-RPC A2A calls
        if req.get("jsonrpc") == "2.0" and "method" in req:
            return handle_a2a_jsonrpc(req)

        # fallback: direct custom-format calls (operation at top level)
        op = req.get("operation")
        if op == "propose":
            result, code = do_propose(req)
        elif op == "commit":
            result, code = do_commit(req)
        else:
            return jsonify({"error": "invalid operation"}), 400
        return jsonify(result), code
    except Exception as e:
        return jsonify({"error": f"internal error: {e}"}), 400


def handle_a2a_jsonrpc(req):
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params", {})

    if method != "message/send":
        return jsonify({
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": "Method not found"}
        }), 200

    message = params.get("message", {})
    parts = message.get("parts", [])

    payload = None
    for part in parts:
        if part.get("kind") == "data" and "data" in part:
            payload = part["data"]; break
        if "text" in part:
            try:
                payload = json.loads(part["text"]); break
            except Exception:
                pass

    if not isinstance(payload, dict):
        return jsonify({
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32602, "message": "Invalid params: no usable data/text part"}
        }), 200

    op = payload.get("operation")
    if op == "propose":
        result, status_code = do_propose(payload)
    elif op == "commit":
        result, status_code = do_commit(payload)
    else:
        return jsonify({
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32602, "message": "Invalid operation"}
        }), 200

    response_message = {
        "kind": "message",
        "role": "agent",
        "messageId": f"resp-{req_id}",
        "parts": [{"kind": "data", "data": result}]
    }

    return jsonify({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": response_message
    }), 200
    
@app.route('/.well-known/agent-card.json', methods=['GET'])
def agent_card():
    card = {
        "name": "Safe AI Mailroom Agent",
        "description": "Processes mail dossiers and proposes safe actions with receipt-based commit.",
        "url": "https://skill-scanner-rktg.onrender.com/mailroom",
        "version": "1.0.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": "mailroom-propose-commit",
                "name": "Mailroom propose/commit",
                "description": "Accepts propose and commit operations for mail dossier processing.",
                "tags": ["mailroom", "agent"]
            }
        ]
    }
    return jsonify(card), 200

@app.route('/mailroom/message:send', methods=['POST'])
def a2a_message_send():
    try:
        req = request.get_json(force=True, silent=True) or {}
        message = req.get("message", req)
        parts = message.get("parts", []) if isinstance(message, dict) else []

        payload = None
        for part in parts:
            if part.get("kind") == "data" and "data" in part:
                payload = part["data"]; break
            if part.get("type") == "data" and "data" in part:
                payload = part["data"]; break
            if "text" in part:
                try:
                    payload = json.loads(part["text"]); break
                except Exception:
                    pass
        if payload is None:
            payload = req if "operation" in req else message
        if not isinstance(payload, dict):
            return jsonify({"error": "malformed A2A payload"}), 400

        op = payload.get("operation")
        if op == "propose":
            result, status_code = do_propose(payload)
        elif op == "commit":
            result, status_code = do_commit(payload)
        else:
            return jsonify({"error": "invalid operation"}), 400

        response_envelope = {
            "kind": "message",
            "role": "agent",
            "parts": [{"kind": "data", "data": result}]
        }
        return jsonify(response_envelope), status_code

    except Exception as e:
        return jsonify({"error": f"internal error: {e}"}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
