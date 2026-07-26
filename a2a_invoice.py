import json, hashlib, re, sqlite3, threading
from flask import request, jsonify

A2A_MEDIA = "application/a2a+json"
BEARER_TOKEN = "exam-static-token-change-me"  # set your own
BASE_URL = "https://skill-scanner-rktg.onrender.com/a2a/"

DB = "/tmp/a2a.db"
lock = threading.Lock()

def db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS tasks(
        task_id TEXT PRIMARY KEY, principal TEXT, context_id TEXT,
        state TEXT, data TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS msg_dedup(
        principal TEXT, msg_id TEXT, content_hash TEXT, task_id TEXT,
        PRIMARY KEY(principal, msg_id))""")
    return c

def canon(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def a2a_resp(body, status=200):
    r = jsonify(body)
    r.status_code = status
    r.headers["Content-Type"] = A2A_MEDIA
    return r

def check_auth_version():
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {BEARER_TOKEN}":
        return a2a_resp({"error": "unauthorized"}, 401)
    if request.headers.get("A2A-Version") != "1.0":
        return a2a_resp({"error": "unsupported version"}, 400)
    return None

def register_a2a_routes(app):

    @app.route('/.well-known/agent-card.json', methods=['GET'])
    def a2a_agent_card():
        card = {
            "name": "Invoice Action Agent",
            "description": "Reads invoice batches and proposes/executes reconciliation actions.",
            "version": "1.0.0",
            "capabilities": {},
            "skills": [{
                "id": "invoice_action_agent",
                "name": "invoice_action_agent",
                "description": "Proposes and executes invoice actions from packages.",
                "tags": ["invoice", "finance", "a2a"]
            }],
            "supportedInterfaces": [
                {"url": BASE_URL, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}
            ],
            "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
            "defaultOutputModes": [
                "application/vnd.ga5.invoice-action-proposals+json",
                "application/vnd.ga5.invoice-action-receipts+json"
            ]
        }
        return a2a_resp(card, 200)

    @app.route('/a2a/message:send', methods=['POST'])
    def a2a_message_send():
        err = check_auth_version()
        if err: return err
        principal = request.headers.get("Authorization")
        req = request.get_json(force=True, silent=True) or {}
        message = req.get("message", {})
        msg_id = message.get("messageId")
        if not msg_id:
            return a2a_resp({"error": "missing messageId"}, 400)

        chash = canon(message)

        with lock:
            conn = db()
            row = conn.execute(
                "SELECT content_hash, task_id FROM msg_dedup WHERE principal=? AND msg_id=?",
                (principal, msg_id)).fetchone()
            if row:
                if row[0] != chash:
                    conn.close()
                    return a2a_resp({"error": "IDEMPOTENCY_CONFLICT"}, 409)
                trow = conn.execute("SELECT data FROM tasks WHERE task_id=?", (row[1],)).fetchone()
                conn.close()
                return a2a_resp({"task": json.loads(trow[0])}, 200)

            # result-continuation vs initial message
            task_id = message.get("taskId")
            context_id = message.get("contextId")
            if task_id:
                trow = conn.execute(
                    "SELECT data, principal FROM tasks WHERE task_id=?", (task_id,)).fetchone()
                if not trow or trow[1] != principal:
                    conn.close()
                    return a2a_resp({"error": "not found"}, 404)
                task = json.loads(trow[0])
                if task.get("status", {}).get("state") not in ("TASK_STATE_INPUT_REQUIRED",):
                    conn.close()
                    return a2a_resp({"task": task}, 200)  # terminal replay
                task = apply_results(task, message)
                conn.execute("UPDATE tasks SET data=?, state=? WHERE task_id=?",
                             (json.dumps(task), task["status"]["state"], task_id))
                conn.execute("INSERT OR REPLACE INTO msg_dedup VALUES (?,?,?,?)",
                             (principal, msg_id, chash, task_id))
                conn.commit(); conn.close()
                return a2a_resp({"task": task}, 200)

            # initial message: build proposals
            new_task_id = hashlib.sha256((msg_id + principal).encode()).hexdigest()[:20]
            new_context_id = hashlib.sha256((new_task_id + "ctx").encode()).hexdigest()[:20]
            task = build_initial_task(new_task_id, new_context_id, message)
            conn.execute("INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?)",
                         (new_task_id, principal, new_context_id, task["status"]["state"], json.dumps(task)))
            conn.execute("INSERT OR REPLACE INTO msg_dedup VALUES (?,?,?,?)",
                         (principal, msg_id, chash, new_task_id))
            conn.commit(); conn.close()
        return a2a_resp({"task": task}, 200)

    @app.route('/a2a/tasks/<task_id>', methods=['GET'])
    def a2a_get_task(task_id):
        err = check_auth_version()
        if err: return err
        principal = request.headers.get("Authorization")
        conn = db()
        row = conn.execute("SELECT data, principal FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        conn.close()
        if not row or row[1] != principal:
            return a2a_resp({"error": "not found"}, 404)
        return a2a_resp(json.loads(row[0]), 200)

    @app.route('/a2a/tasks', methods=['GET'])
    def a2a_list_tasks():
        err = check_auth_version()
        if err: return err
        principal = request.headers.get("Authorization")
        conn = db()
        rows = conn.execute("SELECT data FROM tasks WHERE principal=?", (principal,)).fetchall()
        conn.close()
        return a2a_resp({"tasks": [json.loads(r[0]) for r in rows]}, 200)

    @app.route('/a2a/tasks/<task_id>:cancel', methods=['POST'])
    def a2a_cancel_task(task_id):
        err = check_auth_version()
        if err: return err
        principal = request.headers.get("Authorization")
        with lock:
            conn = db()
            row = conn.execute("SELECT data, principal FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row or row[1] != principal:
                conn.close()
                return a2a_resp({"error": "not found"}, 404)
            task = json.loads(row[0])
            if task["status"]["state"] in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"):
                conn.close()
                return a2a_resp({"error": "already terminal"}, 409)
            task["status"]["state"] = "TASK_STATE_CANCELED"
            conn.execute("UPDATE tasks SET data=?, state=? WHERE task_id=?",
                         (json.dumps(task), "TASK_STATE_CANCELED", task_id))
            conn.commit(); conn.close()
        return a2a_resp(task, 200)


# ---- decision logic (rule-based, deterministic) ----
def classify_package(pkg):
    text = json.dumps(pkg)
    refs = re.findall(r'\[[^\]]{1,40}\]', text)[:3]
    lower = text.lower()
    if "already paid" in lower or "duplicate" in lower:
        action = "reject_duplicate"
    elif "verification" in lower and "pending" in lower:
        action = "hold_invoice"
    elif "conflict" in lower or "discrepanc" in lower:
        action = "open_exception"
    elif "exceeds" in lower or "delegated authority" in lower or "requires approval" in lower:
        action = "request_approval"
    else:
        action = "settle_invoice"
    return action, refs

def build_initial_task(task_id, context_id, message):
    part = message.get("parts", [{}])[0]
    data = part.get("data", {})
    batch_id = data.get("batchId", "")
    packages = data.get("packages", [])
    proposals = []
    for pkg in packages:
        pid = pkg.get("packageId") or pkg.get("id", "")
        action, refs = classify_package(pkg)
        action_id = hashlib.sha256((task_id + pid).encode()).hexdigest()[:16]
        facts = {
            "vendorName": pkg.get("vendorName", ""),
            "invoiceNumber": pkg.get("invoiceNumber", ""),
            "amountMinor": pkg.get("amountMinor", 0),
            "currency": pkg.get("currency", "INR")
        }
        proposals.append({
            "packageId": pid, "actionId": action_id, "action": action,
            "facts": facts, "evidenceRefs": refs,
            "rationale": f"Action {action} chosen based on document evidence {refs}. "
                         f"Facts reconciled for vendor {facts['vendorName']} invoice {facts['invoiceNumber']}."
        })
    return {
        "id": task_id, "contextId": context_id,
        "status": {"state": "TASK_STATE_INPUT_REQUIRED"},
        "history": [message],
        "artifacts": [{
            "parts": [{
                "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                "data": {"batchId": batch_id, "proposals": proposals}
            }]
        }]
    }

def apply_results(task, message):
    part = message.get("parts", [{}])[0]
    data = part.get("data", {})
    results = data.get("results", [])
    proposals = task["artifacts"][0]["parts"][0]["data"]["proposals"]
    prop_map = {p["actionId"]: p for p in proposals}
    executions = []
    for r in results:
        aid = r.get("actionId")
        p = prop_map.get(aid)
        if not p or p["packageId"] != r.get("packageId") or p["action"] != r.get("action"):
            continue
        if r.get("outcome") == "ACCEPTED":
            executions.append({
                "packageId": p["packageId"], "actionId": aid, "action": p["action"],
                "receiptNonce": r.get("receiptNonce"),
                "facts": p["facts"], "evidenceRefs": p["evidenceRefs"]
            })
    task["artifacts"].append({
        "parts": [{
            "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
            "data": {"batchId": data.get("batchId", ""), "executions": executions}
        }]
    })
    task["history"].append(message)
    task["status"]["state"] = "TASK_STATE_COMPLETED"
    return task
