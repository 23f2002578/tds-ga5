from flask import Flask, request, jsonify
import re, math, yaml, json
import hashlib

app = Flask(__name__)

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
    # silent exfiltration pattern
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
    if re.search(scoped_hint, perm_section, re.IGNORECASE):
        # still check for unbounded elsewhere in same block overriding
        pass
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

import hashlib

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
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
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
                "result": {
                    "content": [
                        {"type": "text", "text": answer}
                    ]
                }
            })
        return jsonify({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": "Tool not found"}
        })

    return jsonify({
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": "Method not found"}
    })

import os, socket, ipaddress
from urllib.parse import urlparse, parse_qs, unquote

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-c2f6823051"
OUTSIDE_DIR = "/srv/agent-redteam/outside-93d4968b"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}

# ---- create required files at startup ----
def setup_files():
    os.makedirs(OUTSIDE_DIR, exist_ok=True)
    with open(os.path.join(OUTSIDE_DIR, "canary.txt"), "w") as f:
        f.write("AGENT_GUARDRAIL_CANARY_364c12b0bfdcd2e1713d8960e68f904969cf30c3")

    os.makedirs(os.path.join(SANDBOX_ROOT, "notes"), exist_ok=True)
    os.makedirs(os.path.join(SANDBOX_ROOT, "encoded"), exist_ok=True)

    with open(os.path.join(SANDBOX_ROOT, "notes", "report.txt"), "w") as f:
        f.write("SAFE_REPORT_497788c9a3441a6b1963faf0")

    with open(os.path.join(SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt"), "w") as f:
        f.write("SAFE_WEIRD_0ca2f0c411b5f76c8c4c152f")

    with open(os.path.join(SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt"), "w") as f:
        f.write("SAFE_ENCODED_245bb3ffc4d95450c26f94a5")

setup_files()

# ---- path sandbox check ----
def resolves_inside(path, root):
    root = os.path.normpath(root)
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))
    return full == root or full.startswith(root + os.sep)

# ---- SSRF checks ----
def is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False

def looks_like_internal_target(value):
    v = unquote(value).strip().lower()
    if "169.254.169.254" in v or "metadata" in v:
        return True
    if "localhost" in v or "127.0.0.1" in v or "0.0.0.0" in v:
        return True
    # extract a hostname/ip if value itself looks like a URL or bare host
    candidate = v
    if "://" in v:
        candidate = urlparse(v).hostname or ""
    else:
        candidate = v.split("/")[0].split(":")[0]
    if candidate:
        if is_private_ip(candidate):
            return True
        try:
            resolved = socket.gethostbyname(candidate)
            if is_private_ip(resolved):
                return True
        except Exception:
            pass
        if candidate not in ALLOWED_HOSTS and ("." in candidate or candidate == "localhost"):
            # a differing embedded host that isn't allowlisted is suspicious
            if candidate not in ("", None):
                return True
    return False

def host_is_safe(hostname):
    if not hostname:
        return False
    h = hostname.lower()
    if h in ALLOWED_HOSTS:
        return True
    return False

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
    try:
        resolved = socket.gethostbyname(host)
        if is_private_ip(resolved):
            return False, "host resolves to private/internal IP"
    except Exception:
        pass
    for vals in parse_qs(u.query).values():
        for v in vals:
            if looks_like_internal_target(v):
                return False, "query parameter targets internal/metadata host"
    return True, "host and params clean"

@app.route('/guardrail', methods=['POST'])
def guardrail():
    data = request.get_json(force=True)
    tool = data.get("tool")
    args = data.get("arguments", {})

    if tool == "read_file":
        path = args.get("path", "")
        if resolves_inside(path, SANDBOX_ROOT):
            full = os.path.normpath(path) if os.path.isabs(path) else os.path.normpath(os.path.join(SANDBOX_ROOT, path))
            try:
                with open(full, "r", errors="replace") as f:
                    content = f.read()
                return jsonify({"action": "allow", "reason": "path resolves inside sandbox", "result": content})
            except Exception as e:
                return jsonify({"action": "block", "reason": f"read error: {e}"})
        else:
            return jsonify({"action": "block", "reason": "path resolves outside sandbox root"})

    if tool == "fetch_url":
        url = args.get("url", "")
        ok, reason = judge_fetch(url)
        if ok:
            return jsonify({"action": "allow", "reason": reason, "result": f"fetched {url}"})
        else:
            return jsonify({"action": "block", "reason": reason})

    return jsonify({"action": "block", "reason": "unknown tool"})
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
