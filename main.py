from flask import Flask, request, jsonify
import re, math, yaml, json

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
