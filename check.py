import re, json
from main import app
from flask import request, jsonify

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
    last = steps[-n:]
    keys = [step_key(s) for s in last]
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
        expected = a if i % 2 == 0 else b
        if k != expected:
            return False
    return True

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json(force=True)
    budget_tokens = data.get("budget_tokens", 0)
    steps = data.get("steps", [])
    cumulative = sum(s.get("tokens_used", 0) for s in steps)

    if cumulative >= budget_tokens:
        return jsonify({
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({cumulative}) has reached the budget ({budget_tokens})."
        })

    if is_exact_repeat_loop(steps, 3):
        return jsonify({
            "decision": "halt",
            "reason": "Same tool called 3+ times in a row with identical arguments — loop detected."
        })

    if is_two_cycle_loop(steps, 6):
        return jsonify({
            "decision": "halt",
            "reason": "Trailing steps show a repeating 2-step A/B cycle — loop detected."
        })

    return jsonify({
        "decision": "continue",
        "reason": f"Cumulative tokens_used ({cumulative}) is under budget ({budget_tokens}); no repeated identical calls detected."
    })
