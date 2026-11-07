# ==========================================
# SIEM PERSISTENT BEHAVIOR BASELINE
# ==========================================
import json
import os
import tempfile
from collections import Counter

BASELINE_FILE = os.path.join(os.path.dirname(__file__), "ueba_baseline_store.json")

EMPTY_BASELINE = {
    "user_baseline": {},
    "ip_baseline": {},
    "user_ip_baseline": {}
}

def load_behavior_baseline():
    """Load persisted baseline data; return an empty baseline if unavailable."""
    if not os.path.exists(BASELINE_FILE):
        return {key: value.copy() for key, value in EMPTY_BASELINE.items()}
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
        return {
            "user_baseline": data.get("user_baseline") or {},
            "ip_baseline": data.get("ip_baseline") or {},
            "user_ip_baseline": data.get("user_ip_baseline") or {}
        }
    except (json.JSONDecodeError, OSError, TypeError):
        return {key: value.copy() for key, value in EMPTY_BASELINE.items()}

def calculate_behavior_baseline(events):
    """Count user, IP, and user-IP activity in the supplied learning window."""
    user_activity = Counter()
    ip_activity = Counter()
    user_ip_activity = {}
    for event in events:
        username = event.get("username")
        source_ip = event.get("source_ip")
        if username:
            user_activity[str(username)] += 1
        if source_ip:
            ip_activity[str(source_ip)] += 1
        if username and source_ip:
            user_ip_activity.setdefault(str(username), Counter())[str(source_ip)] += 1
    return {
        "user_baseline": dict(user_activity),
        "ip_baseline": dict(ip_activity),
        "user_ip_baseline": {user: dict(counts) for user, counts in user_ip_activity.items()}
    }

def _moving_average(previous, current, alpha=0.35):
    """Update observed values while slowly decaying entities absent in this window."""
    result = {}
    for key in set(previous) | set(current):
        old = float(previous.get(key, 0) or 0)
        new = float(current.get(key, 0) or 0)
        value = (1 - alpha) * old + alpha * new
        if value >= 0.05:
            result[key] = round(value, 2)
    return result

def save_behavior_baseline(current_baseline):
    """Persist a smoothed baseline and return the saved values."""
    previous = load_behavior_baseline()
    users = _moving_average(previous.get("user_baseline", {}), current_baseline.get("user_baseline", {}))
    ips = _moving_average(previous.get("ip_baseline", {}), current_baseline.get("ip_baseline", {}))
    previous_pairs = previous.get("user_ip_baseline", {})
    current_pairs = current_baseline.get("user_ip_baseline", {})
    pairs = {}
    for username in set(previous_pairs) | set(current_pairs):
        updated = _moving_average(previous_pairs.get(username, {}), current_pairs.get(username, {}))
        if updated:
            pairs[username] = updated
    result = {"user_baseline": users, "ip_baseline": ips, "user_ip_baseline": pairs}
    directory = os.path.dirname(BASELINE_FILE)
    try:
        fd, temp_path = tempfile.mkstemp(prefix="ueba_baseline_", suffix=".json", dir=directory)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(result, file, indent=4)
        os.replace(temp_path, BASELINE_FILE)
    except OSError:
        try:
            if "temp_path" in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
        except OSError:
            pass
    return result
