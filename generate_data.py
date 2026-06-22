"""
generate_data.py
-----------------
Generates two synthetic but realistic-looking datasets for the prototype:
  1. network_flows.csv  - simulated network flow records (like CICIDS-style features)
  2. auth_logs.csv      - simulated authentication / system log events

Why synthetic instead of a real dataset?
  - No download/cleaning time wasted under deadline pressure.
  - We control exactly where attacks happen, so we can later PROVE
    detection accuracy (we know ground truth labels).
  - You can swap this file out later for real CICIDS2017 / NSL-KDD data
    with minimal changes to the rest of the pipeline -- the rest of the
    code only cares about the column names, not where the data came from.

Attack scenario simulated (mapped to MITRE ATT&CK later):
  - A slow, low-and-slow brute force login attempt (T1110 - Brute Force)
  - Followed by unusual lateral movement / data transfer at odd hours
    (T1021 - Remote Services, T1041 - Exfiltration Over C2 Channel)
  This mirrors the APT "low-and-slow" pattern described in the problem
  statement -- exactly what signature-based tools miss.

IMPORTANT: Each generation function uses its OWN independent RNG with a
fixed seed, so results are 100% deterministic across runs.
"""

import pandas as pd
import numpy as np

N_HOURS = 72          # 3 days of simulated activity
EVENTS_PER_HOUR = 40  # baseline normal events per hour, per log type

HOSTS = [f"HOST-{i:03d}" for i in range(1, 21)]
USERS = [f"user{i:02d}" for i in range(1, 16)]

# The attacker's target host/user -- the "needle in the haystack"
ATTACK_HOST = "HOST-007"
ATTACK_USER = "user09"

# Attack window: starts hour 30, brute force runs ~6 hours (low-and-slow),
# then "successful" lateral movement + exfil happens hour 40-42
BRUTE_FORCE_WINDOW = (30, 36)
LATERAL_MOVEMENT_WINDOW = (40, 42)


def generate_network_flows():
    """Generate deterministic network flow data with embedded attack patterns."""
    rng = np.random.default_rng(2026)  # FIXED seed for deterministic output
    rows = []
    flow_id = 0

    for hour in range(N_HOURS):
        n_events = int(rng.poisson(EVENTS_PER_HOUR))
        for _ in range(n_events):
            flow_id += 1
            src_host = rng.choice(HOSTS)
            dst_host = rng.choice(HOSTS)
            rows.append({
                "flow_id": flow_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(rng.integers(0, 60))),
                "src_host": src_host,
                "dst_host": dst_host,
                "bytes_sent": int(rng.normal(5000, 1500)),
                "bytes_received": int(rng.normal(8000, 2000)),
                "duration_ms": int(rng.normal(200, 60)),
                "port": int(rng.choice([80, 443, 22, 3389, 445, 8080])),
                "is_attack": 0,
            })

    # --- Inject lateral movement + exfiltration pattern ---
    for hour in range(*LATERAL_MOVEMENT_WINDOW):
        for _ in range(int(rng.integers(3, 6))):
            flow_id += 1
            rows.append({
                "flow_id": flow_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(rng.integers(0, 60))),
                "src_host": ATTACK_HOST,
                "dst_host": rng.choice(HOSTS),
                "bytes_sent": int(rng.normal(95000, 8000)),
                "bytes_received": int(rng.normal(2000, 500)),
                "duration_ms": int(rng.normal(4500, 800)),
                "port": int(rng.choice([4444, 1337, 8443])),
                "is_attack": 1,
            })

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


def generate_auth_logs():
    """Generate deterministic auth log data with embedded brute force patterns."""
    rng = np.random.default_rng(2026)  # FIXED seed for deterministic output
    rows = []
    log_id = 0

    for hour in range(N_HOURS):
        n_events = int(rng.poisson(EVENTS_PER_HOUR // 2))
        for _ in range(n_events):
            log_id += 1
            user = rng.choice(USERS)
            host = rng.choice(HOSTS)
            rows.append({
                "log_id": log_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(rng.integers(0, 60))),
                "user": user,
                "host": host,
                "event_type": "login_success",
                "failed_attempts_last_hour": 0,
                "is_attack": 0,
            })

    # --- Inject low-and-slow brute force ---
    for hour in range(*BRUTE_FORCE_WINDOW):
        n_attempts = int(rng.integers(4, 8))
        for _ in range(n_attempts):
            log_id += 1
            rows.append({
                "log_id": log_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(rng.integers(0, 60))),
                "user": ATTACK_USER,
                "host": ATTACK_HOST,
                "event_type": "login_failed",
                "failed_attempts_last_hour": n_attempts,
                "is_attack": 1,
            })
        # one success right at the end of the window (the breach)
        if hour == BRUTE_FORCE_WINDOW[1] - 1:
            log_id += 1
            rows.append({
                "log_id": log_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=58),
                "user": ATTACK_USER,
                "host": ATTACK_HOST,
                "event_type": "login_success",
                "failed_attempts_last_hour": n_attempts,
                "is_attack": 1,
            })

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    flows = generate_network_flows()
    auth = generate_auth_logs()

    flows.to_csv("network_flows.csv", index=False)
    auth.to_csv("auth_logs.csv", index=False)

    print(f"network_flows.csv: {len(flows)} rows, {flows['is_attack'].sum()} labeled attack rows")
    print(f"auth_logs.csv:      {len(auth)} rows, {auth['is_attack'].sum()} labeled attack rows")
    print(f"\nAttack scenario: brute force on {ATTACK_USER}@{ATTACK_HOST} "
          f"during hours {BRUTE_FORCE_WINDOW}, followed by lateral movement "
          f"during hours {LATERAL_MOVEMENT_WINDOW}.")