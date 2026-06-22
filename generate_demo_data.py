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
"""

import pandas as pd
import numpy as np

RNG = np.random.default_rng(42)

N_HOURS = 72          # 3 days of simulated activity
EVENTS_PER_HOUR = 40  # baseline normal events per hour, per log type

HOSTS = [f"HOST-{i:03d}" for i in range(1, 21)]
USERS = [f"user{i:02d}" for i in range(1, 16)]

# The attacker's target host/user -- the "needle in the haystack"
ATTACK_HOST = "HOST-007"
ATTACK_USER = "user09"

# Second, independent attack scenario -- a fainter, medium-confidence case,
# so the demo dashboard has range to show (not every alert should look
# identical -- that's not realistic and not a good demo)
ATTACK_HOST_2 = "HOST-014"
ATTACK_USER_2 = "user12"

# Attack window: starts hour 30, brute force runs ~6 hours (low-and-slow),
# then "successful" lateral movement + exfil happens hour 40-42
BRUTE_FORCE_WINDOW = (30, 36)
LATERAL_MOVEMENT_WINDOW = (40, 42)

# Second scenario: shorter, fainter cluster -- fewer failed attempts,
# smaller follow-on transfer -- should land as MEDIUM confidence, not high
BRUTE_FORCE_WINDOW_2 = (10, 13)
LATERAL_MOVEMENT_WINDOW_2 = (16, 17)


def generate_network_flows():
    rows = []
    flow_id = 0

    for hour in range(N_HOURS):
        n_events = RNG.poisson(EVENTS_PER_HOUR)
        for _ in range(n_events):
            flow_id += 1
            src_host = RNG.choice(HOSTS)
            dst_host = RNG.choice(HOSTS)
            rows.append({
                "flow_id": flow_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(RNG.integers(0, 60))),
                "src_host": src_host,
                "dst_host": dst_host,
                "bytes_sent": int(RNG.normal(5000, 1500)),
                "bytes_received": int(RNG.normal(8000, 2000)),
                "duration_ms": int(RNG.normal(200, 60)),
                "port": int(RNG.choice([80, 443, 22, 3389, 445, 8080])),
                "is_attack": 0,
            })

    # --- Inject lateral movement + exfiltration pattern (scenario 1, strong) ---
    for hour in range(*LATERAL_MOVEMENT_WINDOW):
        # unusual large transfer, odd port, long duration -- classic exfil signature
        for _ in range(RNG.integers(3, 6)):
            flow_id += 1
            rows.append({
                "flow_id": flow_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(RNG.integers(0, 60))),
                "src_host": ATTACK_HOST,
                "dst_host": RNG.choice(HOSTS),
                "bytes_sent": int(RNG.normal(95000, 8000)),   # much bigger than normal ~5000
                "bytes_received": int(RNG.normal(2000, 500)),
                "duration_ms": int(RNG.normal(4500, 800)),    # much longer than normal ~200ms
                "port": int(RNG.choice([4444, 1337, 8443])),  # unusual ports
                "is_attack": 1,
            })

    # --- Inject scenario 2: fainter follow-on activity (medium confidence) ---
    for hour in range(*LATERAL_MOVEMENT_WINDOW_2):
        for _ in range(RNG.integers(1, 3)):
            flow_id += 1
            rows.append({
                "flow_id": flow_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(RNG.integers(0, 60))),
                "src_host": ATTACK_HOST_2,
                "dst_host": RNG.choice(HOSTS),
                "bytes_sent": int(RNG.normal(40000, 5000)),   # elevated but less extreme than scenario 1
                "bytes_received": int(RNG.normal(3000, 500)),
                "duration_ms": int(RNG.normal(1800, 400)),
                "port": int(RNG.choice([4444, 8080])),
                "is_attack": 1,
            })

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


def generate_auth_logs():
    rows = []
    log_id = 0

    for hour in range(N_HOURS):
        n_events = RNG.poisson(EVENTS_PER_HOUR // 2)
        for _ in range(n_events):
            log_id += 1
            user = RNG.choice(USERS)
            host = RNG.choice(HOSTS)
            rows.append({
                "log_id": log_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(RNG.integers(0, 60))),
                "user": user,
                "host": host,
                "event_type": "login_success",
                "failed_attempts_last_hour": 0,
                "is_attack": 0,
            })

    # --- Inject low-and-slow brute force (scenario 1, strong) ---
    # Key trait of APT brute force: NOT a burst (that's easy to catch).
    # Instead, a few failed attempts per hour, spread over many hours,
    # designed to stay under simple threshold-based alerting.
    for hour in range(*BRUTE_FORCE_WINDOW):
        n_attempts = RNG.integers(4, 8)  # just a handful per hour -- looks almost normal
        for _ in range(n_attempts):
            log_id += 1
            rows.append({
                "log_id": log_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(RNG.integers(0, 60))),
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

    # --- Inject scenario 2: shorter, fainter brute force cluster ---
    for hour in range(*BRUTE_FORCE_WINDOW_2):
        n_attempts = RNG.integers(3, 5)
        for _ in range(n_attempts):
            log_id += 1
            rows.append({
                "log_id": log_id,
                "hour": hour,
                "timestamp": pd.Timestamp("2026-06-01") + pd.Timedelta(hours=hour, minutes=int(RNG.integers(0, 60))),
                "user": ATTACK_USER_2,
                "host": ATTACK_HOST_2,
                "event_type": "login_failed",
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
