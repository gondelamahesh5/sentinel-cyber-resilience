"""
attack_mapping.py
------------------
A small, honest lookup table mapping OUR anomaly signatures to real
MITRE ATT&CK technique IDs. This is intentionally rule-based, not a
trained classifier -- and that's fine. The problem statement's
suggested tech list includes "Knowledge Graphs (MITRE ATT&CK TTP mapping)";
a clean lookup table is a legitimate, explainable first version of that.
Mention in your document that a v2 could use embeddings/RAG over the
full ATT&CK corpus for broader coverage -- that shows you understand
the upgrade path without overbuilding for a hackathon deadline.

Each entry: condition description -> (technique_id, technique_name, tactic)
Source: MITRE ATT&CK Enterprise matrix (publicly documented framework)
"""

ATTACK_TECHNIQUES = {
    "repeated_login_failures": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Multiple failed authentication attempts against a single account, "
                        "especially when spread over time to evade threshold alerts.",
    },
    "large_outbound_transfer": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Unusually large outbound data volume relative to the host's "
                        "established baseline.",
    },
    "unusual_port_usage": {
        "technique_id": "T1571",
        "technique_name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": "Traffic on ports that don't match the service normally "
                        "associated with that host or application.",
    },
    "long_duration_connection": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Abnormally long-lived connections, consistent with an "
                        "interactive remote session rather than routine traffic.",
    },
    "off_hours_activity": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Persistence / Defense Evasion",
        "description": "Legitimate credentials used at times inconsistent with the "
                        "account's normal activity pattern -- a hallmark of compromised "
                        "(not stolen-and-discarded) accounts.",
    },
}


def tag_network_anomaly(row):
    """Given a flagged network flow row, return the most relevant ATT&CK tag."""
    tags = []
    if row.get("bytes_sent", 0) > 50000:
        tags.append(ATTACK_TECHNIQUES["large_outbound_transfer"])
    if row.get("port", 0) in (4444, 1337, 8443, 31337):
        tags.append(ATTACK_TECHNIQUES["unusual_port_usage"])
    if row.get("duration_ms", 0) > 2000:
        tags.append(ATTACK_TECHNIQUES["long_duration_connection"])
    return tags if tags else [{
        "technique_id": "N/A", "technique_name": "Unclassified anomaly",
        "tactic": "Unknown", "description": "Statistically unusual but doesn't "
        "match a known signature in our lookup table."
    }]


def tag_auth_anomaly(row):
    """Given a flagged auth log row, return the most relevant ATT&CK tag."""
    tags = []
    if row.get("failed_attempts_last_hour", 0) >= 3:
        tags.append(ATTACK_TECHNIQUES["repeated_login_failures"])
    hour_of_day = row.get("hour", 12) % 24
    if hour_of_day < 6 or hour_of_day > 22:
        tags.append(ATTACK_TECHNIQUES["off_hours_activity"])
    return tags if tags else [{
        "technique_id": "N/A", "technique_name": "Unclassified anomaly",
        "tactic": "Unknown", "description": "Statistically unusual but doesn't "
        "match a known signature in our lookup table."
    }]
