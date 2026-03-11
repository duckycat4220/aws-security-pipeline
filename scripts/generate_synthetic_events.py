"""
Synthetic event generator for the Security Intelligence Pipeline.

Generates realistic SecurityEvent payloads covering all 5 event types
with varied risk profiles that trigger different classifier outcomes.

Usage:
    python -m scripts.generate_synthetic_events              # 50 events (default)
    python -m scripts.generate_synthetic_events --count 200
    python -m scripts.generate_synthetic_events --count 100 --output data/generated/custom.jsonl
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Pools: IPs, users, assets
# ---------------------------------------------------------------------------

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.25", "10.0.2.50", "10.0.3.100",
    "172.16.0.5", "172.16.1.20", "192.168.1.10", "192.168.1.55",
]

EXTERNAL_IPS = [
    "203.0.113.45", "198.51.100.78", "185.220.101.33", "91.219.236.10",
    "45.33.32.156", "104.248.50.87", "159.89.174.12", "78.46.89.102",
]

SUSPICIOUS_IPS = [
    "185.220.101.33", "91.219.236.10",
]

USERS = [
    ("usr-001", "admin"),
    ("usr-002", "developer"),
    ("usr-003", "analyst"),
    ("usr-004", "devops"),
    ("usr-005", "intern"),
    ("usr-006", "contractor"),
    ("usr-007", "ciso"),
    ("usr-008", "support"),
]

ASSETS = [
    ("srv-db-prod-01", "database-server", "critical"),
    ("srv-db-staging-01", "database-server", "medium"),
    ("srv-web-prod-01", "web-server", "high"),
    ("srv-web-staging-01", "web-server", "low"),
    ("ws-dev-01", "workstation", "low"),
    ("ws-analyst-01", "workstation", "medium"),
    ("fw-perimeter-01", "firewall", "critical"),
    ("srv-api-prod-01", "api-server", "high"),
    ("srv-ci-01", "ci-server", "medium"),
    ("endpoint-exec-01", "endpoint", "high"),
]

SOURCES = {
    "authentication_event": ["auth-server", "sso-gateway", "vpn-gateway", "ldap-proxy"],
    "file_activity": ["file-monitor", "dlp-agent", "nas-audit", "s3-logger"],
    "process_activity": ["edr-agent", "sysmon", "osquery", "host-ids"],
    "network_activity": ["nids-sensor", "firewall-log", "netflow-collector", "dns-monitor"],
    "security_control_event": ["edr-console", "siem-alert", "waf-engine", "iam-monitor"],
}

EVENT_TYPES = list(SOURCES.keys())

SEVERITIES = ["low", "medium", "high", "critical"]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _random_timestamp(days_back: int = 7) -> str:
    now = datetime.now(timezone.utc)
    offset = timedelta(seconds=random.randint(0, days_back * 86400))
    return (now - offset).isoformat()


def _random_event_id() -> str:
    return f"evt-{uuid.uuid4().hex[:12]}"


def _pick_user() -> tuple[str, str]:
    return random.choice(USERS)


def _pick_asset() -> tuple[str, str, str]:
    return random.choice(ASSETS)


def _pick_ip(pool: list[str]) -> str:
    return random.choice(pool)


# ---------------------------------------------------------------------------
# Detail builders per event type
# ---------------------------------------------------------------------------


def _auth_details_benign() -> dict:
    return {
        "failed_attempts": random.randint(0, 2),
        "mfa_used": True,
        "country_unusual": False,
        "outside_business_hours": False,
        "login_method": random.choice(["password", "sso", "certificate"]),
    }


def _auth_details_suspicious() -> dict:
    return {
        "failed_attempts": random.randint(5, 9),
        "mfa_used": random.choice([True, False]),
        "country_unusual": random.choice([True, False]),
        "outside_business_hours": random.choice([True, False]),
        "login_method": "password",
    }


def _auth_details_malicious() -> dict:
    return {
        "failed_attempts": random.randint(10, 50),
        "mfa_used": False,
        "country_unusual": True,
        "outside_business_hours": True,
        "login_method": "password",
    }


def _file_details_benign() -> dict:
    return {
        "action": random.choice(["read", "list"]),
        "file_path": f"/shared/docs/report-{random.randint(1, 100)}.pdf",
        "download_size_mb": round(random.uniform(0.1, 10), 1),
        "bulk_download": False,
        "sensitive_files": False,
    }


def _file_details_suspicious() -> dict:
    return {
        "action": random.choice(["download", "copy"]),
        "file_path": f"/data/exports/dump-{random.randint(1, 50)}.csv",
        "download_size_mb": round(random.uniform(100, 499), 1),
        "bulk_download": random.choice([True, False]),
        "sensitive_files": random.choice([True, False]),
    }


def _file_details_malicious() -> dict:
    return {
        "action": "download",
        "file_path": f"/data/confidential/full-export-{random.randint(1, 10)}.tar.gz",
        "download_size_mb": round(random.uniform(500, 5000), 1),
        "bulk_download": True,
        "sensitive_files": True,
    }


def _process_details_benign() -> dict:
    return {
        "process_name": random.choice(["python3", "node", "java", "nginx"]),
        "parent_process": random.choice(["systemd", "bash", "init"]),
        "known_malware_pattern": False,
        "ransomware_behavior": False,
        "unsigned_binary": False,
    }


def _process_details_suspicious() -> dict:
    return {
        "process_name": random.choice(["powershell.exe", "cmd.exe", "certutil.exe"]),
        "parent_process": random.choice(["explorer.exe", "svchost.exe"]),
        "known_malware_pattern": False,
        "ransomware_behavior": False,
        "unsigned_binary": True,
    }


def _process_details_malicious() -> dict:
    base = {
        "process_name": random.choice(["mimikatz.exe", "cobalt_strike.bin", "nc.exe"]),
        "parent_process": "cmd.exe",
        "unsigned_binary": True,
    }
    variant = random.choice(["malware", "ransomware", "both"])
    if variant == "malware":
        base["known_malware_pattern"] = True
        base["ransomware_behavior"] = False
    elif variant == "ransomware":
        base["known_malware_pattern"] = False
        base["ransomware_behavior"] = True
    else:
        base["known_malware_pattern"] = True
        base["ransomware_behavior"] = True
    return base


def _network_details_benign() -> dict:
    return {
        "protocol": random.choice(["HTTPS", "SSH", "DNS"]),
        "destination_port": random.choice([443, 22, 53, 80]),
        "data_transfer_mb": round(random.uniform(0.1, 10), 1),
        "suspicious_ip_reputation": False,
        "port_scan_detected": False,
    }


def _network_details_suspicious() -> dict:
    return {
        "protocol": random.choice(["HTTP", "TCP", "UDP"]),
        "destination_port": random.choice([4444, 8080, 8443, 1337]),
        "data_transfer_mb": round(random.uniform(100, 499), 1),
        "suspicious_ip_reputation": True,
        "port_scan_detected": random.choice([True, False]),
    }


def _network_details_malicious() -> dict:
    return {
        "protocol": random.choice(["TCP", "UDP"]),
        "destination_port": random.choice([4444, 1337, 31337, 9001]),
        "data_transfer_mb": round(random.uniform(500, 5000), 1),
        "suspicious_ip_reputation": True,
        "port_scan_detected": True,
    }


def _security_control_details_benign() -> dict:
    return {
        "control_action": random.choice(["policy_update", "scan_completed", "alert_acknowledged"]),
        "edr_disabled": False,
        "privilege_escalation": False,
    }


def _security_control_details_suspicious() -> dict:
    return {
        "control_action": random.choice(["policy_override", "exception_added"]),
        "edr_disabled": False,
        "privilege_escalation": random.choice([True, False]),
    }


def _security_control_details_malicious() -> dict:
    return {
        "control_action": random.choice(["agent_uninstalled", "firewall_disabled"]),
        "edr_disabled": True,
        "privilege_escalation": random.choice([True, False]),
    }


# Map: event_type -> (benign_fn, suspicious_fn, malicious_fn)
DETAIL_BUILDERS = {
    "authentication_event": (_auth_details_benign, _auth_details_suspicious, _auth_details_malicious),
    "file_activity": (_file_details_benign, _file_details_suspicious, _file_details_malicious),
    "process_activity": (_process_details_benign, _process_details_suspicious, _process_details_malicious),
    "network_activity": (_network_details_benign, _network_details_suspicious, _network_details_malicious),
    "security_control_event": (_security_control_details_benign, _security_control_details_suspicious, _security_control_details_malicious),
}

# Risk profiles with weighted severity/criticality combos
RISK_PROFILES = {
    "benign": {
        "severity_weights": {"low": 0.6, "medium": 0.3, "high": 0.08, "critical": 0.02},
        "detail_index": 0,
    },
    "suspicious": {
        "severity_weights": {"low": 0.05, "medium": 0.3, "high": 0.45, "critical": 0.2},
        "detail_index": 1,
    },
    "malicious": {
        "severity_weights": {"low": 0.0, "medium": 0.05, "high": 0.3, "critical": 0.65},
        "detail_index": 2,
    },
}

# Distribution: ~40% benign, ~35% suspicious, ~25% malicious
PROFILE_WEIGHTS = [0.40, 0.35, 0.25]
PROFILE_NAMES = ["benign", "suspicious", "malicious"]


def _weighted_choice(options: dict[str, float]) -> str:
    keys = list(options.keys())
    weights = list(options.values())
    return random.choices(keys, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def build_event(event_type: str | None = None, profile: str | None = None) -> dict:
    if event_type is None:
        event_type = random.choice(EVENT_TYPES)

    if profile is None:
        profile = random.choices(PROFILE_NAMES, weights=PROFILE_WEIGHTS, k=1)[0]

    risk = RISK_PROFILES[profile]
    severity = _weighted_choice(risk["severity_weights"])
    detail_fn = DETAIL_BUILDERS[event_type][risk["detail_index"]]

    user_id, user_role = _pick_user()
    asset_id, asset_type, asset_criticality = _pick_asset()

    use_suspicious_src = profile == "malicious" and random.random() > 0.3
    source_ip = _pick_ip(SUSPICIOUS_IPS if use_suspicious_src else EXTERNAL_IPS)
    destination_ip = _pick_ip(INTERNAL_IPS)

    return {
        "event_id": _random_event_id(),
        "timestamp": _random_timestamp(),
        "event_type": event_type,
        "source": random.choice(SOURCES[event_type]),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user_id": user_id,
        "user_role": user_role,
        "asset_id": asset_id,
        "asset_type": asset_type,
        "asset_criticality": asset_criticality,
        "severity": severity,
        "details": detail_fn(),
    }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


def generate_batch(count: int) -> list[dict]:
    events = []
    per_type = max(1, count // len(EVENT_TYPES))
    remainder = count - per_type * len(EVENT_TYPES)

    for event_type in EVENT_TYPES:
        for _ in range(per_type):
            events.append(build_event(event_type=event_type))

    for _ in range(remainder):
        events.append(build_event())

    random.shuffle(events)
    return events


def write_jsonl(events: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT = Path("data/generated/synthetic_events.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic security events")
    parser.add_argument("--count", type=int, default=50, help="Number of events to generate (default: 50)")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Output JSONL file path")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    events = generate_batch(args.count)
    write_jsonl(events, args.output)

    # Summary
    profile_counts = {"benign": 0, "suspicious": 0, "malicious": 0}
    type_counts = {t: 0 for t in EVENT_TYPES}
    for e in events:
        type_counts[e["event_type"]] += 1

    print(f"Generated {len(events)} events -> {args.output}")
    print(f"  By type: {json.dumps(type_counts)}")


if __name__ == "__main__":
    main()
