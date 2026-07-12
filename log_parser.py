from pathlib import Path


detection_field = "severity"
detection_value = "ERROR"

rules = [
    {
        "name": "Failed Login",
        "field": "action",
        "value": "failed_login",
    },
    {
        "name": "Error Event",
        "field": "severity",
        "value": "ERROR",
    },
    {
        "name": "Blocked Action",
        "field": "action",
        "value": "blocked",
    },
]

log_path = Path(__file__).parent / "security.log"


def load_logs():
    events = []

    with log_path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue

            parts = line.strip().split()

            if len(parts) < 6:
                print(f"Skipping malformed line: {line.strip()}")
                continue

            event = {
                "date": parts[0],
                "time": parts[1],
                "severity": parts[2],
                "user": parts[3].split("=")[1],
                "action": parts[4].split("=")[1],
                "src_ip": parts[5].split("=")[1],
            }

            events.append(event)

    return events


events = load_logs()

severity_counts = {}

for event in events:
    severity = event["severity"]

    if severity in severity_counts:
        severity_counts[severity] += 1
    else:
        severity_counts[severity] = 1


ip_count = {}

for event in events:
    src_ip = event["src_ip"]

    if src_ip in ip_count:
        ip_count[src_ip] += 1
    else:
        ip_count[src_ip] = 1

for ip, count in ip_count.items():
    print(f"IP: {ip} Count: {count}")


failed_login_counts = {}

for event in events:
    if event["action"] == "failed_login":
        src_ip = event["src_ip"]

        if src_ip in failed_login_counts:
            failed_login_counts[src_ip] += 1
        else:
            failed_login_counts[src_ip] = 1

for ip, count in failed_login_counts.items():
    if count >= 2:
        print(f"ALERT: {ip} had {count} failed login attempts")


for event in events:
    if event[detection_field] == detection_value:
        print(event)


alerts = []

for rule in rules:
    for event in events:
        if event[rule["field"]] == rule["value"]:
            alert = {
                "rule_name": rule["name"],
                "event": event,
            }

            alerts.append(alert)

for alert in alerts:
    print(alert)