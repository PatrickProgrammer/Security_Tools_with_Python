from pathlib import Path


LOG_PATH = Path(__file__).parent / "security.log"

RULES = [
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


def load_logs(log_path):
    events = []

    with log_path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            cleaned_line = line.strip()

            if not cleaned_line:
                continue

            parts = cleaned_line.split()

            if len(parts) < 6:
                print(
                    f"Skipping malformed line {line_number}: "
                    f"{cleaned_line}"
                )
                continue

            try:
                event = {
                    "date": parts[0],
                    "time": parts[1],
                    "severity": parts[2],
                    "user": parts[3].split("=", 1)[1],
                    "action": parts[4].split("=", 1)[1],
                    "src_ip": parts[5].split("=", 1)[1],
                }

            except IndexError:
                print(
                    f"Skipping malformed fields on line {line_number}: "
                    f"{cleaned_line}"
                )
                continue

            events.append(event)

    return events


def count_field(events, field):
    counts = {}

    for event in events:
        value = event[field]

        if value in counts:
            counts[value] += 1
        else:
            counts[value] = 1

    return counts


def count_failed_logins(events):
    failed_login_counts = {}

    for event in events:
        if event["action"] != "failed_login":
            continue

        src_ip = event["src_ip"]

        if src_ip in failed_login_counts:
            failed_login_counts[src_ip] += 1
        else:
            failed_login_counts[src_ip] = 1

    return failed_login_counts


def detect_alerts(events, rules):
    alerts = []

    for rule in rules:
        rule_field = rule["field"]
        rule_value = rule["value"]

        for event in events:
            if event.get(rule_field) == rule_value:
                alert = {
                    "rule_name": rule["name"],
                    "event": event,
                }

                alerts.append(alert)

    return alerts


def main():
    events = load_logs(LOG_PATH)

    severity_counts = count_field(events, "severity")
    ip_counts = count_field(events, "src_ip")
    user_counts = count_field(events, "user")
    action_counts = count_field(events, "action")

    failed_login_counts = count_failed_logins(events)
    alerts = detect_alerts(events, RULES)

    print("\nSeverity counts:")
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")

    print("\nSource IP counts:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")

    print("\nUser counts:")
    for user, count in user_counts.items():
        print(f"{user}: {count}")

    print("\nAction counts:")
    for action, count in action_counts.items():
        print(f"{action}: {count}")

    print("\nFailed-login detections:")
    for ip, count in failed_login_counts.items():
        if count >= 2:
            print(
                f"ALERT: {ip} had {count} failed login attempts"
            )

    print("\nRule alerts:")
    for alert in alerts:
        print(f'Rule: {alert["rule_name"]}')
        print(f'Event: {alert["event"]}')
        print()


if __name__ == "__main__":
    main()