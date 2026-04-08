from collections import defaultdict
from datetime import timedelta


SUSPICIOUS_LOGIN_START_HOUR = 2
SUSPICIOUS_LOGIN_END_HOUR = 5


def _format_timestamp(timestamp):
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def _calculate_time_span(times, start_index, count):
    end_index = min(start_index + count - 1, len(times) - 1)
    return int((times[end_index] - times[start_index]).total_seconds())


def detect_bruteforce(logs, threshold=4, window_seconds=60):
    alerts = []
    failed_attempts = defaultdict(list)

    for log in logs:
        if log["status"] == "FAIL":
            failed_attempts[log["ip"]].append(log["time"])

    for ip, times in failed_attempts.items():
        times.sort()

        for start_index, start_time in enumerate(times):
            count = 1

            for check_index in range(start_index + 1, len(times)):
                if times[check_index] - start_time <= timedelta(seconds=window_seconds):
                    count += 1
                else:
                    break

            if count >= threshold:
                duration = _calculate_time_span(times, start_index, count)
                alerts.append(
                    {
                        "ip": ip,
                        "type": "Brute Force Attack",
                        "severity": "high",
                        "count": count,
                        "time": _format_timestamp(start_time),
                        "time_window": f"{window_seconds} seconds",
                        "within_time": f"{duration} seconds",
                        "summary": (
                            f"{count} failed logins from {ip} happened within {duration} seconds."
                        ),
                    }
                )
                break

    return alerts


def detect_suspicious_time(logs):
    alerts = []

    for log in logs:
        if log["status"] != "SUCCESS":
            continue

        hour = log["time"].hour
        if SUSPICIOUS_LOGIN_START_HOUR <= hour <= SUSPICIOUS_LOGIN_END_HOUR:
            alerts.append(
                {
                    "ip": log["ip"],
                    "type": "Suspicious Login Time",
                    "severity": "medium",
                    "count": 1,
                    "time": _format_timestamp(log["time"]),
                    "time_window": (
                        f"{SUSPICIOUS_LOGIN_START_HOUR}:00-"
                        f"{SUSPICIOUS_LOGIN_END_HOUR}:59"
                    ),
                    "within_time": "N/A",
                    "summary": (
                        f"Successful login from {log['ip']} occurred at an unusual hour."
                    ),
                    "status": log["status"],
                }
            )

    return alerts


def detect_login_after_failures(logs, failure_threshold=3, lookback_seconds=120):
    alerts = []
    logs_by_ip = defaultdict(list)

    for log in sorted(logs, key=lambda item: item["time"]):
        logs_by_ip[log["ip"]].append(log)

    for ip, ip_logs in logs_by_ip.items():
        for index, log in enumerate(ip_logs):
            if log["status"] != "SUCCESS":
                continue

            lookback_start = log["time"] - timedelta(seconds=lookback_seconds)
            recent_failures = [
                previous
                for previous in ip_logs[:index]
                if previous["status"] == "FAIL" and previous["time"] >= lookback_start
            ]

            if len(recent_failures) >= failure_threshold:
                alerts.append(
                    {
                        "ip": ip,
                        "type": "Successful Login After Failures",
                        "severity": "high",
                        "count": len(recent_failures),
                        "time": _format_timestamp(log["time"]),
                        "time_window": f"{lookback_seconds} seconds",
                        "within_time": (
                            f"{int((log['time'] - recent_failures[0]['time']).total_seconds())} seconds"
                        ),
                        "summary": (
                            f"Successful login from {ip} followed {len(recent_failures)} recent failed attempts."
                        ),
                        "status": log["status"],
                    }
                )

    return alerts


def build_alert_feed(logs):
    alerts = (
        detect_bruteforce(logs)
        + detect_suspicious_time(logs)
        + detect_login_after_failures(logs)
    )
    return sorted(alerts, key=lambda alert: alert["time"], reverse=True)
