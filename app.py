from collections import Counter
from datetime import datetime, timedelta
import ipaddress
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for

from detector import build_alert_feed
from geolocation import get_ip_location
from parser import parse_logs


app = Flask(__name__)
LOG_PATH = Path("logs/auth.log")


SIMULATION_PRESETS = {
    "bruteforce": {
        "label": "Simulate Brute Force Login",
        "description": "Appends a burst of failed logins from one IP.",
    },
    "odd_hours": {
        "label": "Simulate Login At Odd Hours",
        "description": "Appends a successful login during suspicious hours.",
    },
    "compromised_login": {
        "label": "Simulate Success After Failures",
        "description": "Appends repeated failures followed by a successful login.",
    },
    "normal_login": {
        "label": "Simulate Normal Login",
        "description": "Appends a benign successful login for comparison.",
    },
}


def _timestamp_string(timestamp):
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def get_client_ip():
    # Prefer proxy headers so hosted deployments report the actual visitor IP.
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return request.remote_addr or "127.0.0.1"


def normalize_ip(value):
    if not value:
        return None

    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _append_events(events, log_path=LOG_PATH):
    with log_path.open("a", encoding="utf-8") as log_file:
        for event in events:
            log_file.write(
                f"{_timestamp_string(event['time'])} {event['status']} {event['ip']}\n"
            )


def _build_simulated_events(simulation_name, now=None, source_ip=None):
    now = now or datetime.now().replace(microsecond=0)

    if simulation_name == "bruteforce":
        ip = source_ip or "172.16.50.25"
        base = now
        return [
            {"time": base + timedelta(seconds=offset), "status": "FAIL", "ip": ip}
            for offset in (0, 6, 12, 18, 24)
        ]

    if simulation_name == "odd_hours":
        odd_time = now.replace(hour=2, minute=33, second=0)
        return [{"time": odd_time, "status": "SUCCESS", "ip": source_ip or "203.0.113.77"}]

    if simulation_name == "compromised_login":
        ip = source_ip or "198.51.100.77"
        base = now
        return [
            {"time": base + timedelta(seconds=0), "status": "FAIL", "ip": ip},
            {"time": base + timedelta(seconds=8), "status": "FAIL", "ip": ip},
            {"time": base + timedelta(seconds=16), "status": "FAIL", "ip": ip},
            {"time": base + timedelta(seconds=26), "status": "SUCCESS", "ip": ip},
        ]

    if simulation_name == "normal_login":
        return [{"time": now, "status": "SUCCESS", "ip": source_ip or "10.0.0.25"}]

    return []


def reset_demo_log(log_path=LOG_PATH):
    seed_data = "\n".join(
        [
            "2026-04-02 02:13:42 SUCCESS 203.0.113.5",
            "2026-04-02 08:45:01 FAIL 192.168.1.10",
            "2026-04-02 08:45:08 FAIL 192.168.1.10",
            "2026-04-02 08:45:15 FAIL 192.168.1.10",
            "2026-04-02 08:45:21 FAIL 192.168.1.10",
            "2026-04-02 08:45:28 FAIL 192.168.1.10",
            "2026-04-02 08:48:35 SUCCESS 192.168.1.10",
            "2026-04-02 09:10:03 FAIL 198.51.100.24",
            "2026-04-02 09:10:11 FAIL 198.51.100.24",
            "2026-04-02 09:10:19 FAIL 198.51.100.24",
            "2026-04-02 09:10:29 SUCCESS 198.51.100.24",
            "2026-04-02 11:00:01 FAIL 192.168.1.11",
            "2026-04-02 11:00:05 FAIL 192.168.1.11",
            "2026-04-02 11:00:10 FAIL 192.168.1.11",
            "2026-04-02 11:00:20 FAIL 192.168.1.11",
            "2026-04-02 11:03:00 SUCCESS 192.168.1.11",
            "2026-04-02 13:30:00 SUCCESS 10.0.0.8",
        ]
    )
    log_path.write_text(seed_data + "\n", encoding="utf-8")


def build_dashboard_context(log_path="logs/auth.log"):
    logs = parse_logs(log_path)
    alerts = build_alert_feed(logs)

    # Keep geolocation in the presentation layer so detection stays log-focused.
    for alert in alerts:
        alert["location"] = get_ip_location(alert["ip"])

    statuses = Counter(log["status"] for log in logs)
    alert_types = Counter(alert["type"] for alert in alerts)

    return {
        "alerts": alerts,
        "recent_logs": sorted(logs, key=lambda log: log["time"], reverse=True)[:8],
        "stats": {
            "total_logs": len(logs),
            "total_alerts": len(alerts),
            "failures": statuses.get("FAIL", 0),
            "successes": statuses.get("SUCCESS", 0),
            "alert_types": dict(alert_types),
        },
    }


def serialize_dashboard_context(context):
    return {
        "alerts": context["alerts"],
        "recent_logs": [
            {
                "time": log["time"].strftime("%Y-%m-%d %H:%M:%S"),
                "status": log["status"],
                "ip": log["ip"],
            }
            for log in context["recent_logs"]
        ],
        "stats": context["stats"],
    }


@app.route("/")
def home():
    context = build_dashboard_context()
    geo_ready = any(alert["location"] for alert in context["alerts"])
    simulation_message = request.args.get("message")
    client_ip = get_client_ip()
    return render_template(
        "dashboard.html",
        geo_status="configured" if geo_ready else "not configured / unavailable",
        simulation_presets=SIMULATION_PRESETS,
        simulation_message=simulation_message,
        client_ip=client_ip,
        **context,
    )


@app.get("/api/dashboard")
def dashboard_data():
    context = build_dashboard_context()
    geo_ready = any(alert["location"] for alert in context["alerts"])
    payload = serialize_dashboard_context(context)
    payload["geo_status"] = "configured" if geo_ready else "not configured / unavailable"
    return jsonify(payload)


@app.post("/simulate/<simulation_name>")
def simulate_attack(simulation_name):
    if simulation_name == "reset":
        reset_demo_log()
        return redirect(url_for("home", message="Demo log reset to the default dataset."))

    use_client_ip = request.form.get("use_client_ip") == "true"
    custom_ip = normalize_ip(request.form.get("custom_ip"))

    if request.form.get("custom_ip") and not custom_ip:
        return redirect(url_for("home", message="Custom IP address is not valid."))

    selected_ip = custom_ip or (get_client_ip() if use_client_ip else None)

    events = _build_simulated_events(simulation_name, source_ip=selected_ip)
    if not events:
        return redirect(url_for("home", message="Unknown simulation type requested."))

    _append_events(events)
    if custom_ip:
        message = (
            f"{SIMULATION_PRESETS[simulation_name]['label']} added to the demo log using "
            f"custom IP: {custom_ip}."
        )
    elif selected_ip:
        message = (
            f"{SIMULATION_PRESETS[simulation_name]['label']} added to the demo log using "
            f"your detected IP: {selected_ip}."
        )
    else:
        message = f"{SIMULATION_PRESETS[simulation_name]['label']} added to the demo log."
    return redirect(url_for("home", message=message))


if __name__ == "__main__":
    app.run(debug=True)
