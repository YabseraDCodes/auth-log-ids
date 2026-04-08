from datetime import datetime


def parse_logs(file_path):
    # Normalize raw log lines into a predictable structure for the detectors.
    logs = []

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            # Combine date + time
            time_str = parts[0] + " " + parts[1]
            try:
                timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue

            status = parts[2].upper()
            ip = parts[3]

            log_entry = {
                "time": timestamp,
                "status": status,
                "ip": ip,
            }

            logs.append(log_entry)

    return logs
