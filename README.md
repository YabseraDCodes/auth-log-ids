# Intrusion Detection System Dashboard

This project is a Flask-based intrusion detection dashboard for authentication logs. It parses login events, detects suspicious behavior, enriches alerts with geolocation context, and presents the results in a live web interface.

At the start of the project, the IDS focuses on three common authentication threats:

- Brute-force attack: an attacker tries many passwords one by one against the same account or service until one works. In this project, it is flagged when repeated failed login attempts from the same IP happen inside a short time window.
- Suspicious login time: a successful login happens at an unusual hour, which can indicate stolen credentials or unauthorized access outside normal user behavior.
- Successful login after failures: several failed attempts are followed by a successful login from the same IP, which can suggest that an attacker finally guessed the correct password.

## Features

- Brute-force detection for repeated failed logins within a short time window
- Suspicious login time detection for successful logins between `02:00` and `05:59`
- Successful login after failures detection to highlight likely account compromise
- IP geolocation enrichment for alert source addresses
- Live dashboard with alert cards, alert stats, recent activity, and attack simulation controls
- Automated tests for parsing and detection logic

## Threats handled by this IDS

### Brute Force Attack

A brute-force attack happens when someone keeps trying passwords one after another until access is gained. This IDS watches for repeated failed login attempts from the same IP within a short period and raises an alert when that burst becomes suspicious.

### Suspicious Login Time

Some successful logins are still risky. If a login succeeds at an unusual hour, especially very early in the morning, it may indicate unauthorized access, account sharing, or a compromised credential being used when the legitimate user is unlikely to be active.

### Successful Login After Failures

This pattern is important because the most dangerous moment is often when the attacker finally gets in. If the same IP produces several failed attempts and then a success shortly afterward, the IDS treats that as a higher-risk event and flags it for review.

## How the Python files work

### `app.py`

- Starts the Flask application
- Builds the dashboard context from parsed logs and detected alerts
- Calls the geolocation helper for each alert
- Serves the dashboard page, JSON API endpoint, and simulation routes
- Appends or resets demo events in `logs/auth.log`

### `parser.py`

- Reads `logs/auth.log`
- Skips empty or malformed lines
- Converts each valid line into a dictionary with `time`, `status`, and `ip`
- Returns normalized events for the detection layer

### `detector.py`

- Contains the detection rules
- Detects brute-force activity from clustered failed logins
- Flags successful logins during suspicious hours
- Detects successful logins shortly after repeated failures from the same IP
- Combines all detector output into one alert feed sorted by time

### `geolocation.py`

- Sends alert IPs to the geolocation service
- Returns country, city, coordinates, ISP, and organization details when available
- Adds context to alerts without changing the detection pipeline

## Simulations

The dashboard includes controlled simulation presets so users can trigger visible results without needing a real attack source.

- Brute-force simulation: appends a burst of failed login attempts from one IP
- Odd-hours simulation: appends a successful login during suspicious hours
- Success-after-failures simulation: appends repeated failures followed by a successful login
- Normal-login simulation: appends a benign successful login for comparison

If the viewer does not enter a custom IP and does not choose the detected client IP, the app uses a predefined source IP for that simulation preset.

## Project structure

```text
IDST_1/
|-- app.py
|-- detector.py
|-- geolocation.py
|-- parser.py
|-- Procfile
|-- README.md
|-- requirements.txt
|-- logs/
|   `-- auth.log
|-- static/
|   `-- css/
|       `-- dashboard.css
|-- templates/
|   `-- dashboard.html
`-- tests/
    |-- fixtures/
    |   `-- parser_sample.log
    |-- test_detector.py
    `-- test_parser.py
```

## Dashboard UI

These are the main dashboard panels:

- Detected Alerts: the main analyst view showing each triggered alert, severity, source IP, detection window, summary, and geolocation context when available
- Alert Stats: a compact summary showing how many alerts came from each detection rule
- Recent Log Activity: the newest parsed authentication events entering the dashboard, including whether each event was a `FAIL` or `SUCCESS`

## Screenshots

### Dashboard Overview

<img width="1350" height="2937" alt="web-production-7328e up railway app__message=Simulate+Login+At+Odd+Hours+added+to+the+demo+log+using+your+detected+IP_+196 189 18 92" src="https://github.com/user-attachments/assets/3f5ba2ac-20c9-4c47-9a4c-ce032391838d" />


## Run locally

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set your geolocation API key:

```powershell
$env:IPGEOLOCATION_API_KEY="your_api_key_here"
```

You can get an API key from `https://ipgeolocation.io/`.

4. Start the app:

```bash
python app.py
```

5. Open `http://127.0.0.1:5000`

## Run tests

```bash
python -m unittest discover -s tests
```

The `tests/` folder is still needed. It protects the parser and the detector rules from accidental regressions during cleanup or future refactors.

## Railway deployment

This project is ready for Railway with Gunicorn.

### Required files

- `Procfile` contains `web: gunicorn app:app`
- `requirements.txt` contains the runtime dependencies Railway installs

### Railway settings

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`
- Environment variable: `IPGEOLOCATION_API_KEY=your_api_key_here`

### Deploy from GitHub

1. Push this repository to GitHub.
2. Create a new Railway project from the repository.
3. Confirm the build command is `pip install -r requirements.txt`.
4. Confirm the start command is `gunicorn app:app`.
5. In Railway, open the project variables and add `IPGEOLOCATION_API_KEY`.
6. Deploy and open the generated Railway URL.

## Notes before making the repo public

- `geolocation.py` now reads the API key from the `IPGEOLOCATION_API_KEY` environment variable, so no secret needs to be committed to GitHub.
- The app writes simulated events into `logs/auth.log`, so the hosted version should be treated as a demo environment rather than a production IDS.
- You can check the full working hosted at: https://web-production-7328e.up.railway.app/
