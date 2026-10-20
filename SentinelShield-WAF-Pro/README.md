# SentinelShield — Advanced Intrusion Detection & Web Protection System

A local Flask-based defensive security operations dashboard combining WAF detection, persistent incident logging, live telemetry, analytics, filtering, IP classification, CSV export, alerts, system/process monitoring, heuristic anomaly detection and dashboard authentication.

## Features

1. Real-time dashboard — polls live statistics, alerts and system telemetry.
2. Interactive attack charts — canvas trend chart plus dynamic attack bars.
3. Advanced incident filtering — search, attack type, severity, action, IP and date range.
4. IP intelligence — classifies loopback/private/public/link-local/reserved addresses and attempts reverse DNS.
5. CSV incident export.
6. Alert system — persistent in-app alerts and log file.
7. System/process monitoring — CPU, RAM, disk and process telemetry via psutil.
8. Anomaly detection — simple explainable traffic-spike heuristic.
9. Dashboard authentication — session-based login with password hashing.
10. GitHub/portfolio-ready structure and documentation.

## Run

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

Development login:
- Username: `admin`
- Password: `ChangeMe_123!`

Change credentials using environment variables before sharing the project.

## WAF tests

Normal:
`http://127.0.0.1:5000/`

SQL injection:
`http://127.0.0.1:5000/?id=%27%20OR%201%3D1%20--`

XSS:
`http://127.0.0.1:5000/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E`

Traversal:
`http://127.0.0.1:5000/?file=../../etc/passwd`

Command injection:
`http://127.0.0.1:5000/?cmd=%3Bwhoami`

## API endpoints

- `/health`
- `/api/live`
- `/api/status`
- `/api/system`
- `/api/processes`
- `/api/alerts`
- `/api/anomaly`
- `/api/ip/<ip>`

## Security notes

This is a defensive educational/local project. The WAF uses pattern matching, so it is not a substitute for a production WAF. The anomaly detector is intentionally explainable and heuristic rather than a trained ML model. IP intelligence is local and does not claim geolocation accuracy.

Before public deployment: change the secret key and admin password, disable debug mode, use HTTPS, add CSRF protection, add a production server, and consider a mature WAF/reverse proxy.
