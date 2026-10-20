# SentinelShield — Web Application Firewall (WAF)

A Python Flask-based defensive security project for detecting suspicious web requests and monitoring security incidents.

## Features

- Real-time security dashboard
- Web attack detection using pattern matching
- Security incident logging and filtering
- IP address classification and reverse DNS lookup
- CSV incident export
- In-app alerts and log monitoring
- System and process monitoring
- Heuristic traffic-anomaly detection
- Session-based dashboard authentication
- REST API endpoints for monitoring

## Technology Stack

- Python
- Flask
- SQLite
- HTML and CSS
- JavaScript
- psutil

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/suhagpatel24/SentinelShield-WAF.git
cd SentinelShield-WAF/SentinelShield-WAF-Pro
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Run the application

```powershell
python app.py
```

Open http://127.0.0.1:5000 in your browser.

**Authentication:** Configure your own administrator credentials and secret key using environment variables supported by the application. Do not publish real passwords, secret keys, or other credentials.

## Security Testing

Test the application only on systems you own or have explicit permission to assess.

Example test categories:

- SQL injection detection
- Cross-site scripting (XSS) detection
- Path traversal detection
- Command-injection pattern detection
- Request-rate monitoring

Detection results depend on the implemented rules and application configuration.

## API Endpoints

The application may provide the following endpoints, depending on the configured routes:

- `/health`
- `/api/live`
- `/api/status`
- `/api/system`
- `/api/processes`
- `/api/alerts`
- `/api/anomaly`
- `/api/ip/<ip>`

## Security Disclaimer

SentinelShield is an educational defensive-security project. Pattern-based detection can produce false positives and false negatives and should not be considered a replacement for a professionally configured production WAF.

Before deployment, configure secure credentials and secret keys, disable Flask debug mode, use HTTPS and a production-grade server, implement appropriate CSRF protection, and review access controls.

## Author

**Suhag Patel**

GitHub: [@suhagpatel24](https://github.com/suhagpatel24)
