# 🛡️ SentinelShield — Web Application Firewall (WAF)

**A Python Flask-based defensive security project for monitoring HTTP requests, detecting suspicious activity, and recording security incidents.**

SentinelShield is a learning-oriented Web Application Firewall (WAF) dashboard developed to explore web application security, request inspection, incident logging, and security analytics.

## ✨ Features

- **Security Dashboard** — View request and incident statistics.
- **Request Inspection** — Inspect incoming HTTP requests for suspicious patterns.
- **Threat Detection** — Apply configured detection rules to identify potentially malicious requests.
- **Incident Logging** — Store security events for investigation and review.
- **Incident Management** — Browse and inspect recorded incidents.
- **Search and Filtering** — Search security records using the available interface.
- **Analytics** — Visualize security activity using dashboard statistics and charts.
- **CSV Export** — Export supported incident data for further analysis.
- **IP Intelligence** — Classify or inspect IP-related information using the implemented functionality.
- **Monitoring and Alerts** — Explore supported system monitoring and alert features.

*Note: Available functionality depends on the current implementation and configuration. Authentication is not implemented in this version.*

## 🧰 Technology Stack

- **Language:** Python
- **Web Framework:** Flask
- **Frontend:** HTML, CSS, JavaScript
- **Database:** SQLite
- **Development Tools:** Visual Studio Code, Git, and GitHub

## 📁 Project Structure

```text
SentinelShield-WAF-Pro/
├── app.py
├── database.py
├── waf.py
├── ip_intelligence.py
├── logger.py
├── monitor.py
├── requirements.txt
├── README.md
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── analytics.html
│   ├── incidents.html
│   ├── incident_details.html
│   ├── search.html
│   ├── blocked.html
│   ├── error.html
│   └── login.html
└── .gitignore
```

Runtime files such as databases, logs, and Python cache files may be generated when the application runs.

## ⚙️ Installation and Setup

### 1. Install Python

Install a compatible Python 3 version from:

https://www.python.org/downloads/

Verify the installation:

```bash
python --version
```

### 2. Clone the repository

```bash
git clone https://github.com/suhagpatel24/SentinelShield-WAF.git
```

Navigate to the project directory:

```bash
cd SentinelShield-WAF/SentinelShield-WAF-Pro
```

### 3. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can run the environment's Python executable directly instead.

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

### 6. Open the dashboard

Open your browser and visit:

http://127.0.0.1:5000/

Keep the terminal open while using the application. Stop the development server with `Ctrl + C`.

## 🧪 Testing

You can evaluate the application in a local environment by:

1. Opening the dashboard and generating ordinary HTTP requests.
2. Reviewing the request and incident statistics.
3. Checking whether configured detection rules identify suspicious test requests.
4. Reviewing incident details and available analytics.
5. Testing the supported search and CSV export functionality.

Use only applications and systems you own or have explicit permission to test.

## 🔐 Security Notes

- This project is intended for educational use and local defensive-security experimentation.
- It is **not a production-ready security solution**.
- Run it locally and do not expose the development server to the public internet.
- Do not use Flask's debug mode in a production deployment.
- Do not commit real user data, private logs, databases containing sensitive information, API keys, passwords, or other secrets.
- Detection rules may produce false positives and false negatives.
- Validate and test the implementation before relying on it to protect an application.

## 🚧 Future Improvements

- More comprehensive SQL injection and cross-site scripting detection.
- Improved request validation and configurable security rules.
- Authentication and role-based access control.
- More detailed incident severity scoring.
- Improved IP reputation integrations.
- Automated security testing and unit tests.
- Docker-based deployment and continuous integration.
- Production deployment with secure configuration and monitoring.

## 🎯 Learning Objectives

This project supports hands-on learning in:

- Python and Flask development.
- Web application security fundamentals.
- HTTP request inspection.
- Security incident logging and analysis.
- SQLite database integration.
- Dashboard design and data visualization.
- Git and GitHub project management.

## 👨‍💻 Author

**Suhag Patel**

B.Tech Computer Science and Engineering — Cybersecurity

GitHub: https://github.com/suhagpatel24

## 📄 Disclaimer

SentinelShield is an educational cybersecurity project. It is provided for learning, testing, and authorized defensive-security activities only. The author does not guarantee that it will detect or prevent every attack. Users are responsible for ensuring that their testing and deployment comply with applicable laws and authorization requirements.
