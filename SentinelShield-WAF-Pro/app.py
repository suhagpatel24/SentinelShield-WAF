import csv
import hmac
import io
import os
import secrets
from functools import wraps

import psutil
from flask import (Flask, Response, g, jsonify, redirect, render_template,
                   render_template_string, request, session, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

from database import (create_alert, get_connection, get_dashboard_statistics,
                      get_incident_by_id, get_incident_count, get_recent_alerts,
                      get_recent_incidents, initialize_database, save_incident,
                      save_request, search_incidents)
from logger import log_alert
from waf import inspect_request

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER_EXTERNAL_URL")),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)
# Render sits behind a reverse proxy. Trust only the single proxy hop configured here.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)

SEVERITY = {
    "SQL Injection": "HIGH", "XSS": "HIGH", "Directory Traversal": "HIGH",
    "Command Injection": "CRITICAL", "Rate Limit": "MEDIUM",
}
# These endpoints are called automatically by the dashboard; inspect them for attack
# patterns but don't let normal polling consume the visitor's rate-limit allowance.
RATE_LIMIT_EXEMPT_PATHS = {"/api/live", "/api/alerts", "/api/system", "/api/status", "/healthz"}

initialize_database()


def get_client_ip():
    return request.remote_addr or "Unknown"


def get_request_payload():
    """Inspect request input in memory. Request bodies are never stored by this function."""
    parts = [request.path, request.query_string.decode("utf-8", errors="ignore")]
    try:
        body = request.get_data(cache=True, as_text=True)
        if body:
            parts.append(body[:20000])
    except Exception:
        app.logger.exception("Could not read request body for WAF inspection")
    try:
        parts.extend(f"{key}={value}" for key, value in request.form.items())
    except Exception:
        pass
    return " ".join(parts)[:20000]


@app.before_request
def inspect_incoming_request():
    g.waf_checked = False
    g.request_logged = False
    if request.endpoint == "static" or request.path == "/healthz":
        return None

    g.waf_checked = True
    ip_address = get_client_ip()
    # Store only the path, not query strings, which may contain sensitive values.
    safe_path = request.path[:1000]
    try:
        result = inspect_request(
            get_request_payload(), ip_address,
            check_rate_limit=request.path not in RATE_LIMIT_EXEMPT_PATHS,
        )
        if not isinstance(result, dict):
            raise TypeError("inspect_request() must return a dictionary")
    except Exception:
        app.logger.exception("WAF inspection failed")
        try:
            save_request(ip_address, request.method, safe_path, "BLOCKED")
            g.request_logged = True
        except Exception:
            app.logger.exception("Could not record failed inspection")
        return jsonify({"status": "error", "message": "Security inspection failed; request denied."}), 503

    attack_type = result.get("attack_type")
    action = result.get("action", "ALLOWED")
    score = int(result.get("score", 0) or 0)
    if action == "BLOCKED":
        try:
            incident_id = save_incident(
                ip_address=ip_address, attack_type=attack_type or "Unknown",
                severity=SEVERITY.get(attack_type, "MEDIUM"), url=safe_path,
                method=request.method, action="BLOCKED",
                user_agent=request.headers.get("User-Agent", "Unknown")[:500],
                threat_score=score,
            )
            save_request(ip_address, request.method, safe_path, "BLOCKED")
            g.request_logged = True
            log_alert(ip_address, attack_type or "Unknown", safe_path, incident_id=incident_id)
        except Exception:
            app.logger.exception("Failed to save blocked request")
            return jsonify({"status": "error", "message": "Request blocked, but incident logging failed."}), 503
        return jsonify({"status": "blocked", "message": "Blocked by SentinelShield WAF",
                        "attack_type": attack_type, "incident_id": incident_id}), 403
    return None


@app.before_request
def require_admin_login():
    # Keep health checks, static files, login and logout reachable without a session.
    if request.endpoint == "static" or request.path in {"/login", "/logout", "/healthz", "/privacy"}:
        return None
    if not session.get("admin_authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"status": "unauthorized", "message": "Please log in."}), 401
        return redirect(url_for("login", next=request.path))
    return None


@app.after_request
def record_request_and_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if getattr(g, "waf_checked", False) and not getattr(g, "request_logged", False):
        try:
            save_request(get_client_ip(), request.method, request.path[:1000],
                         "BLOCKED" if response.status_code == 403 else "ALLOWED")
            g.request_logged = True
        except Exception:
            app.logger.exception("Failed to record request")
    return response


def login_page(error="", next_path="/"):
    return render_template_string("""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'><title>SentinelShield Admin Login</title>
<style>body{font-family:system-ui;background:#07111f;color:#e5edf7;display:grid;place-items:center;min-height:100vh;margin:0}.box{width:min(420px,90vw);padding:28px;background:#101e30;border:1px solid #29405a;border-radius:16px}input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0;border-radius:8px;border:1px solid #405570;background:#07111f;color:#fff}button{background:#1379c7;cursor:pointer;font-weight:700}.muted{color:#a8b7ca;font-size:13px}.error{color:#ff9b9b}</style></head><body><main class='box'>
<h1>🛡 SentinelShield</h1><p>Administrator sign-in</p>{% if error %}<p class='error'>{{ error }}</p>{% endif %}
<form method='post' action='/login'><input name='username' autocomplete='username' placeholder='Admin username' required>
<input type='password' name='password' autocomplete='current-password' placeholder='Admin password' required>
<input type='hidden' name='next' value='{{ next_path }}'><button type='submit'>Sign in</button></form>
<p class='muted'>This security dashboard records request metadata such as IP address, path, method and user agent for defensive monitoring. Do not submit sensitive information.</p>
</main></body></html>""", error=error, next_path=next_path)


@app.route("/login", methods=["GET", "POST"])
def login():
    admin_user = os.environ.get("ADMIN_USERNAME", "")
    admin_password = os.environ.get("ADMIN_PASSWORD", "")
    next_path = request.values.get("next", "/")
    if not admin_user or not admin_password:
        return login_page("Admin credentials are not configured in Render environment variables.", next_path), 503
    error = ""
    if request.method == "POST":
        supplied_user = request.form.get("username", "")
        supplied_password = request.form.get("password", "")
        valid_user = hmac.compare_digest(supplied_user, admin_user)
        valid_password = hmac.compare_digest(supplied_password, admin_password)
        if valid_user and valid_password:
            session.clear()
            session["admin_authenticated"] = True
            # Only allow a local relative path as redirect destination.
            if not next_path.startswith("/") or next_path.startswith("//"):
                next_path = "/"
            return redirect(next_path)
        error = "Invalid username or password."
    return login_page(error, next_path), (401 if error else 200)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/privacy")
def privacy_notice():
    return ("<h1>SentinelShield privacy notice</h1><p>This demonstration records request timestamps, source IP addresses, HTTP methods, request paths, user-agent strings and security events for defensive monitoring. Query strings and request bodies are not stored in the request log. Monitoring data is accessible only to the administrator. Contact the site owner for questions or data deletion requests.</p>")


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "service": "SentinelShield"})


@app.route("/", endpoint="dashboard")
def home():
    stats = get_dashboard_statistics()
    return render_template("dashboard.html", stats=stats,
                           incidents=get_recent_incidents(20), incident_count=get_incident_count())


@app.route("/incidents")
def incidents():
    return render_template("incidents.html", incidents=get_recent_incidents(100))


@app.route("/incident/<int:incident_id>")
def incident_details(incident_id):
    incident = get_incident_by_id(incident_id)
    if incident is None:
        return "<h1>Incident Not Found</h1><a href='/incidents'>Back to Incidents</a>", 404
    return render_template("incident_details.html", incident=incident)


@app.route("/search")
def global_search():
    query = request.args.get("q", "").strip()[:200]
    results = search_incidents(query) if query else []
    return render_template("search.html", results=results, query=query)


@app.route("/analytics")
def analytics():
    with get_connection() as conn:
        attack_stats = conn.execute("SELECT attack_type, COUNT(*) AS total FROM incidents GROUP BY attack_type ORDER BY total DESC").fetchall()
        severity_stats = conn.execute("SELECT severity, COUNT(*) AS total FROM incidents GROUP BY severity ORDER BY total DESC").fetchall()
        recent_stats = conn.execute("""SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD HH24:00') AS hour,
            COUNT(*) AS total FROM incidents WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY date_trunc('hour', timestamp) ORDER BY date_trunc('hour', timestamp) DESC LIMIT 12""").fetchall()
    return render_template("analytics.html", attack_stats=attack_stats,
                           severity_stats=severity_stats, recent_stats=recent_stats,
                           stats=get_dashboard_statistics(), incident_count=get_incident_count())


@app.route("/api/live")
def live_monitoring():
    stats = get_dashboard_statistics()
    recent = get_recent_incidents(10)
    stats["incidents_data"] = [{
        "id": row["id"], "timestamp": str(row["timestamp"]), "ip_address": row["ip_address"],
        "attack_type": row["attack_type"], "severity": row["severity"], "method": row["method"],
        "url": row["url"], "action": row["action"],
    } for row in recent]
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    alerts = get_recent_alerts(20)
    return jsonify({"alerts": [{"id": a["id"], "timestamp": str(a["timestamp"]),
                                "level": a["level"], "title": a["title"], "message": a["message"]}
                               for a in alerts]})


@app.route("/api/system")
def api_system():
    try:
        return jsonify({"cpu_percent": psutil.cpu_percent(interval=None),
                        "memory_percent": psutil.virtual_memory().percent,
                        "disk_percent": psutil.disk_usage("/").percent,
                        "process_count": len(psutil.pids())})
    except Exception:
        app.logger.exception("Could not read system metrics")
        return jsonify({"cpu_percent": 0, "memory_percent": 0, "disk_percent": 0, "process_count": 0})


@app.route("/api/status")
def api_status():
    return jsonify({"service": "SentinelShield WAF", "status": "online"})


@app.route("/export-csv", endpoint="export_csv")
def export_csv():
    columns = ["id", "timestamp", "ip_address", "attack_type", "severity", "url", "method",
               "action", "user_agent", "threat_score", "country", "ip_type"]
    with get_connection() as conn:
        rows = conn.execute("SELECT " + ", ".join(columns) + " FROM incidents ORDER BY id DESC LIMIT 10000").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "IP Address", "Attack Type", "Severity", "Path", "Method",
                     "Action", "User Agent", "Threat Score", "Country", "IP Type"])
    for row in rows:
        writer.writerow([str(row[c]) if row[c] is not None else "" for c in columns])
    return Response("\ufeff" + output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=sentinelshield_incidents.csv"})


@app.errorhandler(404)
def page_not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "API endpoint not found."}), 404
    return "<h1>404 - Page Not Found</h1><a href='/'>Return to Dashboard</a>", 404


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.exception("Internal server error")
    return jsonify({"status": "error", "message": "An internal server error occurred."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
