
import csv
import io
import logging

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    g,
    Response,
    redirect,
    url_for,
)

from waf import inspect_request
from logger import log_alert

from database import (
    initialize_database,
    save_incident,
    save_request,
    get_recent_incidents,
    get_incident_count,
    get_connection,
    search_incidents,
    get_dashboard_statistics,
)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

initialize_database()

SEVERITY = {
    "SQL Injection": "HIGH",
    "XSS": "HIGH",
    "Directory Traversal": "HIGH",
    "Command Injection": "CRITICAL",
    "Rate Limit": "MEDIUM",
}


# --------------------------------------------------
# REQUEST HELPERS
# --------------------------------------------------

def get_client_ip():
    """Return the remote client's IP address."""
    return request.remote_addr or "Unknown"


def get_request_payload():
    """Collect request data for WAF inspection."""
    parts = [
        request.path,
        request.query_string.decode(
            "utf-8", errors="ignore"
        ),
    ]

    try:
        body = request.get_data(
            cache=True,
            as_text=True,
        )
        if body:
            parts.append(body)
    except Exception:
        app.logger.exception(
            "Could not read request body"
        )

    try:
        parts.extend(
            f"{key}={value}"
            for key, value in request.form.items()
        )
    except Exception:
        app.logger.exception(
            "Could not read request form"
        )

    return " ".join(parts)[:20000]


# --------------------------------------------------
# DASHBOARD STATISTICS
# --------------------------------------------------

def get_stats():
    """Return dashboard statistics in template-friendly form."""
    data = get_dashboard_statistics()

    attack_counts = {
        "SQL Injection": 0,
        "XSS": 0,
        "Directory Traversal": 0,
        "Command Injection": 0,
        "Rate Limit": 0,
    }

    for item in data.get("attack_stats", []):
        attack_type = item["attack_type"]

        if attack_type in attack_counts:
            attack_counts[attack_type] = item["n"]

    return {
        "total_requests": data["total_requests"],
        "blocked_requests": data["blocked_requests"],
        "allowed_requests": data["allowed_requests"],
        "block_rate": data["block_rate"],
        "incidents": data["incidents"],
        "incident_count": data["incidents"],
        "threat_score": data["threat_score"],
        "sql_injection": attack_counts["SQL Injection"],
        "xss": attack_counts["XSS"],
        "directory_traversal": attack_counts[
            "Directory Traversal"
        ],
        "command_injection": attack_counts[
            "Command Injection"
        ],
        "rate_limit": attack_counts["Rate Limit"],
    }


# --------------------------------------------------
# WEB APPLICATION FIREWALL
# --------------------------------------------------

@app.before_request
def inspect_incoming_request():
    g.waf_checked = False
    g.request_logged = False

    # Do not inspect static assets such as CSS and JavaScript.
    if request.endpoint == "static":
        return None

    g.waf_checked = True

    ip_address = get_client_ip()
    url = request.full_path.rstrip("?")
    method = request.method
    user_agent = request.headers.get(
        "User-Agent", "Unknown"
    )

    try:
        result = inspect_request(
            get_request_payload(),
            ip_address,
        )

        if not isinstance(result, dict):
            raise TypeError(
                "inspect_request() must return a dictionary"
            )

    except Exception:
        app.logger.exception("WAF inspection failed")

        try:
            save_request(
                ip_address,
                method,
                url,
                "BLOCKED",
            )
            g.request_logged = True
        except Exception:
            app.logger.exception(
                "Could not record failed inspection"
            )

        return jsonify({
            "status": "error",
            "message": (
                "Security inspection failed; "
                "request denied."
            ),
        }), 503

    attack_type = result.get("attack_type")
    action = result.get("action", "ALLOWED")
    score = int(result.get("score", 0) or 0)

    if action == "BLOCKED":
        severity = SEVERITY.get(
            attack_type,
            "MEDIUM",
        )

        try:
            incident_id = save_incident(
                ip_address=ip_address,
                attack_type=attack_type or "Unknown",
                severity=severity,
                url=url,
                method=method,
                action="BLOCKED",
                user_agent=user_agent,
                threat_score=score,
            )

            save_request(
                ip_address,
                method,
                url,
                "BLOCKED",
            )
            g.request_logged = True

        except Exception:
            app.logger.exception(
                "Failed to save blocked request"
            )

            return jsonify({
                "status": "error",
                "message": (
                    "Request blocked, but incident "
                    "logging failed."
                ),
            }), 503

        try:
            log_alert(
                ip_address,
                attack_type or "Unknown",
                url,
            )
        except Exception:
            app.logger.exception(
                "Alert logging failed"
            )

        app.logger.warning(
            "Blocked request: IP=%s type=%s incident=%s",
            ip_address,
            attack_type,
            incident_id,
        )

        return jsonify({
            "status": "blocked",
            "message": "Blocked by SentinelShield WAF",
            "attack_type": attack_type,
            "incident_id": incident_id,
        }), 403

    return None


# --------------------------------------------------
# RESPONSE HEADERS AND REQUEST LOGGING
# --------------------------------------------------

@app.after_request
def record_allowed_request(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )
    response.headers["Cache-Control"] = "no-store"

    if (
        getattr(g, "waf_checked", False)
        and not getattr(g, "request_logged", False)
    ):
        try:
            save_request(
                get_client_ip(),
                request.method,
                request.full_path.rstrip("?"),
                "ALLOWED",
            )
            g.request_logged = True
        except Exception:
            app.logger.exception(
                "Failed to record request"
            )

    return response


# --------------------------------------------------
# MAIN DASHBOARD
# --------------------------------------------------

@app.route("/", endpoint="dashboard")
def home():
    return render_template(
        "dashboard.html",
        stats=get_stats(),
        incidents=get_recent_incidents(20),
        incident_count=get_incident_count(),
    )


# --------------------------------------------------
# INCIDENT LIST
# --------------------------------------------------

@app.route("/incidents")
def incidents():
    return render_template(
        "incidents.html",
        incidents=get_recent_incidents(100),
    )


# --------------------------------------------------
# INCIDENT DETAILS
# --------------------------------------------------

@app.route("/incident/<int:incident_id>")
def incident_details(incident_id):
    connection = get_connection()

    try:
        incident = connection.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
    finally:
        connection.close()

    if incident is None:
        return (
            "<h1>Incident Not Found</h1>"
            '<p>The requested incident does not exist.</p>'
            '<a href="/incidents">Back to Incidents</a>'
        ), 404

    return render_template(
        "incident_details.html",
        incident=incident,
    )


# --------------------------------------------------
# INCIDENT SEARCH
# --------------------------------------------------

@app.route("/search")
def global_search():
    query = request.args.get("q", "").strip()

    results = search_incidents(query) if query else []

    return render_template(
        "search.html",
        results=results,
        query=query,
    )


# --------------------------------------------------
# ANALYTICS
# --------------------------------------------------

@app.route("/analytics")
def analytics():
    connection = get_connection()

    try:
        attack_stats = connection.execute("""
            SELECT attack_type, COUNT(*) AS total
            FROM incidents
            GROUP BY attack_type
            ORDER BY total DESC
        """).fetchall()

        severity_stats = connection.execute("""
            SELECT severity, COUNT(*) AS total
            FROM incidents
            GROUP BY severity
            ORDER BY total DESC
        """).fetchall()

        recent_stats = connection.execute("""
            SELECT substr(timestamp, 1, 13) AS hour,
                   COUNT(*) AS total
            FROM incidents
            WHERE timestamp >=
                datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour DESC
            LIMIT 12
        """).fetchall()

    finally:
        connection.close()

    return render_template(
        "analytics.html",
        attack_stats=attack_stats,
        severity_stats=severity_stats,
        recent_stats=recent_stats,
        stats=get_stats(),
        incident_count=get_incident_count(),
    )


# --------------------------------------------------
# LIVE MONITORING API
# --------------------------------------------------

@app.route("/api/live")
def live_monitoring():
    recent = get_recent_incidents(10)

    incidents_data = [
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "ip_address": row["ip_address"],
            "attack_type": row["attack_type"],
            "severity": row["severity"],
            "method": row["method"],
            "url": row["url"],
            "action": row["action"],
        }
        for row in recent
    ]

    return jsonify({
        "status": "online",
        "stats": get_stats(),
        "incident_count": get_incident_count(),
        "incidents": incidents_data,
    })


# --------------------------------------------------
# HEALTH / STATUS API
# --------------------------------------------------

@app.route("/api/status")
def api_status():
    return jsonify({
        "service": "SentinelShield WAF",
        "status": "online",
        "database": "connected",
        "incidents": get_incident_count(),
    })


# --------------------------------------------------
# EXPORT INCIDENTS TO CSV
# --------------------------------------------------

@app.route("/export-csv", endpoint="export_csv")
def export_csv():
    connection = get_connection()

    try:
        rows = connection.execute("""
            SELECT id, timestamp, ip_address, attack_type,
                   severity, url, method, action, user_agent,
                   threat_score, country, ip_type
            FROM incidents
            ORDER BY id DESC
        """).fetchall()
    finally:
        connection.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Timestamp",
        "IP Address",
        "Attack Type",
        "Severity",
        "URL",
        "Method",
        "Action",
        "User Agent",
        "Threat Score",
        "Country",
        "IP Type",
    ])

    for row in rows:
        writer.writerow(list(row))

    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=sentinelshield_incidents.csv"
        },
    )


# --------------------------------------------------
# LOGOUT COMPATIBILITY ROUTE
# --------------------------------------------------

@app.route("/logout", endpoint="logout")
def logout():
    # This app version has no login/session authentication.
    # Redirect to the dashboard to satisfy base.html.
    return redirect(url_for("dashboard"))


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(404)
def page_not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({
            "status": "error",
            "message": "API endpoint not found.",
        }), 404

    return (
        "<h1>404 - Page Not Found</h1>"
        '<a href="/">Return to Dashboard</a>'
    ), 404


@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(
        "Internal server error: %s",
        error,
    )

    return jsonify({
        "status": "error",
        "message": "An internal server error occurred.",
    }), 500


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
