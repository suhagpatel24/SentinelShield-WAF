"""PostgreSQL database layer for SentinelShield (Supabase-compatible)."""
import os
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured. Add your Supabase PostgreSQL connection string in Render Environment Variables.")
    # Supabase connection strings normally require SSL. sslmode=require enforces encryption.
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10, sslmode="require", prepare_threshold=None)


def initialize_database():
    statements = [
        """CREATE TABLE IF NOT EXISTS incidents (
            id BIGSERIAL PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            ip_address TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT NOT NULL,
            action TEXT NOT NULL,
            user_agent TEXT DEFAULT '',
            threat_score INTEGER NOT NULL DEFAULT 0,
            country TEXT NOT NULL DEFAULT 'Unknown',
            ip_type TEXT NOT NULL DEFAULT 'Unknown'
        )""",
        """CREATE TABLE IF NOT EXISTS requests (
            id BIGSERIAL PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            ip_address TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            action TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS rate_limit_requests (
            id BIGSERIAL PRIMARY KEY,
            ip_address TEXT NOT NULL,
            timestamp DOUBLE PRECISION NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS alerts (
            id BIGSERIAL PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            level TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            incident_id BIGINT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_rate_ip_time ON rate_limit_requests(ip_address, timestamp)",
    ]
    with get_connection() as conn:
        for statement in statements:
            conn.execute(statement)
        conn.commit()


def save_incident(ip_address, attack_type, severity, url, method, action,
                  user_agent="", threat_score=0, country="Unknown", ip_type="Unknown"):
    with get_connection() as conn:
        row = conn.execute("""INSERT INTO incidents
            (ip_address, attack_type, severity, url, method, action, user_agent, threat_score, country, ip_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (ip_address, attack_type, severity, url, method, action, user_agent,
             int(threat_score or 0), country, ip_type)).fetchone()
        conn.commit()
        return row["id"]


def get_recent_incidents(limit=20):
    with get_connection() as conn:
        return conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT %s", (max(1, min(int(limit), 500)),)).fetchall()


def get_incident_by_id(incident_id):
    with get_connection() as conn:
        return conn.execute("SELECT * FROM incidents WHERE id=%s", (incident_id,)).fetchone()


def get_incident_count():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) AS total FROM incidents").fetchone()["total"]


def save_request(ip_address, method, url, action):
    with get_connection() as conn:
        conn.execute("INSERT INTO requests(ip_address, method, url, action) VALUES(%s, %s, %s, %s)",
                     (ip_address, method, url, action))
        conn.commit()


def search_incidents(query="", attack_type="", severity="", action="", ip="", start_date="", end_date=""):
    sql = "SELECT * FROM incidents WHERE TRUE"
    params = []
    if query:
        sql += " AND (url ILIKE %s OR user_agent ILIKE %s OR ip_address ILIKE %s OR attack_type ILIKE %s)"
        q = f"%{query}%"
        params.extend([q, q, q, q])
    if attack_type:
        sql += " AND attack_type=%s"; params.append(attack_type)
    if severity:
        sql += " AND severity=%s"; params.append(severity)
    if action:
        sql += " AND action=%s"; params.append(action)
    if ip:
        sql += " AND ip_address ILIKE %s"; params.append(f"%{ip}%")
    if start_date:
        sql += " AND timestamp::date >= %s::date"; params.append(start_date)
    if end_date:
        sql += " AND timestamp::date <= %s::date"; params.append(end_date)
    sql += " ORDER BY id DESC LIMIT 500"
    with get_connection() as conn:
        return conn.execute(sql, params).fetchall()


def get_dashboard_statistics():
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS n FROM requests").fetchone()["n"]
        blocked = conn.execute("SELECT COUNT(*) AS n FROM requests WHERE action='BLOCKED'").fetchone()["n"]
        incidents = conn.execute("SELECT COUNT(*) AS n FROM incidents").fetchone()["n"]
        attacks = conn.execute("SELECT attack_type, COUNT(*) AS n FROM incidents GROUP BY attack_type ORDER BY n DESC").fetchall()
        severity = conn.execute("SELECT severity, COUNT(*) AS n FROM incidents GROUP BY severity ORDER BY n DESC").fetchall()
        hourly = conn.execute("""SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD HH24:00') AS hour,
            COUNT(*) AS n FROM incidents WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY date_trunc('hour', timestamp) ORDER BY date_trunc('hour', timestamp)""").fetchall()
        top_ips = conn.execute("SELECT ip_address, COUNT(*) AS n FROM incidents GROUP BY ip_address ORDER BY n DESC LIMIT 10").fetchall()
        score = conn.execute("SELECT COALESCE(SUM(threat_score), 0) AS n FROM incidents").fetchone()["n"]
    return {
        "total_requests": total, "blocked_requests": blocked,
        "allowed_requests": total - blocked, "incidents": incidents,
        "block_rate": round(blocked / total * 100, 2) if total else 0,
        "threat_score": score, "attack_stats": [dict(r) for r in attacks],
        "severity_stats": [dict(r) for r in severity],
        "hourly_stats": [dict(r) for r in hourly], "top_ips": [dict(r) for r in top_ips],
    }


def get_total_requests():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM requests").fetchone()["n"]


def get_blocked_requests():
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM requests WHERE action='BLOCKED'").fetchone()["n"]


def get_attack_statistics():
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT attack_type, COUNT(*) AS n FROM incidents GROUP BY attack_type ORDER BY n DESC").fetchall()]


def get_severity_statistics():
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT severity, COUNT(*) AS n FROM incidents GROUP BY severity ORDER BY n DESC").fetchall()]


def get_hourly_statistics():
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("""SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD HH24:00') AS hour,
            COUNT(*) AS n FROM incidents WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY date_trunc('hour', timestamp) ORDER BY date_trunc('hour', timestamp)""").fetchall()]


def record_rate_request(ip_address, timestamp=None):
    import time
    ts = time.time() if timestamp is None else timestamp
    with get_connection() as conn:
        conn.execute("INSERT INTO rate_limit_requests(ip_address, timestamp) VALUES(%s, %s)", (ip_address, ts))
        conn.commit()


def get_recent_rate_requests(ip_address, window_start):
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) AS n FROM rate_limit_requests WHERE ip_address=%s AND timestamp >= %s",
                            (ip_address, window_start)).fetchone()["n"]


def cleanup_rate_requests(cutoff):
    with get_connection() as conn:
        conn.execute("DELETE FROM rate_limit_requests WHERE timestamp < %s", (cutoff,))
        conn.commit()


def create_alert(level, title, message, incident_id=None):
    with get_connection() as conn:
        conn.execute("INSERT INTO alerts(level, title, message, incident_id) VALUES(%s, %s, %s, %s)",
                     (level, title, message, incident_id))
        conn.commit()


def get_recent_alerts(limit=20):
    with get_connection() as conn:
        return conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT %s", (max(1, min(int(limit), 100)),)).fetchall()


def get_anomaly_snapshot():
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=10)
    prev_start = now - timedelta(minutes=20)
    with get_connection() as conn:
        current = conn.execute("SELECT COUNT(*) AS n FROM requests WHERE timestamp >= %s", (start,)).fetchone()["n"]
        previous = conn.execute("SELECT COUNT(*) AS n FROM requests WHERE timestamp >= %s AND timestamp < %s",
                                (prev_start, start)).fetchone()["n"]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT ip_address) AS n FROM requests WHERE timestamp >= %s",
                                  (start,)).fetchone()["n"]
    baseline = max(previous, 1)
    ratio = current / baseline
    return {"current_10m": current, "previous_10m": previous, "unique_ips": unique_ips,
            "ratio": round(ratio, 2), "anomalous": current >= 20 or ratio >= 3}
