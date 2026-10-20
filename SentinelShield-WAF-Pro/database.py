import sqlite3
from datetime import datetime, timedelta

import os

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "sentinelshield.db"
)

def get_connection():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    conn = get_connection()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        url TEXT NOT NULL,
        method TEXT NOT NULL,
        action TEXT NOT NULL,
        user_agent TEXT,
        threat_score INTEGER DEFAULT 0,
        country TEXT DEFAULT 'Unknown',
        ip_type TEXT DEFAULT 'Unknown'
    );

    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        action TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS rate_limit_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        timestamp REAL NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        level TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        incident_id INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp);
    CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(ip_address);
    CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
    CREATE INDEX IF NOT EXISTS idx_rate_ip_time ON rate_limit_requests(ip_address, timestamp);
    """)
    # Backward-compatible columns for databases from earlier SentinelShield versions.
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(incidents)").fetchall()}
    for name, ddl in [
        ("threat_score", "ALTER TABLE incidents ADD COLUMN threat_score INTEGER DEFAULT 0"),
        ("country", "ALTER TABLE incidents ADD COLUMN country TEXT DEFAULT 'Unknown'"),
        ("ip_type", "ALTER TABLE incidents ADD COLUMN ip_type TEXT DEFAULT 'Unknown'"),
    ]:
        if name not in cols:
            conn.execute(ddl)

    req_cols = {r["name"] for r in conn.execute("PRAGMA table_info(requests)").fetchall()}
    if "action" not in req_cols:
        conn.execute("ALTER TABLE requests ADD COLUMN action TEXT NOT NULL DEFAULT 'ALLOWED'")
    conn.commit()
    conn.close()

def save_incident(ip_address, attack_type, severity, url, method, action,
                  user_agent="", threat_score=0, country="Unknown", ip_type="Unknown"):
    conn = get_connection()
    cur = conn.execute("""
        INSERT INTO incidents
        (timestamp, ip_address, attack_type, severity, url, method, action,
         user_agent, threat_score, country, ip_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip_address, attack_type,
          severity, url, method, action, user_agent, threat_score, country, ip_type))
    conn.commit()
    incident_id = cur.lastrowid
    conn.close()
    return incident_id

def get_recent_incidents(limit=20):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    conn.close()
    return rows

def get_incident_by_id(incident_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    return row

def get_incident_count():
    conn = get_connection()
    row = conn.execute("SELECT COUNT(*) total FROM incidents").fetchone()
    conn.close()
    return row["total"]

def save_request(ip_address, method, url, action):
    conn = get_connection()
    conn.execute("INSERT INTO requests(timestamp,ip_address,method,url,action) VALUES(?,?,?,?,?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip_address, method, url, action))
    conn.commit()
    conn.close()

def search_incidents(query="", attack_type="", severity="", action="", ip="", start_date="", end_date=""):
    conn = get_connection()
    sql = "SELECT * FROM incidents WHERE 1=1"
    params = []
    if query:
        sql += " AND (url LIKE ? OR user_agent LIKE ? OR ip_address LIKE ? OR attack_type LIKE ?)"
        q = f"%{query}%"
        params += [q, q, q, q]
    if attack_type:
        sql += " AND attack_type=?"; params.append(attack_type)
    if severity:
        sql += " AND severity=?"; params.append(severity)
    if action:
        sql += " AND action=?"; params.append(action)
    if ip:
        sql += " AND ip_address LIKE ?"; params.append(f"%{ip}%")
    if start_date:
        sql += " AND date(timestamp) >= date(?)"; params.append(start_date)
    if end_date:
        sql += " AND date(timestamp) <= date(?)"; params.append(end_date)
    sql += " ORDER BY id DESC"
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return rows

def get_dashboard_statistics():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) n FROM requests").fetchone()["n"]
    blocked = conn.execute("SELECT COUNT(*) n FROM requests WHERE action='BLOCKED'").fetchone()["n"]
    incidents = conn.execute("SELECT COUNT(*) n FROM incidents").fetchone()["n"]
    attacks = conn.execute("""
        SELECT attack_type, COUNT(*) n FROM incidents GROUP BY attack_type ORDER BY n DESC
    """).fetchall()
    severity = conn.execute("""
        SELECT severity, COUNT(*) n FROM incidents GROUP BY severity
    """).fetchall()
    hourly = conn.execute("""
        SELECT substr(timestamp,1,13) hour, COUNT(*) n
        FROM incidents
        WHERE timestamp >= datetime('now','-24 hours')
        GROUP BY hour ORDER BY hour
    """).fetchall()
    top_ips = conn.execute("""
        SELECT ip_address, COUNT(*) n FROM incidents GROUP BY ip_address ORDER BY n DESC LIMIT 10
    """).fetchall()
    score = conn.execute("SELECT COALESCE(SUM(threat_score),0) n FROM incidents").fetchone()["n"]
    conn.close()
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "allowed_requests": total - blocked,
        "incidents": incidents,
        "block_rate": round((blocked / total * 100), 2) if total else 0,
        "threat_score": score,
        "attack_stats": [dict(r) for r in attacks],
        "severity_stats": [dict(r) for r in severity],
        "hourly_stats": [dict(r) for r in hourly],
        "top_ips": [dict(r) for r in top_ips],
    }

def get_total_requests():
    conn=get_connection(); n=conn.execute("SELECT COUNT(*) n FROM requests").fetchone()["n"]; conn.close(); return n

def get_blocked_requests():
    conn=get_connection(); n=conn.execute("SELECT COUNT(*) n FROM requests WHERE action='BLOCKED'").fetchone()["n"]; conn.close(); return n

def get_attack_statistics():
    conn=get_connection()
    rows=conn.execute("SELECT attack_type, COUNT(*) n FROM incidents GROUP BY attack_type ORDER BY n DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_severity_statistics():
    conn=get_connection()
    rows=conn.execute("SELECT severity, COUNT(*) n FROM incidents GROUP BY severity ORDER BY n DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_hourly_statistics():
    conn=get_connection()
    rows=conn.execute("""
        SELECT substr(timestamp,1,13) hour, COUNT(*) n FROM incidents
        WHERE timestamp >= datetime('now','-24 hours') GROUP BY hour ORDER BY hour
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def record_rate_request(ip_address, timestamp=None):
    import time
    ts = time.time() if timestamp is None else timestamp
    conn=get_connection()
    conn.execute("INSERT INTO rate_limit_requests(ip_address,timestamp) VALUES(?,?)",(ip_address,ts))
    conn.commit(); conn.close()

def get_recent_rate_requests(ip_address, window_start):
    import time
    conn=get_connection()
    n=conn.execute("SELECT COUNT(*) n FROM rate_limit_requests WHERE ip_address=? AND timestamp>=?",
                   (ip_address,window_start)).fetchone()["n"]
    conn.close(); return n

def cleanup_rate_requests(cutoff):
    conn=get_connection()
    conn.execute("DELETE FROM rate_limit_requests WHERE timestamp < ?",(cutoff,))
    conn.commit(); conn.close()

def create_alert(level,title,message,incident_id=None):
    conn=get_connection()
    conn.execute("INSERT INTO alerts(timestamp,level,title,message,incident_id) VALUES(?,?,?,?,?)",
                 (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),level,title,message,incident_id))
    conn.commit(); conn.close()

def get_recent_alerts(limit=20):
    conn=get_connection()
    rows=conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?",(int(limit),)).fetchall()
    conn.close(); return rows

def get_anomaly_snapshot():
    conn=get_connection()
    now=datetime.now()
    start=(now-timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
    prev_start=(now-timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S")
    current=conn.execute("SELECT COUNT(*) n FROM requests WHERE timestamp>=?",(start,)).fetchone()["n"]
    previous=conn.execute("SELECT COUNT(*) n FROM requests WHERE timestamp>=? AND timestamp<?",
                          (prev_start,start)).fetchone()["n"]
    unique_ips=conn.execute("SELECT COUNT(DISTINCT ip_address) n FROM requests WHERE timestamp>=?",(start,)).fetchone()["n"]
    conn.close()
    baseline=max(previous,1)
    ratio=current/baseline
    anomalous = current >= 20 or ratio >= 3
    return {"current_10m":current,"previous_10m":previous,"unique_ips":unique_ips,
            "ratio":round(ratio,2),"anomalous":anomalous}
