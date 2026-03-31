import sqlite3


def enrich_ip(ip: str, conn: sqlite3.Connection) -> dict:
    cursor = conn.cursor()
    cursor.execute("SELECT danger_level FROM malicious_ips WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    return {"is_malicious": 1 if row else 0, "threat_score": row[0] if row else 0}