import re
import sqlite3
from enricher import enrich_ip


def clean_timestamp(ts: str) -> str:
    """Normalize any timestamp format to 'YYYY-MM-DD HH:MM:SS'."""
    ts = ts.strip()
    ts = ts.replace(",", ".")
    ts = ts.split(".")[0]  # remove milliseconds
    return ts


# ---------------------------------------------------------------------------
# IDS
# Format: "2026-03-31 00:24:00,123 - ids_logger_1 - low_severity - TCP - 1.2.3.4:1234 --> 5.6.7.8:80 - SYN - Port scanning"
# ---------------------------------------------------------------------------
IDS_PATTERN = re.compile(
    r"(?P<timestamp>[\d\-]+ [\d:,]+)"
    r"\s+-\s+ids_logger_1\s+-\s+"
    r"(?P<severity>[\w_]+)\s+-\s+"
    r"(?P<protocol>\w+)\s+-\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)"
    r"\s+-->\s+"
    r"(?P<dest_ip>[\d.]+):(?P<dest_port>\d+)"
    r"\s+-\s+(?P<flags>\w+)"
    r"\s+-\s+(?P<alert_desc>.+)"
)


def parse_and_store_ids(line: str, conn: sqlite3.Connection) -> None:
    match = IDS_PATTERN.match(line.strip())
    if not match:
        return

    event = match.groupdict()
    src_ip  = str(event["src_ip"]).strip()
    dest_ip = str(event["dest_ip"]).strip()

    src = enrich_ip(src_ip, conn)
    dst = enrich_ip(dest_ip, conn)

    conn.execute("""
        INSERT INTO security_events
            (timestamp, log_type, src_ip, dest_ip, protocol, severity,
             alert_desc, flags,
             is_malicious_src, threat_score_src,
             is_malicious_dst, threat_score_dst)
        VALUES (?, 'ids', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        clean_timestamp(event["timestamp"]),
        src_ip, dest_ip,
        event["protocol"], event["severity"],
        event["alert_desc"].strip(), event["flags"],
        1,                        # ← toujours malveillant (log IDS = menace confirmée)
        src["threat_score"],      # ← danger_level depuis ipsum.txt si connu, sinon 0
        1,                        # ← idem pour la destination
        dst["threat_score"],
    ))
    conn.commit()


# ---------------------------------------------------------------------------
# ACCESS
# Format: "[2026-03-31 00:24:00] - access_logger_1 - 1.2.3.4 - user "GET /path HTTP/1.1 200 512 -" "Mozilla""
# ---------------------------------------------------------------------------
ACCESS_PATTERN = re.compile(
    r"\[(?P<timestamp>[^\]]+)\]"
    r"\s+-\s+access_logger_1\s+-\s+"
    r"(?P<client_ip>[\d.]+)\s+-\s+"
    r"(?P<user>\S+)\s+"
    r'"(?P<method>\S+)\s+(?P<resource>\S+)\s+(?P<protocol>\S+)\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\d+)\s+(?P<referrer>\S+)"\s+'
    r'"(?P<user_agent>.+)"'
)


def parse_and_store_access(line: str, conn: sqlite3.Connection) -> None:
    match = ACCESS_PATTERN.match(line.strip())
    if not match:
        return

    event = match.groupdict()
    client_ip = str(event["client_ip"]).strip()

    src = enrich_ip(client_ip, conn)

    conn.execute("""
        INSERT INTO security_events
            (timestamp, log_type, client_ip, method, status, resource,
             is_malicious_src, threat_score_src)
        VALUES (?, 'access', ?, ?, ?, ?, ?, ?)
    """, (
        clean_timestamp(event["timestamp"]),
        client_ip,
        event["method"],
        int(event["status"]),
        event["resource"],
        src["is_malicious"], src["threat_score"],
    ))
    conn.commit()


# ---------------------------------------------------------------------------
# ENDPOINT (multi-line, no IPs)
# ---------------------------------------------------------------------------
def parse_and_store_endpoint(block: str, conn: sqlite3.Connection) -> None:
    def extract(field: str) -> str:
        match = re.search(rf"{field}:\s*(.+)", block)
        return match.group(1).strip() if match else None

    timestamp  = extract("Date")
    event_type = extract("Event Type")

    if not timestamp or not event_type:
        return

    conn.execute("""
        INSERT INTO security_events (timestamp, log_type, alert_desc)
        VALUES (?, 'endpoint', ?)
    """, (clean_timestamp(timestamp), event_type))
    conn.commit()
