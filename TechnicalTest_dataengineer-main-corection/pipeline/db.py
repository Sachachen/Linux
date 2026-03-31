import sqlite3

DB_PATH = "data/security.db"

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp         TEXT,
            log_type          TEXT,
            src_ip            TEXT,
            dest_ip           TEXT,
            protocol          TEXT,
            severity          TEXT,
            alert_desc        TEXT,
            flags             TEXT,
            client_ip         TEXT,
            method            TEXT,
            status            INTEGER,
            resource          TEXT,
            is_malicious_src  INTEGER DEFAULT 0,
            threat_score_src  INTEGER DEFAULT 0,
            is_malicious_dst  INTEGER DEFAULT 0,
            threat_score_dst  INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malicious_ips (
            ip            TEXT PRIMARY KEY,
            danger_level  INTEGER DEFAULT 0
        )
    """)
    conn.commit()


def init_malicious_ips(db_path=DB_PATH, ipsum_path="data/ipsum.txt"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        with open(ipsum_path, "r") as f:
            rows = []
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                ip = parts[0].strip()
                danger = int(parts[1].strip()) if len(parts) > 1 else 0
                rows.append((ip, danger))

        cursor.executemany(
            "INSERT OR IGNORE INTO malicious_ips (ip, danger_level) VALUES (?, ?)",
            rows
        )
        print(f"[init] {len(rows)} IPs malveillantes chargées.")
    except FileNotFoundError:
        print(f"[init] Fichier introuvable : {ipsum_path}")

    conn.commit()
    conn.close()