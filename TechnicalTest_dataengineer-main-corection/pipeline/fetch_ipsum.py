import argparse
import sqlite3
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

IPSUM_URLS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
]


def download_ipsum(timeout: int = 20) -> str:
    """Download ipsum.txt content from GitHub."""
    headers = {"User-Agent": "TechnicalTest-dataengineer/1.0"}

    for url in IPSUM_URLS:
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except (HTTPError, URLError, TimeoutError):
            continue

    raise RuntimeError("Unable to download ipsum.txt from GitHub.")


def save_content(content: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")


def load_to_db(txt_path: Path, db_path: Path, min_score: int = 3) -> int:
    """Parse ipsum.txt and load malicious IPs into SQLite. Returns count of IPs loaded."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # WAL mode prevents 'database is locked' when dashboard reads concurrently
    cursor.execute("PRAGMA journal_mode=WAL;")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malicious_ips (
            ip          TEXT PRIMARY KEY,
            score       INTEGER NOT NULL,
            updated_at  TEXT DEFAULT (datetime('now'))
        )
    """)

    # Full refresh on each run
    cursor.execute("DELETE FROM malicious_ips;")

    count = 0
    for line in txt_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        ip, score = parts[0], int(parts[1])
        if score >= min_score:
            cursor.execute(
                "INSERT OR REPLACE INTO malicious_ips (ip, score) VALUES (?, ?)",
                (ip, score),
            )
            count += 1

    conn.commit()
    conn.close()
    return count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download IPsum threat feed and load into SQLite."
    )
    parser.add_argument(
        "-o", "--output",
        default="data/ipsum.txt",
        help="Output .txt file path (default: data/ipsum.txt)",
    )
    parser.add_argument(
        "--db",
        default="data/security.db",
        help="SQLite database path (default: data/security.db)",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=3,
        help="Minimum blacklist score to include (default: 3)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="HTTP timeout in seconds (default: 20)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    db_path = Path(args.db)

    try:
        print("Downloading IPsum feed...")
        content = download_ipsum(timeout=args.timeout)
        save_content(content, output_path)
        print(f"IPsum feed saved to: {output_path}")

        print(f"Loading IPs into database (min score >= {args.min_score})...")
        count = load_to_db(output_path, db_path, min_score=args.min_score)
        print(f"Loaded {count} malicious IPs into: {db_path}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
