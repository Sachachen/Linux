import time
from pathlib import Path
from db import get_connection


def tail_file(filepath: str, parse_fn, start_at_end: bool = True) -> None:
    """Each thread creates its own DB connection."""
    conn = get_connection()  # ← own connection per thread
    path = Path(filepath)

    while not path.exists():
        print(f"Waiting for {filepath}...")
        time.sleep(2)

    with open(path, "r") as f:
        if start_at_end:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                parse_fn(line, conn)
            else:
                time.sleep(0.1)


def tail_multiline_file(filepath: str, parse_fn, separator: str = "Date:", start_at_end: bool = True) -> None:
    """Each thread creates its own DB connection."""
    conn = get_connection()  # ← own connection per thread
    path = Path(filepath)

    while not path.exists():
        print(f"Waiting for {filepath}...")
        time.sleep(2)

    buffer = []
    with open(path, "r") as f:
        if start_at_end:
            f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                if line.startswith(separator) and buffer:
                    parse_fn("\n".join(buffer), conn)
                    buffer = []
                buffer.append(line.strip())
            else:
                time.sleep(0.1)
