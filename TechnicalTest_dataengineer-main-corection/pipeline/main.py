import os
import threading
from db import get_connection, init_db, init_malicious_ips
from parsers import parse_and_store_ids, parse_and_store_access, parse_and_store_endpoint
from tailer import tail_file, tail_multiline_file

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

IDS_LOG      = os.path.join(BASE, "Security-Log-Generator/logs/ids.log")
ACCESS_LOG   = os.path.join(BASE, "Security-Log-Generator/logs/access.log")
ENDPOINT_LOG = os.path.join(BASE, "Security-Log-Generator/logs/endpoint.log")


def main():
    # Init DB schema using a temporary connection
    conn = get_connection()
    init_db(conn)
    init_malicious_ips()
    conn.close()  # ← close after init, threads will open their own

    print("Pipeline started. Tailing log files...")

    # Default behavior follows new log lines only; set PIPELINE_READ_FROM_START=1 to replay existing logs.
    read_from_start = os.getenv("PIPELINE_READ_FROM_START", "0") == "1"
    start_at_end = not read_from_start

    threads = [
        threading.Thread(target=tail_file,           args=(IDS_LOG,      parse_and_store_ids),      kwargs={"start_at_end": start_at_end}, daemon=True),
        threading.Thread(target=tail_file,           args=(ACCESS_LOG,   parse_and_store_access),   kwargs={"start_at_end": start_at_end}, daemon=True),
        threading.Thread(target=tail_multiline_file, args=(ENDPOINT_LOG, parse_and_store_endpoint), kwargs={"start_at_end": start_at_end}, daemon=True),
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
