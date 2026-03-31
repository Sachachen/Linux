#!/bin/bash
echo " Stopping all processes..."
pkill -f "python" 2>/dev/null
sleep 1

echo "  Clearing database..."
rm -f data/security.db
rm -f data/security.db-shm
rm -f data/security.db-wal

echo "  Clearing log files..."
rm -f Security-Log-Generator/logs/ids.log
rm -f Security-Log-Generator/logs/access.log
rm -f Security-Log-Generator/logs/endpoint.log

echo " Reset complete. Run ./start.sh to restart."
