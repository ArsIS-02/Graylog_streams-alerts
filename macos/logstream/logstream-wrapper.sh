#!/bin/bash
# ============================================================================
# logstream-wrapper.sh — запускает `log stream` и перезапускает его
# при превышении размера файла, чтобы newsyslog мог ротировать лог.
#
# Зачем: `log stream` держит файл открытым и не отпускает его даже после
# ротации через newsyslog. Поэтому единственный способ — периодически
# перезапускать процесс.
#
# Разворачивается в: /usr/local/bin/logstream-wrapper.sh
# LaunchDaemon:      /Library/LaunchDaemons/com.user.logstream.plist
# newsyslog:         /etc/newsyslog.d/unified.json.conf
# ============================================================================
set -uo pipefail

LOG_FILE="/var/log/unified.json.log"
MAX_SIZE_MB=50   # порог ротации; при превышении — перезапуск log stream

while true; do
    /usr/bin/log stream --style ndjson > "$LOG_FILE" 2>/dev/null &
    LOGPID=$!

    while kill -0 $LOGPID 2>/dev/null; do
        sleep 60
        if [ -f "$LOG_FILE" ]; then
            SIZE_MB=$(( $(stat -f%z "$LOG_FILE") / 1048576 ))
            if [ "$SIZE_MB" -ge "$MAX_SIZE_MB" ]; then
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] rotating: ${SIZE_MB} MB"
                kill -TERM $LOGPID 2>/dev/null
                sleep 3
                /usr/sbin/newsyslog -F -f /etc/newsyslog.d/unified.json.conf 2>/dev/null
                break
            fi
        fi
    done

    wait $LOGPID 2>/dev/null
done
