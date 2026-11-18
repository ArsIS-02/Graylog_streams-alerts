#!/bin/bash
# Непрерывный сбор unified log: один log stream, ротация без его перезапуска.
. /usr/local/etc/logstream/logstream.conf
LEVEL_ARG=(); [ "${LEVEL:-default}" != "default" ] && LEVEL_ARG=(--level "$LEVEL")
trap 'trap - TERM INT; kill 0; exit 0' TERM INT
while true; do
  /usr/bin/log stream --style ndjson --type log "${LEVEL_ARG[@]}" --predicate "$PREDICATE" 2>>/var/log/logstream-collector.err \
    | /usr/bin/perl /usr/local/libexec/logstream/rotate.pl "$LOGFILE" "$MAX_MB" "$KEEP"
  echo "$(date '+%Y-%m-%d %H:%M:%S') log stream завершился, перезапуск через 5 с" >> /var/log/logstream-collector.err
  sleep 5
done
