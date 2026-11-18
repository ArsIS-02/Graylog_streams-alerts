# macOS — агенты на хостах

Файлы для настройки сбора логов на macOS-хостах.

| Файл | Назначение |
|---|---|
| [`filebeat.yml`](filebeat.yml) | Filebeat (unified log, wifi.log, osquery, commands.log) |
| [`osquery.conf`](osquery.conf) | конфиг osquery (расписание запросов) |
| [`osquery.flags`](osquery.flags) | флаги osqueryd: ротация логов (10 × 25 МБ), host_identifier, endpointsecurity |
| [`co.elastic.filebeat.plist`](co.elastic.filebeat.plist) | LaunchDaemon для Filebeat (без `-e`: логи в `logs/*.ndjson`, 7 × 10 МБ) |
| [`com.user.logstream.plist`](com.user.logstream.plist) | LaunchDaemon для `log stream` |
| [`zshrc.local`](zshrc.local) | хук логирования команд |
| [`logstream/`](logstream/) | сбор и ротация `unified.json.log`: `collector.sh` + `rotate.pl` + `logstream.conf` (MAX_MB=50, KEEP=72) |

Эталон с MacMiniM2, 18.11.2026 приведён к единому виду на всех трёх маках
(MacMiniM2, MacBook-Pro, MacBookPro-M4Pro). Ключевое про ротацию: filebeat
запускается **без** флага `-e` и без `StandardOutPath` в plist — иначе
`/var/log/filebeat.log` растёт бесконечно (набегало 500+ МБ). osquery без
`--verbose`, с `logger_rotate`.

Подробная инструкция — [docs/05-macos.md](../docs/05-macos.md): unified log, Filebeat и osquery.

## Второй подход — BI.ZONE Triage

Отдельный способ сбора телеметрии macOS (процессы, сеть, autoruns, baseline)
через BI.ZONE Triage лежит в каталоге [`bztriage/`](bztriage/):

- [`bztriage/scripts/`](bztriage/scripts/) — `bzt-stream.sh`, `bzt-filter.pl`,
  `bzt-diagnose.sh` и три launchd-plist-а;
- [`bztriage/docs/`](bztriage/docs/) — архитектура, поля, настройка Graylog, грабли.

Подробности — в [docs/06-macos-bztriage.md](../docs/06-macos-bztriage.md).
