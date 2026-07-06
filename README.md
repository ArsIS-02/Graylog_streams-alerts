# Graylog + macOS мониторинг: конфигурационные файлы

Этот репозиторий содержит готовые конфигурации для настройки сбора логов с macOS в Graylog с помощью Filebeat и osquery.

## Состав
- `filebeat/filebeat.yml` — конфиг Filebeat для чтения логов (unified logs, osquery, wifi.log и др.).
- `filebeat/co.elastic.filebeat.plist` — LaunchDaemon для автозапуска Filebeat.
- `osquery/osquery.conf` — конфиг osquery с расписанием запросов.
- `logstream/com.user.logstream.plist` — LaunchDaemon для выгрузки unified logs в JSON-файл.

## Использование
1. Замени `YOUR_GRAYLOG_IP` на IP твоего Graylog-сервера в файлах.
2. Скопируй файлы в соответствующие каталоги:
   - `/usr/local/filebeat/filebeat.yml`
   - `/private/var/osquery/osquery.conf`
   - `/Library/LaunchDaemons/co.elastic.filebeat.plist`
   - `/Library/LaunchDaemons/com.user.logstream.plist`
3. Загрузи демоны и проверь логи.

Подробная инструкция — в статье.
