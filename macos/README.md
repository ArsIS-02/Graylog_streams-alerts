# macOS — агенты на хостах

Файлы для настройки сбора логов на macOS-хостах.

| Файл | Назначение |
|---|---|
| [`filebeat.yml`](filebeat.yml) | Filebeat (unified log, wifi.log, osquery) |
| [`osquery.conf`](osquery.conf) | конфиг osquery |
| [`co.elastic.filebeat.plist`](co.elastic.filebeat.plist) | LaunchDaemon для Filebeat |
| [`com.user.logstream.plist`](com.user.logstream.plist) | LaunchDaemon для `log stream` |
| [`zshrc.local`](zshrc.local) | хук логирования команд |
| [`logstream/`](logstream/) | ротация `unified.json.log` (wrapper + newsyslog) |

Подробная инструкция — [docs/05-macos.md](../docs/05-macos.md): unified log, Filebeat и osquery.
