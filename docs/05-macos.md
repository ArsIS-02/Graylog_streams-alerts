# macOS: unified log, Filebeat и osquery

> Сбор логов с macOS-хостов: unified logging, USB-события, снимки osquery и
> доставка через Filebeat в Graylog. Эта часть — расширение лаборатории на macOS;
> в базовых статьях она не описывалась, конфиги собраны в этом репозитории.

## Что собираем

| Источник | Что даёт | Инструмент |
|---|---|---|
| Unified logging | Системные события, ошибки ядра, TCC, AirDrop, USB | `log stream` + Filebeat |
| `wifi.log` | Подключение/отключение USB-устройств | Filebeat |
| osquery | Снимки состояния системы (процессы, порты, FIM) | osqueryd + Filebeat |
| `commands.log` | История команд терминала (кастомно) | zsh hook + Filebeat |

## Файлы в репозитории

| Файл | Назначение |
|---|---|
| [`filebeat.yml`](../filebeat.yml) | Конфиг Filebeat (unified log, wifi.log, osquery) |
| [`co.elastic.filebeat.plist`](../co.elastic.filebeat.plist) | LaunchDaemon для Filebeat |
| [`osquery.conf`](../osquery.conf) | Конфиг osquery |
| [`com.user.logstream.plist`](../com.user.logstream.plist) | LaunchDaemon для `log stream` (через wrapper) |
| [`zshrc.local`](../zshrc.local) | Хук логирования команд |
| [`logstream/logstream-wrapper.sh`](../logstream/logstream-wrapper.sh) | Обёртка: перезапуск `log stream` при ротации |
| [`logstream/unified.json.conf`](../logstream/unified.json.conf) | Конфиг newsyslog для ротации |

## Установка

### Filebeat

```bash
sudo cp filebeat.yml /usr/local/filebeat/filebeat.yml
# замените "YOUR GRAYLOG-SERVER IP:PORT" на адрес своего Graylog
sudo nano /usr/local/filebeat/filebeat.yml

sudo cp co.elastic.filebeat.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/co.elastic.filebeat.plist
sudo chmod 644 /Library/LaunchDaemons/co.elastic.filebeat.plist
sudo launchctl load /Library/LaunchDaemons/co.elastic.filebeat.plist
```

### osquery

```bash
sudo cp osquery.conf /private/var/osquery/osquery.conf
sudo launchctl load /Library/LaunchDaemons/io.osquery.agent.plist
```

### Ротация unified.json.log

```bash
sudo cp logstream/logstream-wrapper.sh /usr/local/bin/
sudo chmod 755 /usr/local/bin/logstream-wrapper.sh
sudo cp logstream/unified.json.conf /etc/newsyslog.d/
sudo cp com.user.logstream.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.user.logstream.plist
sudo chmod 644 /Library/LaunchDaemons/com.user.logstream.plist
sudo launchctl load /Library/LaunchDaemons/com.user.logstream.plist
```

### Логирование команд (опционально)

```bash
mkdir -p ~/.local/log
echo 'source ~/.zshrc.local' >> ~/.zshrc
cp zshrc.local ~/.zshrc.local
```

## Проверка

```bash
sudo launchctl list | grep filebeat          # Filebeat работает?
sudo ls -lah /var/log/unified.json.log       # log stream пишет?
sudo log show --predicate 'process == "filebeat"' --last 5m --info | \
  grep -iE "events.sent|connection"          # данные идут в Graylog?
```

## Важные замечания

- **`include_lines` в Filebeat — подстрочный поиск, не regex.** Не добавляйте паттерны,
  которые матчатся у шумных процессов (например, `Sandbox` или `incorrect` — их
  генерирует Kaspersky).
- **`log stream` держит файл открытым**, поэтому нужен wrapper для ротации
  `unified.json.log`. Без него файл растёт до десятков ГБ.
- **Не дублируйте `preexec`** в `.zshrc` — используйте `add-zsh-hook`, иначе команды
  пишутся в `commands.log` дважды.

Подробнее — в [`docs/troubleshooting.md`](troubleshooting.md).

## Алерты для macOS

Алерты для macOS строятся так же, как для Windows и Linux (см.
[02-streams-alerts.md](02-streams-alerts.md)): выберите поток с macOS-логами,
задайте условие по структурированным полям (`log_type: macos_unified`,
`host`, `process`) и привяжите email-уведомление. Примеры полезных условий:

- `log_type: macos_unified AND message: "kernel panic"` — паника ядра;
- `log_type: macos_wifi_usb AND message: "USBDeviceInserted"` — новое USB-устройство;
- отсутствие логов от хоста за интервал — признак, что Mac выключен или потерял связь.
