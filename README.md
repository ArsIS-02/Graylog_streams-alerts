# Graylog + macOS мониторинг: конфигурационные файлы

Готовые конфигурации для централизованного сбора логов с macOS-хостов
в Graylog с помощью **Filebeat**, **osquery** и **unified logging**.

Репозиторий — практическое дополнение к статье

## Что собираем

| Источник | Что даёт | Инструмент |
|----------|----------|------------|
| Unified logging | Системные события, ошибки ядра, TCC, AirDrop, USB | `log stream` + Filebeat |
| `wifi.log` | Подключение/отключение USB-устройств | Filebeat |
| osquery | Снимки состояния системы (процессы, порты, FIM) | osqueryd + Filebeat |
| `commands.log` | История команд терминала (кастомно) | zsh hook + Filebeat |

## Структура репозитория

```
.
├── README.md
├── filebeat.yml                        # Конфиг Filebeat
├── co.elastic.filebeat.plist           # LaunchDaemon для Filebeat
├── osquery.conf                        # Конфиг osquery
├── com.user.logstream.plist            # LaunchDaemon для log stream (через wrapper)
├── zshrc.local                         # Хук логирования команд
├── logstream/
│   ├── logstream-wrapper.sh            # Обёртка: перезапуск log stream при ротации
│   └── unified.json.conf               # Конфиг newsyslog для ротации
└── docs/
    └── troubleshooting.md              # Грабли и их решения
```

## Установка

### 1. Filebeat

```bash
# Скопировать конфиг
sudo cp filebeat.yml /usr/local/filebeat/filebeat.yml

# Заменить YOUR GRAYLOG-SERVER IP:PORT на свой адрес
sudo nano /usr/local/filebeat/filebeat.yml

# Установить LaunchDaemon
sudo cp co.elastic.filebeat.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/co.elastic.filebeat.plist
sudo chmod 644 /Library/LaunchDaemons/co.elastic.filebeat.plist

# Запустить
sudo launchctl load /Library/LaunchDaemons/co.elastic.filebeat.plist
```

### 2. osquery

```bash
# Скопировать конфиг
sudo cp osquery.conf /private/var/osquery/osquery.conf

# Запустить
sudo launchctl load /Library/LaunchDaemons/io.osquery.agent.plist
```

### 3. Ротация unified.json.log

```bash
# Wrapper
sudo cp logstream/logstream-wrapper.sh /usr/local/bin/
sudo chmod 755 /usr/local/bin/logstream-wrapper.sh

# Конфиг newsyslog
sudo cp logstream/unified.json.conf /etc/newsyslog.d/

# LaunchDaemon
sudo cp com.user.logstream.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.user.logstream.plist
sudo chmod 644 /Library/LaunchDaemons/com.user.logstream.plist

# Запустить
sudo launchctl load /Library/LaunchDaemons/com.user.logstream.plist
```

### 4. Логирование команд (опционально)

```bash
# Создать каталог
mkdir -p ~/.local/log

# Подключить хук в ~/.zshrc
echo 'source ~/.zshrc.local' >> ~/.zshrc

# Скопировать конфиг
cp zshrc.local ~/.zshrc.local
```

## Проверка

```bash
# Filebeat работает?
sudo launchctl list | grep filebeat

# log stream пишет?
sudo ls -lah /var/log/unified.json.log

# Данные идут в Graylog?
sudo log show --predicate 'process == "filebeat"' --last 5m --info | \
  grep -iE "events.sent|connection"
```

## Важные замечания

- **`include_lines` в Filebeat — подстрочный поиск**, не regex.
  Не добавляй паттерны, которые матчатся у шумных процессов
  (например, `Sandbox` или `incorrect` — их генерирует Kaspersky).
  Подробнее — в [docs/troubleshooting.md](docs/troubleshooting.md).

- **`log stream` держит файл открытым**, поэтому нужен wrapper
  для ротации `unified.json.log`. Без него файл растёт до десятков ГБ.

- **Не дублируй `preexec`** в `.zshrc` — используй `add-zsh-hook`.
  Иначе команды пишутся в `commands.log` дважды.

## Troubleshooting

Все найденные грабли и их решения собраны в
[docs/troubleshooting.md](docs/troubleshooting.md):

1. Рост `unified.json.log` до 14 ГБ
2. Дубли команд в `commands.log`
3. Kaspersky засоряет unified logs
4. `include_lines` vs regex
5. APFS snapshots и освобождение места
6. `nc -w 1` (BiZone)
7. Filebeat и права на `audit.log`
8. Beats input: порт не слушается
9. Диагностика «идут ли данные»

## Ссылки

- [Graylog Documentation](https://docs.graylog.org/)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [osquery Documentation](https://osquery.readthedocs.io/)
