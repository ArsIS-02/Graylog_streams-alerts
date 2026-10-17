# Troubleshooting — грабли при настройке мониторинга macOS

Здесь собраны проблемы, с которыми я столкнулся на практике, и их решения.

---

## 1. `unified.json.log` растёт бесконечно (до 14 ГБ)

**Симптом:** файл `/var/log/unified.json.log` растёт до десятков гигабайт,
диск заполняется, `log stream` пишет без остановки.

**Причина:** `log stream` пишет в файл через перенаправление stdout из
LaunchDaemon `com.user.logstream`. Штатный `newsyslog` про этот файл
ничего не знает и не ротирует его.

**Решение:** связка wrapper + newsyslog:

1. `/etc/newsyslog.d/unified.json.conf` — правила ротации (50 МБ, 7 архивов)
2. `/usr/local/bin/logstream-wrapper.sh` — перезапускает `log stream`,
   когда файл превышает порог
3. `/Library/LaunchDaemons/com.user.logstream.plist` — запускает wrapper

Файлы лежат в каталоге `macos/logstream/` этого репозитория.

**Почему wrapper:** `log stream` держит файл открытым (file descriptor).
Даже если `newsyslog` переименует файл, процесс продолжит писать
в старый inode. Единственный способ — перезапустить процесс.

---

## 2. Дубли команд в `commands.log` и в Graylog

**Симптом:** каждая команда в терминале появляется в Graylog **дважды**.

**Причина:** в `~/.zshrc` одновременно оказались **оба** варианта
логирования — через `add-zsh-hook` и через `preexec()` напрямую.

**Решение:** оставить только `add-zsh-hook`:

```bash
function log_command() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $(whoami) | $(pwd) | $1" >> ~/.local/log/commands.log
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec log_command
```

---

## 3. Kaspersky засоряет unified logs

**Симптом:** в `/var/log/unified.json.log` тысячи записей
`Sandbox: System Toolkit ...` и `Entitlement ... com.kaspersky ... is ignored`.

**Причина:** Kaspersky for Mac генерирует много сообщений
о sandbox-блокировках. Если включить `Sandbox` или `incorrect`
в `include_lines` Filebeat — поток вырастет в 10 раз без пользы.

**Решение:** не включать эти паттерны. Оставить только точные:

```yaml
include_lines:
  - 'AirDrop'
  - 'TCC'
  - 'hostNotificationUSB'
  - 'kernel panic'
  - 'SIP'
  - 'FileVault'
  - 'Gatekeeper'
```

Проверка перед добавлением нового паттерна:

```bash
sudo grep -c "паттерн" /var/log/unified.json.log*
```

Если счётчик тысяч — паттерн шумный.

---

## 4. `include_lines` — подстрочный поиск, не regex

**Причина:** `include_lines` в Filebeat — простой поиск подстроки.
Не поддерживает regex и логические операторы.

**Решение:** для сложной логики — processors с `drop_event`:

```yaml
processors:
  - drop_event:
      when:
        and:
          - contains:
              message: "Sandbox"
          - contains:
              message: "kaspersky"
```

---

## 5. macOS APFS snapshots держат "удалённые" данные

**Симптом:** удалил файл, а `df -h` показывает, что место не освободилось.

**Причина:** macOS создаёт локальные snapshots APFS (Time Machine).

**Проверка и очистка:**

```bash
tmutil listlocalsnapshots /
sudo tmutil deletelocalsnapshots /
```

---

## 6. `nc -w 1` рвёт соединение до окончания потока (BiZone)

**Симптом:** `bzt-stream.sh` завершается за 10 секунд вместо 20–25,
в Graylog ничего не приходит.

**Причина:** флаг `-w 1` в BSD `nc` (macOS) означает «закрыть
соединение после 1 секунды тишины». `bz_triage` первые 5–8 секунд
собирает данные молча, `nc` закрывается раньше.

**Решение:**

```bash
# Было
nc -G 5 -w 1 "$GRAYLOG_HOST" "$GRAYLOG_PORT"

# Стало
nc -G 5 -w 180 "$GRAYLOG_HOST" "$GRAYLOG_PORT"
```

---

## 7. Filebeat не может прочитать `audit.log` (Linux/RedOS)

**Симптом:** Filebeat запускается, но данные в Graylog не идут.

**Причина:** пользователь `filebeat` не имеет прав на
`/var/log/audit/audit.log` (владелец `root:root`, права `0600`).

**Решение:** либо запускать Filebeat от root (`User=root`
в systemd-юните), либо дать права через `setfacl`:

```bash
sudo setfacl -m u:filebeat:rx /var/log/audit/
sudo setfacl -m u:filebeat:r /var/log/audit/audit.log
```

На RedOS `setfacl` может не работать — тогда проще запускать
Filebeat от root.

---

## 8. Порт Beats input занят / не слушается

**Симптом:** Filebeat шлёт на 5040/5046, получает connection refused.

**Проверка:**

```bash
sudo ss -tlnp | grep 5044
nc -zv <graylog-ip> 5044
```

**Причина:** либо input не создан, либо SELinux блокирует bind.

**Решение:** проверить состояние input через API:

```bash
curl -s -u admin:admin -H "X-Requested-By: cli" \
  "http://localhost:9000/api/system/inputs" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for inp in d.get('inputs', []):
    print(f\"{inp.get('title')}: state={inp.get('state')}, port={inp.get('attributes',{}).get('port')}\")
"
```

Если `state=FAILED` — смотреть лог:

```bash
sudo tail -50 /var/log/graylog-server/server.log | grep -iE "bind|error"
```

---

## 9. Диагностика «идут ли вообще данные?»

Три команды для быстрой проверки:

```bash
# 1. Что Filebeat отправил за последние 5 минут
sudo log show --predicate 'process == "filebeat"' --last 5m --info | \
  grep -iE "events.sent|connection|error"

# 2. Сколько в Graylog за 5 минут
curl -s "http://<graylog>:9200/graylog_0/_count?pretty" -H 'Content-Type: application/json' -d '{
  "query": {"range": {"timestamp": {"gte": "now-5m"}}}
}' | grep count

# 3. Лог Filebeat
sudo tail -20 /usr/local/filebeat/logs/filebeat.log
```

---

## 10. Алерты не создаются, список Event Definitions падает с `IOException encountered while parsing`

**Симптом:** страница Alerts → Event Definitions пустая или с ошибкой, событий нет,
в `server.log` бесконечно повторяется:

```
ERROR [EventProcessorExecutionJob] Event processor <...> failed to execute ... (retry in 5000 ms)
Caused by: UnrecognizedPropertyException: Unrecognized field "type"
  (class ...NotificationParameters$FallbackParameters)
```

**Причина:** версия Graylog в памяти не совпадает с версией, которая записала документы
в MongoDB (в нашем случае поверх пакета `rc.1` вручную подложили `graylog.jar` и
storage-плагины от `beta.3`). Один нечитаемый алерт ломает весь список.

**Проверка:**

```bash
rpm -V graylog-server                 # "S.5" у graylog.jar = файл подменён
curl -s http://<graylog>:9000/api/     # какая версия реально запущена
```

**Решение:** вернуть файлы пакета (`dnf reinstall graylog-server`, лишние jar из
`plugin/` убрать), в битых алертах сбросить `notification_parameters` в `null`
через pymongo и перезапустить Graylog.

---

## 11. `Limit of total fields [1000] has been exceeded`

**Симптом:** в System → Overview растёт счётчик failed indexing attempts,
часть сообщений и все события алертов не попадают в индекс.

**Причина:** auditd, macOS (osquery `columns_*`) и Windows (winlogbeat) пишут
в один `graylog_*` индекс, и суммарно полей больше 1000. Плюс стримы
«All events» / «All system events» были привязаны к Default index set.

**Решение:**

- отдельный index set на источник: `redos-auditd`, `macos`, `windows`;
- «All events» → `gl-events`, «All system events» → `gl-system-events`;
- ротировать наборы (System → Indices → Rotate active write index);
- при необходимости поднять лимит на текущем индексе:
  `PUT /<index>/_settings {"index.mapping.total_fields.limit": 2000}`.

---

## 12. `failed to parse field [level] of type [long] ... 'warn'`

**Причина:** одно и то же поле приходит то числом (GELF/syslog level), то строкой
(`warn` из unified log). Тип поля в индексе задаёт первый документ.

**Решение:** зафиксировать тип в Graylog (System → Indices → набор → Field types →
`level` = String) и ротировать индекс. Так же сделано для `macos_event_time`.

---

## 13. После создания index set: `deflector_exists_as_index`, ротация падает

**Причина:** сообщения пришли раньше, чем Graylog создал алиас `<prefix>_deflector`,
и OpenSearch автоматически создал *индекс* с этим именем.

**Решение:** перенести документы и атомарно заменить индекс алиасом:

```bash
curl -XPOST "$OS/_reindex?refresh=true" -H 'Content-Type: application/json' \
  -d '{"source":{"index":"<prefix>_deflector"},"dest":{"index":"<prefix>_0"}}'
curl -XPOST "$OS/_aliases" -H 'Content-Type: application/json' \
  -d '{"actions":[{"remove_index":{"index":"<prefix>_deflector"}},
                  {"add":{"index":"<prefix>_0","alias":"<prefix>_deflector"}}]}'
```

Затем ротировать набор в Graylog.
