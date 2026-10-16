# Часть 2. Потоки, алерты и декодер auditd

> **Обновлённая версия.** Вторая часть истории: логи уже собираются, но чтобы
> система стала по-настоящему полезной, она должна сама сортировать события,
> предупреждать о проблемах и показывать auditd в читаемом виде.

## Что мы делаем в этой части

1. **Потоки (Streams)** — раскладываем логи по смыслу: Windows, Linux, Security, Errors.
2. **Декодер auditd** — переводим шестнадцатеричные поля auditd в читаемый вид.
3. **Алерты** — настраиваем email-уведомления о подозрительной активности для Linux и Windows.

## Потоки (Streams)

Поток — логическая группа сообщений, объединённых заданными правилами. Это фильтр,
который автоматически раскладывает входящие логи по «папкам». Все сообщения
по-прежнему хранятся в одном индексе OpenSearch, но в интерфейсе можно переключаться
между потоками и работать только с нужными логами.

По умолчанию в системе есть три потока (активен только `Default stream`).

### Зачем нужны потоки

| Причина | Что даёт |
|---|---|
| Удобство | Не нужно каждый раз составлять сложные поисковые запросы |
| Безопасность | Для каждого потока — свои права доступа |
| Алерты | Для каждого потока — свои уведомления |
| Визуализация | Дашборды строятся на основе потоков |

### Правила потока

Создавая поток, задаёте одно или несколько правил. Если сообщение соответствует всем
правилам (по логике И) — оно попадает в поток. Для логики ИЛИ правила объединяются в
группу. Правила гибкие:

- равенство поля значению (`source == "webserver-01"`);
- наличие подстроки (`message содержит "Out of memory"`);
- сравнение чисел (`event_id >= 4624`);
- проверка по регулярным выражениям.

### Какие потоки создаём

| Поток | Содержимое |
|---|---|
| **Windows Logs** | сообщения от Winlogbeat и Sysmon, только с хостов Windows |
| **Linux Logs** | сообщения с Linux-хостов, полученные по Syslog через UDP |
| **Security Events** | события аутентификации и доступа: event_id 4624, 4625, 4648 и др. (Windows + РЕД ОС) |
| **Errors** | сообщения со словами `error` или `critical` со всех хостов |

### Создание потока

1. Верхнее меню → **Streams**.
2. **Create stream** (правый верхний угол).
3. Заполнить поля: `Title` (например, `Windows Logs`), `Description`.
4. Поставить флажок **Remove matches from Default Stream** — чтобы события не дублировались.
5. Кнопка **More** → **Quick add rule** — задать правило маршрутизации.

## Декодер auditd

### Зачем

События auditd приходят с полями в шестнадцатеричном виде (`comm=73736864` вместо
`comm=sshd`). Декодировать их в уме неудобно. Официальный плагин Graylog для auditd
работает только со старыми версиями, поэтому автор написал собственный декодер.

### Идея

Логи приходят на порт 1514. Декодер принимает их, разбирает пары `key=value`,
декодирует hex-поля и отправляет результат на отдельный вход Graylog в формате
**GELF** (Graylog Extended Log Format — структурированный JSON). Декодированные поля
получают суффикс `_decoded`.

### Какие поля извлекаем

**Общие поля:** `type`, `timestamp`, `serial`, `key`, `msg`, `audit_type`, `message`,
`_udp_source`, `_udp_port`, `_syslog_hostname`.

**SYSCALL** — системный вызов:

| Поле | Значение |
|---|---|
| arch | архитектура (например `c000003e` — x86_64) |
| syscall | номер системного вызова |
| success | `yes` / `no` |
| exit | код возврата |
| a0…a3 | аргументы системного вызова |
| comm | имя команды (декодируется из hex) |
| exe | полный путь к исполняемому файлу |
| uid, gid, pid, ppid, ses, tty | идентификаторы и контекст процесса |
| proctitle | командная строка процесса |

**Другие типы записей:** `EXECVE` (аргументы execve), `PATH` (объект файловой системы),
`CWD`, `PROCTITLE`, `SOCKADDR` (сетевой адрес), `USER_*` (аутентификация и сессии),
`SERVICE_START`/`SERVICE_STOP` (управление службами), `CONFIG_CHANGE` (изменение правил
аудита), `ANOM_ABEND` (аварийное завершение).

### Установка

```bash
# скрипт — в /usr/local/bin
sudo cp decoder/auditd_decoder.py /usr/local/bin/
sudo chmod 755 /usr/local/bin/auditd_decoder.py

# systemd-юнит
sudo cp decoder/audit-decoder.service /etc/systemd/system/

# автозапуск и старт
systemctl enable --now audit-decoder.service
systemctl status audit-decoder.service
```

Декодер слушает UDP 1514, отправляет GELF на `127.0.0.1:12201`. Создайте в Graylog
вход **GELF UDP** на порту 12201.

## Алерты

Алерт — автоматическое уведомление при выполнении заданного условия в выбранном потоке.
Graylog держится на двух «китах»:

1. **Уведомления (Notifications)** — куда и как отправлять сообщение (email, Telegram, Slack, HTTP, скрипт).
2. **Условия алерта (Alert Conditions / Event Definitions)** — при каком событии сработает алерт.

### Почтовый ящик Mail.ru

Mail.ru требует отдельный **пароль приложения** (обычный пароль от ящика не подойдёт):

1. Включите двухфакторную аутентификацию (Настройки → Безопасность).
2. В разделе «Пароли для внешних приложений» нажмите «Добавить» (например, `Graylog Alerts`).
3. Скопируйте сгенерированный пароль — он показывается один раз.

### Настройка SMTP в server.conf

Добавьте в `/etc/graylog/server/server.conf`:

```ini
transport_email_enabled = true
transport_email_hostname = smtp.mail.ru
transport_email_port = 465
transport_email_use_auth = true
transport_email_use_ssl = true
transport_email_use_tls = false
transport_email_auth_username = your-email@mail.ru
transport_email_auth_password = <пароль_приложения>
transport_email_from_email = your-email@mail.ru
transport_email_subject_prefix = [Graylog Alert]
transport_email_web_interface_url = http://192.168.1.210:9000
```

Готовый пример — [`config/server.conf.smtp.example`](../config/server.conf.smtp.example).

Перезапуск и проверка:

```bash
sudo systemctl restart graylog-server
sudo systemctl status graylog-server
sudo tail -f /var/log/graylog-server/server.log
journalctl -u graylog-server | grep -i smtp
```

Важные моменты:

- для Mail.ru надёжнее порт **465 с SSL** (порт 587 с STARTTLS тоже работает, но сложнее);
- в `auth_username` — полный адрес, включая `@mail.ru`;
- в `auth_password` — пароль приложения, а не пароль от ящика;
- **не включайте TLS и SSL одновременно**.

### Уведомление (Notification)

1. **Alerts → Notifications → Create notification**.
2. Тип — **Email**.
3. `Title`: `Mail.ru Alert`.
4. `Email recipients` — адрес получателя.
5. `Subject` (опционально): `[Graylog] ${event_definition_title}`.
6. **Execute test notification** — проверка отправки.

### Условия алерта

Правила проверяют, содержат ли поля определённые значения. Условия для Linux и Windows
различаются — см. [03-windows.md](03-windows.md) и [04-linux.md](04-linux.md).

Общая рекомендация: используйте **структурированные поля**, а не поиск по `message`.
Поиск по индексированным полям OpenSearch быстрее, точнее и даёт больше возможностей
для группировки.

## Дальше

Разделы по каждой операционной системе:

- [Windows: Sysmon, Winlogbeat и алерт 4625](03-windows.md)
- [Linux: auditd, rsyslog и алерт SSH](04-linux.md)
- [macOS: unified log, Filebeat, osquery](05-macos.md)
