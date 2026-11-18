# Глава 35. Fluent Bit теряет journald после ротации — лаг доставки логов в Graylog

> Вечер 18.11 контейнерные логи в Graylog отставали на 10+ минут, а loki, grafana,
> netalertx и zaslon стояли сутки. Причина оказалась не в Graylog и не в сети:
> явный `Path /var/log/journal` в systemd input fluent-bit ломал отслеживание
> журнала после каждой ротации. Лечится одной закомментированной строкой.

## Симптомы

- Логи контейнеров в Graylog отстают на 10+ минут или замирают совсем
  (loki/grafana/netalertx/zaslon стояли с 17.11).
- Детекторы по контейнерам («всплеск ошибок», доступность) срабатывают
  с большим опозданием или молчат.
- После рестарта fluent-bit поток оживает, догоняет backlog до живого края
  и снова замирает.

## Причина

В `[INPUT] Name systemd` был задан явный `Path /var/log/journal` (на части
хостов `/run/log/journal`). С явным Path fluent-bit после ротации journald
(sealed-файл → новый active `system.journal`) не подхватывает новый файл:
курсор в `journal.db` остаётся на старом sealed-файле, `sd_journal_wait`
не просыпается на новые записи.

## Фикс

Закомментировать `Path` в секции systemd input и перезапустить сервис:

```
[INPUT]
    Name             systemd
    Tag              journal.*
    # Path убран 18.11: fluent-bit терял journal после ротации файлов.
    # Без Path sd_journal сам следит за ротацией.
    # Path             /var/log/journal
    DB               /var/lib/fluent-bit/journal.db
    Read_From_Tail   On
    Strip_Underscores On
```

```bash
sudo systemctl restart fluent-bit
```

Внимание: не трогать `Path` в других input-секциях — например, `tail`
для `/wazuh-alerts/alerts.json` на redosrp16, там Path обязателен.

Применено 18.11.2026 на: homelab, redos-server, homeserver, redos-raspi,
redosrp16, wazuh-homelab (конфиг про запас, сервис не поднят). Бэкап на
каждом хосте: `/etc/fluent-bit/fluent-bit.conf.bak-20261118-rotation`.
Хост wazuh — fluent-bit отсутствует.

## Проверка

- Маркер end-to-end: `logger --journald` с `CONTAINER_NAME=lagmark*` →
  появление в Graylog через **~30 с** (до фикса — не появлялся вообще
  из system journal).
- Маркеры `pathfix1811` со всех четырёх активных хостов доставлены < 65 с.
- blackbox/loki/grafana/netalertx/zaslon/wyl — поток возобновился;
  caddy (redos-server) шлёт ошибки штатно.

## Диагностика (как повторить)

1. Сравнить свежесть на хосте и в Graylog:
   - хост: `sudo journalctl CONTAINER_NAME=<имя> -n 1 -o short-iso`
   - Graylog: поиск `container_name:<имя>` с **узким range=300 и без sort**.
2. Маркер из system journal (см. выше) — разделяет «не читает journal»
   и «не доходит GELF».
3. Курсор fluent-bit:
   `sqlite3 /var/lib/fluent-bit/journal.db 'SELECT * FROM in_systemd_cursor;'`
   — cursor на sealed-файле (`system@<id>....journal`) вместо active = эта болезнь.

## Грабли, пойманные по дороге

- **`sort=timestamp:desc` в Graylog universal search ненадёжен**: при живом
  потоке (15:56) «новейшая» строка по сорту возвращалась как 13:20 — ложная
  картина полной остановки. Проверять узким `range` без сортировки.
- **Syslog-путь-дубликат**: journald параллельно форвардит в Graylog Syslog
  input. Он доставляет быстро, но БЕЗ `container_name` (вида `blackbox[pid]:`),
  создавая иллюзию «сообщения доходят», когда контейнерный (GELF) путь стоит.
  Кандидат на фильтрацию как шум.
- **Quadlet-контейнеры** перезапускать только через `systemctl restart <имя>`:
  `podman restart <quadlet>` убивает контейнер, и сервис остаётся dead
  (18.11 так fluent-bit на homelab простаивал ~9 минут).
- Образ `ghcr.io/fluent/fluent-bit:latest` с `AutoUpdate=registry` — версия
  плавает (на 18.11 была v5.2.0). Кандидат на пин конкретной версии.
