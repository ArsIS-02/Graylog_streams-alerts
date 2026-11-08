# 21. Свои инструменты в Graylog: ZaSlon, HomeRepo, HostDeck, LogAtlas

В лаборатории есть три самописных инструмента, которые знают то, чего нет в журналах хостов:

- **[ZaSlon](https://github.com/ArsIS-02/zaslon)** — панель управления firewalld и SELinux на хостах RED OS;
- **[HomeRepo](https://github.com/ArsIS-02/HomeRepo)** — домашний репозиторий RPM с подписью пакетов, менеджером устройств и сканером сети;
- **[HostDeck](https://github.com/ArsIS-02/HostDeck)** — инвентарь и проверки безопасности хостов (macOS и Linux);
- **[LogAtlas](https://github.com/ArsIS-02/logatlas)** — офлайн-разбор архивов журналов с правилами обнаружения и Sigma.

Эта глава подключает их к Graylog так же, как TrafficLens в главе 20: события по GELF в свои потоки с алертами, а инвентарь по HTTP в справочники.

> **Статус проверки.** Отправка GELF и выгрузки проверены тестами в каждом репозитории. В лаборатории на Graylog 7.2.1 (ноябрь 2026) собрано всё: вход «Homelab tools» на UDP 12206, потоки ZaSlon, HomeRepo, HostDeck и LogAtlas, уведомление «Mail.ru Alert Homelab tools», 14 определений событий, пять таблиц инвентаря и pipeline `inventory: fallback` на восьми потоках. В потоки уже пришли тестовые сообщения, входы в панели, импорт плейбуков HomeRepo и находки LogAtlas; симулятор подтверждает, что `inventory: fallback` добавляет `host_profile` из HostDeck и не трогает `host_os` из ручного справочника.

## Зачем

1. **Действия администратора видны рядом с их следами.** ZaSlon переводит SELinux в permissive через `setenforce 0`, и алерт «Отключение SELinux или аудита» из главы 14 сработает на это так же, как на атаку. Событие ZaSlon в ту же минуту с тем же хостом показывает, что это было действие из панели и кто его подтвердил.
2. **Журналы самих инструментов защищены алертами.** У ZaSlon нет ограничения частоты входа, у HostDeck есть консоль root в браузере, а ключу HomeRepo доверяют все устройства. Подбор пароля к любой из панелей, переподпись пакетов, новые пользователи и токены теперь видны в Graylog.
3. **То, чего нет в логах.** HostDeck видит выключенное шифрование диска, выпадение хоста из домена, лишний открытый порт, ожидающие обновления безопасности. HomeRepo видит новое устройство в сети. Ни один журнал хоста об этом не пишет.
4. **Разбор архива становится частью SIEM.** Находки LogAtlas по архиву хоста кнопкой уходят в Graylog рядом с живыми журналами того же хоста. Правило Sigma, которое нашло что-то в архиве, LogAtlas отдаёт файлом: его можно провести через sigma2graylog и получить постоянный детект на живом потоке.
5. **Инвентарь вместо ручных справочников.** `homelab-ip-names`, `homelab-host-os` и `homelab-host-roles` из главы 13 ведутся руками. HostDeck и HomeRepo знают хосты, их адреса и ОС сами, поэтому справочники пополняются из них: новый хост получает ОС и имя в Graylog без правки CSV.

## Как это устроено

```
ZaSlon   ──┐                                        ┌─ поток «ZaSlon»   (homelab_app = zaslon)   ─ 4 алерта
HomeRepo ──┼─ GELF UDP ─▶ вход «Homelab tools» :12206 ┼─ поток «HomeRepo» (homelab_app = homerepo) ─ 4 алерта
HostDeck ──┤                                        ├─ поток «HostDeck» (homelab_app = hostdeck) ─ 5 алертов
LogAtlas ──┘ (по кнопке)                            └─ поток «LogAtlas» (homelab_app = logatlas) ─ 1 алерт
                                                                           │
                                                                     письмо «Mail.ru Alert Homelab tools» 🧰

HostDeck /api/export/hosts.csv     ──▶ hostdeck-host-os, hostdeck-host-profile, hostdeck-ip-names ─┐
HomeRepo /api/export/inventory.csv ──▶ homerepo-host-os, homerepo-ip-names                         ├─ pipeline «inventory: fallback»
                                                                                                   │  host_os, host_profile, src_host,
                                                                                                   │  если ручные справочники молчат
```

## Где что работает в лаборатории

Все четыре инструмента открываются через Caddy на redos-server (`*.apps.monitoring.test`), а сами работают так:

| Инструмент | Сервер | Как запущен | Куда слать GELF | Адрес выгрузки для Graylog |
|---|---|---|---|---|
| ZaSlon | redos-server | rootless-контейнер, порт 8585 | `host.containers.internal:12206` | — |
| LogAtlas | redos-server | rootless-контейнер, порт 8484 | `host.containers.internal:12206` | — |
| HostDeck | redos-server | rootless-контейнер в сети Caddy, порт 8080 на 127.0.0.1 | `host.containers.internal:12206` | `http://127.0.0.1:8080/api/export/hosts.csv?token=…` |
| HomeRepo | redosrp16 | службы systemd за nginx (HTTPS) | `redos-server.monitoring.test:12206` | `https://homerepo.apps.monitoring.test/api/export/inventory.csv?token=…` (через Caddy) |

Три инструмента живут на одном сервере с Graylog, поэтому им не нужен ни открытый порт, ни TLS: из rootless-контейнера Podman хост виден как `host.containers.internal`, а свой IP хоста в сети pasta указывает на сам контейнер. HomeRepo — на другой машине, ему нужен открытый порт 12206/udp на redos-server (шаг 1), а выгрузку Graylog забирает через Caddy. Для этого Java в Graylog должна доверять внутреннему центру сертификации Caddy (см. «Доверие к корню Caddy» в шаге 5).

## Шаг 1. Вход GELF

Один вход на все четыре инструмента: потоки разделяют их по полю `homelab_app`.

System → Inputs → **GELF UDP** → Launch new input: Title `Homelab tools`, Bind address `0.0.0.0`, Port `12206`.

Если какой-то из инструментов работает на другой машине, откройте порт:

```bash
sudo firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="12206" protocol="udp" accept'
sudo firewall-cmd --reload
```

SELinux: как и для 12205 в главе 20, метка порта не нужна, если Graylog работает как `unconfined_service_t`.

## Шаг 2. Включить отправку в инструментах

Адрес Graylog: имя или IP сервера. Если инструмент работает в rootless-контейнере Podman на том же сервере, используйте `host.containers.internal`.

**ZaSlon** — в `.env` рядом с `docker-compose.yml`, затем `docker compose up -d`:

```bash
ZASLON_GELF_HOST=redos-server.example
ZASLON_GELF_PORT=12206
```

Проверка: «Администрирование» → «Журнал в Graylog» → «Отправить тестовое сообщение», в Graylog запрос `zs_op:test`.

**HomeRepo** — секция `[graylog]` в `/etc/homerepo/homerepo.conf`, затем перезапуск служб HomeRepo:

```ini
[graylog]
gelf_host = redos-server.example
gelf_port = 12206
export_token = <токен>      ; python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

Проверка: раздел «Журнал» → «тестовое сообщение», в Graylog `hr_event:test`.

**HostDeck** — в quadlet `hostdeck.container` (или `docker-compose.yml`), затем `systemctl --user daemon-reload && systemctl --user restart hostdeck`:

```ini
Environment=HOSTDECK_GELF_HOST=host.containers.internal
Environment=HOSTDECK_GELF_PORT=12206
Environment=HOSTDECK_EXPORT_TOKEN=<токен>
```

Проверка: карточка «Оповещения в Graylog» на главной → «Тестовое сообщение», в Graylog `hd_event:test`.

**LogAtlas** — в `.env` рядом с `docker-compose.yml`, затем `docker compose up -d`:

```bash
LOGATLAS_GELF_HOST=redos-server.example
LOGATLAS_GELF_PORT=12206
```

LogAtlas работает офлайн и сам ничего не отправляет: на вкладке «Находки» сбора появляется блок «Graylog» с порогом важности и кнопкой «Отправить находки в Graylog». В Graylog находки сбора ищутся запросом `la_case:<id сбора>`.

Отправка в ZaSlon, HomeRepo и HostDeck идёт из фонового потока: если Graylog недоступен, инструмент работает как обычно, а журнал в его собственной базе остаётся полным.

## Шаг 3. Потоки

Три потока, у каждого одно правило: поле `homelab_app`, **match exactly**.

| Поток | Значение `homelab_app` | Remove matches from 'Default Stream' |
|---|---|---|
| `ZaSlon` | `zaslon` | да |
| `HomeRepo` | `homerepo` | да |
| `HostDeck` | `hostdeck` | да |
| `LogAtlas` | `logatlas` | да |

### Что приходит

| Инструмент | Событие | Поля |
|---|---|---|
| ZaSlon | каждая запись журнала действий: порт, служба, firewalld, SELinux, подтверждение и откат, хосты, пароль, вход | `zs_op`, `zs_host`, `zs_host_address`, `zs_arg_*`, `zs_ok`, `zs_error`, `zs_tx`, `zs_who`, `zs_login`, `zs_client_ip` |
| HomeRepo | запись журнала (`hr_event=audit`) из панели, исполнителя и командной строки (подписыватель изолирован от сети, переподпись записывает панель) | `hr_action`, `hr_action_name`, `hr_user`, `hr_client_ip`, `hr_agent`, `hr_detail`, `hr_detail_*` |
| HomeRepo | новое устройство в сети (`hr_event=device_new`) | `hr_ip`, `hr_mac`, `hr_vendor`, `hr_hostname`, `hr_ports`, `hr_os_family`, `hr_network` |
| HostDeck | смена статуса проверки (`hd_event=check_changed`) | `hd_host`, `hd_os`, `hd_profile`, `hd_check`, `hd_from`, `hd_to`, `hd_effective`, `hd_value`, `hd_detail`, `hd_exception`, `hd_recovered` |
| HostDeck | запись журнала (`hd_event=audit`) | `hd_action`, `hd_actor`, `hd_host`, `hd_detail` |
| LogAtlas | находка сбора, одно сообщение на сработавшее правило (`la_event=finding`) | `la_case`, `la_host`, `la_rule`, `la_rule_title`, `la_severity`, `la_mitre`, `la_sigma`, `la_count`, `la_top`, `la_first`, `la_last` |

Уровень `level` в сообщениях уже расставлен самими инструментами: 3 (error) — проверка HostDeck в `fail`; 4 (warning) — неудачные входы, изменения доверия, ослабление защиты, переподпись пакетов, новые устройства; 5 — прочие изменения; 6 — входы, восстановление проверок, исключённое.

У HostDeck важно поле `hd_effective`: это статус с учётом профиля хоста и исключений. Если в HostDeck для проверки добавлено исключение, событие приходит с `hd_effective=info`, и алерт на `fail` не срабатывает. Исключения ведутся в одном месте.

## Шаг 4. Уведомление и алерты

Уведомление «Mail.ru Alert Homelab tools» сделайте копией «Mail.ru Alert Linux» (глава 2) с эмодзи 🧰 в теме и шапке «🧰 HOMELAB TOOLS» (в лаборатории так и сделано: в шаблоне заменены 🐧, «LINUX» и запасной текст «хост не определён» на «инструменты лаборатории»). Поле `host` в событиях заполнено у всех определений: имя хоста, а для подбора пароля — адрес, с которого подбирают.

Определения — [graylog/homelab-tools-event-definitions.json](../graylog/homelab-tools-event-definitions.json). Плейсхолдеры: `<ZASLON_STREAM_ID>`, `<HOMEREPO_STREAM_ID>`, `<HOSTDECK_STREAM_ID>`, `<LOGATLAS_STREAM_ID>` и `<NOTIFICATION_ID>`.

| Определение | Запрос | Важность | Письмо |
|---|---|---|---|
| ZASLON - Подбор пароля к панели | `zs_op:login_failed`, ≥ 5 за 10 мин по `zs_client_ip` | high | да |
| ZASLON - SELinux переведён в permissive или disabled из панели | `zs_op:selinux_mode AND zs_ok:true AND zs_arg_mode:(permissive OR disabled)` | medium | да |
| ZASLON - firewalld остановлен из панели | `zs_op:firewalld_set AND zs_ok:true AND zs_arg_running:false` | high | да |
| ZASLON - Изменения доверия: пароль, хосты | `zs_op:(admin_password OR host_add OR host_enroll OR host_remove)` | low | да |
| HOMEREPO - Подбор пароля к панели | `hr_action:login_failed`, ≥ 5 за 10 мин по `hr_client_ip` | high | да |
| HOMEREPO - Переподпись, удаление пакетов или смена ключа | `hr_action:(package_resign OR resign_foreign OR package_delete OR repo_key)` | high | да |
| HOMEREPO - Пользователи, роли и токены | `hr_action:(user_create OR … OR ansible_access)` | medium | да |
| HOMEREPO - Новое устройство в сети | `hr_event:device_new` | medium | да |
| HOSTDECK - Проверка безопасности перешла в fail | `hd_event:check_changed AND hd_effective:fail` | high | да, не чаще раза в час на хост и проверку |
| HOSTDECK - Проверка безопасности перешла в warn | `hd_event:check_changed AND hd_effective:warn` | low | нет |
| HOSTDECK - Открыта консоль root в браузере | `hd_action:(term-open OR term-denied)` | medium | да |
| HOSTDECK - Подбор пароля | `hd_action:login-failed`, ≥ 5 за 10 мин по адресу | high | да |
| HOSTDECK - Риск принят: добавлено исключение | `hd_action:exception-set` | low | нет |
| LOGATLAS - Находка высокой важности в разборе журналов | `la_event:finding AND la_severity:(critical OR high)` | high | да, по хосту и правилу |

## Шаг 5. Инвентарь в справочниках

1. **URL Allowlist** (System → Configurations): добавьте адреса выгрузок, например регулярными выражениями `^https://hostdeck\.example/api/export/hosts\.csv\?.*$` и `^http://127\.0\.0\.1:8090/api/export/inventory\.csv\?.*$`.
2. Таблицы создаёт [`import-lookup-tables.js`](../graylog/pipelines/import-lookup-tables.js). Адреса передаются без `key` и `header`, их скрипт добавит сам для каждой таблицы:
   ```js
   await importLookupTables({only: ['hostdeck-host-os', 'hostdeck-host-profile', 'hostdeck-ip-names',
                                    'homerepo-host-os', 'homerepo-ip-names'],
     hostdeckUrl: 'https://hostdeck.example/api/export/hosts.csv?token=<токен HostDeck>',
     homerepoUrl: 'http://127.0.0.1:8090/api/export/inventory.csv?token=<токен HomeRepo>', dryRun: true})
   ```
   Затем то же без `dryRun`.

| Таблица | Ключ | Значение | Колонка |
|---|---|---|---|
| `hostdeck-host-os` | имя хоста, полное и короткое | ОС | 2 |
| `hostdeck-host-profile` | имя хоста | профиль: `server`, `laptop`, `lab` | 3 |
| `hostdeck-ip-names` | адрес из снимка сети или подпись с карты | имя | 1 |
| `homerepo-host-os` | имя устройства, полное и короткое | ОС | 3 |
| `homerepo-ip-names` | адрес устройства с агентом или найденного сканером | имя | 1 |

Выгрузки перечитываются раз в 15 минут. HostDeck отдаёт адреса, только если на хосте включён сбор сети (`HOSTDECK_NETWORK=1`).

### Доверие к корню Caddy

Браузеры в лаборатории доверяют внутреннему центру сертификации Caddy, а Java внутри Graylog — нет. Адаптер по HTTPS тогда ничего не скачивает, а в журнале Graylog (`/var/log/graylog-server/server.log`) появляется `PKIX path building failed`. При этом в веб-интерфейсе ошибки у адаптера не видно: таблица просто отвечает пусто.

Решение — отдельное хранилище сертификатов: стандартные корни из Java Graylog плюс корень Caddy. Отдельное, чтобы его не затёрло обновлением пакета:

```bash
J=/usr/share/graylog-server/jvm
podman exec caddy cat /data/caddy/pki/authorities/local/root.crt > /tmp/caddy-root.crt
sudo cp $J/lib/security/cacerts /etc/graylog/server/cacerts.jks
sudo $J/bin/keytool -importcert -noprompt -alias caddy-local-root -file /tmp/caddy-root.crt \
  -keystore /etc/graylog/server/cacerts.jks -storepass changeit
sudo chown root:graylog /etc/graylog/server/cacerts.jks && sudo chmod 640 /etc/graylog/server/cacerts.jks
```

Затем в **первую** строку `GRAYLOG_SERVER_JAVA_OPTS=` файла `/etc/sysconfig/graylog-server` допишите `-Djavax.net.ssl.trustStore=/etc/graylog/server/cacerts.jks -Djavax.net.ssl.trustStorePassword=changeit` и перезапустите `graylog-server`. В этом файле несколько строк вида `GRAYLOG_SERVER_JAVA_OPTS="$GRAYLOG_SERVER_JAVA_OPTS …"`, параметры нужны только в первой. Хранилище скопировано один раз, поэтому новые общедоступные корни из обновлений Java в него сами не попадут; если Graylog начнёт ходить по HTTPS на внешние сайты и упираться в PKIX, повторите копирование и импорт.

### Повторяющиеся ключи

Адаптер «DSV File from HTTP» при повторяющемся ключе не загружает таблицу целиком и тоже ничего не показывает в интерфейсе. Так было с подписями устройств сканера HomeRepo: два телефона с подписью «Android» и два Mac с одинаковой подписью. Выгрузки HostDeck и HomeRepo теперь отдают каждый ключ один раз (без учёта регистра), а при совпадении оставляют строку агента. Свою выгрузку для такой таблицы проверяйте так: `curl -s '<адрес>&header=0' | cut -d, -f1 | tr A-Z a-z | sort | uniq -d` ничего не должен выводить.

Подписи из сканера HomeRepo попадают в справочник «адрес → имя» как есть. Если устройства подписаны по типу («Windows», «Android»), в Graylog они так и будут называться; лучше дать им имена хостов.

## Шаг 6. Pipeline «inventory: fallback»

Ручные справочники остаются главными: инвентарь подставляет значение, только если они молчат. Правила:

| Файл | Правило | Что делает |
|---|---|---|
| `inventory-host-os-hostdeck.rule` | `inventory: host_os from HostDeck` | `host_os` по `source`, если его ещё нет; `host_os_from=hostdeck` |
| `inventory-host-os-homerepo.rule` | `inventory: host_os from HomeRepo` | то же из HomeRepo, если не помог и HostDeck |
| `inventory-host-profile.rule` | `inventory: host_profile` | `host_profile` по `source` |
| `inventory-windows-src-host-hostdeck.rule` | `inventory: windows src_host from HostDeck` | `src_host` по адресу входа в Windows, если `homelab-ip-names` его не знает |
| `inventory-windows-src-host-homerepo.rule` | `inventory: windows src_host from HomeRepo` | то же из HomeRepo |

Отдельный pipeline, чтобы не трогать существующие:

```
pipeline "inventory: fallback"
stage 3 match either
rule "inventory: host_os from HostDeck"
rule "inventory: host_profile"
rule "inventory: windows src_host from HostDeck"
stage 4 match either
rule "inventory: host_os from HomeRepo"
rule "inventory: windows src_host from HomeRepo"
end
```

Стадия 3 идёт после `homelab: host info` (стадия 2), где `host_os` ставится из ручного справочника, и после `homelab: windows enrichment` (стадия 0), где ставится `src_host`. Правила HomeRepo вынесены в стадию 4: правила одной стадии сначала все проверяют условия и только потом выполняются, поэтому «если HostDeck не помог» можно проверить только в следующей стадии.

Подключите pipeline к тем же потокам, что и `homelab: host info`. Проверка — System → Pipelines → Simulate на сообщении с `source` = имя хоста, которого нет в `homelab-host-os`, но есть в HostDeck: должны появиться `host_os` и `host_os_from: hostdeck`.

## Ограничения

- **Автоматически погасить алерт auditd на `setenforce` из ZaSlon нельзя.** Запись PROCTITLE с `setenforce 0` не содержит пользователя, а сопоставлять разные записи и разные потоки Graylog Open не умеет: корреляция событий есть только в Enterprise. Поэтому алерт главы 14 приходит, а событие ZaSlon в ту же минуту объясняет его. Если `setenforce 0` есть, а события ZaSlon нет — это и есть повод разбираться.
- В HostDeck смена статуса считается по сырому статусу агента. Если вы поменяли профиль хоста или исключение без смены статуса, события не будет: оно придёт при следующей смене.
- HomeRepo пишет о новых устройствах только после второго сканирования подсети: первое — перепись.
- У сообщений LogAtlas время — момент отправки, а не время событий в архиве (иначе алерты, которые смотрят последние минуты, их бы не увидели). Время событий — в `la_first` и `la_last`.
- Токены выгрузок видны в настройках адаптеров всем администраторам Graylog. Это токены только на чтение инвентаря.

## Файлы

| Файл | Зачем |
|---|---|
| [`graylog/homelab-tools-event-definitions.json`](../graylog/homelab-tools-event-definitions.json) | 14 определений событий для четырёх инструментов |
| [`graylog/pipelines/rules/inventory-*.rule`](../graylog/pipelines/rules/) | обогащение из инвентаря, когда ручные справочники молчат |
| [`graylog/pipelines/rules.json`](../graylog/pipelines/rules.json) | все правила для `import-rules.js` |
| [`graylog/pipelines/import-lookup-tables.js`](../graylog/pipelines/import-lookup-tables.js) | таблицы `hostdeck-*` и `homerepo-*` с адаптером «DSV File from HTTP» |

Код отправки и выгрузок — в самих инструментах: `panel/gelf.py` в ZaSlon, `lib/homerepo/gelf.py` и `/api/export/inventory.csv` в HomeRepo, `server/app/gelf.py` и `/api/export/hosts.csv` в HostDeck, `app/gelf.py` и `/api/cases/{id}/graylog` в LogAtlas.

Лицензия: GPL-3.0, как и весь репозиторий.
