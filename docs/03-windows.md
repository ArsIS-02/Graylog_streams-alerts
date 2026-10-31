# Windows: Sysmon, Winlogbeat и алерт 4625

> Сбор логов с Windows-хостов: Sysmon для детального мониторинга, Winlogbeat для
> доставки событий, и алерт на неудачные входы (событие 4625).

## Sysmon

**Sysmon** (System Monitor) — бесплатная утилита из набора Microsoft Sysinternals
для мониторинга активности системы: запуск процессов, создание сетевых соединений,
модификация реестра и другие действия.

**Что умеет:**

- регистрирует создание/завершение процессов, изменения реестра, файлов и DLL, сетевую активность;
- поддерживает эвристические правила для выявления аномалий;
- фильтрует события по множеству критериев;
- настраивается через XML-конфиг (удобно автоматизировать через GPO);
- хорошо интегрируется с SIEM (Splunk, ELK, Graylog);
- минимальные системные требования (работает даже на Windows XP).

### Установка

1. Скачай Sysmon с официального сайта Microsoft Sysinternals.
2. Подготовь конфиг (свой или скачанный).
3. Распакуй архив, открой PowerShell от имени администратора:

```powershell
.\Sysmon64.exe -i .\sysmonconfig-export.xml -accepteula
```

![Установка Sysmon](images/sysmon-install.png)

![Sysmon: подготовка конфига](images/sysmon.png)

Проверка логов: `eventvwr.msc` → «Журналы приложений и служб → Microsoft → Windows →
Sysmon → Operational».

## Winlogbeat

**Winlogbeat** — легковесный агент (из стека Elastic) для сбора и отправки событий
журналов Windows (Event Logs) в Elasticsearch, Logstash, Kafka и другие системы,
включая Graylog.

**Что умеет:** собирает события из Application, Security, System и других журналов;
поддерживает SSL/TLS; работает с несколькими транспортами; имеет встроенные модули.

### Настройка

Установи Winlogbeat на каждый Windows-хост. Отредактируй `winlogbeat.yml`
(обычно `C:\Program Files\winlogbeat\winlogbeat.yml`), указав адрес сервера Graylog:

```yaml
winlogbeat.event_logs:
  - name: Application
  - name: Security
  - name: System

output.logstash:
  hosts: ["<ip сервера Graylog>:5044"]
```

Готовый пример — [`config/winlogbeat.yml.example`](../windows/winlogbeat.yml.example).

Проверка и установка службы:

```powershell
cd "C:\Program Files\winlogbeat"
./winlogbeat test config
./winlogbeat test output
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

На сервере Graylog создай вход **Beats** на порту 5044/TCP:
`System/Overview → Inputs → Beats → Launch new input`.

![Настройка входа Beats для Winlogbeat](images/beats-input.png)

## Поток Windows Logs

Создай поток **Windows Logs** (см. [02-streams-alerts.md](02-streams-alerts.md)),
в который попадают сообщения от Winlogbeat и Sysmon с Windows-хостов.

## Алерт на неудачный вход (4625)

Windows пишет в журнал Security событие **4625** при неудачной попытке входа.

Структурированные поля события (после доставки Winlogbeat):

```
winlogbeat_event_code:4625
winlogbeat_event_action: Logon
winlogbeat_event_outcome: failure
winlogbeat_event_provider: Microsoft-Windows-Security-Auditing
winlogbeat_log_level: information
winlogbeat_tags: ["windows","security","sysmon"]
winlogbeat_winlog_channel: Security
winlogbeat_winlog_event_data_FailureReason: Неизвестное имя пользователя или неверный пароль.
winlogbeat_winlog_event_id: 4625
winlogbeat_winlog_keywords: ["Audit Failure"]
winlogbeat_winlog_opcode: Info
winlogbeat_winlog_provider_name: Microsoft-Windows-Security-Auditing
winlogbeat_winlog_task: Logon
```

Для детекта достаточно пары критериев:

```
winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure
```

![Поиск события 4625](images/windows-4625-search.png)

![Детали события 4625](images/windows-event-detail.png)

### Создание алерта

1. **Alerts → Event Definitions → Create event definition**.
2. **Event Details** — тема, приоритет, сводка.
3. **Filter & Aggregation** — ищем в потоке **Windows Logs** по паттерну выше,
   проверка каждые 5 минут, условие «больше нуля сообщений».
4. **Fields** — добавь поля, которые должны попадать в алерт.
5. **Notifications** — выбери созданное email-уведомление, нажми **Add notification**.

![Создание алерта для Windows](images/windows-alert-form.png)

![Поля для поиска в событиях Windows](images/windows-alert-fields.png)

Проверка: попытка входа с неверным паролем → в течение пары минут письмо со ссылкой
на событие.

![Сработавший алерт для Windows](images/windows-alert-result.png)

![Письмо с алертом](images/windows-alert-email.png)

> Не ищи события по русскому тексту в `message` — используй точные
> `event_code` и `outcome`. Это быстрее и без ложных срабатываний.

## Ещё 11 алертов по Sysmon и Security

Кроме базовых алертов в Graylog добавлен набор из 11 определений, которые смотрят в Sysmon (события 1, 3, 11,
12, 13, 17, 18, 22) и Security (4624, 4625). Спецификация лежит в
[`graylog/windows-event-definitions.json`](../graylog/windows-event-definitions.json): вместо `<WINDOWS_STREAM_ID>`
подставляется id потока `WindowsLogs`, вместо `<NOTIFICATION_ID>` — id email-уведомления. Скрипт импорта такой же, как
для [контейнерных правил](09-containers-dashboards.md#импорт-правил) (`POST /api/events/definitions?schedule=true`,
существующие названия пропускаются). Поля MITRE (`mitre_*`) записаны в определения сразу.

| Алерт | Что ловит | Приоритет |
|---|---|---|
| Вход из неизвестной сети (4624, тип 3 или 10) | сетевой вход или RDP с адреса вне справочника `homelab-subnets` (нужен `src_zone`, см. [главу 13](13-lookup-tables.md)) | 3 |
| Именованные каналы C2 | каналы `msagent_*`, `postex_*`, `status_*`, `MSSE-*` (Cobalt Strike и аналоги) | 3 |
| DNS-запрос к туннелям и файлообменникам | ngrok, pastebin, transfer.sh, trycloudflare, duckdns, anonfiles, serveo | 2 |
| wscript, cscript, mshta или regsvr32 ходит во внешнюю сеть | Sysmon 3 на внешний IP | 3 |
| Исключения или отключение защиты Defender | `Add-/Set-MpPreference`, ключ `Windows Defender\Exclusions` | 3 |
| Закрепление через IFEO Debugger, AppInit_DLLs и Winlogon | Sysmon 12/13 | 2 |
| Дамп учётных данных | `reg save` для SAM/SECURITY/SYSTEM, `comsvcs.dll MiniDump`, `ntdsutil` | 3 |
| Office, wscript или mshta создал исполняемый файл | Sysmon 11 в Temp, AppData, Public, ProgramData | 3 |
| Командная оболочка запущена через WMI | родитель `WmiPrvSE.exe` | 3 |
| Добавление в локальные администраторы | `net localgroup administrators /add`, `Add-LocalGroupMember` | 3 |
| Перебор несуществующих пользователей | 5+ событий 4625 с `SubStatus 0xc0000064` с одного IP за 10 минут | 2 |

**Как проверялись запросы.** Поля Sysmon (`win_image`, `ParentImage`, `PipeName`, `TargetObject`, `win_filename`,
`win_command_line`) в индексе хранятся как keyword: ищется точное значение с учётом регистра, поиск по слову из
пути не работает. Поэтому в запросах используются регулярные выражения (`win_image:/.*\\(mshta|wscript)\.exe/`),
а по командной строке — поиск в `message`. Каждый запрос перед созданием прогнали по `WindowsLogs` за 30 дней:
слишком шумные варианты сузили. Например, для `powershell` и `rundll32` соединения с GitHub, Cloudflare и Azure давали
около одного срабатывания в день, а запись `RunOnce` постоянно делают Office, Edge и Defender, поэтому их в алертах нет.
Сейчас за 30 дней срабатываний нет, кроме алерта на неизвестную сеть (до подключения pipeline поле `src_zone` не
заполнялось) и перебора несуществующих пользователей (6 событий).
