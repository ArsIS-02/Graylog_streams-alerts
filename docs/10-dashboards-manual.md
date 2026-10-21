# Часть 10. Дашборды руками: инструкция по каждому виджету

> Эта глава для тех, кто собирает дашборды не скриптом, а мышкой. Для каждого из 22 дашбордов
> перечислены виджеты и то, что выбрать в каждом поле редактора. Автоматический вариант:
> [`graylog/import-dashboards.js`](../graylog/import-dashboards.js) и
> [`graylog/dashboards-spec.json`](../graylog/dashboards-spec.json).

## Как собрать любой виджет

1. **Dashboards → Create new dashboard**. Откроется пустая страница. Сразу задай название, описание и краткое
   описание: **три точки у названия → Edit → Title / Summary / Description**. Эмодзи в названии помогает
   находить дашборд в списке.
2. Вверху справа поставь окно времени (**Time range**), указанное в таблице дашборда. У каждого виджета оно
   может быть своим: в редакторе виджета есть переключатель **Override global time range**.
3. **Create → Aggregation** (графики, числа, таблицы), **Message List** (лента сообщений) или **Markdown** (текст).
4. Поля **Aggregation**:

| Поле редактора | Что выбрать |
|---|---|
| **Visualization** | Тип из столбца «Тип» в таблице виджета |
| **Group By → Rows** | Поле, **Values** (Limit — число значений) или **Time** (интервал) |
| **Group By → Columns** | Вторая разбивка: у графиков с накоплением, у тепловой карты |
| **Metrics** | `count()`, либо `latest(timestamp)`, `card(source)` (число уникальных) |
| **Sort** | Поле сортировки и направление |
| **Visualization config → Barmode** | У Bar chart: Group (рядом) или Stack (с накоплением) |
| **Search bar в виджете** | Запрос из столбца «Запрос». Пусто — все сообщения |
| **Streams** | Поток(и) из столбца «Потоки». Пусто — все потоки |

5. **Message List**: в **Fields** отметь поля из таблицы, **Sort** — `timestamp` по убыванию, число строк задаётся
   в **Page size** при просмотре; в таблице указан ориентир.
6. Размер и место: перетащи за правый нижний угол. Ширина в таблицах — в колонках из 12, высота — в строках.
   Точные позиции не важны, порядок виджетов в таблице идёт сверху вниз, слева направо.
7. Не забудь **Save** дашборд (**Save** вверху справа).

> **Подсказка.** Запрос со скобками и `AND`/`OR` копируй целиком, как написано. Если на твоём сервере название
> потока другое, выбери свой поток с тем же смыслом. Названия полей (`kn_event_type`, `winlogbeat_event_code`,
> `container_name` и другие) зависят от твоих пайплайнов и extractor-ов.

## Оглавление


1. [🏠 Лаборатория за 60 секунд](#1-dash)
2. [🛡️ Центр безопасности (SOC)](#2-dash)
3. [🌐 Сеть глазами Keenetic](#3-dash)
4. [🪟 Контроллер домена: кто и как заходит](#4-dash)
5. [🐧 Linux: кто что запускает](#5-dash)
6. [🍎 macOS: приватность и периферия](#6-dash)
7. [🔐 FreeIPA: аутентификация в домене](#7-dash)
8. [🔥 Детекты: кто шумит](#8-dash)
9. [🩺 Здоровье сбора логов](#9-dash)
10. [🚨 Кто ломится: неудачные входы](#10-dash)
11. [🌐 Сеть и устройства (Keenetic + netalertx)](#11-dash)
12. [📦 Контейнеры: доставка логов](#12-dash)
13. [📅 Недельный обзор](#13-dash)
14. [🍎 macOS: журналы Unified и osquery](#14-dash)
15. [🛡️ macOS: BI.ZONE Triage](#15-dash)
16. [🪟 Windows: Sysmon и события входа](#16-dash)
17. [🐧 РЕД ОС: auditd](#17-dash)
18. [📡 Keenetic: журналы роутера](#18-dash)
19. [📦 Контейнеры](#19-dash)
20. [🔧 Контейнеры: диагностика](#20-dash)
21. [⚙️ Контейнеры: процессы](#21-dash)
22. [📊 Общий базовый дашборд](#22-dash)

<a id="1-dash"></a>

## 1. 🏠 Лаборатория за 60 секунд

- **Краткое описание (Summary):** Обзор всей лаборатории: объём, хосты, источники
- **Описание (Description):** Масштаб домашней лаборатории мониторинга одним экраном.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 7

### 1.1. 📨 Сообщений за 24 ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs, FreeIPA Logs, WindowsLogs, BiZone_macOS, MacOS Logs, RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 1.2. 🖥️ Уникальных хостов

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs, FreeIPA Logs, WindowsLogs, BiZone_macOS, MacOS Logs, RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `card(source)` |
| Размер (ш×в) | 3×2 |

### 1.3. 🛡️ Событий ИБ за 24 ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 1.4. 🔴 HIGH за 24 ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:3` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 1.5. 📈 Поток сообщений по источникам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Syslog Logs, FreeIPA Logs, WindowsLogs, BiZone_macOS, MacOS Logs, RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `streams` — **Values**, Limit 8 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 1.6. 🥧 Доли источников

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Syslog Logs, FreeIPA Logs, WindowsLogs, BiZone_macOS, MacOS Logs, RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `streams` — **Values**, Limit 8 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×5 |

### 1.7. 🔊 Самые «болтливые» хосты

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Syslog Logs, FreeIPA Logs, WindowsLogs, BiZone_macOS, MacOS Logs, RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `source` — **Values**, Limit 12 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

<a id="2-dash"></a>

## 2. 🛡️ Центр безопасности (SOC)

- **Краткое описание (Summary):** Алерты детектирования: приоритеты, правила, хосты
- **Описание (Description):** Что система находит и о чём сообщает. Приоритет: 3=HIGH, 2=MEDIUM, 1=LOW.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 8

### 2.1. 🛡️ Событий ИБ за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 2.2. 🔴 HIGH

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:3` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 2.3. 🟠 MEDIUM

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:2` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 2.4. 🔵 LOW

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:1` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 2.5. 📈 Алерты во времени по приоритету

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `priority` — **Values**, Limit 3 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 2.6. 🎯 По приоритету (3=HIGH · 2=MED · 1=LOW)

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `priority` — **Values**, Limit 3 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×5 |

### 2.7. 🖥️ Хосты с наибольшим числом событий

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `source` — **Values**, Limit 12 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 2.8. 📋 Лента последних событий ИБ

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Fields | `timestamp`, `priority`, `source`, `event_definition_id`, `message` |
| Sort | `timestamp` по убыванию; строк: 100 |
| Размер (ш×в) | 12×6 |

<a id="3-dash"></a>

## 3. 🌐 Сеть глазами Keenetic

- **Краткое описание (Summary):** WireGuard, конфликты ARP, SSH, Wi-Fi на домашнем роутере
- **Описание (Description):** Сетевая активность и аномалии по логам роутера Keenetic.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 8

### 3.1. 📡 Событий роутера 7д

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 3.2. ⚡ Конфликтов ARP

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:ARP_Conflict` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 3.3. 🔒 WireGuard: отказов

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:Wireguard_Failed` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 3.4. ✅ WireGuard: успешно

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:Wireguard_Success` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 3.5. 📈 Активность роутера по типам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Syslog Logs |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `kn_event_type` — **Values**, Limit 8 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 3.6. 🥧 Типы событий

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Syslog Logs |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `kn_event_type` — **Values**, Limit 10 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×5 |

### 3.7. ⚡ Конфликты ARP по IP

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:ARP_Conflict` |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `kn_conflict_ip` — **Values**, Limit 10 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 3.8. 🔐 Активность WireGuard и SSH

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:(Wireguard_Failed OR Wireguard_Success OR SSH_Connection)` |
| Окно времени | 7 дней (**Override** на виджете) |
| Fields | `timestamp`, `kn_event_type`, `message` |
| Sort | `timestamp` по убыванию; строк: 80 |
| Размер (ш×в) | 12×6 |

<a id="4-dash"></a>

## 4. 🪟 Контроллер домена: кто и как заходит

- **Краткое описание (Summary):** Входы, сетевые соединения, DNS и процессы на Windows DC
- **Описание (Description):** Доступ к контроллеру домена и активность процессов по Sysmon и журналу безопасности.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 9

### 4.1. 🪟 События Windows 24ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 4.2. 🌐 Сетевых соединений

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:3` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 4.3. ⚙️ Запусков процессов

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:1` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 4.4. 🔑 Успешных входов

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:4624` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 4.5. 🔥 Соединения: порт × хост

| Поле | Значение |
|---|---|
| Тип | **Heatmap** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:3` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `winlogbeat_winlog_event_data_DestinationPort` — **Values**, Limit 15 |
| Group By → Columns | `win_host` — **Values**, Limit 6 |
| Metrics | `count()` |
| Размер (ш×в) | 12×5 |

### 4.6. 🌍 Топ DNS-запросов

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:22` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `winlogbeat_winlog_event_data_QueryName` — **Values**, Limit 15 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 4.7. 🔑 Входы по типам (LogonType)

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:4624` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `winlogbeat_winlog_event_data_LogonType` — **Values**, Limit 8 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×5 |

### 4.8. 📈 Активность по журналам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | WindowsLogs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `win_channel` — **Values**, Limit 6 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 4.9. ⚙️ Создание процессов

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:1` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `win_host`, `win_user`, `win_image`, `win_command_line` |
| Sort | `timestamp` по убыванию; строк: 80 |
| Размер (ш×в) | 12×6 |

<a id="5-dash"></a>

## 5. 🐧 Linux: кто что запускает

- **Краткое описание (Summary):** auditd РЕД ОС: команды, sudo, категории правил, SELinux
- **Описание (Description):** Активность на Linux-хостах по данным auditd.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 9

### 5.1. 🐧 Событий auditd 24ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 5.2. ⚡ EXECVE (запуски)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:EXECVE` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 5.3. 🔐 sudo

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:EXECVE AND a0:"sudo"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 5.4. 🛡️ Отказов SELinux

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:AVC` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 5.5. 📈 Активность по хостам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `source` — **Values**, Limit 8 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 5.6. ⌨️ Топ команд (a0)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:EXECVE` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `a0` — **Values**, Limit 15 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 5.7. 🎯 Типы аудита

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `audit_type` — **Values**, Limit 12 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×5 |

### 5.8. 🏷️ Категории правил (key)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `key` — **Values**, Limit 15 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 5.9. 🔐 Запуски sudo

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:EXECVE AND a0:"sudo"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `auid_decoded`, `a1`, `a2`, `a3` |
| Sort | `timestamp` по убыванию; строк: 80 |
| Размер (ш×в) | 12×6 |

<a id="6-dash"></a>

## 6. 🍎 macOS: приватность и периферия

- **Краткое описание (Summary):** TCC, USB, AirDrop и запуск программ на Маках
- **Описание (Description):** Приватность и активность приложений на хостах macOS.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 9

### 6.1. 🍎 События macOS 24ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 6.2. ⚙️ Запусков процессов

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | `name:es_process_events` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 6.3. 🔒 Обращений к TCC

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | `processImagePath:"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 6.4. 🔌 USB / AirDrop

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | `log_type:macos_wifi_usb OR processImagePath:"/usr/libexec/sharingd"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 6.5. 🔒 Категории запросов TCC

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | MacOS Logs |
| Запрос | `processImagePath:"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `macos_category` — **Values**, Limit 10 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×5 |

### 6.6. 📦 Топ запускаемых программ

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | MacOS Logs |
| Запрос | `name:es_process_events` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `columns_path` — **Values**, Limit 15 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 6.7. 📈 Активность по типам логов

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | MacOS Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `log_type` — **Values**, Limit 6 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 6.8. ⚙️ Топ процессов (unified log)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | MacOS Logs |
| Запрос | `log_type:macos_unified` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `processImagePath` — **Values**, Limit 12 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 6.9. 📦 Запуск программ (Endpoint Security)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | MacOS Logs |
| Запрос | `name:es_process_events` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `columns_username`, `columns_path`, `columns_cmdline` |
| Sort | `timestamp` по убыванию; строк: 80 |
| Размер (ш×в) | 12×6 |

<a id="7-dash"></a>

## 7. 🔐 FreeIPA: аутентификация в домене

- **Краткое описание (Summary):** Kerberos, LDAP, SSSD и объём логов FreeIPA
- **Описание (Description):** Аутентификация в домене monitoring.test и доля служебного шума.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 8

### 7.1. 🔐 Сообщений FreeIPA 24ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | FreeIPA Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 7.2. 🎫 Kerberos (krb5kdc)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | FreeIPA Logs |
| Запрос | `application_name:freeipa_krb5kdc` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 7.3. 📇 LDAP-доступ (389)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | FreeIPA Logs |
| Запрос | `application_name:freeipa_389_access` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 7.4. 🔁 SSSD

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | FreeIPA Logs |
| Запрос | `application_name:freeipa_sssd` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×2 |

### 7.5. 🥧 Доли подсистем

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | FreeIPA Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `application_name` — **Values**, Limit 10 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×5 |

### 7.6. 📈 Активность по подсистемам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | FreeIPA Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `application_name` — **Values**, Limit 8 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 7.7. 📊 Объём по подсистемам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | FreeIPA Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `application_name` — **Values**, Limit 10 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Group |
| Размер (ш×в) | 6×5 |

### 7.8. 🔒 Журнал безопасности

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | FreeIPA Logs |
| Запрос | `application_name:freeipa_secure` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `message` |
| Sort | `timestamp` по убыванию; строк: 80 |
| Размер (ш×в) | 12×6 |

<a id="8-dash"></a>

## 8. 🔥 Детекты: кто шумит

- **Краткое описание (Summary):** Какие правила срабатывают чаще всего и на каких объектах
- **Описание (Description):** 
- **Окно времени дашборда:** 7 дней
- **Виджетов:** 10

### 8.1. События за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 8.2. HIGH за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:3` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 8.3. MEDIUM за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:2` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 8.4. События за 24 ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 8.5. По приоритету

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (как у дашборда) |
| Group By → Rows | `priority` — **Values**, Limit 3 |
| Metrics | `count()` |
| Размер (ш×в) | 4×5 |

### 8.6. Срабатывания по времени и приоритету

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `priority` — **Values**, Limit 3 |
| Metrics | `count()` |
| Размер (ш×в) | 8×5 |

### 8.7. Топ правил (по id)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (как у дашборда) |
| Group By → Rows | `event_definition_id` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 6×6 |

### 8.8. Топ объектов срабатываний (key)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (как у дашборда) |
| Group By → Rows | `key` — **Values**, Limit 12 |
| Metrics | `count()` |
| Размер (ш×в) | 6×6 |

### 8.9. Справочник правил

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×6 |

Текст виджета (вставь в редактор Markdown):

```markdown
**Справочник: id правила → название**

- `1d7ddf` … LNX - Отказ SELinux (AVC)
- `225c18` … Контейнеры: всплеск ошибок
- `1d7dc7` … LNX - Исполнение из памяти (memfd_create)
- `1d903d` … macOS - Bi.Zone: новый элемент автозагрузки
- `1d8195` … 6ad30b47cc18050c4f1d8195
- `225c28` … Контейнеры: перезапуски MariaDB
- `1d7dbf` … LNX - Подозрительные утилиты (base64, nc, socat, scp)
- `1d814b` … 6ad30b46cc18050c4f1d814b
- `1d7dd7` … LNX - Изменение правил firewall (iptables, nft)
- `1d816f` … 6ad30b46cc18050c4f1d816f
- `9ed46e` … LNX - Использование sudo
- `9ed450` … LNX - Изменение прав доступа (chmod)
- `1d7e3c` … Windows - Автозагрузка через ключ реестра Run
- `1ecca8` … KEENETIC - Новое устройство в сети
- `1d7de7` … LNX - Разведка (id, whoami)
```

### 8.10. Последние события

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 7 дней (как у дашборда) |
| Fields | `timestamp`, `priority`, `source`, `event_definition_id`, `message` |
| Sort | `timestamp` по убыванию; строк: 30 |
| Размер (ш×в) | 12×6 |

<a id="9-dash"></a>

## 9. 🩺 Здоровье сбора логов

- **Краткое описание (Summary):** Доходят ли логи: объём по входам и потокам, последнее сообщение от каждого источника
- **Описание (Description):** 
- **Окно времени дашборда:** 24 часа
- **Виджетов:** 7

### 9.1. Сообщений за 24 ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 6×3 |

### 9.2. Источников (хостов)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `card(source)` |
| Размер (ш×в) | 6×3 |

### 9.3. Объём по входам во времени

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `gl2_source_input` — **Values**, Limit 8 |
| Metrics | `count()` |
| Размер (ш×в) | 12×6 |

### 9.4. Объём по потокам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `streams` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 6×6 |

### 9.5. Доли входов

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `gl2_source_input` — **Values**, Limit 8 |
| Metrics | `count()` |
| Размер (ш×в) | 6×6 |

### 9.6. Последнее сообщение по источникам (самые «тихие» сверху)

| Поле | Значение |
|---|---|
| Тип | **Data Table** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `source` — **Values**, Limit 40 |
| Metrics | `latest(timestamp)`, `count()` |
| Sort | latest(timestamp) по возрастанию |
| Размер (ш×в) | 12×8 |

### 9.7. Справочник

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×6 |

Текст виджета (вставь в редактор Markdown):

```markdown
**Справочник: входы и потоки**

- вход `2882bf` … MacOS Beats
- вход `5b20b1` … BiZone macOS
- вход `fdb8f8` … Syslog UDP
- вход `fdb8ef` … Beats Input
- вход `fdb8e5` … GELF UDP
- вход `1f2e27` … Podman Logs
- поток `2559a4` … RedOS auditd Logs
- поток `fde88f` … Syslog Logs
- поток `fdd94e` … MacOS Logs
- поток `1a556b` … BiZone_macOS
- поток `fde575` … WindowsLogs
- поток `885bca` … FreeIPA Logs
- поток `1fa113` … Containers
```

<a id="10-dash"></a>

## 10. 🚨 Кто ломится: неудачные входы

- **Краткое описание (Summary):** Неудачная аутентификация со всех источников за 7 дней
- **Описание (Description):** 
- **Окно времени дашборда:** 7 дней
- **Виджетов:** 12

### 10.1. Windows: ошибки входа 4625

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.2. Linux: SSH

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `(message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.3. Linux: неудачный sudo

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `message:"sudo" AND (message:"authentication failure" OR message:"incorrect password" OR (message:"pam_sss" AND message:"failure"))` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.4. FreeIPA: PREAUTH_FAILED

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | FreeIPA Logs |
| Запрос | `message:PREAUTH_FAILED` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.5. Keenetic: отказы WireGuard

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:Wireguard_Failed` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.6. Grafana: неудачный вход

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Containers |
| Запрос | `container_name:grafana AND (message:"Invalid username or password" OR message:"Failed to authenticate" OR message:"login attempt failed")` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.7. macOS: неудачный вход (Triage)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | BiZone_macOS |
| Запрос | `mac_bz_event_type:LogonHistoryFailure` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.8. Всего за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | FreeIPA Logs, Syslog Logs, WindowsLogs, BiZone_macOS, Containers, RedOS auditd Logs |
| Запрос | `(winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure) OR ((message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")) OR message:PREAUTH_FAILED OR kn_event_type:Wireguard_Failed OR (container_name:grafana AND (message:"Invalid username or password" OR message:"Failed to authenticate" OR message:"login attempt failed")) OR mac_bz_event_type:LogonHistoryFailure OR (message:"sudo" AND (message:"authentication failure" OR message:"incorrect password" OR (message:"pam_sss" AND message:"failure")))` |
| Окно времени | 7 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 10.9. Попытки по времени и хостам

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | FreeIPA Logs, Syslog Logs, WindowsLogs, BiZone_macOS, Containers, RedOS auditd Logs |
| Запрос | `(winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure) OR ((message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")) OR message:PREAUTH_FAILED OR kn_event_type:Wireguard_Failed OR (container_name:grafana AND (message:"Invalid username or password" OR message:"Failed to authenticate" OR message:"login attempt failed")) OR mac_bz_event_type:LogonHistoryFailure OR (message:"sudo" AND (message:"authentication failure" OR message:"incorrect password" OR (message:"pam_sss" AND message:"failure")))` |
| Окно времени | 7 дней (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `source` — **Values**, Limit 6 |
| Metrics | `count()` |
| Размер (ш×в) | 8×5 |

### 10.10. По источникам данных

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | FreeIPA Logs, Syslog Logs, WindowsLogs, BiZone_macOS, Containers, RedOS auditd Logs |
| Запрос | `(winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure) OR ((message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")) OR message:PREAUTH_FAILED OR kn_event_type:Wireguard_Failed OR (container_name:grafana AND (message:"Invalid username or password" OR message:"Failed to authenticate" OR message:"login attempt failed")) OR mac_bz_event_type:LogonHistoryFailure OR (message:"sudo" AND (message:"authentication failure" OR message:"incorrect password" OR (message:"pam_sss" AND message:"failure")))` |
| Окно времени | 7 дней (как у дашборда) |
| Group By → Rows | `streams` — **Values**, Limit 6 |
| Metrics | `count()` |
| Размер (ш×в) | 4×5 |

### 10.11. Хосты, на которые идут попытки

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | FreeIPA Logs, Syslog Logs, WindowsLogs, BiZone_macOS, Containers, RedOS auditd Logs |
| Запрос | `(winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure) OR ((message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")) OR message:PREAUTH_FAILED OR kn_event_type:Wireguard_Failed OR (container_name:grafana AND (message:"Invalid username or password" OR message:"Failed to authenticate" OR message:"login attempt failed")) OR mac_bz_event_type:LogonHistoryFailure OR (message:"sudo" AND (message:"authentication failure" OR message:"incorrect password" OR (message:"pam_sss" AND message:"failure")))` |
| Окно времени | 7 дней (как у дашборда) |
| Group By → Rows | `source` — **Values**, Limit 12 |
| Metrics | `count()` |
| Размер (ш×в) | 12×5 |

### 10.12. Последние неудачные входы

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | FreeIPA Logs, Syslog Logs, WindowsLogs, BiZone_macOS, Containers, RedOS auditd Logs |
| Запрос | `(winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure) OR ((message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")) OR message:PREAUTH_FAILED OR kn_event_type:Wireguard_Failed OR (container_name:grafana AND (message:"Invalid username or password" OR message:"Failed to authenticate" OR message:"login attempt failed")) OR mac_bz_event_type:LogonHistoryFailure OR (message:"sudo" AND (message:"authentication failure" OR message:"incorrect password" OR (message:"pam_sss" AND message:"failure")))` |
| Окно времени | 7 дней (как у дашборда) |
| Fields | `timestamp`, `source`, `message` |
| Sort | `timestamp` по убыванию; строк: 25 |
| Размер (ш×в) | 12×6 |

<a id="11-dash"></a>

## 11. 🌐 Сеть и устройства (Keenetic + netalertx)

- **Краткое описание (Summary):** Роутер и сканер сети в одной картине
- **Описание (Description):** 
- **Окно времени дашборда:** 24 часа
- **Виджетов:** 9

### 11.1. Событий роутера за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 11.2. ARP-конфликтов за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:ARP_Conflict` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 11.3. WireGuard: отказов за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:Wireguard_Failed` |
| Окно времени | 7 дней (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 11.4. Сканов netalertx за 24 ч

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Containers |
| Запрос | `container_name:netalertx AND message:"Scan Stats" AND message:"New Devices"` |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 11.5. Типы событий роутера

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Syslog Logs |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `kn_event_type` — **Values**, Limit 8 |
| Metrics | `count()` |
| Размер (ш×в) | 4×5 |

### 11.6. Конфликты ARP по IP

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:ARP_Conflict` |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `kn_conflict_ip` — **Values**, Limit 8 |
| Metrics | `count()` |
| Размер (ш×в) | 4×5 |

### 11.7. Активность netalertx по времени

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | `container_name:netalertx` |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 4×5 |

### 11.8. Результаты сканов netalertx (New Devices)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Containers |
| Запрос | `container_name:netalertx AND message:"Scan Stats" AND message:"New Devices"` |
| Окно времени | 24 часа (как у дашборда) |
| Fields | `timestamp`, `source`, `message` |
| Sort | `timestamp` по убыванию; строк: 20 |
| Размер (ш×в) | 12×6 |

### 11.9. Wi-Fi: подключения и отключения клиентов

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Syslog Logs |
| Запрос | `message:"WifiMonitor" AND message:("deauthenticated" OR "authenticated")` |
| Окно времени | 7 дней (**Override** на виджете) |
| Fields | `timestamp`, `source`, `message` |
| Sort | `timestamp` по убыванию; строк: 20 |
| Размер (ш×в) | 12×6 |

<a id="12-dash"></a>

## 12. 📦 Контейнеры: доставка логов

- **Краткое описание (Summary):** promtail → Loki, ошибки Loki и объём логов по хостам
- **Описание (Description):** 
- **Окно времени дашборда:** 24 часа
- **Виджетов:** 9

### 12.1. promtail → Loki: ошибки доставки

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Containers |
| Запрос | `message:"context deadline exceeded" AND container_name:promtail` |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 4×3 |

### 12.2. Loki: ошибки приёма

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Containers |
| Запрос | `container_name:loki AND loglevel:error` |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 4×3 |

### 12.3. Хостов с контейнерами

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `card(source)` |
| Размер (ш×в) | 4×3 |

### 12.4. Ошибки доставки по времени и хостам

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | `message:"context deadline exceeded" AND container_name:promtail` |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `source` — **Values**, Limit 6 |
| Metrics | `count()` |
| Размер (ш×в) | 8×5 |

### 12.5. Ошибки доставки по хостам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | `message:"context deadline exceeded" AND container_name:promtail` |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `source` — **Values**, Limit 6 |
| Metrics | `count()` |
| Размер (ш×в) | 4×5 |

### 12.6. Объём логов по хостам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `source` — **Values**, Limit 8 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 12.7. Ошибки Loki по компонентам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | `container_name:loki AND loglevel:error` |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `logcaller` — **Values**, Limit 8 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 12.8. Последние ошибки Loki

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Containers |
| Запрос | `container_name:loki AND loglevel:error` |
| Окно времени | 24 часа (как у дашборда) |
| Fields | `timestamp`, `source`, `message` |
| Sort | `timestamp` по убыванию; строк: 15 |
| Размер (ш×в) | 12×6 |

### 12.9. Последние ошибки доставки promtail

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Containers |
| Запрос | `message:"context deadline exceeded" AND container_name:promtail` |
| Окно времени | 24 часа (как у дашборда) |
| Fields | `timestamp`, `source`, `message` |
| Sort | `timestamp` по убыванию; строк: 15 |
| Размер (ш×в) | 12×6 |

<a id="13-dash"></a>

## 13. 📅 Недельный обзор

- **Краткое описание (Summary):** Тренды: события ИБ за 30 дней и объём логов за 7 дней
- **Описание (Description):** 
- **Окно времени дашборда:** 30 дней
- **Виджетов:** 10

### 13.1. События за 30 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 30 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 13.2. HIGH за 30 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:3` |
| Окно времени | 30 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 13.3. MEDIUM за 30 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:2` |
| Окно времени | 30 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 13.4. LOW за 30 дней

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | All events |
| Запрос | `priority:1` |
| Окно времени | 30 дней (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×3 |

### 13.5. События по дням и приоритету

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 30 дней (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал 1 дн |
| Group By → Columns | `priority` — **Values**, Limit 3 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×5 |

### 13.6. Топ-15 правил за 30 дней (по id)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 30 дней (как у дашборда) |
| Group By → Rows | `event_definition_id` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 6×6 |

### 13.7. Объём логов по дням и потокам (7 дней)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал 1 дн |
| Group By → Columns | `streams` — **Values**, Limit 10 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 6×6 |

### 13.8. Доли потоков за 7 дней

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 7 дней (**Override** на виджете) |
| Group By → Rows | `streams` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 13.9. Топ объектов срабатываний за 30 дней

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | All events |
| Запрос | пусто |
| Окно времени | 30 дней (как у дашборда) |
| Group By → Rows | `key` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 13.10. Справочник

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×6 |

Текст виджета (вставь в редактор Markdown):

```markdown
**Справочник: id правила → название**

- `1d7ddf` … LNX - Отказ SELinux (AVC)
- `225c18` … Контейнеры: всплеск ошибок
- `1d7dc7` … LNX - Исполнение из памяти (memfd_create)
- `1d8195` … 6ad30b47cc18050c4f1d8195
- `1d903d` … macOS - Bi.Zone: новый элемент автозагрузки
- `225c28` … Контейнеры: перезапуски MariaDB
- `1d814b` … 6ad30b46cc18050c4f1d814b
- `1d7dbf` … LNX - Подозрительные утилиты (base64, nc, socat, scp)
- `1d817c` … 6ad30b47cc18050c4f1d817c
- `1d7dd7` … LNX - Изменение правил firewall (iptables, nft)
- `1d816f` … 6ad30b46cc18050c4f1d816f
- `9ed46e` … LNX - Использование sudo
- `1d81c2` … 6ad30b48cc18050c4f1d81c2
- `9ed450` … LNX - Изменение прав доступа (chmod)
- `1d7e3c` … Windows - Автозагрузка через ключ реестра Run

**Потоки**

- `2559a4` … RedOS auditd Logs
- `fde88f` … Syslog Logs
- `fdd94e` … MacOS Logs
- `1a556b` … BiZone_macOS
- `fde575` … WindowsLogs
- `885bca` … FreeIPA Logs
- `1fa113` … Containers
```

<a id="14-dash"></a>

## 14. 🍎 macOS: журналы Unified и osquery

- **Краткое описание (Summary):** Сбои, ошибки, TCC и события безопасности macOS (Unified и osquery через Filebeat)
- **Описание (Description):** Данные Filebeat с macOS-хостов (поток MacOS Logs): unified log, osquery, wifi.log.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 11

### 14.1. Виджет без названия

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×1 |

Текст виджета (вставь в редактор Markdown):

```markdown
🍎 **Overview (Обзор)**
━━━━━━━━━━━━━━━━━━━━━━━
```

### 14.2. Total Events(Всего событий за сутки)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Sort | count() по возрастанию |
| Размер (ш×в) | 3×1 |

### 14.3. ❌ Error Count (Ошибки)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | `macos_level:"Error"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Sort | count() по возрастанию |
| Размер (ш×в) | 3×1 |

### 14.4. Fault Count (Критические сбои)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | `macos_level:"Fault"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Sort | count() по возрастанию |
| Размер (ш×в) | 3×1 |

### 14.5. 🔒 TCC Events (Приватность TCC)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | `macos_subsystem:"com.apple.TCC"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Sort | count() по возрастанию |
| Размер (ш×в) | 3×1 |

### 14.6. 🛡️ Security Events (События безопасности)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | MacOS Logs |
| Запрос | `macos_subsystem:"com.apple.securityd"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Sort | count() по возрастанию |
| Размер (ш×в) | 12×1 |

### 14.7. 📊Activity Over Time (Активность по времени)

| Поле | Значение |
|---|---|
| Тип | **Line Chart** |
| Потоки | MacOS Logs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 12×2 |

### 14.8. Виджет без названия

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×1 |

Текст виджета (вставь в редактор Markdown):

```markdown
🍎 **Security Deep Dive (Детали безопасности)**
   ━━━━━━━━━━━━━━━━━━━━━━
```

### 14.9. 🔴 Security Errors (Ошибки безопасности)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | MacOS Logs |
| Запрос | `macos_level:Error` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `log_type`, `macos_eventType`, `macos_eventMessage`, `subsystem` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×7 |

### 14.10. 🔒 TCC Violations (Нарушения приватности)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | MacOS Logs |
| Запрос | `macos_subsystem:"com.apple.TCC" OR macos_eventMessage:"privacy"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `subsystem`, `eventMessage` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×8 |

### 14.11. ⚠️ Fault Events (Критические сбои)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | MacOS Logs |
| Запрос | `macos_level:"Fault"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `subsystem`, `eventMessage` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×6 |

<a id="15-dash"></a>

## 15. 🛡️ macOS: BI.ZONE Triage

- **Краткое описание (Summary):** Телеметрия BI.ZONE Triage: процессы, пользователи, неподписанные файлы, подозрительные команды
- **Описание (Description):** Данные агентов bz_triage (поток BiZone_macOS): активность хостов, администраторы, дерево процессов, инвентаризация сенсоров.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 11

### 15.1. 📉 Активность во времени (Line Chart)

| Поле | Значение |
|---|---|
| Тип | **Line Chart** |
| Потоки | BiZone_macOS |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 12×3 |

### 15.2. 🥧 Типы событий (Donut Chart)

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | BiZone_macOS |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `mac_bz_event_type` — **Values**, Limit 8 |
| Metrics | `count()` |
| Размер (ш×в) | 5×5 |

### 15.3. 👥 Топ пользователей (Horizontal Bar Chart)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | BiZone_macOS |
| Запрос | `_exists_: mac_bz_user` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `mac_bz_user` — **Values**, Limit 10 |
| Metrics | `count()` |
| Barmode | Group |
| Размер (ш×в) | 7×5 |

### 15.4. 🖥️ Топ хостов (Horizontal Bar Chart)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | BiZone_macOS |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `mac_bz_host` — **Values**, Limit 10 |
| Metrics | `count()` |
| Barmode | Group |
| Размер (ш×в) | 5×4 |

### 15.5. 🔐 Admin Access Monitor (таблица)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | BiZone_macOS |
| Запрос | `event_type:LogonInfo OR mac_bz_event_type:LogonInfo` |
| Окно времени | 5 минут (как у дашборда) |
| Fields | `timestamp`, `mac_bz_host`, `mac_bz_user`, `usr_tgt_groups`, `mac_bz_rule` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 7×4 |

### 15.6. 📋 Журнал событий (Message Table)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | BiZone_macOS |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `mac_bz_host`, `mac_bz_event_type`, `mac_bz_rule`, `mac_bz_os` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×6 |

### 15.7. Виджет для поиска администраторов

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | BiZone_macOS |
| Запрос | `usr_tgt_groups:80(admin)` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `mac_bz_host`, `mac_bz_user`, `usr_tgt_groups`, `mac_bz_rule` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×3 |

### 15.8. 🛡️Неподписанные процессы

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | BiZone_macOS |
| Запрос | `proc_file_signed:false` |
| Окно времени | 1 час (**Override** на виджете) |
| Fields | `timestamp`, `mac_bz_host`, `usr_tgt_name`, `proc_file_path`, `proc_file_name`, `proc_file_sha256` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

### 15.9. 🔍 Подозрительные командные строки

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | BiZone_macOS |
| Запрос | `mac_bz_cmdline:(curl OR wget OR base64 OR python OR osascript OR "hidden")` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `mac_bz_host`, `mac_bz_user`, `mac_bz_cmdline` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×3 |

### 15.10. 🌳 Дерево процессов (Parent → Child)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | BiZone_macOS |
| Запрос | `mac_bz_event_type:ProcessInfo` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `mac_bz_host`, `mac_bz_cmdline` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

### 15.11. 💻 Инвентаризация сенсоров

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | BiZone_macOS |
| Запрос | `mac_bz_event_type:HostInfo` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `mac_bz_host`, `source`, `dev_serial`, `mac_bz_os`, `mac_bz_sensor_version` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

<a id="16-dash"></a>

## 16. 🪟 Windows: Sysmon и события входа

- **Краткое описание (Summary):** Sysmon и Security с Windows-хостов: процессы, входы, реестр, загрузка DLL
- **Описание (Description):** Данные Winlogbeat (поток WindowsLogs): Sysmon и журнал Security контроллера домена и рабочей станции.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 14

### 16.1. Виджет без названия

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×1 |

Текст виджета (вставь в редактор Markdown):

```markdown
🪟 **Overview (Обзор)**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 16.2. Total Windows Events (Всего событий Windows)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×1 |

### 16.3. Process Create (Создание процессов)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:"1"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×1 |

### 16.4. Image Load (Загрузка DLL)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:"7"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×1 |

### 16.5. Registry Events (Реестр)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:"13"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×1 |

### 16.6. 🔐 Success Logins (Успешные входы)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:"4624"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Metrics | `count()` |
| Размер (ш×в) | 3×1 |

### 16.7. 📈 Activity Over Time (Активность по времени)

| Поле | Значение |
|---|---|
| Тип | **Line Chart** |
| Потоки | WindowsLogs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал 15 мин |
| Metrics | `count()` |
| Размер (ш×в) | 12×4 |

### 16.8. 🎯 Event ID Distribution (Распределение Event ID)

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | WindowsLogs |
| Запрос | `_exists_:win_event_id` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `winlogbeat_event_code` — **Values**, Limit 10 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×6 |

### 16.9. 📂 Event Sources (Channels)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | WindowsLogs |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `win_channel` — **Values**, Limit 15 |
| Metrics | `count()` |
| Barmode | Overlay |
| Размер (ш×в) | 6×6 |

### 16.10. 🖥️ Top Hosts

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | WindowsLogs |
| Запрос | пусто |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `win_host` — **Values**, Limit 5 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Barmode | Overlay |
| Размер (ш×в) | 6×5 |

### 16.11. 📋 Recent Windows Events

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:"13" OR win_event_id:"4624"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `win_event_id`, `win_host`, `win_image`, `win_user`, `message` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×7 |

### 16.12. 🔑 Recent Logins (Последние входы)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | WindowsLogs |
| Запрос | `winlogbeat_winlog_event_id:"4624"` |
| Окно времени | 5 минут (как у дашборда) |
| Fields | `timestamp`, `source`, `win_user`, `win_channel` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×6 |

### 16.13. 📝 Registry Changes (Event ID 13)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:"13"` |
| Окно времени | 5 минут (как у дашборда) |
| Fields | `timestamp`, `win_host`, `win_image`, `win_registry_key`, `win_user` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

### 16.14. 🔄 Process Creation

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | WindowsLogs |
| Запрос | `win_event_id:"1" AND message:"powershell"` |
| Окно времени | 5 минут (как у дашборда) |
| Fields | `timestamp`, `win_host`, `win_image`, `win_user`, `win_command_line`, `message` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

<a id="17-dash"></a>

## 17. 🐧 РЕД ОС: auditd

- **Краткое описание (Summary):** События auditd РЕД ОС после декодера: команды, сервисы, сессии, типы аудита
- **Описание (Description):** Данные auditd с хостов РЕД ОС (поток RedOS auditd Logs), обработанные Python-декодером.
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 13

### 17.1. Виджет без названия

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×1 |

Текст виджета (вставь в редактор Markdown):

```markdown
**Overview (Обзор)**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 17.2. 📊 Total Audit Events (Всего событий аудита)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 5×1 |

### 17.3. SYSCALL Events (Системные вызовы)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:"SYSCALL"` |
| Окно времени | 5 минут (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 4×1 |

### 17.4. ⚡ EXECVE Events (Запуски команд)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:"EXECVE"` |
| Окно времени | 5 минут (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 3×1 |

### 17.5. Service Events (События сервисов)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:("SERVICE_START" OR "SERVICE_STOP")` |
| Окно времени | 5 минут (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 6×1 |

### 17.6. 👥 User Sessions (Пользовательские сессии)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:("USER_START" OR "USER_END")` |
| Окно времени | 5 минут (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 6×1 |

### 17.7. Activity Over Time (Активность по времени)

| Поле | Значение |
|---|---|
| Тип | **Line Chart** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 12×2 |

### 17.8. 🎯 Audit Types (Типы аудита)

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `audit_type` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 4×5 |

### 17.9. Top Hosts (Топ хостов)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | RedOS auditd Logs |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `syslog_hostname` — **Values**, Limit 15 |
| Metrics | `count()` |
| Sort | syslog_hostname по убыванию |
| Barmode | Group |
| Размер (ш×в) | 8×5 |

### 17.10. Виджет без названия

| Поле | Значение |
|---|---|
| Тип | **Markdown (Text)** |
| Размер (ш×в) | 12×1 |

Текст виджета (вставь в редактор Markdown):

```markdown
**Security Deep Dive (Детали безопасности)**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 17.11. ⚡ EXECVE Commands (Запущенные команды)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:"EXECVE"` |
| Окно времени | 5 минут (как у дашборда) |
| Fields | `timestamp`, `source`, `a0`, `a1`, `a2`, `a3` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×4 |

### 17.12. 🔄 Service Changes (Изменения сервисов)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:("SERVICE_START" OR "SERVICE_STOP")` |
| Окно времени | 5 минут (как у дашборда) |
| Fields | `timestamp`, `source`, `audit_type`, `ses`, `comm`, `pid`, `exe`, `msg` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

### 17.13. 👥 User Logins (Входы пользователей)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | RedOS auditd Logs |
| Запрос | `audit_type:("USER_START" OR "USER_END" OR "USER_LOGIN")` |
| Окно времени | 5 минут (как у дашборда) |
| Fields | `timestamp`, `source`, `audit_type`, `uid`, `auid`, `message` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×7 |

<a id="18-dash"></a>

## 18. 📡 Keenetic: журналы роутера

- **Краткое описание (Summary):** Активность роутера, ARP-конфликты, SSH, Wi-Fi и WireGuard: детальные журналы
- **Описание (Description):** Подробные журналы Keenetic (поток Syslog Logs). Сводные цифры — на дашборде «Сеть глазами Keenetic».
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 7

### 18.1. 🚨 Total ARP Conflicts (KPI)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Syslog Logs |
| Запрос | `message:"network conflict"` |
| Окно времени | 5 минут (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 2×2 |

### 18.2. 📈 Keenetic Activity Timeline (Line Chart) Router Activity Over Time

| Поле | Значение |
|---|---|
| Тип | **Line Chart** |
| Потоки | Syslog Logs |
| Запрос | `source:Keenetic\-7625` |
| Окно времени | 24 часа (**Override** на виджете) |
| Group By → Rows | `timestamp` — **Time**, интервал 1 ч |
| Metrics | `count()` |
| Размер (ш×в) | 10×2 |

### 18.3. 📋 Detailed Conflict Log (Message Table)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Syslog Logs |
| Запрос | `message:"network conflict"` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `arp_ip`, `arp_mac1`, `arp_mac2` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

### 18.4. Конфликты ARP по IP

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Syslog Logs |
| Запрос | пусто |
| Окно времени | 1 час (**Override** на виджете) |
| Group By → Rows | `kn_conflict_ip` — **Values**, Limit 15 |
| Metrics | `count(source)` |
| Barmode | Group |
| Размер (ш×в) | 12×4 |

### 18.5. SSH Connections

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Syslog Logs |
| Запрос | `message:"dropbear"` |
| Окно времени | всё время (**Override** на виджете) |
| Fields | `timestamp`, `source`, `facility`, `level`, `message` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×6 |

### 18.6. WireGuard: отказы и успешные входы

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Syslog Logs |
| Запрос | `kn_event_type:(Wireguard_Failed OR Wireguard_Success)` |
| Окно времени | 24 часа (**Override** на виджете) |
| Fields | `timestamp`, `source`, `level`, `message` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

### 18.7. WiFi Events (отключение/подключение клиентов)

| Поле | Значение |
|---|---|
| Тип | **Message List** |
| Потоки | Syslog Logs |
| Запрос | `message:"WifiMonitor" AND message:("deauthenticated" OR "authenticated")` |
| Окно времени | всё время (**Override** на виджете) |
| Fields | `timestamp`, `source`, `level`, `message` |
| Sort | `timestamp` по убыванию; строк: 150 |
| Размер (ш×в) | 12×5 |

<a id="19-dash"></a>

## 19. 📦 Контейнеры

- **Краткое описание (Summary):** Логи Podman-контейнеров: объём, уровни, ошибки
- **Описание (Description):** Контейнеры с хостов Podman через Fluent Bit, стрим Containers
- **Окно времени дашборда:** 24 часа
- **Виджетов:** 7

### 19.1. Всего сообщений

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 4×3 |

### 19.2. Ошибки и предупреждения (24 ч)

| Поле | Значение |
|---|---|
| Тип | **Single Number** |
| Потоки | Containers |
| Запрос | `(loglevel:(error OR warn OR fatal) OR message:(error OR fatal OR panic OR exception OR traceback)) AND NOT container_name:(cadvisor OR fluent-bit)` |
| Окно времени | 24 часа (как у дашборда) |
| Metrics | `count()` |
| Размер (ш×в) | 4×3 |

### 19.3. Приоритет journald (6 — stdout, 3 — stderr)

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `level` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 4×3 |

### 19.4. Активность по времени

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 12×4 |

### 19.5. Сообщения по контейнерам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `container_name` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 19.6. Ошибки и предупреждения по контейнерам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | `(loglevel:(error OR warn OR fatal) OR message:(error OR fatal OR panic OR exception OR traceback)) AND NOT container_name:(cadvisor OR fluent-bit)` |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `container_name` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 19.7. Контейнер × уровень

| Поле | Значение |
|---|---|
| Тип | **Data Table** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `container_name` — **Values**, Limit 30<br>`level` — **Values**, Limit 30 |
| Metrics | `count()` |
| Размер (ш×в) | 12×5 |

<a id="20-dash"></a>

## 20. 🔧 Контейнеры: диагностика

- **Краткое описание (Summary):** Ошибки, перезапуски, права доступа, уровни логов контейнеров
- **Описание (Description):** Диагностика контейнеров: Observium, MongoDB, Loki/Promtail, источники логов
- **Окно времени дашборда:** 24 часа
- **Виджетов:** 6

### 20.1. Ошибки и предупреждения по времени

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | `(loglevel:(error OR warn OR fatal) OR message:(error OR fatal OR panic OR exception OR traceback)) AND NOT container_name:(cadvisor OR fluent-bit)` |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 20.2. Перезапуски MariaDB по времени

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 20.3. Ошибки прав доступа по контейнерам

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `container_name` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 20.4. Источники логов (хосты)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `source` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 6×5 |

### 20.5. Уровни MongoDB (log_s)

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `log_s` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 20.6. Уровни Loki и Promtail

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `loglevel` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

<a id="21-dash"></a>

## 21. ⚙️ Контейнеры: процессы

- **Краткое описание (Summary):** Жизненный цикл MariaDB, компоненты MongoDB и Loki, попытки без авторизации, активность Observium
- **Описание (Description):** Процессы внутри контейнеров по логам stdout/stderr
- **Окно времени дашборда:** 24 часа
- **Виджетов:** 6

### 21.1. MariaDB: готовность к подключению

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 21.2. MariaDB: остановки

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 21.3. MongoDB: компоненты логов

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `log_c` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 21.4. MongoDB: подключения без авторизации (клиенты)

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `log_attr_client` — **Values**, Limit 15 |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 21.5. Loki и Promtail: компоненты с ошибками

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `logcaller` — **Values**, Limit 10 |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

### 21.6. Observium: активность по времени

| Поле | Значение |
|---|---|
| Тип | **Area Chart** |
| Потоки | Containers |
| Запрос | пусто |
| Окно времени | 24 часа (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Metrics | `count()` |
| Размер (ш×в) | 6×4 |

<a id="22-dash"></a>

## 22. 📊 Общий базовый дашборд

- **Краткое описание (Summary):** Все источники: объём сообщений по входам, потокам и узлам
- **Описание (Description):** Это список всех источников, отправивших сообщения.  Вы можете сузить временной диапазон, увеличив масштаб гистограммы сообщений, или расширить его, выбрав более
- **Окно времени дашборда:** 5 минут
- **Виджетов:** 5

### 22.1. Messages over time by Streams

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `streams` — **Values**, Limit 15 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 12×4 |

### 22.2. Messages over time by Inputs

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `gl2_source_input` — **Values**, Limit 15 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 6×4 |

### 22.3. Messages over time by Nodes

| Поле | Значение |
|---|---|
| Тип | **Bar Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `timestamp` — **Time**, интервал Auto |
| Group By → Columns | `gl2_source_node` — **Values**, Limit 15 |
| Metrics | `count()` |
| Barmode | Stack |
| Размер (ш×в) | 6×4 |

### 22.4. Selected sources

| Поле | Значение |
|---|---|
| Тип | **Data Table** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `source` — **Values**, Limit 15 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×4 |

### 22.5. Messages per Source

| Поле | Значение |
|---|---|
| Тип | **Pie Chart** |
| Потоки | все |
| Запрос | пусто |
| Окно времени | 5 минут (как у дашборда) |
| Group By → Rows | `source` — **Values**, Limit 10 |
| Metrics | `count()` |
| Sort | count() по убыванию |
| Размер (ш×в) | 6×4 |

---

Главы: [Дашборды](07-dashboards.md) · [Контейнеры: дашборды](09-containers-dashboards.md) · [Troubleshooting](troubleshooting.md)
