<p align="center">
  <img src="https://img.shields.io/badge/Graylog-7.2.1-FF6B00?style=for-the-badge&logo=graylog&logoColor=white" alt="Graylog version"/>
  <img src="https://img.shields.io/badge/MongoDB-7.0.43-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB version"/>
  <img src="https://img.shields.io/badge/OpenSearch-2.19.5-005EB8?style=for-the-badge&logo=opensearch&logoColor=white" alt="OpenSearch version"/>
  <img src="https://img.shields.io/badge/License-GPL%20v3-blue?style=for-the-badge" alt="License"/>
</p>

# 🛡️ Graylog: домашняя лаборатория со сбором логов, потоками и алертами

> Единая история: от установки Graylog до активного мониторинга безопасности.
> Собираем логи с Windows, Linux, macOS и контейнеров, раскладываем по потокам,
> декодируем auditd и настраиваем email-алерты на подозрительную активность.

## 📑 Оглавление

- [О репозитории](#-о-репозитории)
- [Быстрый старт](#-быстрый-старт)
- [Главы](#-главы)
  - [Основа: установка, потоки, алерты](#основа-установка-потоки-алерты)
  - [Источники логов: Windows, Linux, macOS, контейнеры](#источники-логов-windows-linux-macos-контейнеры)
  - [Дашборды](#дашборды)
  - [Разбор проблем](#разбор-проблем)
- [Что внутри](#-что-внутри)
- [Структура репозитория](#-структура-репозитория)
- [Ссылки](#-ссылки)

## 📖 О репозитории

Централизованный сбор логов полезен, когда система сама сортирует события и
предупреждает о проблемах. Здесь собран весь путь:

1. **База**: Graylog на Java, MongoDB и OpenSearch, приём логов.
2. **Потоки**: логи раскладываются по смыслу (Windows, Linux, Security, Errors, Containers).
3. **Декодер auditd**: собственный Python-демон переводит hex-поля в читаемый вид.
4. **Алерты**: email-уведомления о неудачных входах, sudo, USB и других событиях.
5. **Дашборды**: от обзора лаборатории до центра безопасности (SOC).

> Раньше это руководство публиковалось и в репозитории MyHomeLaboratory. Там осталась более ранняя
> версия (Graylog 7.1.3, без глав 10–12), и она больше не поддерживается: актуальный текст только здесь.

> Картинки в главах 05–09 и в разделе «Troubleshooting» воссозданы по реальным данным
> лаборатории (названия, счётчики, сообщения из Graylog) в стиле его интерфейса.

## 🚀 Быстрый старт

1. Установи стек по [части 1](docs/01-home-lab.md): Java 17, MongoDB, OpenSearch, Graylog.
2. Подключи агенты своей ОС: [Windows](docs/03-windows.md), [Linux](docs/04-linux.md),
   [macOS](docs/05-macos.md), [контейнеры](docs/08-containers.md) — или сразу
   [Collectors](docs/11-collectors.md), где настройка всех ОС живёт на сервере.
3. Создай потоки и алерты по [части 2](docs/02-streams-alerts.md) или импортируй готовые
   63 алерта из [content pack](graylog/content-pack-homelab-alerts.json).
4. Подключи [декодер auditd](decoder/auditd_decoder.py): события станут читаемыми.

## 📚 Главы

### Основа: установка, потоки, алерты

| # | Глава | О чём |
|---|---|---|
| 1 | [Домашняя лаборатория: разворачиваем Graylog](docs/01-home-lab.md) | Java, MongoDB, OpenSearch, Graylog server |
| 2 | [Потоки, алерты и декодер auditd](docs/02-streams-alerts.md) | Потоки, email-уведомления, декодер auditd |

### Источники логов: Windows, Linux, macOS, контейнеры

| # | Глава | О чём |
|---|---|---|
| 3 | [Windows](docs/03-windows.md) | Sysmon, Winlogbeat, алерт на событие 4625 |
| 4 | [Linux](docs/04-linux.md) | auditd, rsyslog, алерт на SSH |
| 5 | [macOS: unified log, Filebeat, osquery](docs/05-macos.md) | Unified log, USB, osquery, ротация логов |
| 6 | [macOS: BI.ZONE Triage](docs/06-macos-bztriage.md) | Три launchd-агента, телеметрия по `nc` |
| 8 | [Контейнеры: логи Podman](docs/08-containers.md) | Fluent Bit, GELF, extractor-ы, поток Containers |
| 11 | [Collectors: агенты под управлением сервера](docs/11-collectors.md) | Один агент на Linux, macOS и Windows, настройка из Graylog |
| 12 | [Graylog + Grafana](docs/12-graylog-grafana.md) | Логи и алерты Graylog на дашбордах Grafana, аннотации; полный набор — в [grafana-homelab](https://github.com/ArsIS-02/grafana-homelab) |

### Дашборды

| # | Глава | О чём |
|---|---|---|
| 7 | [Дашборды](docs/07-dashboards.md) | Семь дашбордов для доклада и шесть рабочих: детекты, здоровье сбора, неудачные входы |
| 9 | [Контейнеры: дашборды, поиски, события](docs/09-containers-dashboards.md) | Дашборды через API, Saved Searches, 18 детектов по контейнерам |
| 10 | [Дашборды руками](docs/10-dashboards-manual.md) | Мини-инструкция по каждому из 22 дашбордов: что выбрать в каждом виджете |

### Разбор проблем

| Глава | О чём |
|---|---|
| [Troubleshooting](docs/troubleshooting.md) | 22 грабли: ротация логов, дубли, лимит полей, extractor-ы, Fluent Bit, OpenSearch (память, автозапуск), Collectors |

## ✨ Что внутри

| Функция | Описание |
|---|---|
| 📂 **Потоки** | Windows, Linux, Security Events, Errors, Containers |
| 🐍 **Декодер auditd** | Python-демон принимает сырые логи по UDP, декодирует hex-поля, отправляет GELF |
| 📧 **Алерты по email** | SMTP через Mail.ru, письмо с прямой ссылкой на событие |
| ⚡ **Быстрая реакция** | Проверка условий каждые 5 минут, уведомление в течение 1–2 минут |
| 🖥 **Четыре источника** | Windows, Linux (РЕД ОС), macOS, контейнеры Podman |
| 🛰 **Collectors** | Один агент на 12 хостов: настройка источников на сервере, без конфигов на машинах |
| 📊 **Дашборды** | Семь дашбордов для доклада, шесть рабочих и три для контейнеров |

## 🗂 Структура репозитория

```
.
├── README.md                          ← этот обзор
├── docs/                              ← главы
│   ├── 01-home-lab.md                 ← установка Graylog, MongoDB, OpenSearch
│   ├── 02-streams-alerts.md           ← потоки, алерты, декодер auditd
│   ├── 03-windows.md                  ← Windows: Sysmon, Winlogbeat, алерт 4625
│   ├── 04-linux.md                    ← Linux: auditd, rsyslog, алерт SSH
│   ├── 05-macos.md                    ← macOS: unified log, Filebeat, osquery
│   ├── 06-macos-bztriage.md           ← macOS: BI.ZONE Triage
│   ├── 07-dashboards.md               ← дашборды для доклада
│   ├── 08-containers.md               ← контейнеры: Podman → Fluent Bit → Graylog
│   ├── 09-containers-dashboards.md    ← контейнеры: дашборды, поиски, события
│   ├── 10-dashboards-manual.md        ← 22 дашборда руками, виджет за виджетом
│   ├── 11-collectors.md               ← Collectors: агенты под управлением сервера
│   ├── 12-graylog-grafana.md          ← Graylog + Grafana: логи и аннотации на дашбордах
│   ├── troubleshooting.md             ← грабли и решения
│   └── images/                        ← скриншоты и иллюстрации к главам
├── decoder/                           ← декодер auditd (auditd_decoder.py, systemd-юнит)
├── config/                            ← server.conf (SMTP), opensearch.yml
├── containers/                        ← Fluent Bit: Quadlet-юнит и конфиг
├── graylog/                           ← content pack (63 алерта + 3 email-уведомления) и 18 детектов по контейнерам, 22 дашборда (`dashboards-spec.json` + `import-dashboards.js`), правила pipeline с импортёром (`pipelines/`)
├── linux/                             ← rsyslog.conf.example
├── windows/                           ← winlogbeat.yml.example
└── macos/                             ← Filebeat, osquery, LaunchDaemon-ы, bztriage/
```

## 🔗 Ссылки

- [Graylog Documentation](https://docs.graylog.org/)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Winlogbeat Documentation](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)
- [osquery Documentation](https://osquery.readthedocs.io/)
- [Sysmon (Sysinternals)](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Fluent Bit Documentation](https://docs.fluentbit.io/)
- [Grafana Documentation](https://grafana.com/docs/grafana/latest/)

## 📄 Лицензия

[GNU GPL версии 3](LICENSE) (GPL-3.0-or-later): код можно свободно использовать, изменять и распространять; изменённая версия при распространении остаётся под GPL с открытым исходным кодом и указанием авторства. Программа поставляется «как есть», без гарантий.

Copyright (C) 2026 ArsIS-02.
