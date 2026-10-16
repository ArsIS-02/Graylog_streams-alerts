<p align="center">
  <img src="https://img.shields.io/badge/Graylog-7.1.3-FF6B00?style=for-the-badge&logo=graylog&logoColor=white" alt="Graylog version"/>
  <img src="https://img.shields.io/badge/MongoDB-7.0.37-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB version"/>
  <img src="https://img.shields.io/badge/OpenSearch-2.19.5-005EB8?style=for-the-badge&logo=opensearch&logoColor=white" alt="OpenSearch version"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/>
</p>

# 🛡️ Graylog: домашняя лаборатория со сбором логов, потоками и алертами

> **Единая история** — от первого опыта до активного мониторинга безопасности.
> Разворачиваем Graylog, собираем логи с Windows, Linux и macOS, раскладываем их по
> потокам, декодируем auditd и настраиваем email-алерты на подозрительную активность.

---

## 📖 О чём этот репозиторий

Централизованный сбор логов становится по-настоящему полезным, когда система сама
сортирует события и предупреждает о проблемах. В этом репозитории — полный путь:

1. **База** — разворачиваем Graylog (Java + MongoDB + OpenSearch) и настраиваем приём логов.
2. **Потоки** — раскладываем логи по смыслу: Windows, Linux, Security, Errors.
3. **Декодер auditd** — переводим шестнадцатеричные поля в читаемый вид (собственный Python-демон).
4. **Алерты** — email-уведомления о неудачных входах на Linux и Windows.

Материал объединяет мои статьи о Graylog и дополнен конфигурацией для macOS, Linux, Windows.

## 🗂 Структура

```
.
├── README.md                         ← этот обзор
├── docs/                             ← единая история по главам
│   ├── 01-home-lab.md                ← часть 1: установка Graylog, MongoDB, OpenSearch
│   ├── 02-streams-alerts.md          ← часть 2: потоки, алерты, декодер auditd
│   ├── 03-windows.md                 ← Windows: Sysmon, Winlogbeat, алерт 4625
│   ├── 04-linux.md                   ← Linux: auditd, rsyslog, алерт SSH
│   ├── 05-macos.md                   ← macOS: unified log, Filebeat, osquery
│   ├── 06-macos-bztriage.md          ← macOS: телеметрия через BI.ZONE Triage
│   └── troubleshooting.md            ← грабли и их решения
├── decoder/                          ← декодер auditd (на сервере)
│   ├── auditd_decoder.py             ← Python-демон: UDP → GELF
│   └── audit-decoder.service         ← systemd-юнит
├── config/                           ← конфиги сервера Graylog/OpenSearch
│   ├── server.conf.smtp.example      ← SMTP для email-алертов (Mail.ru)
│   └── opensearch.yml.example        ← OpenSearch для Graylog
├── linux/                            ← агенты для Linux-хостов
│   └── rsyslog.conf.example          ← пересылка syslog в Graylog
├── windows/                          ← агенты для Windows-хостов
│   └── winlogbeat.yml.example        ← доставка событий Windows
└── macos/                            ← агенты для macOS-хостов
    ├── filebeat.yml                  ← Filebeat (unified log, wifi.log, osquery)
    ├── osquery.conf                  ← osquery
    ├── co.elastic.filebeat.plist     ← LaunchDaemon Filebeat
    ├── com.user.logstream.plist      ← LaunchDaemon log stream
    ├── zshrc.local                   ← хук логирования команд
    ├── logstream/                    ← ротация unified.json.log
    └── bztriage/                     ← BI.ZONE Triage: скрипты, plist-ы, документация
```

## 🚀 Быстрый старт

1. **Установи стек** по [части 1](docs/01-home-lab.md): Java 17, MongoDB,
   OpenSearch, Graylog server.
2. **Настрой агенты** по своей ОС: [Windows](docs/03-windows.md),
   [Linux](docs/04-linux.md), [macOS](docs/05-macos.md).
3. **Создай потоки и алерты** по [части 2](docs/02-streams-alerts.md).
4. **Подключи декодер auditd** из [`decoder/`](decoder/auditd_decoder.py) — и
   события auditd станут читаемыми.

## ✨ Что мы получаем

| Функция | Описание |
|---|---|
| 📂 **Потоки** | Windows Logs, Linux Logs, Security Events, Errors — всё разложено |
| 🐍 **Декодер auditd** | Python-демон принимает сырые логи по UDP, декодирует hex-поля, отправляет GELF |
| 📧 **Алерты по email** | SMTP через Mail.ru, письмо с прямой ссылкой на событие |
| ⚡ **Быстрая реакция** | Проверка условий каждые 5 минут, уведомление в течение 1–2 минут |
| 🖥 **Три платформы** | Windows, Linux (РЕД ОС), macOS |

## 📚 Читай по главам

- [Часть 1. Домашняя лаборатория: разворачиваем Graylog](docs/01-home-lab.md)
- [Часть 2. Потоки, алерты и декодер auditd](docs/02-streams-alerts.md)
- [Windows: Sysmon, Winlogbeat и алерт 4625](docs/03-windows.md)
- [Linux: auditd, rsyslog и алерт SSH](docs/04-linux.md)
- [macOS: unified log, Filebeat и osquery](docs/05-macos.md)
- [macOS: телеметрия через BI.ZONE Triage](docs/06-macos-bztriage.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🔗 Ссылки

- [Graylog Documentation](https://docs.graylog.org/)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Winlogbeat Documentation](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)
- [osquery Documentation](https://osquery.readthedocs.io/)
- [Sysmon (Sysinternals)](https://learn.microsoft.com/sysinternals/downloads/sysmon)
