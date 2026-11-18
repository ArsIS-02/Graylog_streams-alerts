# Глава 36. SSH-харденинг лаборатории: только ключи, без паролей и root

> 18.11.2026 за один день вся лаборатория (8 хостов РЕД ОС) переведена на
> строгий SSH: вход по паролю выключен везде, root по SSH запрещён, машинные
> ключи привязаны к адресам источников, автоматика переведена с
> expect-паролей на ключи. Попутно починен p2p между MacBook через WireGuard
> и убран crash-loop осиротевшего мониторинг-стека на wazuh-homelab.

## Зачем

Открытый вход по паролю на восьми хостах — это и риск подбора, и вечный шум
в алертах (каждый `Accepted password` от собственной автоматики выглядел
как событие). Плюс машинные ключи хостов были «всепогодными»: скомпретируй
один — ходи им отовсюду.

## Хосты

| Хост | IP | Волна |
|---|---|---|
| redos-server | 192.168.1.137 | 1 |
| homelab | 192.168.1.210 | 1 |
| server | 192.168.1.50 | 1 |
| redosrp16 | 192.168.1.55 | 1 |
| homeserver | 192.168.1.56 | 2 |
| redos-raspi | 192.168.1.148 | 2 |
| wazuh-homelab | 192.168.1.37 | 2 |
| wazuh | 192.168.1.117 | 2 |

Вторая волна сначала казалась недоступной — выяснилось, что фильтрация
22-го порта была **по источнику**: с redos-server блокировала, с Mac mini
пускала. Зашли с Mac под штатными пользователями.

## Что сделано

### 1. PermitRootLogin no (все 8)

`/etc/ssh/sshd_config.d/00-no-root-login.conf`, `sshd -t`, reload.
Подтверждено логами: root отклоняется с `[preauth]`. Root-входов в логах
ранее не было — ничего не сломано. (Предварительно обсуждено с владельцем:
root по SSH не нужен ничему, везде есть sudo.)

### 2. Привязка машинных ключей

Каждому межхостовому ключу в `authorized_keys` добавлены
`from="192.168.1.X"` и ограничения
`no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding`.
Бэкапы: `~/.ssh/authorized_keys.bak-20261118` на каждом хосте.
Человеческие ключи (W11, MacBook, Mac mini ×2, Workstation) не тронуты.
Ключ `root@homelab` для бэкапов уже был ограничен ранее forced command
backup-ingress (только с redos-server).

### 3. PasswordAuthentication no (все 8)

`/etc/ssh/sshd_config.d/00-no-password.conf`:
`PasswordAuthentication no` + `KbdInteractiveAuthentication no`,
`sshd -t`, reload. Верификация клиентом: серверы предлагают только
`publickey,gssapi-keyex,gssapi-with-mic`. Откат: удалить файл + reload.

Перед выключением паролей проверено, что ключевой доступ есть отовсюду,
откуда нужно: Mac mini → все 8, MacBookPro → все 8, цепочка разбана
Keenetic end-to-end, Graylog API 200.

### 4. Автоматика Mac переведена с expect-паролей на ключи

20 expect-скриптов (`ssh_run.exp` и т.п.) переписаны в key-based sh
с сохранением интерфейса. `BatchMode=yes` — без ключа падают сразу,
а не висят в ожидании пароля. Оригиналы сохранены в `exp-backup-20261118/`.
`ssh_keenetic.exp` не тронут (роутер, там пароль остаётся).

### 5. Уборка

- homelab: удалены 7 одинаковых битых строк `ssh-rsa AAAAB3...AQ...`
  (обрывки вставки из усечённого вывода, sshd их игнорировал).
- wazuh-homelab: осиротевшие user-сервисы старого мониторинг-стека
  (grafana, loki, blackbox, observiumapp/db, alertmanager, dozzle,
  prometheus) crash-loop'или с NRestarts>2000 — живой стек с 14.11
  на homelab. Quadlet-файлы переименованы в `*.disabled-20261118`,
  daemon-reload, reset-failed. Итог: 0 failed user-сервисов, минус
  источник шума «всплески контейнеров».

## Найденное по ходу (разгаданные тайны)

- **Ночные входы 03:18 с wazuh-homelab на redos-server** — старый бэкап
  monitoring-стека; `backup-monitoring.sh` перенесён на homelab 16.11,
  после чего входы прекратились. Тайна закрыта без действий.
- **redosrp16**: firewalld rich rule явно REJECT ssh с 192.168.1.137 —
  осознанное правило, оставлено.

## MacBook ↔ MacBook через WireGuard

Симптом: оба ноута в VPN, но не достучаться друг до друга.
Причина: в клиентских конфигах WireGuard `AllowedIPs = 192.168.1.0/24` —
маршрута до пир-сети `172.16.6.0/24` нет. Hairpin на Keenetic не запрещён.
Headless-правка невозможна: туннели в Keychain с ACL на приложение
WireGuard (`errSecInteractionNotAllowed` через SSH).

Фикс (1 минута на ноуте, вручную): WireGuard app → туннель → Edit →
`AllowedIPs: 192.168.1.0/24, 172.16.6.0/24` → Save. Исполнено владельцем,
прямой ssh 172.16.6.2 ↔ 172.16.6.4 работает в обе стороны. Ping не ходит —
macOS firewall в stealth-режиме режет ICMP, это норма.

Запасной вариант на время до правки: алиасы в `~/.ssh/config` через
`ProxyJump igor@192.168.1.3` (Mac mini как джамп-хост) — проверено,
после прямого фикса убрано.

## Контрольные точки

- 19.11 03:17 — первый ночной бэкап homelab → redos-server через
  forced command (`scp -O`).
- Утренняя сверка алертов 19.11: фон не должен вырасти, новых
  «Accepted password» быть не может в принципе.
