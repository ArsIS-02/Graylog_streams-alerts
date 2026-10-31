# Соответствие определений событий и техник ATT&CK v20.0

Черновик на проверку. Первая техника в ячейке — основная (по ней будет считаться дашборд). Уверенность: **высокая** — прямое соответствие; **средняя** — подходит, но можно уточнить; **низкая** — приблизительно, нужен ваш взгляд.

| № | Определение | Техники | Тактика основной | Уверенность | Пометка |
|---|---|---|---|---|---|
| 1 | FREEIPA - Выпуск сертификата в CA (Dogtag) | `T1649` Steal or Forge Authentication Certificates | Credential Access | средняя | выпуск сертификата в центре сертификации |
| 2 | FREEIPA - Подбор пароля (10+ PREAUTH_FAILED за 5 мин) | `T1110.001` Password Guessing | Credential Access | высокая |  |
| 3 | HEALTH - Клиенты не могут связаться с KDC | — | — | высокая | операционное событие |
| 4 | KEENETIC - Вход в админку роутера (SSH) | `T1021.004` SSH | Lateral Movement | средняя |  |
| 5 | KEENETIC - Новое устройство в сети | `T1200` Hardware Additions | Initial Access | средняя |  |
| 6 | KEENETIC - Отказы WireGuard (ежедневная сводка) | `T1133` External Remote Services | Persistence, Initial Access | низкая | отказы VPN: возможен подбор |
| 7 | LNX - Брутфорс SSH (5+ неудачных входов за 5 мин) | `T1110` Brute Force | Credential Access | высокая |  |
| 8 | LNX - Добавление SSH-ключа в authorized_keys | `T1098.004` SSH Authorized Keys | Persistence, Privilege Escalation | высокая |  |
| 9 | LNX - Добавление/удаление пользователя | `T1136.001` Local Account | Persistence | высокая | удаление — T1531 |
| 10 | LNX - Закрепление через systemctl enable | `T1543.002` Systemd Service | Persistence, Privilege Escalation | высокая |  |
| 11 | LNX - Затирание следов (shred, history, truncate логов) | `T1070` Indicator Removal<br>`T1070.003` Clear Command History<br>`T1685.006` Clear Linux or Mac System Logs | Stealth | высокая |  |
| 12 | LNX - Изменение /etc/passwd, shadow, group | `T1098` Account Manipulation | Persistence, Privilege Escalation | средняя |  |
| 13 | LNX - Изменение sshd_config | `T1556` Modify Authentication Process | Defense Impairment, Persistence, Credential Access | низкая | изменение настроек входа |
| 14 | LNX - Изменение прав доступа (chmod) | `T1222.002` Linux and Mac Permissions | Defense Impairment | высокая |  |
| 15 | LNX - Изменение правил firewall (iptables, nft) | `T1686` Disable or Modify System Firewall | Defense Impairment | высокая |  |
| 16 | LNX - Исполнение из памяти (memfd_create) | `T1620` Reflective Code Loading | Stealth | средняя |  |
| 17 | LNX - Использование sudo | `T1548.003` Sudo and Sudo Caching | Privilege Escalation | средняя |  |
| 18 | LNX - Неудачная попытка sudo | `T1548.003` Sudo and Sudo Caching | Privilege Escalation | низкая |  |
| 19 | LNX - Обратная оболочка (/dev/tcp) | `T1059.004` Unix Shell | Execution | высокая |  |
| 20 | LNX - Остановка службы (systemctl stop) | `T1489` Service Stop | Impact | высокая |  |
| 21 | LNX - Отказ SELinux (AVC) | — | — | высокая | срабатывание защиты, не техника |
| 22 | LNX - Отключение аудита или удаление правил auditd | `T1685.004` Disable or Modify Linux Audit System Log | Defense Impairment | высокая |  |
| 23 | LNX - Подозрительные утилиты (base64, nc, socat, scp) | `T1105` Ingress Tool Transfer<br>`T1140` Deobfuscate/Decode Files or Information | Command and Control | средняя |  |
| 24 | LNX - Разведка (id, whoami) | `T1033` System Owner/User Discovery | Discovery | высокая |  |
| 25 | System notification events | — | — | высокая | служебное событие Graylog |
| 26 | Windows - Defender обнаружил угрозу или отключён | `T1685` Disable or Modify Tools | Defense Impairment | средняя | обнаружение угрозы само по себе — не техника |
| 27 | Windows - LOLBins (certutil, mshta, bitsadmin, regsvr32) | `T1218` System Binary Proxy Execution<br>`T1218.005` Mshta<br>`T1218.010` Regsvr32<br>`T1105` Ingress Tool Transfer | Stealth | высокая |  |
| 28 | Windows - PowerShell с закодированной командой | `T1059.001` PowerShell<br>`T1027.010` Command Obfuscation | Execution | высокая |  |
| 29 | Windows - PowerShell скачивает и исполняет код | `T1059.001` PowerShell<br>`T1105` Ingress Tool Transfer | Execution | высокая |  |
| 30 | Windows - Автозагрузка через ключ реестра Run | `T1547.001` Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | высокая |  |
| 31 | Windows - Вход по RDP | `T1021.001` Remote Desktop Protocol | Lateral Movement | высокая |  |
| 32 | Windows - Доступ к памяти LSASS | `T1003.001` LSASS Memory | Credential Access | высокая |  |
| 33 | Windows - Изменение группы «Администраторы домена» | `T1098` Account Manipulation | Persistence, Privilege Escalation | средняя |  |
| 34 | Windows - Изменение привилегированных групп и учёток | `T1098` Account Manipulation | Persistence, Privilege Escalation | средняя |  |
| 35 | Windows - Новая служба | `T1543.003` Windows Service | Persistence, Privilege Escalation | высокая |  |
| 36 | Windows - Отключение Firewall (netsh или PS) | `T1686.003` Windows Host Firewall | Defense Impairment | высокая |  |
| 37 | Windows - Офисное приложение запустило оболочку | `T1204.002` Malicious File<br>`T1059` Command and Scripting Interpreter | Execution | средняя |  |
| 38 | Windows - Очистка журнала событий | `T1685.005` Clear Windows Event Logs | Defense Impairment | высокая |  |
| 39 | Windows - Подбор пароля (5+ ошибок входа 4625 за 5 мин) | `T1110` Brute Force | Credential Access | высокая |  |
| 40 | Windows - Серия разведки (5+ команд за 5 мин) | `T1082` System Information Discovery | Discovery | низкая | общая разведка, уточнить по командам |
| 41 | Windows - Создание задачи через schtasks | `T1053.005` Scheduled Task | Execution, Persistence, Privilege Escalation | высокая |  |
| 42 | Windows - Создание/удаление локального пользователя (net user) | `T1136.001` Local Account | Persistence | высокая |  |
| 43 | Windows - Удаление теневых копий | `T1490` Inhibit System Recovery | Impact | высокая |  |
| 44 | macOS - Bi.Zone: неизвестный SSH-ключ в authorized_keys | `T1098.004` SSH Authorized Keys | Persistence, Privilege Escalation | высокая |  |
| 45 | macOS - Bi.Zone: неудачные входы по SSH | `T1110` Brute Force | Credential Access | высокая |  |
| 46 | macOS - Bi.Zone: новое правило в sudoers | `T1548.003` Sudo and Sudo Caching | Privilege Escalation | средняя |  |
| 47 | macOS - Bi.Zone: новый пользователь | `T1136.001` Local Account | Persistence | высокая |  |
| 48 | macOS - Bi.Zone: новый элемент автозагрузки | `T1543.004` Launch Daemon<br>`T1543.001` Launch Agent | Persistence, Privilege Escalation | средняя | LaunchDaemon / LaunchAgent |
| 49 | macOS - Bi.Zone: опасная команда в истории оболочки | `T1059.004` Unix Shell | Execution | низкая | в запросе разные команды (csrutil, spctl, base64) |
| 50 | macOS - Bi.Zone: подозрительная запись в hosts | `T1565.001` Stored Data Manipulation | Impact | низкая | точного соответствия нет |
| 51 | macOS - Bi.Zone: процесс из /tmp или /Users/Shared | `T1059` Command and Scripting Interpreter | Execution | низкая | запуск из временных каталогов |
| 52 | macOS - Bi.Zone: смена DNS-серверов | — | — | низкая | точного соответствия нет |
| 53 | macOS - Активность AirDrop | — | — | низкая | точного соответствия нет |
| 54 | macOS - Включение удалённого входа или Screen Sharing | `T1021.004` SSH<br>`T1021.005` VNC | Lateral Movement | средняя |  |
| 55 | macOS - Вмешательство в TCC | `T1548.006` TCC Manipulation | Privilege Escalation | высокая |  |
| 56 | macOS - Выгрузка паролей из Keychain | `T1555.001` Keychain | Credential Access | высокая |  |
| 57 | macOS - Выполнение команды через sudo | `T1548.003` Sudo and Sudo Caching | Privilege Escalation | средняя |  |
| 58 | macOS - Загрузка расширения ядра | `T1547.006` Kernel Modules and Extensions | Persistence, Privilege Escalation | высокая |  |
| 59 | macOS - Запуск программы из /tmp или /Users/Shared | `T1059` Command and Scripting Interpreter | Execution | низкая | запуск из временных каталогов |
| 60 | macOS - Изменение /etc/sudoers | `T1548.003` Sudo and Sudo Caching | Privilege Escalation | высокая |  |
| 61 | macOS - Неудачная попытка sudo (неверный пароль) | `T1548.003` Sudo and Sudo Caching | Privilege Escalation | низкая |  |
| 62 | macOS - Новый/изменённый plist в автозагрузке | `T1543.004` Launch Daemon<br>`T1543.001` Launch Agent | Persistence, Privilege Escalation | средняя |  |
| 63 | macOS - Обратная оболочка (/dev/tcp, pty.spawn) | `T1059.004` Unix Shell | Execution | высокая |  |
| 64 | macOS - Отключение SIP или Gatekeeper | `T1685` Disable or Modify Tools | Defense Impairment | высокая |  |
| 65 | macOS - Подключено Apple-устройство (iPhone/iPad/iPod) | `T1200` Hardware Additions | Initial Access | низкая | подключение устройства |
| 66 | macOS - Подключено мобильное устройство (не Apple) | `T1200` Hardware Additions | Initial Access | низкая | подключение устройства |
| 67 | macOS - Подключён USB-накопитель | `T1200` Hardware Additions<br>`T1052.001` Exfiltration over USB | Initial Access | низкая | подключение или вынос данных |
| 68 | macOS - Подозрительный процесс открыл TCP-порт | `T1571` Non-Standard Port | Command and Control | низкая |  |
| 69 | macOS - Снятие карантина с приложения | `T1553.001` Gatekeeper Bypass | Defense Impairment | высокая |  |
| 70 | macOS - Создание пользователя или изменение групп | `T1136.001` Local Account<br>`T1098` Account Manipulation | Persistence | средняя |  |
| 71 | macOS - Фишинговый запрос пароля через osascript | `T1056.002` GUI Input Capture | Collection, Credential Access | высокая |  |
| 72 | Контейнеры: Grafana — неудачный вход (подбор пароля) | `T1110` Brute Force | Credential Access | высокая |  |
| 73 | Контейнеры: Loki — ошибки приёма | — | — | высокая | операционное событие |
| 74 | Контейнеры: MongoDB — ошибки | — | — | высокая | операционное событие |
| 75 | Контейнеры: netalertx — всплеск объёма логов | — | — | высокая | операционное событие |
| 76 | Контейнеры: netalertx — новое устройство в сети | `T1200` Hardware Additions | Initial Access | средняя |  |
| 77 | Контейнеры: promtail не доставляет логи в Loki | — | — | высокая | операционное событие |
| 78 | Контейнеры: всплеск ошибок | — | — | высокая | операционное событие |
| 79 | Контейнеры: нехватка памяти или падение процесса | — | — | высокая | операционное событие |
| 80 | Контейнеры: ошибки прав доступа | — | — | высокая | операционное событие |
| 81 | Контейнеры: перезапуски MariaDB | — | — | высокая | операционное событие |
| 82 | Контейнеры: тишина — atrium | — | — | высокая | здоровье сбора |
| 83 | Контейнеры: тишина — grafana | — | — | высокая | здоровье сбора |
| 84 | Контейнеры: тишина — komodo_mongo_1 | — | — | высокая | здоровье сбора |
| 85 | Контейнеры: тишина — loki | — | — | высокая | здоровье сбора |
| 86 | Контейнеры: тишина — netalertx | — | — | высокая | здоровье сбора |
| 87 | Контейнеры: тишина — wazuh.dashboard | — | — | высокая | здоровье сбора |
| 88 | Контейнеры: тишина — zaslon | — | — | высокая | здоровье сбора |
| 89 | Контейнеры: тишина — нет логов ни от одного контейнера | — | — | высокая | здоровье сбора |
