# Каталог детектов Graylog

> Все правила (event definitions) лаборатории в одном месте: какой лог проверяется, по какому условию, как коррелируются события, к какой тактике и технике MITRE ATT&CK относятся. Всего **263** правил: активны **259**, отключены **4** (сохранены для истории). Из них **203** привязаны к технике ATT&CK v20 (118 разных техник). Остальные описывают здоровье сервисов и тишину в логах: атак они не ловят.

Встроенное определение `System notification events` (`system-notifications-v1`) в каталог не входит: это не пользовательское правило детектирования. Поэтому при 264 определениях в API здесь 263 пользовательских правила.

Страница собирается скриптом из выгрузки Graylog и руками не правится: [как обновить](#как-обновить-каталог). Запросы очищены: IP, MAC, отпечатки ключей и белые списки заменены на `<IP>`, `<MAC>`, `<белый список>`. Готовые определения для импорта лежат в `graylog/*-event-definitions.json`, соответствие техникам подробно описано в [graylog/mitre](../graylog/mitre/README.md).

## Содержание

- [Покрытие: тактики × платформы](#покрытие-тактики--платформы)
- [Windows](#windows) — 59
- [Linux](#linux) — 50
- [macOS (osquery и unified log)](#macos-osquery-и-unified-log) — 50
- [macOS (BI.ZONE Triage)](#macos-bizone-triage) — 9
- [Keenetic](#keenetic) — 9
- [FreeIPA и здоровье сервисов](#freeipa-и-здоровье-сервисов) — 27
- [Контейнеры](#контейнеры) — 18
- [Экосистема и служебные правила](#экосистема-и-служебные-правила) — 41
- [Как читать таблицы](#как-читать-таблицы)
- [Как обновить каталог](#как-обновить-каталог)

## Покрытие: тактики × платформы

Основная тактика правила — первая из записанных в событии (поле `mitre_tactic`). Пустая ячейка означает, что правил на эту тактику на платформе нет.

| Тактика | Windows | Linux | macOS | Keenetic | FreeIPA | Контейнеры | Экосистема | Всего |
|---|---|---|---|---|---|---|---|---|
| Reconnaissance (Разведка) |  |  |  | 1 |  |  |  | **1** |
| Initial Access (Первоначальный доступ) | 2 | 3 | 3 | 1 | 2 | 1 | 2 | **14** |
| Execution (Выполнение) | 6 | 4 | 7 |  |  |  | 1 | **18** |
| Persistence (Закрепление) | 14 | 9 | 12 | 1 | 3 |  | 2 | **41** |
| Privilege Escalation (Повышение привилегий) | 2 | 7 | 6 |  | 2 |  |  | **17** |
| Defense Evasion (Обход защиты) | 1 |  |  |  |  |  | 1 | **2** |
| Stealth (Скрытность) | 4 | 4 | 4 |  |  |  |  | **12** |
| Defense Impairment (Подавление защиты) | 6 | 6 | 6 | 1 | 1 |  | 3 | **23** |
| Credential Access (Доступ к учётным данным) | 11 | 4 | 8 | 3 | 5 | 1 | 3 | **35** |
| Discovery (Исследование среды) | 2 | 2 | 1 |  | 1 |  |  | **6** |
| Lateral Movement (Перемещение) | 3 | 1 | 2 | 1 |  |  |  | **7** |
| Collection (Сбор данных) | 1 | 1 | 2 |  |  |  |  | **4** |
| Command and Control (управление, C2) | 3 | 3 | 2 |  |  |  | 3 | **11** |
| Exfiltration (Вывод данных) | 1 | 2 | 2 |  |  |  |  | **5** |
| Impact (Воздействие) | 2 | 3 | 2 |  |  |  |  | **7** |
| Без техники (служебные) | 1 | 1 | 2 | 1 | 13 | 16 | 26 | **60** |
| **Всего** | **59** | **50** | **59** | **9** | **27** | **18** | **41** | **263** |

## Windows

Sysmon, Security, PowerShell, Defender; поток WindowsLogs. Правил: 59. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| DCSync: репликация каталога не от контроллера домена (4662) | высокий | WindowsLogs<br>канал Security, EventID 4662 | Чтение прав репликации каталога учётной записью, которая не является компьютером. Так атака DCSync забирает хэши всех паролей. Работает только при включённой SACL на корне домена. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1003.006` DCSync |
| Defender обнаружил угрозу или отключён | высокий | WindowsLogs<br>канал Microsoft-Windows-Windows Defender/Operational, EventID 1116, 1117, 5001, 5010, 5012 | Defender обнаружил или обезвредил угрозу (1116, 1117) либо защита в реальном времени отключена (5001, 5010, 5012). | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Kerberoasting: билет службы с шифрованием RC4 (4769) | высокий | WindowsLogs<br>канал Security, EventID 4769 | Запрошен билет службы с шифрованием RC4 (0x17) к учётной записи службы, не к компьютеру. Так выглядит Kerberoasting: атакующий забирает билеты, чтобы подобрать пароль службы офлайн.… | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1558.003` Kerberoasting |
| Office, wscript или mshta создал исполняемый файл | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 11 | Sysmon 11: Office, wscript, cscript или mshta записал exe, dll, scr, hta, js, vbs, ps1 или bat в Temp, AppData, Public, ProgramData, Downloads, PerfLogs. powershell не включён: он… | каждое событие | Execution | `T1204.002` Malicious File<br>`T1105` |
| PowerShell с закодированной командой | высокий | WindowsLogs<br>EventID 1 | PowerShell запущен с -EncodedCommand или декодирует Base64. Так прячут вредоносные скрипты. | каждое событие | Execution | `T1059.001` PowerShell<br>`T1027.010` |
| PowerShell скачивает и исполняет код | высокий | WindowsLogs<br>EventID 4104 | Script Block Logging (4104): DownloadString, Net.WebClient, Invoke-WebRequest или IEX. Типичный загрузчик. | каждое событие | Execution | `T1059.001` PowerShell<br>`T1105` |
| PsExec и аналоги (процесс, служба, канал) | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, канал System, EventID 1, EventID 7045 | Признаки удалённого выполнения: запуск PsExec, PAExec, RemCom, winexesvc или wsmprovhost, установка службы PSEXESVC и именованные каналы этих утилит. | каждое событие; повтор не чаще раза в 1 ч | Lateral Movement | `T1021.002` SMB/Windows Admin Shares<br>`T1569.002` |
| wscript, cscript, mshta или regsvr32 ходит во внешнюю сеть | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 3 | Sysmon 3: исходящее соединение на внешний IP от wscript, cscript, mshta или regsvr32. Эти программы почти не ходят в сеть сами, поэтому соединение похоже на загрузчик или канал… | каждое событие | Stealth | `T1218` System Binary Proxy Execution<br>`T1071.001` |
| Вход из неизвестной сети (4624, тип 3 или 10) | высокий | WindowsLogs<br>канал Security, EventID 4624 | Сетевой вход (тип 3) или RDP (тип 10) с адреса, которого нет в справочнике homelab-subnets (поле src_zone не заполнено). Требует pipeline «homelab: windows enrichment» и обновлённую… | каждое событие | Initial Access | `T1078` Valid Accounts<br>`T1021` |
| Дамп учётных данных (reg save, comsvcs, ntdsutil) | высокий | WindowsLogs<br>EventID 1 | Выгрузка кустов SAM/SECURITY/SYSTEM через reg save, дамп памяти через comsvcs.dll MiniDump или копирование NTDS через ntdsutil. | каждое событие | Credential Access | `T1003.002` Security Account Manager<br>`T1003.001`, `T1003.003` |
| Добавление в группу администраторов (4728, 4732, 4756) | высокий | WindowsLogs<br>канал Security, EventID 4728, 4732, 4756 | В привилегированную группу (администраторы, администраторы домена, предприятия, схемы) добавлен участник. | каждое событие; повтор не чаще раза в 1 ч | Privilege Escalation | `T1098` Account Manipulation<br>`T1078.002` |
| Добавление в локальные администраторы (командная строка) | высокий | WindowsLogs<br>EventID 1 | net localgroup administrators /add или Add-LocalGroupMember. Дополняет алерт по событиям 4728/4732 для случаев, когда аудит групп отключён. | каждое событие | Persistence | `T1098` Account Manipulation |
| Доступ к памяти LSASS | высокий | WindowsLogs<br>EventID 10 | Процесс открыл память lsass.exe (Sysmon 10). Типичный признак кражи учётных данных (mimikatz, procdump). | каждое событие | Credential Access | `T1003.001` LSASS Memory |
| Изменение группы «Администраторы домена» | высокий | WindowsLogs | Добавление или удаление учётной записи в группе «Администраторы домена» (net group). Критично: высшие привилегии в домене. | каждое событие | Persistence | `T1098` Account Manipulation |
| Изменение объектов AD: GPO и AdminSDHolder (5136) | высокий | WindowsLogs<br>канал Security, EventID 5136 | Изменён объект групповой политики или AdminSDHolder. Через них закрепляются и раздают права по всему домену. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1484.001` Group Policy Modification<br>`T1098` |
| Изменение политики аудита (4719) | высокий | WindowsLogs<br>канал Security, EventID 4719 | Изменена политика аудита системы. Атакующий отключает аудит, чтобы не оставлять следов. | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Изменение привилегированных групп и учёток | высокий | WindowsLogs<br>EventID 4720, 4726, 4728, 4732, 4756, 4740, 4724 | Создание/удаление учётки (4720, 4726), сброс пароля (4724), добавление в привилегированную группу (4728, 4732, 4756) или блокировка (4740). Требует включённого аудита управления учётными… | каждое событие | Persistence | `T1098` Account Manipulation |
| Именованные каналы C2 (Cobalt Strike и аналоги) | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 17, 18 | Sysmon 17/18: имена каналов, характерные для Cobalt Strike (msagent_*, postex_*, status_*, MSSE-*-server). Каналы нужны для связи бекона и инъекций. | каждое событие | Stealth | `T1055` Process Injection |
| Исключения или отключение защиты Defender | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1, EventID 13 | Команда Add-/Set-MpPreference с исключениями или отключением мониторинга, либо запись в ключ Windows Defender\Exclusions (Sysmon 13). | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Командная оболочка запущена через WMI | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Sysmon 1: WmiPrvSE.exe породил cmd, powershell, wscript, cscript, mshta или rundll32. Так работает удалённое выполнение через WMI (wmic /node, Impacket wmiexec). | каждое событие | Execution | `T1047` Windows Management Instrumentation |
| Обход UAC через реестр (fodhelper, eventvwr, ms-settings) | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 13 | Запись в ветки реестра, через которые обходят UAC и получают высокие права без запроса (ms-settings, mscfile, exefile, подмена windir и SystemRoot). Sysmon 13. | каждое событие; повтор не чаще раза в 1 ч | Privilege Escalation | `T1548.002` Bypass User Account Control |
| Отключение Firewall (netsh или PS) | высокий | WindowsLogs<br>EventID 1 | Запуск "netsh advfirewall ... disable" или PowerShell "Disable-NetFirewall...". Атакующий отключает брандмауэр, чтобы открыть сетевые соединения. | каждое событие | Defense Impairment | `T1686.003` Windows Host Firewall |
| Офисное приложение запустило оболочку | высокий | WindowsLogs<br>EventID 1 | Word/Excel/Outlook/PowerPoint запустили cmd, powershell, wscript, cscript или mshta. Характерно для вредоносных макросов. | каждое событие | Execution | `T1204.002` Malicious File<br>`T1059` |
| Очистка журнала событий | высокий | WindowsLogs<br>EventID 1102, 104 | Журнал Security (1102) или System (104) очищен. Почти всегда признак заметания следов. | каждое событие | Defense Impairment | `T1685.005` Clear Windows Event Logs |
| Подбор пароля (5+ ошибок входа 4625 за 5 мин) | высокий | WindowsLogs<br>EventID 4625 | 5 и более неудачных входов (Event ID 4625) на одном хосте за 5 минут. Возможен брутфорс, в том числе учётной записи администратора. | число событий ≥ 5 за 5 мин, группировка по source | Credential Access | `T1110` Brute Force |
| Подбор пароля и успешный вход с одного IP (4625 и 4624) | высокий | WindowsLogs<br>EventID 4624, 4625 | С одного адреса за 15 минут 5 и более сетевых или RDP-входов, среди которых есть и неудачные (4625), и успешные (4624). Так выглядит подбор пароля, закончившийся успехом. | число событий && None за 15 мин, группировка по IpAddress | Credential Access | `T1110` Brute Force<br>`T1078` |
| Подбор пароля на DC по Kerberos (10+ ошибок 4771 за 5 мин) | высокий | WindowsLogs<br>канал Security, EventID 4771 | Десять и более ошибок предварительной проверки Kerberos (4771) с одного адреса за 5 минут. Подбор пароля к доменным учётным записям. | число событий ≥ 10 за 5 мин, группировка по IpAddress | Credential Access | `T1110.001` Password Guessing<br>`T1110.003` |
| Подбор пароля на DC по NTLM (10+ ошибок 4776 за 5 мин) | высокий | WindowsLogs<br>канал Security, EventID 4776 | Десять и более неудачных проверок NTLM (4776) с одного рабочего места за 5 минут. Подбор пароля или забытый пароль в службе. | число событий ≥ 10 за 5 мин, группировка по Workstation | Credential Access | `T1110.001` Password Guessing<br>`T1110.003` |
| Постоянная подписка WMI (5861) | высокий | WindowsLogs<br>канал Microsoft-Windows-WMI-Activity/Operational, EventID 5861 | Создана постоянная подписка на события WMI. Этим способом закрепляются без файлов. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1546.003` Windows Management Instrumentation Event Subscription |
| Признаки шифровальщика (расширения и записки) | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 11 | Создан файл с расширением известного шифровальщика (locked, lockbit, akira, conti и другие) или файл-записка с требованием выкупа. | каждое событие; повтор не чаще раза в 1 ч | Impact | `T1486` Data Encrypted for Impact |
| Создание, удаление или изменение доверия домена (4706/4707/4716) | высокий | WindowsLogs<br>канал Security, EventID 4706, 4707, 4716 | Создано, удалено или изменено доверительное отношение между доменами. Тип и направление доверия, а также отключение фильтрации SID видно в тексте события. Плановые изменения (например,… | каждое событие; повтор не чаще раза в 1 ч | Defense Evasion, Privilege Escalation | `T1484.002` Domain Trust Modification |
| Создание/удаление локального пользователя (net user) | высокий | WindowsLogs<br>EventID 1 | Создан или удалён локальный пользователь командой net user /add или /delete (Sysmon Event 1). | каждое событие | Persistence | `T1136.001` Local Account |
| Удаление теневых копий | высокий | WindowsLogs<br>EventID 1 | Удаление теневых копий или отключение восстановления (vssadmin, wmic shadowcopy, bcdedit). Типичный шаг шифровальщика. | каждое событие | Impact | `T1490` Inhibit System Recovery |
| DNS-запрос к туннелям и файлообменникам | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 22 | Sysmon 22: запрос к ngrok, pastebin, transfer.sh, trycloudflare, duckdns, anonfiles, serveo. Через них обходят периметр и забирают данные. | каждое событие | Command and Control | `T1572` Protocol Tunneling<br>`T1102` |
| LOLBins (certutil, mshta, bitsadmin, regsvr32) | средний | WindowsLogs<br>EventID 1 | Системные утилиты в роли загрузчика: certutil -urlcache, mshta, bitsadmin, regsvr32 /i:http (Squiblydoo). | каждое событие | Stealth | `T1218` System Binary Proxy Execution<br>`T1218.005`, `T1218.010`, `T1105` |
| Автозагрузка через ключ реестра Run | средний | WindowsLogs<br>EventID 13 | Запись в ключ CurrentVersion\Run (Sysmon 13) не известным приложением. Классический способ закрепления. | каждое событие | Persistence | `T1547.001` Registry Run Keys / Startup Folder |
| Блокировка учётной записи (4740) | средний | WindowsLogs<br>канал Security, EventID 4740 | Учётная запись заблокирована после череды ошибок входа. Возможен подбор пароля. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1110` Brute Force |
| Вход по сети или RDP ночью (00:00-06:00) | средний | WindowsLogs<br>EventID 4624 | Успешный сетевой вход или вход по RDP под обычной (не машинной) учёткой ночью, с 00:00 до 06:00 по Екатеринбургу. Правило проверяется только в ночные часы. | каждое событие; повтор не чаще раза в 1 ч | Initial Access | `T1078` Valid Accounts<br>`T1021.001` |
| Задание планировщика с Temp, AppData или Public (4698) | средний | WindowsLogs<br>канал Security, EventID 4698 | Создано задание планировщика, в котором упомянуты временные или пользовательские папки. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1053.005` Scheduled Task |
| Закрепление через IFEO Debugger, AppInit_DLLs и Winlogon | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 12, 13 | Sysmon 12/13: значения Debugger, GlobalFlag и VerifierDlls в Image File Execution Options, AppInit_DLLs, Winlogon Shell и Userinit. RunOnce и MitigationOptions не включены: их постоянно… | каждое событие | Persistence | `T1546.012` Image File Execution Options Injection<br>`T1546.010`, `T1547.004` |
| Запуск утилит удалённого доступа и туннелей | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Запущена утилита удалённого доступа или туннелирования (ngrok, cloudflared, AnyDesk, TeamViewer, RustDesk, chisel, tailscale, plink и аналоги). За 30 дней в логах не встречалась. | каждое событие; повтор не чаще раза в 1 ч | Command and Control | `T1219` Remote Access Tools<br>`T1572` |
| Маскировка под системный процесс (svchost, lsass, csrss вне System32) | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Процесс с именем системного (svchost, lsass, csrss и другие) запущен не из System32, SysWOW64 или WinSxS. Так прячут вредоносный файл. За 30 дней более 330 тысяч запусков таких имён, все… | каждое событие; повтор не чаще раза в 1 ч | Stealth | `T1036.005` Match Legitimate Resource Name or Location |
| Новая служба | средний | WindowsLogs<br>EventID 7045, 4697 | Установлена новая служба (7045, 4697), кроме драйверов Kaspersky. Частый способ закрепления. | каждое событие | Persistence | `T1543.003` Windows Service |
| Остановка Sysmon, winlogbeat, Defender или журнала событий | средний | WindowsLogs<br>канал System, EventID 7036 | Остановлена служба, от которой зависят защита или сбор логов: Sysmon, winlogbeat, Defender, брандмауэр или журнал событий. Атакующий отключает агентов, чтобы действовать незаметно.… | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Перебор несуществующих пользователей (5+ за 10 мин) | средний | WindowsLogs<br>EventID 4625 | 5 и более неудачных входов с одного IP за 10 минут с причиной «пользователь не существует» (SubStatus 0xc0000064): перебор имён учёток. | число событий ≥ 5 за 10 мин, группировка по IpAddress | Credential Access | `T1110` Brute Force<br>`T1087` |
| Подозрительно длинные DNS-имена (туннель, DGA) | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 22 | DNS-запрос с меткой длиннее 40 символов или всё имя длиннее 70. Так выглядят DNS-туннели и сгенерированные домены. Служебные записи AD (_ldap, _kerberos, _msdcs) и крупные CDN исключены. | каждое событие; повтор не чаще раза в 1 ч | Command and Control | `T1071.004` DNS<br>`T1568.002` |
| Поиск паролей в файлах (findstr, Select-String) | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Рекурсивный поиск слов password, secret, credential, id_rsa и подобных по файлам (findstr /s, Select-String -Recurse). Проверки политики паролей через secedit исключены. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1552.001` Credentials In Files |
| Разведка в домене (nltest, dsquery, AdFind, SharpHound) | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Запущены утилиты разведки в Active Directory (nltest, dsquery, AdFind, SharpHound, ldifde, csvde) или команды Get-AD* и nltest /dclist, /domain_trusts. | каждое событие; повтор не чаще раза в 1 ч | Discovery | `T1087.002` Domain Account<br>`T1018`, `T1482` |
| Сброс пароля учётной записи (4724) | средний | WindowsLogs<br>канал Security, EventID 4724 | Кто-то сбросил пароль другой учётной записи. Плановые сбросы тоже сработают. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1098` Account Manipulation |
| Создана компьютерная учётная запись пользователем (4741) | средний | WindowsLogs<br>канал Security, EventID 4741 | Компьютерную учётную запись создал пользователь, а не компьютер. Может быть присоединением к домену, а может быть атакой через MachineAccountQuota. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1136.002` Domain Account |
| Создана учётная запись (4720) | средний | WindowsLogs<br>канал Security, EventID 4720 | Создана новая учётная запись пользователя. Нужно для закрепления. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1136` Create Account<br>`T1136.001`, `T1136.002` |
| Создание задачи через schtasks | средний | WindowsLogs<br>EventID 1 | Запланированная задача создана командой schtasks /create. Частый способ закрепления и запуска. | каждое событие | Execution | `T1053.005` Scheduled Task |
| Удалённый вход по WinRM (91) | средний | WindowsLogs<br>канал Microsoft-Windows-WinRM/Operational, EventID 91 | Создана сессия WinRM (удалённое управление PowerShell). | каждое событие; повтор не чаще раза в 1 ч | Lateral Movement | `T1021.006` Windows Remote Management |
| Установка службы вне System32 и Program Files (4697) | средний | WindowsLogs<br>канал Security, EventID 4697 | Установлена служба, файл которой лежит не в System32 и не в Program Files. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1543.003` Windows Service<br>`T1569.002` |
| Утилиты выгрузки в облако (rclone, MEGAsync, WinSCP) | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Запущена утилита синхронизации или выгрузки файлов в облако (rclone, MEGAsync, MEGAcmd, WinSCP, pCloud). Так выводят данные наружу. | каждое событие; повтор не чаще раза в 1 ч | Exfiltration | `T1567.002` Exfiltration to Cloud Storage<br>`T1048` |
| Defender: сигнатуры не обновлялись 7 дней | низкий | WindowsLogs<br>канал Microsoft-Windows-Windows Defender/Operational, EventID 2000 | За 7 дней ни один Windows-хост не прислал событие об обновлении сигнатур Defender (2000). Защита работает с устаревшей базой или хосты не в сети. | число событий < 1 за 7 сут; повтор не чаще раза в 1 сут | — | — |
| Архивация не из проводника (7z, WinRAR, Compress-Archive) | низкий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Запуск архиватора (7-Zip, WinRAR, zip) не из проводника, либо Compress-Archive и tar -c. Установщики во временных папках и ручной запуск из проводника исключены. | каждое событие; повтор не чаще раза в 1 ч | Collection | `T1560.001` Archive via Utility |
| Вход по RDP | низкий | WindowsLogs<br>EventID 4624 | Успешный интерактивный вход по RDP (4624, LogonType 10). | каждое событие | Lateral Movement | `T1021.001` Remote Desktop Protocol |
| Серия разведки (5+ команд за 5 мин) | низкий | WindowsLogs<br>EventID 1 | 5 и более запусков net, whoami, nltest, systeminfo, quser, arp на одном хосте за 5 минут — типичная разведка после проникновения. | число событий ≥ 5 за 5 мин, группировка по source | Discovery | `T1082` System Information Discovery |

<details><summary>Запросы Graylog (очищенные)</summary>

**Windows - DCSync: репликация каталога не от контроллера домена (4662)**

```
win_channel:Security AND win_event_id:4662 AND winlogbeat_winlog_event_data_Properties:/.*(1131[fF]6[aA][aA]-9[cC]07-11[dD]1-[fF]79[fF]-00[cC]04[fF][cC]2[dD][cC][dD]2|1131[fF]6[aA][dD]-9[cC]07-11[dD]1-[fF]79[fF]-00[cC]04[fF][cC]2[dD][cC][dD]2|89[eE]95[bB]76-444[dD]-4[cC]62-991[aA]-0[fF][aA][cC][bB][eE][dD][aA]640[cC]).*/ AND NOT winlogbeat_winlog_event_data_SubjectUserName:/.*[$]/
```

**Windows - Defender обнаружил угрозу или отключён**

```
win_channel:"Microsoft-Windows-Windows Defender/Operational" AND win_event_id:(1116 OR 1117 OR 5001 OR 5010 OR 5012)
```

**Windows - Kerberoasting: билет службы с шифрованием RC4 (4769)**

```
win_channel:Security AND win_event_id:4769 AND winlogbeat_winlog_event_data_TicketEncryptionType:"0x17" AND NOT winlogbeat_winlog_event_data_ServiceName:"krbtgt" AND NOT winlogbeat_winlog_event_data_ServiceName:/.*[$]/
```

**Windows - Office, wscript или mshta создал исполняемый файл**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:11 AND win_image:/.*\\(winword|excel|powerpnt|outlook|wscript|cscript|mshta)\.exe/ AND win_filename:/.*\\(Temp|AppData|Users\\Public|ProgramData|Downloads|PerfLogs)\\.*\.(exe|dll|scr|hta|js|jse|vbs|ps1|bat)/
```

**Windows - PowerShell с закодированной командой**

```
win_event_id:1 AND win_image:("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" OR "C:\\Program Files\\PowerShell\\7\\pwsh.exe") AND message:("-enc" OR "-encodedcommand" OR "-ec" OR "frombase64string") AND NOT winlogbeat_winlog_event_data_ParentImage:"C:\\Program Files\\LogAtlas\\python\\pythonw.exe"
```

**Windows - PowerShell скачивает и исполняет код**

```
win_event_id:4104 AND message:("DownloadString" OR "DownloadFile" OR "Invoke-Expression" OR "IEX" OR "Net.WebClient" OR "Invoke-WebRequest")
```

**Windows - PsExec и аналоги (процесс, служба, канал)**

```
(win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND winlogbeat_winlog_event_data_Image:/.*([pP][sS][eE][xX][eE][cC]|[pP][sS][eE][xX][eE][sS][vV][cC]|[pP][aA][eE][xX][eE][cC]|[wW][iI][nN][eE][xX][eE][sS][vV][cC]|[rR][eE][mM][cC][oO][mM]|[wW][sS][mM][pP][rR][oO][vV][hH][oO][sS][tT]).*/) OR (win_channel:System AND win_event_id:7045 AND message:(PSEXESVC OR PAExec OR RemCom OR winexesvc)) OR (win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:(17 OR 18) AND winlogbeat_winlog_event_data_PipeName:/.*([pP][sS][eE][xX][eE][sS][vV][cC]|[pP][aA][eE][xX][eE][cC]|[rR][eE][mM][cC][oO][mM]).*/)
```

**Windows - wscript, cscript, mshta или regsvr32 ходит во внешнюю сеть**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:3 AND win_image:/.*\\(wscript|cscript|mshta|regsvr32)\.exe/ AND winlogbeat_winlog_event_data_Initiated:true AND _exists_:winlogbeat_winlog_event_data_DestinationIp AND NOT winlogbeat_winlog_event_data_DestinationIp:(10.* OR 192.168.* OR 127.* OR 169.254.* OR fe80* OR "::1" OR fc* OR fd* OR /172\.(1[6-9]|2[0-9]|3[01])\..*/)
```

**Windows - Вход из неизвестной сети (4624, тип 3 или 10)**

```
win_channel:Security AND win_event_id:4624 AND winlogbeat_winlog_event_data_LogonType:(3 OR 10) AND _exists_:win_ip AND NOT win_ip:(<белый список>) AND NOT _exists_:src_zone
```

**Windows - Дамп учётных данных (reg save, comsvcs, ntdsutil)**

```
win_event_id:1 AND (message:("reg save hklm sam" OR "reg save hklm security" OR "reg save hklm system" OR "reg.exe save hklm sam" OR "reg.exe save hklm security" OR "reg.exe save hklm system" OR "reg save hkey_local_machine sam" OR "reg save hkey_local_machine security" OR "reg save hkey_local_machine system") OR (message:"comsvcs.dll" AND message:minidump) OR (message:"ntdsutil.exe" AND message:(ifm OR ntds)))
```

**Windows - Добавление в группу администраторов (4728, 4732, 4756)**

```
win_channel:Security AND win_event_id:(4728 OR 4732 OR 4756) AND win_target_user_name:(Администраторы OR "Администраторы домена" OR "Администраторы предприятия" OR "Администраторы схемы" OR Administrators OR "Domain Admins" OR "Enterprise Admins" OR "Schema Admins")
```

**Windows - Добавление в локальные администраторы (командная строка)**

```
win_event_id:1 AND ((message:localgroup AND message:(administrators OR администраторы) AND message:add) OR (message:"Add-LocalGroupMember" AND message:(administrators OR администраторы)))
```

**Windows - Доступ к памяти LSASS**

```
win_event_id:10 AND message:"lsass.exe" AND NOT winlogbeat_winlog_event_data_SourceImage:("C:\\WINDOWS\\system32\\svchost.exe" OR "C:\\Windows\\InfraxAgent.exe" OR "C:\\WINDOWS\\system32\\wbem\\wmiprvse.exe" OR "C:\\WINDOWS\\system32\\tasklist.exe" OR "C:\\Program Files\\Zabbix Agent\\zabbix_agentd.exe" OR "C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe" OR "C:\\Program Files\\CCleaner\\CCleaner64.exe" OR "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe") AND NOT message:"Kaspersky Lab" AND NOT message:(<белый список>) AND NOT winlogbeat_winlog_event_data_GrantedAccess:(0x1000 OR 0x1400 OR 0x100000 OR 0x101000)
```

**Windows - Изменение группы «Администраторы домена»**

```
message:"net group" AND message:("/add" OR "/delete") AND message:"Администраторы домена"
```

**Windows - Изменение объектов AD: GPO и AdminSDHolder (5136)**

```
win_channel:Security AND win_event_id:5136 AND (winlogbeat_winlog_event_data_ObjectClass:groupPolicyContainer OR winlogbeat_winlog_event_data_ObjectDN:/.*[aA][dD][mM][iI][nN][sS][dD][hH][oO][lL][dD][eE][rR].*/)
```

**Windows - Изменение политики аудита (4719)**

```
win_channel:Security AND win_event_id:4719
```

**Windows - Изменение привилегированных групп и учёток**

```
win_event_id:(4720 OR 4726 OR 4728 OR 4732 OR 4756 OR 4740 OR 4724)
```

**Windows - Именованные каналы C2 (Cobalt Strike и аналоги)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:(17 OR 18) AND winlogbeat_winlog_event_data_PipeName:/\\(msagent_|postex_|status_|MSSE-).*/
```

**Windows - Исключения или отключение защиты Defender**

```
(win_event_id:1 AND (message:"Add-MpPreference" OR message:"Set-MpPreference") AND message:(ExclusionPath OR ExclusionExtension OR ExclusionProcess OR DisableRealtimeMonitoring OR DisableIOAVProtection OR DisableBehaviorMonitoring)) OR (win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:13 AND winlogbeat_winlog_event_data_TargetObject:/.*Windows Defender\\Exclusions.*/ AND NOT win_image:/.*\\(MsMpEng|MsMpEngCP)\.exe/)
```

**Windows - Командная оболочка запущена через WMI**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND winlogbeat_winlog_event_data_ParentImage:/.*\\[Ww]mi[Pp]rv[Ss][Ee]\.exe/ AND win_image:/.*\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)\.exe/
```

**Windows - Обход UAC через реестр (fodhelper, eventvwr, ms-settings)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:13 AND (winlogbeat_winlog_event_data_TargetObject:/.*(ms-settings|mscfile|exefile|Folder).*[Ss]hell.*[Oo]pen.*[Cc]ommand.*/ OR winlogbeat_winlog_event_data_TargetObject:/.*[Ee]nvironment.*(windir|SystemRoot).*/)
```

**Windows - Отключение Firewall (netsh или PS)**

```
win_event_id:1 AND ((message:"netsh" AND message:"firewall" AND message:("disable" OR "off")) OR message:"Disable-NetFirewall")
```

**Windows - Офисное приложение запустило оболочку**

```
win_event_id:1 AND message:("WINWORD.EXE" OR "EXCEL.EXE" OR "OUTLOOK.EXE" OR "POWERPNT.EXE") AND win_image:("C:\\Windows\\System32\\cmd.exe" OR "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" OR "C:\\Windows\\System32\\wscript.exe" OR "C:\\Windows\\System32\\cscript.exe" OR "C:\\Windows\\System32\\mshta.exe")
```

**Windows - Очистка журнала событий**

```
win_event_id:(1102 OR 104)
```

**Windows - Подбор пароля (5+ ошибок входа 4625 за 5 мин)**

```
winlogbeat_event_code:4625 AND winlogbeat_event_outcome:failure
```

**Windows - Подбор пароля и успешный вход с одного IP (4625 и 4624)**

```
winlogbeat_event_code:(4624 OR 4625) AND winlogbeat_winlog_event_data_LogonType:(3 OR 10) AND _exists_:win_ip AND NOT win_ip:(<белый список>)
```

**Windows - Подбор пароля на DC по Kerberos (10+ ошибок 4771 за 5 мин)**

```
win_channel:Security AND win_event_id:4771
```

**Windows - Подбор пароля на DC по NTLM (10+ ошибок 4776 за 5 мин)**

```
win_channel:Security AND win_event_id:4776 AND NOT winlogbeat_winlog_event_data_Status:"0x0"
```

**Windows - Постоянная подписка WMI (5861)**

```
win_channel:"Microsoft-Windows-WMI-Activity/Operational" AND win_event_id:5861
```

**Windows - Признаки шифровальщика (расширения и записки)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:11 AND winlogbeat_winlog_event_data_TargetFilename:/.*([.](locked|encrypted|crypt|crypted|enc|lockbit|akira|conti|ryuk|wncry|wnry|blackcat|hive|royal|basta|babuk|djvu|zepto|cerber|petya|phobos|mallox|makop)|[\\]([hH][oO][wW]_[tT][oO]_[dD][eE][cC][rR][yY][pP][tT]|[dD][eE][cC][rR][yY][pP][tT]_[iI][nN][sS][tT][rR][uU][cC][tT][iI][oO][nN]|[rR][eE][sS][tT][oO][rR][eE]_[fF][iI][lL][eE][sS]|[rR][eE][aA][dD]_[mM][eE]_[nN][oO][wW]|_[rR][eE][aA][dD][mM][eE]|[hH][oO][wW]_[tT][oO]_[rR][eE][cC][oO][vV][eE][rR]|[rR][eE][cC][oO][vV][eE][rR]_[fF][iI][lL][eE][sS]|[rR][eE][aA][dD][mM][eE]_[tT][oO]_[rR][eE][sS][tT][oO][rR][eE]|@[pP][lL][eE][aA][sS][eE]_[rR][eE][aA][dD]_[mM][eE]@|@[wW][aA][nN][aA][dD][eE][cC][rR][yY][pP][tT][oO][rR]@)[^\\]*)/
```

**Windows - Создание, удаление или изменение доверия домена (4706/4707/4716)**

```
win_channel:Security AND win_event_id:(4706 OR 4707 OR 4716)
```

**Windows - Создание/удаление локального пользователя (net user)**

```
winlogbeat_winlog_event_id:1 AND message:"net user" AND (message:"/add" OR message:"/delete")
```

**Windows - Удаление теневых копий**

```
win_event_id:1 AND ((message:"vssadmin" AND message:"delete") OR (message:"shadowcopy" AND message:"delete") OR (message:"bcdedit" AND message:"recoveryenabled"))
```

**Windows - DNS-запрос к туннелям и файлообменникам**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:22 AND winlogbeat_winlog_event_data_QueryName:/.*(ngrok|pastebin|transfer\.sh|trycloudflare|duckdns|anonfiles|serveo).*/
```

**Windows - LOLBins (certutil, mshta, bitsadmin, regsvr32)**

```
win_event_id:1 AND message:("urlcache" OR "mshta.exe" OR "bitsadmin" OR "scrobj.dll" OR "/i:http")
```

**Windows - Автозагрузка через ключ реестра Run**

```
win_event_id:13 AND message:"CurrentVersion\\Run" AND NOT win_image:("C:\\Program Files\\Yandex\\YandexBrowser\\Application\\browser.exe" OR "C:\\Program Files\\CCleaner\\CCleaner64.exe" OR "C:\\ProgramData\\Wargaming.net\\GameCenter\\wgc.exe" OR "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe")
```

**Windows - Блокировка учётной записи (4740)**

```
win_channel:Security AND win_event_id:4740
```

**Windows - Вход по сети или RDP ночью (00:00-06:00)**

```
winlogbeat_event_code:4624 AND winlogbeat_winlog_event_data_LogonType:(3 OR 10) AND NOT winlogbeat_winlog_event_data_TargetUserName:/.*[$]/ AND NOT winlogbeat_winlog_event_data_IpAddress:(<белый список>)
```

**Windows - Задание планировщика с Temp, AppData или Public (4698)**

```
win_channel:Security AND win_event_id:4698 AND message:(Temp OR AppData OR Public)
```

**Windows - Закрепление через IFEO Debugger, AppInit_DLLs и Winlogon**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:(12 OR 13) AND winlogbeat_winlog_event_data_TargetObject:/.*(Image File Execution Options\\[^\\]+\\(Debugger|GlobalFlag|VerifierDlls)|\\AppInit_DLLs|CurrentVersion\\Winlogon\\(Userinit|Shell))/
```

**Windows - Запуск утилит удалённого доступа и туннелей**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND win_image:/.*([nN][gG][rR][oO][kK]|[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE][dD]|[aA][nN][yY][dD][eE][sS][kK]|[tT][eE][aA][mM][vV][iI][eE][wW][eE][rR]|[rR][uU][sS][tT][dD][eE][sS][kK]|[uU][lL][tT][rR][aA][vV][iI][eE][wW][eE][rR]|[sS][cC][rR][eE][eE][nN][cC][oO][nN][nN][eE][cC][tT]|[mM][eE][sS][hH][aA][gG][eE][nN][tT]|[cC][hH][iI][sS][eE][lL]|[tT][aA][iI][lL][sS][cC][aA][lL][eE]|[zZ][eE][rR][oO][tT][iI][eE][rR]|[fF][rR][pP][cC]|[pP][lL][iI][nN][kK]).*/
```

**Windows - Маскировка под системный процесс (svchost, lsass, csrss вне System32)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND win_image:/.*[\\](svchost|lsass|csrss|smss|wininit|services|winlogon|spoolsv|lsm|taskhostw|conhost|dllhost|RuntimeBroker|SearchIndexer)[.]exe/ AND NOT win_image:/.*[wW][iI][nN][dD][oO][wW][sS][\\]([sS][yY][sS][tT][eE][mM]32|[sS][yY][sS][wW][oO][wW]64|[wW][iI][nN][sS][xX][sS]).*/
```

**Windows - Новая служба**

```
win_event_id:(7045 OR 4697) AND NOT winlogbeat_winlog_event_data_ServiceName:Kaspersky*
```

**Windows - Остановка Sysmon, winlogbeat, Defender или журнала событий**

```
win_channel:System AND win_event_id:7036 AND winlogbeat_winlog_event_data_param2:Остановлена AND winlogbeat_winlog_event_data_param1:(winlogbeat OR Sysmon* OR WinDefend OR "Антивирусная программа Microsoft Defender" OR "Служба защиты от угроз Microsoft Defender" OR "Брандмауэр Защитника Windows" OR "Журнал событий Windows")
```

**Windows - Перебор несуществующих пользователей (5+ за 10 мин)**

```
win_event_id:4625 AND winlogbeat_winlog_event_data_SubStatus:0xc0000064
```

**Windows - Подозрительно длинные DNS-имена (туннель, DGA)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:22 AND (winlogbeat_winlog_event_data_QueryName:/[^.]{40,}[.].*/ OR winlogbeat_winlog_event_data_QueryName:/.{70,}/) AND NOT winlogbeat_winlog_event_data_QueryName:/.*(_msdcs|_sites|_tcp|_udp|[Mm]icrosoft|[Aa]kamai|cloudfront|amazonaws|googleapis).*/
```

**Windows - Поиск паролей в файлах (findstr, Select-String)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND win_command_line:/.*(findstr.*[ ]\/[a-zA-Z]*[sS]|[Rr]ecurse.*[Ss]elect-[Ss]tring).*([pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][dD]|[sS][eE][cC][rR][eE][tT]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[aA][pP][iI][kK][eE][yY]|[iI][dD]_[rR][sS][aA]|[kK][dD][bB][xX]).*/ AND NOT win_command_line:/.*secedit.*/
```

**Windows - Разведка в домене (nltest, dsquery, AdFind, SharpHound)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND (win_image:/.*([nN][lL][tT][eE][sS][tT]|[dD][sS][qQ][uU][eE][rR][yY]|[aA][dD][fF][iI][nN][dD]|[sS][hH][aA][rR][pP][hH][oO][uU][nN][dD]|[bB][lL][oO][oO][dD][hH][oO][uU][nN][dD]|[lL][dD][iI][fF][dD][eE]|[cC][sS][vV][dD][eE]).*/ OR win_command_line:/.*(domain_trusts|dclist|[Gg]et-[Aa][Dd][A-Za-z]+).*/)
```

**Windows - Сброс пароля учётной записи (4724)**

```
win_channel:Security AND win_event_id:4724
```

**Windows - Создана компьютерная учётная запись пользователем (4741)**

```
win_channel:Security AND win_event_id:4741 AND NOT winlogbeat_winlog_event_data_SubjectUserName:/.*[$]/
```

**Windows - Создана учётная запись (4720)**

```
win_channel:Security AND win_event_id:4720
```

**Windows - Создание задачи через schtasks**

```
win_event_id:1 AND message:"schtasks" AND message:"/create"
```

**Windows - Удалённый вход по WinRM (91)**

```
win_channel:"Microsoft-Windows-WinRM/Operational" AND win_event_id:91
```

**Windows - Установка службы вне System32 и Program Files (4697)**

```
win_channel:Security AND win_event_id:4697 AND NOT winlogbeat_winlog_event_data_ServiceFileName:/.*([Ss]ystem32|[Pp]rogram [Ff]iles).*/
```

**Windows - Утилиты выгрузки в облако (rclone, MEGAsync, WinSCP)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND win_image:/.*([rR][cC][lL][oO][nN][eE]|[mM][eE][gG][aA][sS][yY][nN][cC]|[mM][eE][gG][aA][cC][mM][dD]|[wW][iI][nN][sS][cC][pP]|[pP][cC][lL][oO][uU][dD]).*/
```

**Windows - Defender: сигнатуры не обновлялись 7 дней**

```
win_channel:"Microsoft-Windows-Windows Defender/Operational" AND win_event_id:2000
```

**Windows - Архивация не из проводника (7z, WinRAR, Compress-Archive)**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:1 AND ((win_image:/.*(7[zZ]|7[zZ][aA]|7[zZ][gG]|[wW][iI][nN][rR][aA][rR]|[rR][aA][rR]|[zZ][iI][pP])[.]exe/ AND NOT winlogbeat_winlog_event_data_ParentImage:/.*explorer[.]exe/ AND NOT win_image:/.*[Tt]emp.*/) OR win_command_line:/.*([Cc]ompress-[Aa]rchive|tar([.]exe)?[ ]+-[a-zA-Z]*c[a-zA-Z]*[ ]).*/)
```

**Windows - Вход по RDP**

```
win_event_id:4624 AND winlogbeat_winlog_event_data_LogonType:10
```

**Windows - Серия разведки (5+ команд за 5 мин)**

```
win_event_id:1 AND message:("whoami.exe" OR "nltest.exe" OR "net.exe" OR "net1.exe" OR "systeminfo.exe" OR "quser.exe" OR "arp.exe")
```

</details>

## Linux

auditd на RED OS; поток RedOS auditd Logs. Правил: 50. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Брутфорс SSH (5+ неудачных входов за 5 мин) | высокий | RedOS auditd Logs | 5 и более неудачных SSH-аутентификаций на одном хосте за 5 минут. Возможен подбор пароля. | число событий ≥ 5 за 5 мин, группировка по source | Credential Access | `T1110` Brute Force |
| Веб-сервер запустил оболочку | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ susp_shell | Пользователь веб-сервера (apache, uid 48, или www-data, uid 33) запустил bash. Признак веб-шелла или эксплуатации сайта. Исключены redos-raspi и homeserver: там apache штатно запускает… | каждое событие; повтор не чаще раза в 1 ч | Initial Access | `T1190` Exploit Public-Facing Application<br>`T1505.003`, `T1059.004` |
| Вход по SSH из неизвестной сети | высокий | RedOS auditd Logs<br>auditd USER_LOGIN | Успешный вход по SSH (USER_LOGIN) с адреса вне справочника homelab-subnets (поле src_zone не заполнено). Требует pipeline «homelab: linux enrichment»: он достаёт IP из addr= и ищет сеть… | каждое событие | Initial Access | `T1078` Valid Accounts<br>`T1021.004` |
| Добавление SSH-ключа в authorized_keys | высокий | RedOS auditd Logs | Запись в файл authorized_keys. Возможно добавление SSH-ключа для постоянного доступа. Проверьте, кто изменил файл и легитимен ли ключ. | число событий > 0 за 5 мин, группировка по source | Persistence | `T1098.004` SSH Authorized Keys |
| Добавление/удаление пользователя | высокий | RedOS auditd Logs<br>auditd ADD_USER, auditd DEL_USER | На хосте успешно добавлен или удалён локальный пользователь. В исходных сообщениях: учётка и инициатор (auid). | число событий > 0 за 5 мин, группировка по source | Persistence | `T1136.001` Local Account |
| Запуск из /tmp, /dev/shm, /var/tmp | высокий | RedOS auditd Logs<br>auditd EXECVE | EXECVE: программа запущена из /tmp, /dev/shm или /var/tmp, либо интерпретатор (sh, bash, dash, python, perl) исполняет оттуда скрипт. Скрипты Wazuh `execute-*.sh` исключены. Так обычно… | каждое событие | Execution | `T1059.004` Unix Shell<br>`T1036` |
| Затирание следов (shred, history, truncate логов) | высокий | RedOS auditd Logs<br>auditd EXECVE | Уничтожение файлов через shred, работа с .bash_history или обрезка логов в /var/log. Типичное заметание следов после атаки. | каждое событие | Stealth | `T1070` Indicator Removal<br>`T1070.003`, `T1685.006` |
| Изменение /etc/passwd, shadow, group | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ etcpasswd, etcgroup, opasswd | Запись или смена атрибутов файлов учётных записей (/etc/passwd, /etc/shadow, /etc/group, /etc/security/opasswd) вне штатных служб. Возможно создание скрытой учётки или смена пароля. | каждое событие | Persistence | `T1098` Account Manipulation |
| Изменение sshd_config | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ sshd | Изменение конфигурации SSH-сервера. Возможны включение входа root, паролей или подмена AuthorizedKeysFile. | каждое событие | Defense Impairment | `T1556` Modify Authentication Process |
| Массовое удаление файлов (200+ за 5 мин) | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ file_deletion | Один процесс удалил 200 и более файлов за 5 минут (обычный максимум в лаборатории около 30). Так выглядит затирание данных или шифровальщик. | число событий ≥ 200 за 5 мин, группировка по source, exe | Impact | `T1485` Data Destruction<br>`T1070.004` |
| Обратная оболочка (/dev/tcp) | высокий | RedOS auditd Logs<br>auditd EXECVE | В командной строке использован /dev/tcp — типичный приём reverse shell в bash. | каждое событие | Execution | `T1059.004` Unix Shell |
| Обратная оболочка (bash -i, nc -e, socat exec) | высокий | RedOS auditd Logs<br>auditd PROCTITLE | В командной строке типичные приёмы обратной оболочки. Проверки порта вида echo > /dev/tcp/хост/порт не считаются. | каждое событие; повтор не чаще раза в 1 ч | Execution | `T1059.004` Unix Shell<br>`T1071` |
| Обратная оболочка (python, perl, nc, socat, mkfifo) | высокий | RedOS auditd Logs<br>auditd PROCTITLE | Командная строка с типовыми обратными оболочками: python -c с socket, perl -e с socket, nc -e, mkfifo, socat с exec:, bash -i с перенаправлением. Дополняет алерт на /dev/tcp. | каждое событие | Execution | `T1059.004` Unix Shell<br>`T1571` |
| Опасный запуск контейнера (--privileged, -v /:/, docker.sock) | высокий | RedOS auditd Logs<br>auditd PROCTITLE | Контейнер запущен с полным доступом к хосту: привилегированный режим, корень хоста, сокет docker, пространство процессов хоста. | каждое событие; повтор не чаще раза в 1 ч | Privilege Escalation | `T1611` Escape to Host |
| Отключение SELinux или аудита (setenforce 0, auditctl -e 0) | высокий | RedOS auditd Logs<br>auditd PROCTITLE | SELinux переведён в разрешающий режим или отключён аудит ядра. | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Отключение аудита или удаление правил auditd | высокий | RedOS auditd Logs<br>auditd CONFIG_CHANGE | Удалено правило auditd или аудит отключён (audit_enabled=0). Атакующий может ослеплять мониторинг. | каждое событие | Defense Impairment | `T1685.004` Disable or Modify Linux Audit System Log |
| Подбор пароля sudo или su (5+ ошибок за 5 мин) | высокий | RedOS auditd Logs<br>auditd USER_AUTH | Пять и более неудачных вводов пароля для sudo или su на одном хосте за 5 минут. | число событий ≥ 5 за 5 мин, группировка по source | Credential Access | `T1110` Brute Force |
| Подбор пароля и успешный вход по SSH (6+ событий за 15 мин) | высокий | RedOS auditd Logs<br>auditd USER_LOGIN | На одном хосте за 15 минут 6 и более событий входа по SSH, среди которых есть и неудачные, и успешные. Похоже на подбор пароля, закончившийся входом. | число событий && None за 15 мин, группировка по source | Credential Access | `T1110` Brute Force<br>`T1078` |
| Привилегированный контейнер или docker.sock | высокий | RedOS auditd Logs<br>auditd EXECVE | Запуск docker или podman с флагом --privileged или с монтированием docker.sock. Это путь к root на хосте. | каждое событие | Privilege Escalation | `T1611` Escape to Host<br>`T1610` |
| Успешный вход root по SSH | высокий | RedOS auditd Logs<br>auditd USER_LOGIN | Успешный вход по SSH под root. Прямой вход под root обычно отключают, повод проверить. | каждое событие; повтор не чаще раза в 1 ч | Lateral Movement | `T1021.004` SSH<br>`T1078.003` |
| Установка setuid или setgid | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ perm_modification | chmod, fchmod, fchmodat с битом setuid (04000) или setgid (02000). Исключены systemd-tmpfiles, rpm и dnf: их установки штатно выставляют такие права. | каждое событие | Privilege Escalation | `T1548.001` Setuid and Setgid |
| Участник добавлен в группу wheel, sudo, root, adm или docker | высокий | RedOS auditd Logs<br>auditd USER_MGMT | Пользователь добавлен в привилегированную группу. Группа docker равна root. Служебный beszel исключён. | каждое событие; повтор не чаще раза в 1 ч | Privilege Escalation | `T1098` Account Manipulation |
| SSH-туннель (-R, -L, -D) | средний | RedOS auditd Logs<br>auditd PROCTITLE | Запуск ssh с пробросом портов (-R, -L, -D). Так выводят внутренние сервисы наружу или строят прокси. | каждое событие | Command and Control | `T1572` Protocol Tunneling<br>`T1090` |
| Вход по SSH ночью (00:00-06:00) | средний | RedOS auditd Logs | Успешный вход по SSH ночью (с 00:00 до 06:00 по Екатеринбургу). Правило проверяется только в ночные часы. Часы подгоните под свой распорядок. | каждое событие; повтор не чаще раза в 1 ч | Initial Access | `T1078` Valid Accounts<br>`T1021.004` |
| Загрузка или выгрузка модуля ядра (insmod, modprobe, rmmod) | средний | RedOS auditd Logs<br>auditd EXECVE | Загружен или выгружен модуль ядра. Так ставят руткиты. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1547.006` Kernel Modules and Extensions |
| Загрузка модуля ядра | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ kernel_modules, kernel_modules_config | Загрузка или смена конфигурации модулей ядра (init_module, finit_module, modprobe). Вредоносные модули (руткиты) загружаются так же; штатные загрузки драйверов (udev) тоже попадают сюда,… | каждое событие | Persistence | `T1547.006` Kernel Modules and Extensions |
| Закрепление через cron | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ cron_persistence | Запись в каталоги и файлы cron (crontab, /etc/cron.*, /var/spool/cron). | каждое событие | Persistence | `T1053.003` Cron |
| Закрепление через systemctl enable | средний | RedOS auditd Logs<br>auditd EXECVE | Служба добавлена в автозапуск командой systemctl enable. Проверьте, что это ожидаемая служба. | каждое событие | Persistence | `T1543.002` Systemd Service |
| Запуск утилит удалённого доступа и туннелей | средний | RedOS auditd Logs<br>auditd EXECVE | Запущена утилита удалённого доступа или туннелирования (ngrok, cloudflared, AnyDesk, TeamViewer, RustDesk, chisel, tailscale, zerotier, frpc, plink). | каждое событие; повтор не чаще раза в 1 ч | Command and Control | `T1219` Remote Access Tools<br>`T1572` |
| Изменение прав доступа (chmod) | средний | RedOS auditd Logs<br>auditd SYSCALL | Изменение прав доступа через chmod (кроме uid 1001). В исходных сообщениях: режим, файл и пользователь. | число событий > 0 за 5 мин, группировка по source | Defense Impairment | `T1222.002` Linux and Mac Permissions |
| Исполнение из памяти (memfd_create) | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ anon_file_create | Создан анонимный файл в памяти (memfd_create). Так работают fileless-загрузчики; легитимно — некоторые AppImage. | каждое событие | Stealth | `T1620` Reflective Code Loading |
| Неудачная попытка sudo | средний | RedOS auditd Logs | Неудачная аутентификация sudo: неверный пароль или отказ PAM/SSSD. Возможен подбор пароля или ошибка пользователя. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Остановка auditd, rsyslog, wazuh, filebeat, sshd или firewalld | средний | RedOS auditd Logs<br>auditd SERVICE_STOP | Остановлена служба аудита, логирования, защиты или SSH. Исключён постоянно перезапускающийся юнит filebeat-wazuh на хосте wazuh (около тысячи остановок в месяц). | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Остановка службы (systemctl stop) | средний | RedOS auditd Logs<br>auditd EXECVE | Остановка системной службы через systemctl stop. Имя службы: аргумент a2 в исходных сообщениях. | число событий > 0 за 5 мин, группировка по source | Impact | `T1489` Service Stop |
| Очистка истории команд (history -c, unset HISTFILE) | средний | RedOS auditd Logs<br>auditd PROCTITLE | Очищена или отключена история командной строки. Так заметают следы. | каждое событие; повтор не чаще раза в 1 ч | Stealth | `T1070.003` Clear Command History |
| Передача файлов наружу (scp, sftp, rsync) из терминала | средний | RedOS auditd Logs<br>auditd SYSCALL | Пользователь запустил scp, sftp или rsync в интерактивной сессии. Служебные запуски без терминала не учитываются. | каждое событие | Exfiltration | `T1048` Exfiltration Over Alternative Protocol |
| Подозрительные утилиты (base64, nc, socat, scp) | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ susp_activity | Запуск утилит, часто используемых для передачи и кодирования данных: base64, nc, socat, scp. | каждое событие | Command and Control | `T1105` Ingress Tool Transfer<br>`T1140` |
| Поиск паролей в файлах (grep -r, find) | средний | RedOS auditd Logs<br>auditd EXECVE | Рекурсивный поиск слов password, secret, id_rsa, api_key и подобных по файлам (grep -r, find, rg). | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1552.001` Credentials In Files |
| Сканеры сети (nmap, masscan, arp-scan) | средний | RedOS auditd Logs<br>auditd EXECVE | Запущен сканер сети (nmap, masscan, arp-scan, netdiscover, nbtscan, fping, zmap). | каждое событие; повтор не чаще раза в 1 ч | Discovery | `T1046` Network Service Discovery<br>`T1018` |
| Создана локальная учётная запись (useradd) | средний | RedOS auditd Logs<br>auditd ADD_USER | Создана новая локальная учётная запись. Нужно для закрепления. Исключены служебные учётные записи, которые ты разворачиваешь сам: beszel, node_exporter, graylog-collector,… | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1136.001` Local Account |
| Установка бита setuid или setgid (chmod u+s) | средний | RedOS auditd Logs<br>auditd EXECVE | Файлу выставлен бит setuid или setgid. Так готовят повышение прав. | каждое событие; повтор не чаще раза в 1 ч | Privilege Escalation | `T1548.001` Setuid and Setgid |
| Утилиты выгрузки в облако (rclone, MEGAcmd) | средний | RedOS auditd Logs<br>auditd EXECVE | Запущена утилита выгрузки в облако (rclone, MEGAcmd, megatools). | каждое событие; повтор не чаще раза в 1 ч | Exfiltration | `T1567.002` Exfiltration to Cloud Storage<br>`T1048` |
| Архивация данных пользователем (tar, zip, 7z) | низкий | RedOS auditd Logs<br>auditd SYSCALL, ключ Data_Compressed | Пользователь запустил архиватор (tar, zip и аналоги). Частая подготовка к выгрузке данных. gzip и pigz исключены, их запускают logrotate и системные задачи. | каждое событие | Collection | `T1560.001` Archive via Utility |
| Изменение правил firewall (iptables, nft) | низкий | RedOS auditd Logs<br>auditd SYSCALL, ключ sbin_susp | Запуск iptables/nft. Обычно Docker или firewalld, но так же отключают защиту. | каждое событие | Defense Impairment | `T1686` Disable or Modify System Firewall |
| Изменение сетевых настроек и /etc/hosts | низкий | RedOS auditd Logs<br>auditd SYSCALL, ключ network_modifications | Правка сетевых файлов (hosts, resolv.conf и аналогов) не NetworkManager и не рантаймом контейнеров. Так подменяют DNS или перенаправляют трафик. | каждое событие | Impact | `T1565.001` Stored Data Manipulation |
| Использование sudo | низкий | RedOS auditd Logs<br>auditd EXECVE | Выполнение команды через sudo (кроме uid 1001). Команда собирается из аргументов a0 a1 a2 a3 в исходных сообщениях. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Отказ SELinux (AVC) | низкий | RedOS auditd Logs<br>auditd AVC | SELinux запретил действие процессу. Может указывать на попытку обхода политики или на ошибку настройки. | каждое событие | — | — |
| Правка crontab (crontab -e) | низкий | RedOS auditd Logs<br>auditd PROCTITLE | Пользователь открыл редактирование своего crontab. Закрепление через планировщик. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1053.003` Cron |
| Разведка (id, whoami) | низкий | RedOS auditd Logs<br>auditd SYSCALL, ключ recon | Запуск команд разведки системы. Сами по себе безобидны, важны в связке с другими событиями. | каждое событие | Discovery | `T1033` System Owner/User Discovery |
| Ручная смена системного времени | низкий | RedOS auditd Logs<br>auditd PROCTITLE | Время вручную изменено. Сбивает корреляцию событий. | каждое событие; повтор не чаще раза в 1 ч | Stealth | `T1070` Indicator Removal |

<details><summary>Запросы Graylog (очищенные)</summary>

**LNX - Брутфорс SSH (5+ неудачных входов за 5 мин)**

```
(message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")
```

**LNX - Веб-сервер запустил оболочку**

```
key:susp_shell AND audit_type:SYSCALL AND uid:(48 OR 33) AND NOT source:(redos-raspi OR homeserver)
```

**LNX - Вход по SSH из неизвестной сети**

```
audit_type:USER_LOGIN AND res:success* AND _exists_:src_ip AND NOT _exists_:src_zone AND NOT src_ip:("::1" OR fe80* OR fd* OR fc*)
```

**LNX - Добавление SSH-ключа в authorized_keys**

```
message:"authorized_keys" AND (message:"CREATE" OR message:"write")
```

**LNX - Добавление/удаление пользователя**

```
(audit_type:ADD_USER OR audit_type:DEL_USER) AND res:success*
```

**LNX - Запуск из /tmp, /dev/shm, /var/tmp**

```
audit_type:EXECVE AND (a0:/\/(tmp|dev\/shm|var\/tmp)\/.*/ OR (a0:/(.*\/)?(sh|bash|dash|python3?|perl)/ AND a1:/\/(tmp|dev\/shm|var\/tmp)\/.*/ AND NOT a1:/\/tmp\/execute-.*\.sh/))
```

**LNX - Затирание следов (shred, history, truncate логов)**

```
audit_type:EXECVE AND (a0:("shred" OR "/usr/bin/shred") OR message:".bash_history" OR (a0:("truncate" OR "/usr/bin/truncate") AND message:"/var/log"))
```

**LNX - Изменение /etc/passwd, shadow, group**

```
key:(etcpasswd OR etcgroup OR opasswd) AND audit_type:SYSCALL AND NOT exe:("/usr/sbin/unix_chkpwd" OR "/usr/lib/systemd/systemd-userwork" OR "/var/ossec/bin/wazuh-modulesd" OR "/var/ossec/bin/wazuh-syscheckd" OR "/usr/libexec/accounts-daemon") AND NOT auid:4294967295
```

**LNX - Изменение sshd_config**

```
key:sshd AND audit_type:SYSCALL AND NOT exe:("/var/ossec/bin/wazuh-syscheckd" OR "/usr/sbin/sshd")
```

**LNX - Массовое удаление файлов (200+ за 5 мин)**

```
audit_type:SYSCALL AND key:file_deletion
```

**LNX - Обратная оболочка (/dev/tcp)**

```
audit_type:EXECVE AND message:"/dev/tcp"
```

**LNX - Обратная оболочка (bash -i, nc -e, socat exec)**

```
audit_type:PROCTITLE AND proctitle:/.*(bash[ ]+-i.*\/dev\/tcp|\/dev\/tcp\/.*0\>\&1|\>\&[ ]*\/dev\/tcp|nc[ ]+-[a-z]*e[ ]|ncat[ ].*-e[ ]|socat[ ].*exec|mkfifo[ ].*nc[ ]).*/
```

**LNX - Обратная оболочка (python, perl, nc, socat, mkfifo)**

```
audit_type:PROCTITLE AND proctitle:/.*(python[0-9.]* -c .*socket.*(dup2|pty[.]spawn|subprocess)|perl -e .*socket.*(exec|open|system)|nc(at)? .* -e |mkfifo |socat .*exec:|bash -i .*\>\&).*/
```

**LNX - Опасный запуск контейнера (--privileged, -v /:/, docker.sock)**

```
audit_type:PROCTITLE AND proctitle:/.*docker[ ]+(run|create)[ ].*(--privileged|-v[ ]+\/:|--pid=host|docker[.]sock|--cap-add[ =]+(SYS_ADMIN|ALL)).*/
```

**LNX - Отключение SELinux или аудита (setenforce 0, auditctl -e 0)**

```
audit_type:PROCTITLE AND proctitle:/.*(setenforce[ ]+0|auditctl[ ]+-e[ ]+0|semanage[ ]+permissive|SELINUX=(disabled|permissive)).*/
```

**LNX - Отключение аудита или удаление правил auditd**

```
audit_type:CONFIG_CHANGE AND (op:remove_rule OR message:"audit_enabled=0")
```

**LNX - Подбор пароля sudo или su (5+ ошибок за 5 мин)**

```
audit_type:USER_AUTH AND res:failed AND exe:("/usr/bin/sudo" OR "/usr/bin/su")
```

**LNX - Подбор пароля и успешный вход по SSH (6+ событий за 15 мин)**

```
audit_type:USER_LOGIN AND exe:"/usr/libexec/openssh/sshd-session"
```

**LNX - Привилегированный контейнер или docker.sock**

```
audit_type:EXECVE AND a0:(docker OR podman) AND message:(privileged OR "docker.sock")
```

**LNX - Успешный вход root по SSH**

```
audit_type:USER_LOGIN AND exe:"/usr/libexec/openssh/sshd-session" AND acct:root AND res:success*
```

**LNX - Установка setuid или setgid**

```
audit_type:SYSCALL AND key:perm_modification AND ((syscall:(53 OR 268) AND a2:/[4-9a-f][0-9a-f]{2}/) OR (syscall:(52 OR 90 OR 91) AND a1:/[4-9a-f][0-9a-f]{2}/)) AND NOT exe:("/usr/bin/systemd-tmpfiles" OR "/usr/bin/rpm" OR "/usr/bin/dnf" OR "/usr/bin/dnf5")
```

**LNX - Участник добавлен в группу wheel, sudo, root, adm или docker**

```
audit_type:USER_MGMT AND message:"add-user-to-group" AND message:(wheel OR sudo OR root OR adm OR docker) AND NOT acct:(beszel OR node_exporter OR "graylog-collector" OR "logatlas-collect" OR nginx OR zaslon)
```

**LNX - SSH-туннель (-R, -L, -D)**

```
audit_type:PROCTITLE AND proctitle:/(.*[ \/])?ssh( .*)? -[RLD] ?[^ ]+.*/
```

**LNX - Вход по SSH ночью (00:00-06:00)**

```
message:"sshd" AND message:"Accepted"
```

**LNX - Загрузка или выгрузка модуля ядра (insmod, modprobe, rmmod)**

```
audit_type:EXECVE AND a0:(insmod OR modprobe OR rmmod)
```

**LNX - Загрузка модуля ядра**

```
audit_type:SYSCALL AND key:(kernel_modules OR kernel_modules_config)
```

**LNX - Закрепление через cron**

```
audit_type:SYSCALL AND key:cron_persistence
```

**LNX - Закрепление через systemctl enable**

```
audit_type:EXECVE AND a0:("systemctl" OR "/usr/bin/systemctl") AND message:"enable"
```

**LNX - Запуск утилит удалённого доступа и туннелей**

```
audit_type:EXECVE AND a0:(ngrok OR cloudflared OR anydesk OR teamviewer OR rustdesk OR chisel OR tailscale OR zerotier OR frpc OR plink)
```

**LNX - Изменение прав доступа (chmod)**

```
audit_type:SYSCALL AND comm:chmod AND success:yes AND -uid:"1001"
```

**LNX - Исполнение из памяти (memfd_create)**

```
key:anon_file_create AND audit_type:SYSCALL AND NOT exe:(<белый список>) AND NOT outline
```

**LNX - Неудачная попытка sudo**

```
message:"sudo" AND (message:"authentication failure" OR message:"incorrect password" OR (message:"pam_sss" AND message:"failure"))
```

**LNX - Остановка auditd, rsyslog, wazuh, filebeat, sshd или firewalld**

```
audit_type:SERVICE_STOP AND message:(auditd OR rsyslog OR "wazuh-agent" OR "wazuh-manager" OR filebeat OR "systemd-journald" OR sshd OR firewalld) AND NOT message:"filebeat-wazuh"
```

**LNX - Остановка службы (systemctl stop)**

```
audit_type:EXECVE AND a0:"systemctl" AND a1:"stop"
```

**LNX - Очистка истории команд (history -c, unset HISTFILE)**

```
audit_type:PROCTITLE AND proctitle:/.*(history[ ]+-c|unset[ ]+HISTFILE|HISTFILE=\/dev\/null|rm[ ].*bash_history|HISTSIZE=0).*/
```

**LNX - Передача файлов наружу (scp, sftp, rsync) из терминала**

```
audit_type:SYSCALL AND exe:("/usr/bin/scp" OR "/usr/bin/sftp" OR "/usr/bin/rsync") AND NOT auid:4294967295 AND NOT tty:"(none)"
```

**LNX - Подозрительные утилиты (base64, nc, socat, scp)**

```
key:susp_activity AND audit_type:SYSCALL AND NOT exe:("/usr/bin/netstat" OR "/usr/bin/curl" OR "/usr/bin/ssh")
```

**LNX - Поиск паролей в файлах (grep -r, find)**

```
audit_type:EXECVE AND a0:(grep OR egrep OR rg OR find OR locate) AND a1:("-r" OR "-R" OR "-rn" OR "-ri" OR "-rI" OR "-ir" OR "-nr") AND message:(password OR passwd OR secret OR id_rsa OR api_key OR credentials)
```

**LNX - Сканеры сети (nmap, masscan, arp-scan)**

```
audit_type:EXECVE AND a0:(nmap OR masscan OR "arp-scan" OR netdiscover OR nbtscan OR fping OR zmap)
```

**LNX - Создана локальная учётная запись (useradd)**

```
audit_type:ADD_USER AND NOT acct:(beszel OR node_exporter OR "graylog-collector" OR "logatlas-collect" OR nginx OR zaslon)
```

**LNX - Установка бита setuid или setgid (chmod u+s)**

```
audit_type:EXECVE AND a0:chmod AND a1:("u+s" OR "g+s" OR 4755 OR 2755 OR 4777 OR 6755 OR 4750 OR 4711)
```

**LNX - Утилиты выгрузки в облако (rclone, MEGAcmd)**

```
audit_type:EXECVE AND a0:(rclone OR megacmd OR megatools OR megaput)
```

**LNX - Архивация данных пользователем (tar, zip, 7z)**

```
key:Data_Compressed AND audit_type:SYSCALL AND NOT exe:("/usr/bin/gzip" OR "/usr/bin/pigz") AND NOT auid:4294967295
```

**LNX - Изменение правил firewall (iptables, nft)**

```
key:sbin_susp AND audit_type:SYSCALL
```

**LNX - Изменение сетевых настроек и /etc/hosts**

```
key:network_modifications AND audit_type:SYSCALL AND NOT exe:("/usr/sbin/NetworkManager" OR "/runc" OR "/usr/bin/runc")
```

**LNX - Использование sudo**

```
audit_type:EXECVE AND a0:"sudo" AND NOT uid:"1001" AND NOT a2="/usr/local/libexec/zaslon/agent"
```

**LNX - Отказ SELinux (AVC)**

```
audit_type:AVC AND NOT comm:ftdc AND NOT comm:"flb-pipeline" AND NOT comm:portainer
```

**LNX - Правка crontab (crontab -e)**

```
audit_type:PROCTITLE AND proctitle:/.*crontab[ ]+-e.*/
```

**LNX - Разведка (id, whoami)**

```
key:recon AND audit_type:SYSCALL AND NOT exe:("/usr/bin/uname" OR "/usr/bin/hostname" OR "/usr/lib/systemd/systemd-hostnamed" OR "/usr/bin/id")
```

**LNX - Ручная смена системного времени**

```
audit_type:PROCTITLE AND proctitle:/.*(date[ ]+-s|timedatectl[ ]+set-time|hwclock[ ]+--set).*/
```

</details>

## macOS (osquery и unified log)

osquery Endpoint Security и unified log; поток MacOS Logs. Правил: 50. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Включение удалённого доступа (SSH, Screen Sharing, ARD) | высокий | MacOS Logs<br>osquery es_process_events | Включён удалённый вход по SSH, общий экран или Remote Desktop. Простые launchctl print не учитываются. | каждое событие; повтор не чаще раза в 1 ч | Lateral Movement | `T1021.004` SSH<br>`T1021.005` |
| Вмешательство в TCC | высокий | MacOS Logs<br>osquery es_process_events | Сброс разрешений приватности (tccutil) или прямой доступ к базе TCC.db. | каждое событие | Privilege Escalation | `T1548.006` TCC Manipulation |
| Выгрузка паролей из Keychain | высокий | MacOS Logs<br>osquery es_process_events | Команда security читает пароли из Keychain (dump-keychain, find-generic-password, find-internet-password). Типично для стилеров. | ОТКЛЮЧЕНО; каждое событие | Credential Access | `T1555.001` Keychain |
| Выгрузка паролей из Keychain (security dump-keychain) | высокий | MacOS Logs<br>osquery es_process_events | Команда security выгружает связку ключей или печатает пароль из неё. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1555.001` Keychain |
| Изменение /etc/sudoers | высокий | MacOS Logs<br>osquery file_events | Изменён файл /etc/sudoers, задающий права суперпользователя. Возможна эскалация привилегий. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Изменение базы авторизации (authorizationdb) | высокий | MacOS Logs<br>osquery es_process_events | security authorizationdb: правка прав на системные действия. Позволяет выполнять привилегированные операции без пароля. | каждое событие | Privilege Escalation | `T1548` Abuse Elevation Control Mechanism |
| Копирование данных браузера | высокий | MacOS Logs<br>osquery es_process_events | sqlite3, cp, cat, strings, tar, zip или python, работающие с Login Data, Cookies.binarycookies, key4.db, logins.json, Local State. Видны только команды, чтение файлов самим процессом не… | каждое событие | Credential Access | `T1555.003` Credentials from Web Browsers |
| Новый/изменённый plist в автозагрузке | высокий | MacOS Logs<br>osquery file_events | Создан, изменён или удалён plist в LaunchDaemons/LaunchAgents (кроме com.apple.*). Типичный способ закрепления (persistence). | число событий > 0 за 5 мин, группировка по source | Persistence | `T1543.004` Launch Daemon<br>`T1543.001` |
| Обратная оболочка (/dev/tcp, pty.spawn) | высокий | MacOS Logs<br>osquery es_process_events | В командной строке /dev/tcp, pty.spawn или socket.socket — признаки reverse shell. | каждое событие | Execution | `T1059.004` Unix Shell |
| Отключение SIP (csrutil disable) | высокий | MacOS Logs<br>osquery es_process_events | Запрошено отключение защиты целостности системы (SIP). | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Отключение SIP или Gatekeeper | высокий | MacOS Logs<br>osquery es_process_events | Попытка отключить SIP (csrutil disable) или Gatekeeper (spctl --master-disable). Резко снижает защищённость системы. | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Отключение межсетевого экрана (socketfilterfw, pfctl) | высокий | MacOS Logs<br>osquery es_process_events | socketfilterfw с --set… off либо pfctl с ключами -d, -F, -f, -e. Включение режима stealth (on) не срабатывает. | каждое событие | Defense Impairment | `T1686` Disable or Modify System Firewall |
| Очистка журналов | высокий | MacOS Logs<br>osquery es_process_events | log erase, log config, rm в /var/log или diagnostics, killall syslogd, truncate логов. Так заметают следы. | каждое событие | Stealth | `T1070.002` Clear Linux or Mac System Logs<br>`T1070` |
| Подключено мобильное устройство (не Apple) | высокий | MacOS Logs<br>журнал macos_wifi_usb | По USB подключено мобильное устройство не Apple (isApple N). Возможна попытка первоначального доступа. | каждое событие | Initial Access | `T1200` Hardware Additions |
| Подмена библиотек (DYLD_INSERT_LIBRARIES) | высокий | MacOS Logs<br>osquery es_process_events | DYLD_INSERT_LIBRARIES в окружении или командной строке процесса: внедрение динамической библиотеки. | каждое событие | Persistence | `T1574.006` Dynamic Linker Hijacking |
| Подозрительный процесс открыл TCP-порт | высокий | MacOS Logs<br>osquery listening_ports | nc/ncat/python/bash/sh начал слушать нестандартный порт. Возможен бэкдор или reverse shell. | каждое событие | Command and Control | `T1571` Non-Standard Port |
| Скачивание и запуск (curl \| sh) | высокий | MacOS Logs<br>osquery es_process_events | curl или wget с конвейером в sh, bash, zsh либо bash -c "$(curl …)". Типичный способ запустить загруженный скрипт без файла. | каждое событие | Execution | `T1059.004` Unix Shell<br>`T1105` |
| Создана учётная запись (dscl, sysadminctl) | высокий | MacOS Logs<br>osquery es_process_events | Создана локальная учётная запись или скрыты учётные записи с экрана входа. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1136.001` Local Account |
| Уничтожение резервных копий или дисков (tmutil, diskutil) | высокий | MacOS Logs<br>osquery es_process_events | Удалены резервные копии Time Machine или стёрт диск. | каждое событие; повтор не чаще раза в 1 ч | Impact | `T1490` Inhibit System Recovery<br>`T1485` |
| Установка доверенного корневого сертификата | высокий | MacOS Logs<br>osquery es_process_events | В систему добавлен доверенный сертификат. Так подменяют TLS. Свой сертификат caddy-root исключён. | каждое событие; повтор не чаще раза в 1 ч | Stealth | `T1553.004` Install Root Certificate |
| Установка или удаление профиля конфигурации | высокий | MacOS Logs<br>osquery es_process_events | Запуск profiles с install, remove, -I или -R. Профили конфигурации ставят прокси, сертификаты и VPN, отключают защиту. Штатные `profiles list` и `profiles status` не попадают. | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools<br>`T1553.004` |
| Установка конфигурационного профиля (profiles install) | высокий | MacOS Logs<br>osquery es_process_events | Установлен конфигурационный профиль. Через профили меняют настройки безопасности, прокси и сертификаты. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1547` Boot or Logon Autostart Execution |
| Фишинговый запрос пароля через osascript | высокий | MacOS Logs<br>osquery es_process_events | osascript показывает диалог со скрытым вводом — так вредоносы выманивают пароль пользователя. | каждое событие | Collection | `T1056.002` GUI Input Capture |
| JXA-скрипт через osascript | средний | MacOS Logs | Запуск osascript с JavaScript (JXA). Такие скрипты используют для сбора данных и запуска команд. Исключены инвентаризация Wi-Fi через CoreWLAN и подбор приложения для файла (NSWorkspace). | каждое событие; повтор не чаще раза в 1 ч | Execution | `T1059.002` AppleScript |
| Активность AirDrop | средний | MacOS Logs<br>журнал macos_unified | Передача или приём через AirDrop (sharingd). Возможна утечка данных. | число событий ≥ 1 за 5 мин, группировка по source | — | — |
| Включение удалённого входа или Screen Sharing | средний | MacOS Logs<br>osquery es_process_events | systemsetup -setremotelogin, kickstart ARD или setremoteappleevents — открытие удалённого доступа к Маку. | каждое событие | Lateral Movement | `T1021.004` SSH<br>`T1021.005` |
| Добавление корневого сертификата | средний | MacOS Logs<br>osquery es_process_events | security add-trusted-cert, trust-settings-import или add-certificates: сертификат становится доверенным в системе. Так подготавливают перехват TLS. | каждое событие | Stealth | `T1553.004` Install Root Certificate |
| Загрузка launchd-задания (load, bootstrap, submit) | средний | MacOS Logs<br>osquery es_process_events | launchctl load, bootstrap или submit для заданий вне исключений (Apple, hostdeck, Graylog, Elastic, beszel, Homebrew, homelab, logatlas). Так запускают закреплённые задания. | каждое событие | Execution | `T1569.001` Launchctl<br>`T1543.004` |
| Загрузка расширения ядра | средний | MacOS Logs<br>osquery es_process_events | Загрузка kext через kextload или kmutil load. | каждое событие | Persistence | `T1547.006` Kernel Modules and Extensions |
| Загрузка расширения ядра или системного расширения | средний | MacOS Logs<br>osquery es_process_events | Загружено расширение ядра или системное расширение. Служба logkextloadsd не считается. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1547.006` Kernel Modules and Extensions |
| Запуск программы из /tmp или /Users/Shared | средний | MacOS Logs<br>osquery es_process_events | Исполняемый файл запущен из временного или общего каталога (кроме Bi.Zone Triage). Типично для загрузчиков. | каждое событие | Execution | `T1059` Command and Scripting Interpreter |
| Запуск утилит удалённого доступа и туннелей | средний | MacOS Logs<br>osquery es_process_events | В командной строке процесса есть утилита удалённого доступа или туннелирования (ngrok, cloudflared, AnyDesk, TeamViewer, RustDesk, chisel, tailscale, zerotier, frpc). | каждое событие; повтор не чаще раза в 1 ч | Command and Control | `T1219` Remote Access Tools<br>`T1572` |
| Неудачная попытка sudo (неверный пароль) | средний | MacOS Logs<br>журнал macos_unified | При выполнении sudo введён неверный пароль. Возможен подбор пароля. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Остановка агентов сбора логов и защиты (launchctl) | средний | MacOS Logs<br>osquery es_process_events | launchctl остановил или отключил агент сбора логов или защиты (osquery, filebeat, Graylog collector, Bi.Zone, Velociraptor, HostDeck, firewall). Плановое обслуживание тоже срабатывает,… | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Передача данных наружу (scp, rsync, nc, socat) | средний | MacOS Logs<br>osquery es_process_events | scp или rsync на user@host с точкой в имени, а также nc, ncat, socat без -l, если адрес не из частных сетей и не в <домен>. | каждое событие | Exfiltration | `T1048` Exfiltration Over Alternative Protocol |
| Поддельное окно ввода пароля (osascript hidden answer) | средний | MacOS Logs<br>osquery es_process_events | AppleScript показывает окно со скрытым вводом. Так выманивают пароль. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1056.002` GUI Input Capture |
| Подключено Apple-устройство (iPhone/iPad/iPod) | средний | MacOS Logs<br>журнал macos_wifi_usb | По USB подключено и распознано Apple-устройство (wifi.log, hostNotificationUSBDeviceInserted). | каждое событие | Initial Access | `T1200` Hardware Additions |
| Подключён USB-накопитель | средний | MacOS Logs<br>журнал macos_unified | Ядро распознало USB-накопитель (IOUSBMassStorageDriver): флешку или внешний диск. | число событий > 0 за 5 мин, группировка по source | Initial Access | `T1200` Hardware Additions<br>`T1052.001` |
| Поиск паролей в файлах (grep -r по / и ~) | средний | MacOS Logs<br>osquery es_process_events | Рекурсивный поиск слов password, secret, token, id_rsa по домашней папке или всему диску (grep -r, rg, find). Запуски через ssh с BatchMode (автоматизация) и поиск внутри рабочих… | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1552.001` Credentials In Files |
| Сканеры сети (nmap, masscan, arp-scan) | средний | MacOS Logs<br>osquery es_process_events | В командной строке процесса есть сканер сети (nmap, masscan, arp-scan, netdiscover, nbtscan, fping, zmap). | каждое событие; повтор не чаще раза в 1 ч | Discovery | `T1046` Network Service Discovery<br>`T1018` |
| Смена DNS или прокси (networksetup) | средний | MacOS Logs<br>osquery es_process_events | Изменены DNS-серверы или прокси. Так перехватывают трафик. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1557` Adversary-in-the-Middle |
| Снятие карантина вне Applications или отключение Gatekeeper | средний | MacOS Logs<br>osquery es_process_events | Отключён Gatekeeper или снят атрибут карантина с файла вне /Applications. Установка приложений в /Applications и hostdeck-agent исключены. | каждое событие; повтор не чаще раза в 1 ч | Stealth | `T1553.001` Gatekeeper Bypass |
| Создание пользователя или изменение групп | средний | MacOS Logs<br>osquery es_process_events | dscl, sysadminctl или dseditgroup создают пользователя или меняют членство в группах (в т.ч. admin). | каждое событие | Persistence | `T1136.001` Local Account<br>`T1098` |
| Утилиты выгрузки в облако (rclone, MEGAsync) | средний | MacOS Logs<br>osquery es_process_events | В командной строке процесса есть утилита выгрузки в облако (rclone, MEGAsync, MEGAcmd). | каждое событие; повтор не чаще раза в 1 ч | Exfiltration | `T1567.002` Exfiltration to Cloud Storage<br>`T1048` |
| Элемент входа через sfltool или osascript | средний | MacOS Logs<br>osquery es_process_events | Добавление Login Items командами sfltool или osascript (System Events, login item). Закрепление без plist; дополняет алерт на LaunchAgents. | каждое событие | Persistence | `T1547.015` Login Items |
| Выполнение команды через sudo | низкий | MacOS Logs<br>osquery sudo_commands | Выполнение команды с повышенными привилегиями через sudo (не от root). | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Добавление элемента входа (sfltool, osascript login item) | низкий | MacOS Logs<br>osquery es_process_events | Добавлен элемент автозапуска при входе. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1547.015` Login Items |
| Запись экрана на MacBook (replayd) | низкий | MacOS Logs<br>журнал macos_unified | Служба replayd начала сессию захвата экрана на MacBook. Mac mini исключён: на нём захват экрана идёт при твоей удалённой работе. | каждое событие; повтор не чаще раза в 1 ч | Collection | `T1113` Screen Capture |
| Открытая Wi-Fi сеть в сохранённых (сводка раз в сутки) | низкий | MacOS Logs | В сохранённых сетях есть открытая Wi-Fi сеть без шифрования. Через такую сеть трафик можно перехватить. Сводка раз в сутки, повтор не чаще раза в неделю. | число событий ≥ 1 за 1 сут, группировка по source, columns_network_name; повтор не чаще раза в 7 сут | Credential Access | `T1557` Adversary-in-the-Middle |
| Снятие карантина с приложения | низкий | MacOS Logs<br>osquery es_process_events | С файла снят атрибут com.apple.quarantine — Gatekeeper не проверит приложение при запуске. | каждое событие | Defense Impairment | `T1553.001` Gatekeeper Bypass |

<details><summary>Запросы Graylog (очищенные)</summary>

**macOS - Включение удалённого доступа (SSH, Screen Sharing, ARD)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*(systemsetup.*-setremotelogin[ ]+on|kickstart.*-activate|launchctl[ ]+(load|enable|bootstrap|kickstart).*(com[.]apple[.]screensharing|com[.]openssh[.]sshd)).*/
```

**macOS - Вмешательство в TCC**

```
name:es_process_events AND message:("tccutil" OR "TCC.db")
```

**macOS - Выгрузка паролей из Keychain**

```
name:es_process_events AND message:("dump-keychain" OR "find-generic-password" OR "find-internet-password" OR "export-keychain")
```

**macOS - Выгрузка паролей из Keychain (security dump-keychain)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*security[ ]+(dump-keychain|find-(generic|internet)-password[ ].*-[a-z]*w).*/
```

**macOS - Изменение /etc/sudoers**

```
name:file_events AND columns_category:sudoers AND (action:added OR columns_action:(MOVED_TO OR ROOT_CHANGED OR ATTRIBUTES_MODIFIED OR UPDATED))
```

**macOS - Изменение базы авторизации (authorizationdb)**

```
name:es_process_events AND columns_cmdline:/.*authorizationdb.*/
```

**macOS - Копирование данных браузера**

```
name:es_process_events AND columns_cmdline:/.*(sqlite3|cp|cat|strings|python3?|tar|zip) .*(Login Data|Cookies\.binarycookies|key4\.db|logins\.json|Local State).*/
```

**macOS - Новый/изменённый plist в автозагрузке**

```
name:file_events AND (columns_action:CREATED OR columns_action:UPDATED OR columns_action:DELETED) AND (columns_category:launch_agents OR columns_category:launch_daemons) AND -columns_target_path:"com.apple*"
```

**macOS - Обратная оболочка (/dev/tcp, pty.spawn)**

```
name:es_process_events AND message:("/dev/tcp" OR "pty.spawn" OR "socket.socket") AND NOT message:"/dev/tcp/<IP>"
```

**macOS - Отключение SIP (csrutil disable)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*csrutil[ ]+(disable|authenticated-root[ ]+disable).*/
```

**macOS - Отключение SIP или Gatekeeper**

```
name:es_process_events AND ((message:"spctl" AND message:("master-disable" OR "global-disable")) OR (message:"csrutil" AND message:"disable"))
```

**macOS - Отключение межсетевого экрана (socketfilterfw, pfctl)**

```
name:es_process_events AND (columns_cmdline:/.*socketfilterfw --set(globalstate|stealthmode|blockall|allowsigned|allowsignedapp) off.*/ OR columns_cmdline:/(.*[ \/])?pfctl( .*)? -(d|F|f|e)( .*)?/)
```

**macOS - Очистка журналов**

```
name:es_process_events AND columns_cmdline:/.*(log erase|log config|rm .*(\/var\/log|diagnostics)|killall syslogd|truncate .*\/var\/log).*/
```

**macOS - Подключено мобильное устройство (не Apple)**

```
log_type:macos_wifi_usb AND message:(hostNotificationUSBDeviceInserted AND "isApple N")
```

**macOS - Подмена библиотек (DYLD_INSERT_LIBRARIES)**

```
name:es_process_events AND (columns_env:/.*DYLD_INSERT_LIBRARIES.*/ OR columns_cmdline:/.*DYLD_INSERT_LIBRARIES.*/)
```

**macOS - Подозрительный процесс открыл TCP-порт**

```
name:listening_ports AND (columns_name:(nc OR ncat OR netcat OR python OR python3 OR bash OR sh) AND NOT columns_port:(22 OR 80 OR 443 OR 4000)) AND action:added
```

**macOS - Скачивание и запуск (curl | sh)**

```
name:es_process_events AND (columns_cmdline:/.*(curl|wget).*\| *(sudo )?(ba|z|da)?sh( .*)?/ OR columns_cmdline:/.*sh -c [\\"]*\$\((curl|wget) .*/)
```

**macOS - Создана учётная запись (dscl, sysadminctl)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*(dscl[ ]+[^ ]+[ ]+-create[ ]+\/Users|sysadminctl.*-addUser|Hide500Users).*/
```

**macOS - Уничтожение резервных копий или дисков (tmutil, diskutil)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*(tmutil[ ]+(delete|disable|deletelocalsnapshots)|diskutil[ ]+(eraseDisk|eraseVolume|secureErase|apfs[ ]+deleteVolume)).*/
```

**macOS - Установка доверенного корневого сертификата**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*security[ ]+(add-trusted-cert|trust-settings-import).*/ AND NOT columns_cmdline:/.*caddy-root.*/
```

**macOS - Установка или удаление профиля конфигурации**

```
name:es_process_events AND columns_cmdline:/(.*[ \/])?profiles( .*)? (install|remove|-I|-R)( .*)?/
```

**macOS - Установка конфигурационного профиля (profiles install)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*profiles[ ]+(install|-I).*/
```

**macOS - Фишинговый запрос пароля через osascript**

```
name:es_process_events AND message:"osascript" AND message:("display dialog" OR "hidden answer")
```

**macOS - JXA-скрипт через osascript**

```
log_type:macos_osquery AND name:suspicious_processes AND columns_cmdline:/.*osascript.*-l[ ]JavaScript.*/ AND NOT columns_cmdline:(/.*CoreWLAN.*/ OR /.*URLForApplicationT.*/ OR /.*CGWindowListCopyWindowInfo.*NSRunningApplication.*NSBitmapImageFileTypePNG.*/ OR /.*iconDataURL.*NSWorkspace.*TIFFRepresentation.*base64EncodedStringWithOptions.*/)
```

**macOS - Активность AirDrop**

```
log_type:macos_unified AND processImagePath:"/usr/libexec/sharingd" AND (eventMessage:"Creating new AirDrop connection" OR eventMessage:"SDAirDropReceiveService.transfers ADD" OR eventMessage:"Received ASK request")
```

**macOS - Включение удалённого входа или Screen Sharing**

```
name:es_process_events AND message:("setremotelogin" OR "kickstart" OR "setremoteappleevents")
```

**macOS - Добавление корневого сертификата**

```
name:es_process_events AND columns_cmdline:/.*(add-trusted-cert|trust-settings-import|add-certificates).*/
```

**macOS - Загрузка launchd-задания (load, bootstrap, submit)**

```
name:es_process_events AND columns_cmdline:/.*launchctl (load|bootstrap|submit).*/ AND NOT columns_cmdline:/.*(com\.apple\.|hostdeck|org\.graylog|co\.elastic|beszel|homebrew|com\.homelab|logatlas).*/
```

**macOS - Загрузка расширения ядра**

```
name:es_process_events AND (message:"kextload" OR (columns_path:"/usr/bin/kmutil" AND message:"load"))
```

**macOS - Загрузка расширения ядра или системного расширения**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*(kextload[ ]|kmutil[ ]+load|systemextensionsctl[ ]+(install|developer)).*/
```

**macOS - Запуск программы из /tmp или /Users/Shared**

```
name:es_process_events AND columns_path:(\/tmp\/* OR \/private\/tmp\/* OR \/Users\/Shared\/* OR \/private\/var\/tmp\/*) AND NOT columns_path:(\/private\/tmp\/bzt.* OR \/private\/tmp\/bz_triage_tmp_*)
```

**macOS - Запуск утилит удалённого доступа и туннелей**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*([nN][gG][rR][oO][kK]|[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE][dD]|[aA][nN][yY][dD][eE][sS][kK]|[tT][eE][aA][mM][vV][iI][eE][wW][eE][rR]|[rR][uU][sS][tT][dD][eE][sS][kK]|[cC][hH][iI][sS][eE][lL]|[tT][aA][iI][lL][sS][cC][aA][lL][eE]|[zZ][eE][rR][oO][tT][iI][eE][rR]|[fF][rR][pP][cC]).*/
```

**macOS - Неудачная попытка sudo (неверный пароль)**

```
log_type:macos_unified AND processImagePath:"/usr/bin/sudo" AND message:"incorrect password"
```

**macOS - Остановка агентов сбора логов и защиты (launchctl)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*launchctl[ ]+(bootout|unload|remove|disable|kill).*(osquery|filebeat|graylog|bizone|bi[.]zone|velociraptor|hostdeck|socketfilterfw|endpointsecurity).*/
```

**macOS - Передача данных наружу (scp, rsync, nc, socat)**

```
name:es_process_events AND ((columns_cmdline:/(.*[ \/])?(scp|rsync)( .*)? [^ ]*@[^ ]*[.][^ ]*:.*/) OR (columns_cmdline:/(.*[ \/])?(nc|ncat|socat)( .*)?/ AND NOT columns_cmdline:/.* -l .*/)) AND NOT columns_cmdline:/.*(--server|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost|127\.0\.0\.1|<домен>).*/
```

**macOS - Поддельное окно ввода пароля (osascript hidden answer)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*osascript.*hidden[ ]+answer.*/
```

**macOS - Подключено Apple-устройство (iPhone/iPad/iPod)**

```
log_type:macos_wifi_usb AND message:(hostNotificationUSBDeviceInserted AND (iPad OR iPhone OR iPod))
```

**macOS - Подключён USB-накопитель**

```
log_type:macos_unified AND processImagePath:\/kernel AND senderImagePath:"\/System\/Library\/Extensions\/IOUSBMassStorageDriver.kext\/Contents\/MacOS\/IOUSBMassStorageDriver" AND message:start AND NOT message:(stop OR termination OR terminated)
```

**macOS - Поиск паролей в файлах (grep -r по / и ~)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*(grep|rg|find)[ ]+(-[a-zA-Z]*[rR][a-zA-Z]*[ ]+)+.*([pP][aA][sS][sS][wW][oO][rR][dD]|[pP][aA][sS][sS][wW][dD]|[sS][eE][cC][rR][eE][tT]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[aA][pP][iI][kK][eE][yY]|[iI][dD]_[rR][sS][aA]|[kK][dD][bB][xX]).*[ ](\/|~|[$]HOME|\/Users[^ ]*)/ AND NOT columns_cmdline:/.*BatchMode.*/
```

**macOS - Сканеры сети (nmap, masscan, arp-scan)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*([nN][mM][aA][pP]|[mM][aA][sS][sS][cC][aA][nN]|[aA][rR][pP]-[sS][cC][aA][nN]|[nN][eE][tT][dD][iI][sS][cC][oO][vV][eE][rR]|[nN][bB][tT][sS][cC][aA][nN]|[fF][pP][iI][nN][gG]|[zZ][mM][aA][pP]).*/
```

**macOS - Смена DNS или прокси (networksetup)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*networksetup.*-set(dnsservers|webproxy|securewebproxy|autoproxyurl|socksfirewallproxy).*/
```

**macOS - Снятие карантина вне Applications или отключение Gatekeeper**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*(spctl[ ]+--(master|global)-disable|xattr[ ]+.*-[a-z]*[dc].*)/ AND NOT columns_cmdline:/.*(\/Applications\/|hostdeck-agent).*/ AND columns_cmdline:/.*(spctl|quarantine|xattr[ ]+-[a-z]*c).*/
```

**macOS - Создание пользователя или изменение групп**

```
name:es_process_events AND columns_path:("/usr/bin/dscl" OR "/usr/sbin/sysadminctl" OR "/usr/sbin/dseditgroup") AND message:("-create" OR "-append" OR "-addUser" OR "-edit")
```

**macOS - Утилиты выгрузки в облако (rclone, MEGAsync)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*([rR][cC][lL][oO][nN][eE]|[mM][eE][gG][aA][sS][yY][nN][cC]|[mM][eE][gG][aA][cC][mM][dD]).*/
```

**macOS - Элемент входа через sfltool или osascript**

```
name:es_process_events AND columns_cmdline:/.*(sfltool|osascript.*login item|System Events.*login item).*/
```

**macOS - Выполнение команды через sudo**

```
name:sudo_commands AND -columns_uid:0
```

**macOS - Добавление элемента входа (sfltool, osascript login item)**

```
log_type:macos_osquery AND name:es_process_events AND columns_cmdline:/.*(sfltool[ ]+add|osascript.*make[ ]+login[ ]+item).*/
```

**macOS - Запись экрана на MacBook (replayd)**

```
log_type:macos_unified AND macos_processImagePath:"/usr/libexec/replayd" AND macos_eventMessage:/.*createAndStartStream.*/ AND NOT source:macminim2
```

**macOS - Открытая Wi-Fi сеть в сохранённых (сводка раз в сутки)**

```
log_type:macos_osquery AND name:wifi_history AND columns_security_type:Open
```

**macOS - Снятие карантина с приложения**

```
name:es_process_events AND columns_path:"/usr/bin/xattr" AND message:"com.apple.quarantine"
```

</details>

## macOS (BI.ZONE Triage)

снимки состояния BI.ZONE Triage; поток BiZone_macOS. Правил: 9. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Bi.Zone: неизвестный SSH-ключ в authorized_keys | высокий | BiZone_macOS<br>BI.ZONE SSHKeyInfo | В authorized_keys появился ключ, отпечатка которого нет в белом списке (14 ключей на 17.10.2026). Возможен бэкдор-доступ по SSH. | каждое событие; повтор не чаще раза в 7 сут | Persistence | `T1098.004` SSH Authorized Keys |
| Bi.Zone: новое правило в sudoers | высокий | BiZone_macOS<br>BI.ZONE SudoersInfo | В sudoers появилось правило не из белого списка (root, %admin, logatlas-collect). Возможна эскалация привилегий. | каждое событие; повтор не чаще раза в 7 сут | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Bi.Zone: новый пользователь | высокий | BiZone_macOS<br>BI.ZONE UserInfo | В системе появился пользователь с uid ≥ 500, которого нет в белом списке (igor, logatlas-collect, nobody). | каждое событие; повтор не чаще раза в 7 сут | Persistence | `T1136.001` Local Account |
| Bi.Zone: подозрительная запись в hosts | высокий | BiZone_macOS<br>BI.ZONE NetworkHostsFileInfo | В /etc/hosts появилась запись не из белого списка. Так перенаправляют обновления, антивирус или банк на чужой адрес. | каждое событие; повтор не чаще раза в 7 сут | Impact | `T1565.001` Stored Data Manipulation |
| Bi.Zone: процесс из /tmp или /Users/Shared | высокий | BiZone_macOS<br>BI.ZONE ProcessInfo | Работает процесс, исполняемый файл которого лежит во временном или общем каталоге (кроме Bi.Zone Triage). Типично для загрузчиков. | каждое событие; повтор не чаще раза в 7 сут | Execution | `T1059` Command and Scripting Interpreter |
| Bi.Zone: смена DNS-серверов | высокий | BiZone_macOS | В resolv.conf появился DNS-сервер не из белого списка. Возможна подмена DNS (перехват трафика, фишинг). | каждое событие; повтор не чаще раза в 7 сут | — | — |
| Bi.Zone: новый элемент автозагрузки | средний | BiZone_macOS<br>BI.ZONE AsepInfo | LaunchAgent/LaunchDaemon или другой элемент автозагрузки создан менее суток назад (кроме служб com.homelab.bzt-*). Классический способ закрепления. | каждое событие; повтор не чаще раза в 7 сут | Persistence | `T1543.004` Launch Daemon<br>`T1543.001` |
| Bi.Zone: опасная команда в истории оболочки | средний | BiZone_macOS<br>BI.ZONE ConsoleCommandInfo | В истории zsh/bash появилась новая опасная команда: curl \| sh, base64 -d, nc -l, csrutil/spctl disable, dump-keychain, dscl -create, /dev/tcp, снятие карантина, launchctl load. Команды,… | каждое событие; повтор не чаще раза в 30 сут | Execution | `T1059.004` Unix Shell |
| Bi.Zone: неудачные входы по SSH | низкий | BiZone_macOS<br>BI.ZONE LogonHistoryFailure | В журнале sshd есть ошибки аутентификации (по снимку Bi.Zone). Повтор не чаще раза в сутки на хост. | каждое событие; повтор не чаще раза в 1 сут | Credential Access | `T1110` Brute Force |

<details><summary>Запросы Graylog (очищенные)</summary>

**macOS - Bi.Zone: неизвестный SSH-ключ в authorized_keys**

```
mac_bz_event_type:SSHKeyInfo AND NOT auth_key_fingerprint:(<белый список>)
```

**macOS - Bi.Zone: новое правило в sudoers**

```
mac_bz_event_type:SudoersInfo AND NOT sudoers_rule:("%admin ALL = (ALL) ALL" OR "logatlas-collect ALL=(root) NOPASSWD: /usr/local/libexec/logatlas/collect.sh" OR "root ALL = (ALL) ALL")
```

**macOS - Bi.Zone: новый пользователь**

```
mac_bz_event_type:UserInfo AND usr_tgt_id:>=500 AND NOT mac_bz_user:("igor" OR "logatlas-collect" OR "nobody")
```

**macOS - Bi.Zone: подозрительная запись в hosts**

```
mac_bz_event_type:NetworkHostsFileInfo AND inventory_task_name:"LineInFileFound - Hosts Inventory" AND NOT file_match:(<белый список>)
```

**macOS - Bi.Zone: процесс из /tmp или /Users/Shared**

```
mac_bz_event_type:ProcessInfo AND proc_file_path:(\/tmp\/* OR \/private\/tmp\/* OR \/Users\/Shared\/* OR \/private\/var\/tmp\/*) AND NOT proc_file_path:(\/tmp\/bzt.* OR \/private\/tmp\/bzt.* OR \/tmp\/bz_triage_tmp_* OR \/private\/tmp\/bz_triage_tmp_* OR \/tmp\/bun-node-* OR \/private\/tmp\/bun-node-*)
```

**macOS - Bi.Zone: смена DNS-серверов**

```
inventory_task_name:"LineInFileFound - Resolv Inventory" AND file_match:nameserver* AND NOT file_match:(<белый список>)
```

**macOS - Bi.Zone: новый элемент автозагрузки**

```
mac_bz_event_type:AsepInfo AND asep_file_age:<86400 AND NOT asep_file_path:\/Library\/LaunchDaemons\/com.homelab.bzt*
```

**macOS - Bi.Zone: опасная команда в истории оболочки**

```
mac_bz_event_type:ConsoleCommandInfo AND ((message:"csrutil" AND message:"disable") OR (message:"spctl" AND message:"disable") OR (message:"base64" AND message:("-d" OR "--decode" OR "-D")) OR (message:"curl" AND message:("sh" OR "bash")) OR (message:"nc" AND message:"-l") OR message:"ncat" OR message:"dump-keychain" OR message:"find-generic-password" OR (message:"dscl" AND message:"-create") OR message:"/dev/tcp" OR (message:"xattr" AND message:"quarantine") OR (message:"launchctl" AND message:("load" OR "bootstrap"))) AND NOT cmdline:("sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-activity.plist\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-persistence.plist\\" OR "sudo launchctl load -w /System/Library/LaunchDaemons/org.net-snmp.snmpd.plist" OR "sudo launchctl load /Library/LaunchDaemons/com.wazuh.agent.plist" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-${p}.plist\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/co.elastic.filebeat.plist\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/co.elastic.filebeat.plist" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.velocidex.velociraptor.client.plist" OR "sudo launchctl load /Library/LaunchDaemons/com.velocidex.velociraptor.client.plist" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.user.logstream.plist\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-baseline.plist\\" OR "nc -l 19095 > /tmp/bz_cap.out 2>/tmp/bz_cap.err &\\" OR "nc -l 19095 > /tmp/bz_capture.out 2>/tmp/bz_capture.err &\\" OR "nc -l 5555 > /tmp/bzt_test/stream.bin" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.homelab.bzt-stream.plist 2>/dev/null \\\\" OR "sudo launchctl load /Library/LaunchDaemons/co.elastic.filebeat.plist" OR "sudo launchctl load /Library/LaunchDaemons/io.osquery.agent.plist" OR "timeout 3 bash -c 'cat < /dev/null > /dev/tcp/<IP>/9095' && echo OPEN || echo BLOCKED" OR "|| sudo launchctl load -w /Library/LaunchDaemons/com.homelab.bzt-stream.plist" OR "curl -fsSL http://<домен>:8484/setup/host.sh | sudo bash" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.velocidex.velociraptor.plist" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/io.osquery.agent.plist" OR "sudo launchctl load /Library/LaunchDaemons/com.example.bzt-collector.plist\\" OR "sudo nc -l 9999 > /tmp/bzt-test.out &" OR "launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-fast.plist" OR "launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-slow.plist" OR "nc -l 9998 > /tmp/test-nc.out" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.bzt-collector.plist\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.user.logstream.plist" OR "sudo launchctl load /Library/LaunchDaemons/com.bzt.stream.plist" OR "sudo launchctl load /Library/LaunchDaemons/com.graylog.logstream.plist" OR "sudo launchctl load /Library/LaunchDaemons/com.user.logstream.plist\\" OR "sudo launchctl load /Library/LaunchDaemons/org.syslog-ng.plist" OR "sudo nc -l 9998 > /tmp/test1.out &\\" OR "sudo nc -l 9999 > /tmp/test2.out &\\" OR "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"" OR "launchctl bootstrap" OR "nc -l 9096 > /tmp/bzt_manual.log" OR "nc -l 9999 > /tmp/local_received.json\\" OR "openssl base64 -d -A < /tmp/la-fix.b64 > /tmp/la-fix.bundle" OR "openssl base64 -d -A < /tmp/la.b64 > /tmp/logatlas-release.bundle" OR "openssl base64 -d -A < /tmp/zs-fix.b64 > /tmp/zs-fix.bundle" OR "openssl base64 -d -A < /tmp/zs.b64 > /tmp/zaslon-release.bundle" OR "sh -c \"$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)\"" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-activity.plist 2>/dev/null\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-baseline.plist 2>/dev/null\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-fast.plist\\" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/ru.bi.zone.bzt-persistence.plist 2>/dev/null\\" OR "sudo launchctl load -w /Library/LaunchDaemons/co.elastic.filebeat.plist\\" OR "sudo launchctl load /Library/LaunchDaemons/com.example.bzt-collector.plist" OR "sudo launchctl load /Library/LaunchDaemons/com.velocidex.velociraptor.client.plist\\" OR "curl -fsSL http://<домен>:8484/setup/host.sh | sudo bash" OR "grep -E \"bash|zsh|sudo|curl|python|ssh\" strings.txt | head -30\\" OR "nc -l 9095 > /tmp/bzt_listen.log" OR "strings memory.raw | grep -E \"bash|zsh|sudo|curl\" > commands.txt\\" OR "sudo launchctl bootstrap system --force /Library/LaunchDaemons/co.elastic.filebeat.plist" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.bzt-collector.plist" OR "sudo launchctl bootstrap system /Library/LaunchDaemons/com.user.streamapps.plist\\" OR "sudo launchctl load /Library/LaunchDaemons/com.user.logstream.plist" OR "sudo launchctl load /Library/LaunchDaemons/io.osquery.agent.plist\\" OR "sudo launchctl load /System/Library/LaunchDaemons/com.apple.syslogd.plist 2>/dev/null" OR "sudo launchctl load com.velocidex.velociraptor.client") AND NOT message:("<домен>" OR "downloads.graylog.org")
```

**macOS - Bi.Zone: неудачные входы по SSH**

```
mac_bz_event_type:LogonHistoryFailure AND NOT script_output:"Timestamp                       (process)[PID]"
```

</details>

## Keenetic

syslog роутера; поток Syslog Logs. Правил: 9. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Вход в админку роутера (SSH) | высокий | Syslog Logs<br>событие Keenetic SSH_Connection, SSH_Success | SSH-подключение к роутеру Keenetic с IP, не входящего в белый список (сервер мониторинга <IP> и <IP>). | каждое событие | Lateral Movement | `T1021.004` SSH |
| Отказ во входе на роутер | высокий | Syslog Logs<br>событие Keenetic Auth_Denied | Отказ в доступе к роутеру (Auth_Denied). | каждое событие | Credential Access | `T1110` Brute Force |
| ARP-конфликт на новом адресе | средний | Syslog Logs<br>событие Keenetic ARP_Conflict | Конфликт ARP (два MAC на одном IP) на адресе, которого нет среди постоянных пар. Исключены <IP>, .54, .118, .38, .117, .146, .145: у них за месяц десятки тысяч конфликтов из-за двух… | каждое событие | Credential Access | `T1557.002` ARP Cache Poisoning |
| Блокировка адреса за попытки входа в веб-интерфейс | средний | Syslog Logs | Роутер заблокировал удалённый адрес за подбор или сканирование веб-интерфейса (Netfilter Lockout, ban remote host). Адреса из интернета означают, что веб-интерфейс доступен снаружи. | каждое событие | Credential Access | `T1110` Brute Force |
| Новое устройство в сети | средний | Syslog Logs<br>событие Keenetic DHCP_Request | DHCP выдал адрес устройству, MAC которого отсутствует в белом списке (15 MAC на 17.10.2026). Возможно подключение нового клиента. | каждое событие; повтор не чаще раза в 7 сут | Initial Access | `T1200` Hardware Additions |
| Сканирование веб-интерфейса из интернета | средний | Syslog Logs | Запросы к веб-интерфейсу роутера несуществующих или служебных файлов (.env, readme.html и т. п.): типичное сканирование уязвимостей. | каждое событие | Reconnaissance | `T1595.002` Vulnerability Scanning<br>`T1190` |
| Сохранена конфигурация роутера | средний | Syslog Logs | Конфигурация роутера сохранена (StartupConfig: configuration saved). Событие редкое: сверьте, что это ваша правка. | каждое событие | Defense Impairment | `T1686` Disable or Modify System Firewall |
| Обрыв PPPoE-соединения с провайдером | низкий | Syslog Logs | Роутер потерял PPPoE-соединение с провайдером (pppd: Connection terminated или Modem hangup). Интернет пропал или роутер переподключился. | каждое событие; повтор не чаще раза в 1 ч | — | — |
| Отказы WireGuard (ежедневная сводка) | низкий | Syslog Logs<br>событие Keenetic Wireguard_Failed | Количество неудачных WireGuard-handshake за прошедшие сутки. Высокое число (сотни-тысячи) может означать подбор ключа или скан извне. Проверяется раз в сутки в 09:00, одно письмо в день. | число событий ≥ 1 за 1 сут, группировка по source | Persistence | `T1133` External Remote Services |

<details><summary>Запросы Graylog (очищенные)</summary>

**KEENETIC - Вход в админку роутера (SSH)**

```
kn_event_type:(SSH_Connection OR SSH_Success) AND NOT kn_src_ip:(<белый список>)
```

**KEENETIC - Отказ во входе на роутер**

```
kn_event_type:Auth_Denied
```

**KEENETIC - ARP-конфликт на новом адресе**

```
kn_event_type:ARP_Conflict AND NOT kn_conflict_ip:(<белый список>)
```

**KEENETIC - Блокировка адреса за попытки входа в веб-интерфейс**

```
source:"Keenetic-7625" AND message:"Lockout" AND message:"ban remote host"
```

**KEENETIC - Новое устройство в сети**

```
kn_event_type:DHCP_Request AND NOT message:STATE_RENEWING AND NOT kn_mac:(<белый список>)
```

**KEENETIC - Сканирование веб-интерфейса из интернета**

```
source:"Keenetic-7625" AND message:"Core::Scgi::Session" AND (message:"unsupported file path" OR message:"not found")
```

**KEENETIC - Сохранена конфигурация роутера**

```
source:"Keenetic-7625" AND message:"StartupConfig" AND message:"configuration saved"
```

**KEENETIC - Обрыв PPPoE-соединения с провайдером**

```
process:pppd* AND message:("Connection terminated" OR "Modem hangup")
```

**KEENETIC - Отказы WireGuard (ежедневная сводка)**

```
kn_event_type:Wireguard_Failed
```

</details>

## FreeIPA и здоровье сервисов

аудит FreeIPA и служебные проверки. Правил: 27. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Kerberos: билет службы с шифрованием RC4 (Kerberoasting) | высокий | FreeIPA Logs<br>приложение freeipa_krb5kdc | KDC выдал билет службы с шифрованием RC4. Современные клиенты просят AES, RC4 указывает на Kerberoasting или устаревший клиент. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1558.003` Kerberoasting |
| Изменение HBAC и sudo-правил (API) | высокий | FreeIPA Logs<br>приложение freeipa_httpd_error | Изменены правила доступа (HBAC) или sudo-правила. Через них выдают право входа и повышения прав на хостах домена. | каждое событие; повтор не чаще раза в 1 ч | Privilege Escalation | `T1548.003` Sudo and Sudo Caching<br>`T1098` |
| Изменение политик паролей, Kerberos и конфигурации (API) | высокий | FreeIPA Logs<br>приложение freeipa_httpd_error | Изменены политики паролей, времени жизни Kerberos-билетов, глобальная конфигурация или доверительные отношения. Так ослабляют защиту. | каждое событие; повтор не чаще раза в 1 ч | Credential Access | `T1556` Modify Authentication Process |
| Изменение привилегированных групп и ролей (API) | высокий | FreeIPA Logs<br>приложение freeipa_httpd_error | Через API изменены роли, привилегии или группа admins. Так повышают права в домене. | каждое событие; повтор не чаще раза в 1 ч | Privilege Escalation | `T1098` Account Manipulation |
| Остановка служб IPA на сервере (dirsrv, krb5kdc, httpd, pki) | высокий | RedOS auditd Logs<br>auditd SERVICE_STOP | На сервере FreeIPA остановлена одна из служб домена. Без неё не работают вход, DNS и сертификаты. | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Подбор пароля (10+ PREAUTH_FAILED за 5 мин) | высокий | FreeIPA Logs | Серия отказов предварительной аутентификации Kerberos на DC. Возможен подбор пароля доменной учётной записи (password spray). | число событий ≥ 10 за 5 мин, группировка по source | Credential Access | `T1110.001` Password Guessing |
| Клиенты не могут связаться с KDC | высокий | RedOS auditd Logs | На хостах auditd/sssd сообщает "Cannot contact any KDC for realm". Признак того, что контроллер домена FreeIPA упал или недоступен по сети. | каждое событие | — | — |
| Kerberos: вход отключённой, заблокированной или просроченной учётной записи | средний | FreeIPA Logs<br>приложение freeipa_krb5kdc | KDC отказал: учётная запись отключена, заблокирована, или истёк срок ключа. Использование чужих или забытых учётных записей. | каждое событие; повтор не чаще раза в 1 ч | Initial Access | `T1078` Valid Accounts |
| Выпуск сертификата в CA (Dogtag) | средний | FreeIPA Logs<br>приложение freeipa_389_audit | Запрос на выпуск сертификата через CA FreeIPA (Dogtag). Выпуски должны происходить только при добавлении новых сервисов/хостов. Внезапный массовый выпуск — повод проверить. | каждое событие | Credential Access | `T1649` Steal or Forge Authentication Certificates |
| Изменение пользователей, групп и правил через API | средний | FreeIPA Logs<br>приложение freeipa_httpd_error | Администратор FreeIPA изменил пользователей, группы, правила HBAC или sudo, роли, пароли или хосты через API. В журнале записаны только такие вызовы, чтения (show, find) не учитываются.… | каждое событие | Persistence | `T1098` Account Manipulation<br>`T1136` |
| Массовая выгрузка из каталога LDAP (100+ записей за запрос) | средний | FreeIPA Logs<br>приложение freeipa_389_access | Один LDAP-запрос вернул сто и более записей. Разведка по каталогу или выгрузка учётных записей. | каждое событие; повтор не чаще раза в 1 ч | Discovery | `T1087.002` Domain Account<br>`T1018` |
| Неудачный вход в веб-интерфейс | средний | FreeIPA Logs<br>приложение freeipa_httpd_access | Веб-интерфейс FreeIPA ответил 401 на вход по паролю. Одиночный случай значит опечатку, серия значит подбор пароля. | каждое событие | Credential Access | `T1110` Brute Force |
| Прямое изменение атрибутов безопасности в каталоге (389) | средний | FreeIPA Logs<br>приложение freeipa_389_audit | В журнале аудита 389 DS изменён атрибут блокировки, пароля или ключа Kerberos. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1098` Account Manipulation |
| Разблокировка учётной записи, ключи и сертификаты пользователя (API) | средний | FreeIPA Logs<br>приложение freeipa_httpd_error | Разблокирована или включена учётная запись, изменены OTP-токены, сертификаты или альтернативные имена пользователя. | каждое событие; повтор не чаще раза в 1 ч | Persistence | `T1098` Account Manipulation |
| Сбои certmonger (продление сертификатов) | средний | FreeIPA Logs | Certmonger не смог продлить или получить сертификат. Сертификаты сервера могут истечь, после чего FreeIPA перестанет работать. | каждое событие; повтор не чаще раза в 1 сут | — | — |
| Тишина: <хост> не шлёт логи (час) | средний | MacOS Logs | За последний час от <хост> не пришло ни одного сообщения. Агент сбора остановился, Mac выключен или пропала сеть. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: FreeIPA (3 часа) | средний | FreeIPA Logs | За 3 часа не пришло ни одного сообщения от FreeIPA. Сервер или доставка логов остановились. | число событий < 1 за 3 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: HomeRepo (3 часа) | средний | HomeRepo | За 3 часа панель HomeRepo не прислала ни одного пульса (hr_event=heartbeat, уходит раз в час от сторожа панели). Панель, служба homerepo-web или доставка GELF остановились — проверить… | число событий < 1 за 3 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: HostDeck (3 часа) | средний | HostDeck | За 3 часа панель HostDeck не прислала ни одного пульса (hd_event=heartbeat, уходит раз в час от панели). Панель, контейнер hostdeck или доставка GELF остановились — проверить сервер.… | число событий < 1 за 3 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: Keenetic не шлёт логи (час) | средний | Syslog Logs | За последний час от роутера не пришло ни одного сообщения. Роутер или связь с Graylog отвалились. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: TrafficLens (3 часа) | средний | TrafficLens | За 3 часа сервис TrafficLens не прислал ни одного пульса (tl_event=heartbeat, уходит раз в час). Контейнер trafficlens или доставка GELF остановились — проверить сервер. Пока сервис… | число событий < 1 за 3 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: ZaSlon (3 часа) | средний | ZaSlon | За 3 часа панель ZaSlon не прислала ни одного пульса (zs_event=heartbeat, уходит раз в час от панели). Панель, контейнер zaslon или доставка GELF остановились — проверить сервер. Пока… | число событий < 1 за 3 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: auditd на <хост> (час) | средний | RedOS auditd Logs | За последний час от <хост> не пришло ни одного события auditd. Служба или доставка логов остановились. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Kerberos: расхождение часов (CLOCK_SKEW) | низкий | FreeIPA Logs<br>приложение freeipa_krb5kdc | Клиент отправил запрос с расхождением часов больше допустимого. Kerberos перестанет работать для этого хоста. | каждое событие; повтор не чаще раза в 1 ч | — | — |
| Успешный вход в веб-интерфейс | низкий | FreeIPA Logs<br>приложение freeipa_httpd_access | Успешный вход по паролю в веб-интерфейс FreeIPA. Входов мало (около 10 в месяц), все видны. | каждое событие; повтор не чаще раза в 1 ч | Initial Access | `T1078` Valid Accounts |
| Тишина: <хост> не шлёт логи (3 часа) | низкий | MacOS Logs | За 3 часа от <хост> не пришло ни одного сообщения. Ноутбук мог уснуть или выключиться, поэтому приоритет низкий. | число событий < 1 за 3 ч; повтор не чаще раза в 1 сут | — | — |
| Тишина: macOS (сутки) | низкий | MacOS Logs | За сутки не пришло ни одного сообщения от Mac-хостов. Агент сбора остановился или все Mac выключены. | число событий < 1 за 1 сут; повтор не чаще раза в 1 сут | — | — |

<details><summary>Запросы Graylog (очищенные)</summary>

**FREEIPA - Kerberos: билет службы с шифрованием RC4 (Kerberoasting)**

```
application_name:freeipa_krb5kdc AND message:"TGS_REQ" AND message:ISSUE AND message:"rep=arcfour"
```

**FREEIPA - Изменение HBAC и sudo-правил (API)**

```
application_name:freeipa_httpd_error AND message:"ipa: INFO" AND message:(hbacrule_add OR hbacrule_mod OR hbacrule_del OR hbacrule_add_user OR hbacrule_add_host OR hbacrule_add_service OR hbacrule_enable OR hbacrule_disable OR sudorule_add OR sudorule_mod OR sudorule_del OR sudorule_add_user OR sudorule_add_host OR sudorule_add_option OR sudorule_add_allow_command OR sudorule_enable OR sudorule_disable)
```

**FREEIPA - Изменение политик паролей, Kerberos и конфигурации (API)**

```
application_name:freeipa_httpd_error AND message:"ipa: INFO" AND message:(pwpolicy_add OR pwpolicy_mod OR pwpolicy_del OR krbtpolicy_mod OR krbtpolicy_reset OR config_mod OR trust_add OR trust_del)
```

**FREEIPA - Изменение привилегированных групп и ролей (API)**

```
application_name:freeipa_httpd_error AND message:"ipa: INFO" AND (message:(role_add_member OR role_remove_member OR privilege_add_member OR privilege_remove_member OR role_add_privilege OR privilege_add_permission) OR (message:(group_add_member OR group_mod OR group_remove_member) AND message:admins))
```

**FREEIPA - Остановка служб IPA на сервере (dirsrv, krb5kdc, httpd, pki)**

```
audit_type:SERVICE_STOP AND source:server AND message:(krb5kdc OR kadmin OR httpd OR dirsrv* OR pki* OR named* OR ipa*)
```

**FREEIPA - Подбор пароля (10+ PREAUTH_FAILED за 5 мин)**

```
message:PREAUTH_FAILED
```

**HEALTH - Клиенты не могут связаться с KDC**

```
message:"Cannot contact any KDC"
```

**FREEIPA - Kerberos: вход отключённой, заблокированной или просроченной учётной записи**

```
application_name:freeipa_krb5kdc AND message:(CLIENT_REVOKED OR KEY_EXP OR LOCKED_OUT OR DISABLED)
```

**FREEIPA - Выпуск сертификата в CA (Dogtag)**

```
application_name:freeipa_389_audit AND message:cert--005frequest
```

**FREEIPA - Изменение пользователей, групп и правил через API**

```
application_name:freeipa_httpd_error AND message:"ipa: INFO" AND message:(user_add OR user_del OR user_mod OR user_disable OR group_add OR group_del OR group_mod OR group_add_member OR group_remove_member OR passwd OR cert_revoke OR otptoken_add OR host_add OR host_del OR service_add)
```

**FREEIPA - Массовая выгрузка из каталога LDAP (100+ записей за запрос)**

```
application_name:freeipa_389_access AND ldap_nentries:/[0-9]{3,}/
```

**FREEIPA - Неудачный вход в веб-интерфейс**

```
application_name:freeipa_httpd_access AND message:"login_password http 1.1 401"
```

**FREEIPA - Прямое изменение атрибутов безопасности в каталоге (389)**

```
application_name:freeipa_389_audit AND message:("replace: nsAccountLock" OR "add: nsAccountLock" OR "replace: userPassword" OR "replace: krbPrincipalKey")
```

**FREEIPA - Разблокировка учётной записи, ключи и сертификаты пользователя (API)**

```
application_name:freeipa_httpd_error AND message:"ipa: INFO" AND message:(user_unlock OR user_enable OR user_undel OR user_stage OR otptoken_mod OR otptoken_del OR user_add_cert OR user_add_certmapdata OR user_add_principal)
```

**FREEIPA - Сбои certmonger (продление сертификатов)**

```
message:certmonger AND NOT message:ansible* AND message:("Cannot contact" OR CA_UNREACHABLE OR NEED_GUIDANCE OR CA_REJECTED OR "ca-error")
```

**HEALTH - Тишина: <хост> не шлёт логи (час)**

```
source:macminim2
```

**HEALTH - Тишина: FreeIPA (3 часа)**

```
*
```

**HEALTH - Тишина: HomeRepo (3 часа)**

```
hr_event:heartbeat
```

**HEALTH - Тишина: HostDeck (3 часа)**

```
hd_event:heartbeat
```

**HEALTH - Тишина: Keenetic не шлёт логи (час)**

```
*
```

**HEALTH - Тишина: TrafficLens (3 часа)**

```
tl_event:heartbeat
```

**HEALTH - Тишина: ZaSlon (3 часа)**

```
zs_event:heartbeat
```

**HEALTH - Тишина: auditd на <хост> (час)**

```
source:<хост>
```

**FREEIPA - Kerberos: расхождение часов (CLOCK_SKEW)**

```
application_name:freeipa_krb5kdc AND message:CLOCK_SKEW
```

**FREEIPA - Успешный вход в веб-интерфейс**

```
application_name:freeipa_httpd_access AND message:"login_password http 1.1 200"
```

**HEALTH - Тишина: <хост> не шлёт логи (3 часа)**

```
source:macbook-pro
```

**HEALTH - Тишина: macOS (сутки)**

```
*
```

</details>

## Контейнеры

Docker-логи через promtail и Filebeat; поток Containers. Правил: 18. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Контейнеры: Grafana — неудачный вход (подбор пароля) | высокий | Containers<br>контейнер grafana | Больше 5 неудачных входов в Grafana за 5 минут. | число событий > 5 за 5 мин, группировка по container_name; повтор не чаще раза в 1 ч | Credential Access | `T1110` Brute Force |
| Контейнеры: нехватка памяти или падение процесса | высокий | Containers | В логах контейнера OOM, Killed process, segfault или core dumped. | число событий > 0 за 5 мин, группировка по container_name; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: перезапуски MariaDB | высокий | Containers<br>контейнер observiumdb | Больше 2 запусков entrypoint MariaDB (контейнер observiumdb) за 15 минут — цикл перезапусков БД Observium. | число событий > 2 за 15 мин, группировка по container_name | — | — |
| Контейнеры: тишина — atrium | высокий | Containers<br>контейнер atrium | Контейнер atrium не прислал ни одного сообщения за час — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — grafana | высокий | Containers<br>контейнер grafana | Контейнер grafana не прислал ни одного сообщения за час — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — komodo_mongo_1 | высокий | Containers<br>контейнер komodo_mongo_1 | Контейнер komodo_mongo_1 не прислал ни одного сообщения за час — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — loki | высокий | Containers<br>контейнер loki | Контейнер loki не прислал ни одного сообщения за час — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — netalertx | высокий | Containers<br>контейнер netalertx | Контейнер netalertx не прислал ни одного сообщения за час — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — wazuh.dashboard | высокий | Containers<br>контейнер wazuh.dashboard | Контейнер wazuh.dashboard не прислал ни одного сообщения за час — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — zaslon | высокий | Containers<br>контейнер zaslon | Контейнер zaslon не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 15 мин; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: тишина — нет логов ни от одного контейнера | высокий | Containers | Поток Containers не получил ни одного сообщения за 10 минут — упал input «Podman Logs», Graylog или все хосты разом. | число событий < 1 за 10 мин; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: Loki — ошибки приёма | средний | Containers<br>контейнер loki | Loki пишет level=error (например, write operation failed). | число событий > 0 за 15 мин, группировка по container_name; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: MongoDB — ошибки | средний | Containers<br>контейнер komodo_mongo_1 | Сообщение уровня E (ошибка) в логе MongoDB (komodo_mongo_1). | число событий > 0 за 10 мин, группировка по container_name; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: netalertx — новое устройство в сети | средний | Containers<br>контейнер netalertx | Скан netalertx нашёл новые устройства (New Devices больше нуля). | число событий > 0 за 5 мин, группировка по container_name; повтор не чаще раза в 1 ч | Initial Access | `T1200` Hardware Additions |
| Контейнеры: promtail не доставляет логи в Loki | средний | Containers<br>контейнер promtail | Больше 15 ошибок «context deadline exceeded» за 10 минут на одном хосте — promtail не может записать в Loki. | число событий > 15 за 10 мин, группировка по source; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: всплеск ошибок | средний | Containers | Больше 10 реальных ошибок за 5 минут в одном контейнере: loglevel error/warn/fatal (loki/promtail) или ключевые слова error/fatal/panic/exception/traceback в message. Исключены cadvisor,… | число событий > 10 за 5 мин, группировка по container_name | — | — |
| Контейнеры: ошибки прав доступа | средний | Containers | Больше 50 сообщений Operation not permitted за 10 минут | число событий > 50 за 10 мин, группировка по container_name | — | — |
| Контейнеры: netalertx — всплеск объёма логов | низкий | Containers<br>контейнер netalertx | Больше чем втрое выше обычного: более 4500 сообщений netalertx за 15 минут (норма около 1500). | число событий > 4500 за 15 мин, группировка по container_name; повтор не чаще раза в 1 ч | — | — |

<details><summary>Запросы Graylog (очищенные)</summary>

**Контейнеры: Grafana — неудачный вход (подбор пароля)**

```
container_name:grafana AND (message:"Invalid username or password" OR message:"Failed to authenticate" OR message:"login attempt failed")
```

**Контейнеры: нехватка памяти или падение процесса**

```
message:("out of memory" OR OOM OR "Killed process" OR segfault OR "core dumped") AND _exists_:container_name
```

**Контейнеры: перезапуски MariaDB**

```
container_name:observiumdb AND message:"Entrypoint script"
```

**Контейнеры: тишина — atrium**

```
container_name:"atrium"
```

**Контейнеры: тишина — grafana**

```
container_name:"grafana"
```

**Контейнеры: тишина — komodo_mongo_1**

```
container_name:"komodo_mongo_1"
```

**Контейнеры: тишина — loki**

```
container_name:"loki"
```

**Контейнеры: тишина — netalertx**

```
container_name:"netalertx"
```

**Контейнеры: тишина — wazuh.dashboard**

```
container_name:"wazuh.dashboard"
```

**Контейнеры: тишина — zaslon**

```
container_name:"zaslon"
```

**Контейнеры: тишина — нет логов ни от одного контейнера**

```
*
```

**Контейнеры: Loki — ошибки приёма**

```
container_name:loki AND loglevel:error
```

**Контейнеры: MongoDB — ошибки**

```
container_name:komodo_mongo_1 AND log_s:E
```

**Контейнеры: netalertx — новое устройство в сети**

```
container_name:netalertx AND message:"Scan Stats" AND message:"New Devices" AND NOT message:"New Devices 0"
```

**Контейнеры: promtail не доставляет логи в Loki**

```
message:"context deadline exceeded" AND container_name:promtail
```

**Контейнеры: всплеск ошибок**

```
(loglevel:(error OR warn OR fatal) OR message:(error OR fatal OR panic OR exception OR traceback)) AND _exists_:container_name AND NOT container_name:(cadvisor OR fluent-bit OR promtail)
```

**Контейнеры: ошибки прав доступа**

```
message:"Operation not permitted" AND _exists_:container_name
```

**Контейнеры: netalertx — всплеск объёма логов**

```
container_name:netalertx
```

</details>

## Экосистема и служебные правила

AUDIT, HOMEREPO, HOSTDECK, TRAFFICLENS, ZASLON, CANARY, COWRIE, DIFFWATCH, DIGEST, LABSCORE, LOGATLAS и SANDBOX. Правил: 41. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Запуск программы из временного каталога | высокий | RedOS auditd Logs | Выполнен бинарник или скрипт из /tmp, /var/tmp или /dev/shm — классическое место распаковки дропперов и малвари. Команда и аргументы — в тексте события (EXECVE). | ОТКЛЮЧЕНО; каждое событие | — | — |
| Изменение файлов учётных записей | высокий | RedOS auditd Logs | Изменены /etc/passwd, /etc/shadow, /etc/group или /etc/gshadow — создание или правка учётной записи (persistence). Файл и операция — в тексте события. | ОТКЛЮЧЕНО; каждое событие | — | — |
| Работа с модулями ядра | высокий | RedOS auditd Logs | Запущены insmod/modprobe/rmmod или изменён /etc/modprobe.d — загрузка или выгрузка модулей ядра (rootkit-активность). Команда — в тексте события. | каждое событие | — | — |
| Логин в ловушку | высокий | Canary | Кто-то ввёл логин/пароль в ловушку canary (Telnet 2323 или HTTP Basic 8081). Легитимных обращений к ловушке нет: это сканер с подбором паролей или злоумышленник в сети. Логин и пароль —… | каждое событие | — | — |
| Открытие honeytoken-файла | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ honeytoken | Чтение канареечного файла (passwords.xlsx, backup_credentials.txt) — признак разведки или компрометации хоста | число событий ≥ 1 за 1 мин, группировка по source | — | — |
| Команда в honeypot | высокий | Cowrie | Внутри honeypot выполнена команда: разведка (uname, ip a), закачка (wget/curl), запуск вредоноса. Текст команды — в поле input, адрес — src_ip. | каждое событие | — | — |
| Скачивание файла в honeypot | высокий | Cowrie | Злоумышленник скачал файл внутрь honeypot (wget/curl) — адрес и URL в полях события, файл сохранён в var/lib/cowrie/downloads. URL и хэш — готовые IOC для TrafficLens. | каждое событие | — | — |
| Успешный вход в honeypot | высокий | Cowrie | Злоумышленник подобрал пароль и вошёл в SSH/Telnet honeypot (порт 2222/2223). Логин, пароль, адрес и клиент (hassh) — в полях события; дальше обычно следуют команды разведки. | каждое событие | — | — |
| Изменение автозагрузки (unit/cron) | высокий | DiffWatch | DiffWatch: добавление/удаление/изменение systemd-юнита или crontab — возможное закрепление | каждое событие | — | — |
| Новый открытый порт | высокий | DiffWatch | DiffWatch: появился слушающий порт — кто-то поднял сервис на хосте | каждое событие | — | — |
| Переподпись, удаление пакетов или смена ключа репозитория | высокий | HomeRepo | В HomeRepo переподписаны пакеты (в том числе чужие), удалены пакеты или изменён ключ подписи. Всё, что подписано ключом репозитория, устройства установят без вопросов: такие действия… | каждое событие | Initial Access | `T1195.002` Compromise Software Supply Chain |
| Подбор пароля к панели (5+ неудачных входов за 10 мин) | высокий | HomeRepo | Пять и более неудачных входов в панель HomeRepo с одного адреса за 10 минут. Панель хранит репозиторий, которому доверяют все устройства, поэтому подбор к ней — повод разобраться сразу. | число событий ≥ 5 за 10 мин, группировка по hr_client_ip; повтор не чаще раза в 1 ч | Credential Access | `T1110` Brute Force |
| Подбор пароля (5+ неудачных входов за 10 мин) | высокий | HostDeck | Пять и более неудачных входов в HostDeck за 10 минут. У HostDeck есть консоль root, поэтому учётная запись администратора — ценная цель. | число событий ≥ 5 за 10 мин, группировка по hd_detail; повтор не чаще раза в 1 ч | Credential Access | `T1110` Brute Force |
| Проверка безопасности перешла в fail | высокий | HostDeck | Проверка HostDeck на хосте перешла в fail с учётом профиля и исключений: выключено шифрование диска, хост выпал из домена, SELinux или межсетевой экран выключены, вышли обновления… | каждое событие; повтор не чаще раза в 1 ч | Defense Impairment | `T1685` Disable or Modify Tools |
| Находка высокой важности в разборе журналов | высокий | LogAtlas | LogAtlas разобрал архив журналов хоста, и сработало правило критичной или высокой важности (встроенное или импортированное правило Sigma). Хост — la_host, правило — la_rule_title, когда… | каждое событие | — | — |
| Подозрительное поведение файла | высокий | Sandbox | Песочница-мини: у образца сетевые обращения, работа с системными путями, дочерние процессы или URL по IP-литералу | каждое событие | — | — |
| Адрес из базы IOC в логах хостов | высокий | Syslog Logs, WindowsLogs, RedOS auditd Logs | Правило pipeline сверило адрес из логов (бан Keenetic, вход в Linux, вход в Windows) с lookup table trafficlens-iocs, которую TrafficLens отдаёт по HTTP, и поставило tl_ioc_hit=true.… | каждое событие; повтор не чаще раза в 1 ч | Command and Control | `T1071` Application Layer Protocol |
| Компрометация по итогам анализа трафика | высокий | TrafficLens | TrafficLens разобрал запись трафика (загрузка или живой захват) и выставил итог «Компрометация»: есть совпадение с IOC, сигнатура Suricata высокой важности или файл из базы. Причины и… | каждое событие | — | — |
| Обращение к индикатору компрометации | высокий | TrafficLens | В трафике найдено обращение к индикатору из базы TrafficLens с уверенностью не ниже 70: адрес, домен, URL, хэш файла или отпечаток JA3/JA4. Где найдено — поле tl_contexts, какие хосты —… | каждое событие; повтор не чаще раза в 1 ч | Command and Control | `T1071` Application Layer Protocol |
| Ретропроверка: прошлый трафик совпал с новым IOC | высокий | TrafficLens | Индикатор появился в базе после анализа, а трафик с ним уже был: TrafficLens перепроверил прошлые задачи после обновления IOC. Когда это было в трафике — поле tl_seen_ts. | каждое событие | Command and Control | `T1071` Application Layer Protocol |
| firewalld остановлен из панели | высокий | ZaSlon | Через ZaSlon остановлена служба firewalld: хост остался без межсетевого экрана. Если остановка с таймером отката не была подтверждена, ZaSlon вернёт службу сам (zs_op:tx_rollback). | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Подбор пароля к панели (5+ неудачных входов за 10 мин) | высокий | ZaSlon | Пять и более неудачных входов в панель ZaSlon с одного адреса за 10 минут. Своего ограничения частоты входа у панели нет, поэтому подбор замечает Graylog. Адрес клиента — поле… | число событий ≥ 5 за 10 мин, группировка по zs_client_ip; повтор не чаще раза в 1 ч | Credential Access | `T1110` Brute Force |
| Base64-декодирование в командной строке | средний | RedOS auditd Logs | В командной строке выполнено base64 -d/--decode — обфускация команд (часто связка echo BASE64 \| base64 -d \| bash). Команда — в тексте события. | каждое событие | — | — |
| Изменение systemd-юнитов | средний | RedOS auditd Logs | Изменены юниты systemd (/etc/systemd/system или ~/.config/systemd/user) — установка сервиса (persistence). Файл — в тексте события. | каждое событие | — | — |
| Изменение расписаний cron | средний | RedOS auditd Logs | Изменены файлы cron (/etc/cron.d, /etc/crontab, /var/spool/cron) — создание или правка задачи (persistence). Файл — в тексте события. | ОТКЛЮЧЕНО; каждое событие | — | — |
| Касание ловушки | средний | Canary | TCP-подключение к порту-ловушке canary (SMB 445, MSSQL 1433, MySQL 3306, VNC 5900, Redis 6379, Memcached 11211, Docker API 2375 и др.). Легитимных обращений к ловушке нет: это… | каждое событие | — | — |
| Изменение состава пакетов | средний | DiffWatch | DiffWatch: установка или удаление пакетов на хосте | каждое событие | — | — |
| Агент молчит больше суток | средний | HomeRepo | Сторож HomeRepo: устройство не выходило на связь с панелью дольше суток — агент остановлен, хост выключен или сеть недоступна. Пока устройство молчит, напоминание приходит раз в сутки;… | каждое событие | Defense Evasion | `T1562.001` Disable or Modify Tools |
| Деградация: молчат 3+ агентов | средний | HomeRepo | Пульс панели HomeRepo сообщает, что молчат 3 или больше агентов (hr_hosts_silent >= 3). Панель жива, но парк агентов деградирует — проверить, кто отвалился, на дашборде «Пульс… | число событий ≥ 1 за 9 ч; повтор не чаще раза в 1 сут | — | — |
| Новое устройство в сети | средний | HomeRepo | Сканер HomeRepo нашёл адрес, которого раньше не видел: адрес, MAC, производитель, имя, открытые порты. Первое сканирование подсети событий не создаёт. | каждое событие | Initial Access | `T1200` Hardware Additions |
| Пользователи, роли и токены | средний | HomeRepo | Создан или удалён пользователь, изменена роль, сброшен или сменён пароль, создан или удалён токен API, выдан доступ Ansible. | каждое событие | Persistence | `T1098` Account Manipulation |
| Деградация: провалов проверок 3+ | средний | HostDeck | Пульс панели HostDeck сообщает о 3 или больше провалах проверок безопасности (hd_checks_failing >= 3). Панель жива, но состояние парка деградирует — открыть HostDeck и разобрать… | число событий ≥ 1 за 9 ч; повтор не чаще раза в 1 сут | — | — |
| Открыта консоль root в браузере | средний | HostDeck | Из HostDeck открыта консоль root на хосте (или в ней отказано). Действие редкое и мощное: стоит знать о каждом. | каждое событие | Execution | `T1059.004` Unix Shell |
| SELinux переведён в permissive или disabled из панели | средний | ZaSlon | Через ZaSlon SELinux на хосте переведён в разрешающий режим или отключён. Это легитимное действие администратора, но защита хоста ослаблена: событие позволяет отличить его от setenforce… | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Утренний дайджест экосистемы | низкий | — | Скрипт morning-digest.py на <хост> (systemd-таймер, 08:47 YEKT) присылает GELF-сообщение dg_event=digest с пульсами инструментов и сводкой алертов за сутки; это правило превращает его в… | каждое событие | — | — |
| Агент вернулся на связь | низкий | HomeRepo | Агент снова шлёт heartbeat — TicketBridge автоматически закрывает открытый тикет инцидента. | каждое событие | — | — |
| Проверка безопасности перешла в warn | низкий | HostDeck | Проверка HostDeck перешла в warn с учётом профиля и исключений. Без письма: для разбора на странице Alerts & Events. | каждое событие | — | — |
| Риск принят: добавлено исключение | низкий | HostDeck | В HostDeck добавлено исключение для проверки: её отклонение больше не попадает в итог и в алерты. Событие для учёта принятых рисков. | каждое событие | — | — |
| Еженедельный отчёт зрелости | низкий | Lab Score | Lab Score: правила, срабатывания за неделю, покрытие HomeWiki, техники MITRE — одним письмом | каждое событие | — | — |
| Подозрительный трафик | низкий | TrafficLens | Итог анализа «Подозрительно»: эвристики (маячки, крупные выгрузки, невалидный TLS, нестандартные порты) без сильных признаков. Событие без уведомления, для разбора на странице Alerts &… | каждое событие | — | — |
| Изменения доверия: пароль панели, добавление и удаление хостов | низкий | ZaSlon | Сменён пароль администратора панели, добавлен, зарегистрирован или удалён управляемый хост. Редкие действия, после которых меняется круг доверия ZaSlon. | каждое событие | Persistence | `T1098` Account Manipulation |

<details><summary>Запросы Graylog (очищенные)</summary>

**AUDIT - Запуск программы из временного каталога**

```
audit AND EXECVE AND ("/tmp/" OR "/var/tmp/" OR "/dev/shm/")
```

**AUDIT - Изменение файлов учётных записей**

```
audit AND PATH AND ("/etc/passwd" OR "/etc/shadow" OR "/etc/group" OR "/etc/gshadow")
```

**AUDIT - Работа с модулями ядра**

```
audit AND (insmod OR modprobe OR rmmod)
```

**CANARY - Логин в ловушку**

```
tool:canary AND event:auth
```

**CANARY - Открытие honeytoken-файла**

```
audit_type:SYSCALL AND key:honeytoken AND success:yes AND syscall:(2 OR 5 OR 56 OR 257 OR 295 OR 437) AND NOT exe:"/var/ossec/bin/wazuh-syscheckd"
```

**COWRIE - Команда в honeypot**

```
tool:cowrie AND event:"cowrie.command.input"
```

**COWRIE - Скачивание файла в honeypot**

```
tool:cowrie AND event:"cowrie.session.file_download"
```

**COWRIE - Успешный вход в honeypot**

```
tool:cowrie AND event:"cowrie.login.success"
```

**DIFFWATCH - Изменение автозагрузки (unit/cron)**

```
tool:diffwatch AND (dw_kind:unit OR dw_kind:cron)
```

**DIFFWATCH - Новый открытый порт**

```
tool:diffwatch AND dw_kind:port AND dw_event:added
```

**HOMEREPO - Переподпись, удаление пакетов или смена ключа репозитория**

```
hr_event:audit AND hr_action:(package_resign OR resign_foreign OR package_delete OR repo_key)
```

**HOMEREPO - Подбор пароля к панели (5+ неудачных входов за 10 мин)**

```
hr_event:audit AND hr_action:login_failed
```

**HOSTDECK - Подбор пароля (5+ неудачных входов за 10 мин)**

```
hd_event:audit AND hd_action:login-failed
```

**HOSTDECK - Проверка безопасности перешла в fail**

```
hd_event:check_changed AND hd_effective:fail
```

**LOGATLAS - Находка высокой важности в разборе журналов**

```
la_event:finding AND la_severity:(critical OR high)
```

**SANDBOX - Подозрительное поведение файла**

```
tool:sandbox AND sb_event:alert
```

**TRAFFICLENS - Адрес из базы IOC в логах хостов**

```
tl_ioc_hit:true
```

**TRAFFICLENS - Компрометация по итогам анализа трафика**

```
tl_event:verdict AND tl_level:critical
```

**TRAFFICLENS - Обращение к индикатору компрометации**

```
tl_event:ioc_hit AND tl_ioc_conf:>=70
```

**TRAFFICLENS - Ретропроверка: прошлый трафик совпал с новым IOC**

```
tl_event:retro_hit
```

**ZASLON - firewalld остановлен из панели**

```
zs_op:firewalld_set AND zs_ok:true AND zs_arg_running:false
```

**ZASLON - Подбор пароля к панели (5+ неудачных входов за 10 мин)**

```
zs_op:login_failed
```

**AUDIT - Base64-декодирование в командной строке**

```
audit AND EXECVE AND base64 AND ("-d" OR "--decode")
```

**AUDIT - Изменение systemd-юнитов**

```
audit AND PATH AND ("/etc/systemd/system" OR "config/systemd")
```

**AUDIT - Изменение расписаний cron**

```
audit AND PATH AND cron
```

**CANARY - Касание ловушки**

```
tool:canary AND event:connect
```

**DIFFWATCH - Изменение состава пакетов**

```
tool:diffwatch AND dw_kind:package
```

**HOMEREPO - Агент молчит больше суток**

```
hr_event:agent_silent
```

**HOMEREPO - Деградация: молчат 3+ агентов**

```
hr_event:heartbeat AND hr_hosts_silent:[3 TO *]
```

**HOMEREPO - Новое устройство в сети**

```
hr_event:device_new
```

**HOMEREPO - Пользователи, роли и токены**

```
hr_event:audit AND hr_action:(user_create OR user_delete OR user_role OR user_reset_password OR password_changed OR token_create OR token_delete OR ansible_access)
```

**HOSTDECK - Деградация: провалов проверок 3+**

```
hd_event:heartbeat AND hd_checks_failing:[3 TO *]
```

**HOSTDECK - Открыта консоль root в браузере**

```
hd_event:audit AND hd_action:(term-open OR term-denied)
```

**ZASLON - SELinux переведён в permissive или disabled из панели**

```
zs_op:selinux_mode AND zs_ok:true AND zs_arg_mode:(permissive OR disabled)
```

**DIGEST - Утренний дайджест экосистемы**

```
dg_event:digest
```

**HOMEREPO - Агент вернулся на связь**

```
hr_event:agent_recovered
```

**HOSTDECK - Проверка безопасности перешла в warn**

```
hd_event:check_changed AND hd_effective:warn
```

**HOSTDECK - Риск принят: добавлено исключение**

```
hd_event:audit AND hd_action:exception-set
```

**LABSCORE - Еженедельный отчёт зрелости**

```
tool:labscore AND ls_event:weekly
```

**TRAFFICLENS - Подозрительный трафик**

```
tl_event:verdict AND tl_level:suspicious
```

**ZASLON - Изменения доверия: пароль панели, добавление и удаление хостов**

```
zs_op:(admin_password OR host_add OR host_enroll OR host_remove)
```

</details>

## Как читать таблицы

| Колонка | Смысл |
|---|---|
| Приоритет | Приоритет события в Graylog: высокий (3), средний (2), низкий (1). Низкие чаще уходят сводкой, а не отдельным письмом |
| Источник логов | Поток Graylog и ключевые поля запроса: тип записи auditd, `EventID`, имя таблицы osquery, тип события Keenetic и т. п. |
| Что проверяет | Первое предложение описания правила |
| Корреляция | «каждое событие» — алерт на любое совпадение. «число событий ≥ N за M мин» — агрегация с порогом и группировкой. «повтор не чаще раза в …» — пауза (grace period), в течение которой одно и то же событие повторно не отправляется |
| Тактика, техника | MITRE ATT&CK v20 (Enterprise). В ячейке «Техника» первой стоит основная, ниже через запятую дополнительные |

Проверка приблизительна там, где в [таблице соответствий](../graylog/mitre/attack-mapping.md) стоит «низкая» уверенность: такие привязки стоит перепроверять.

## Как обновить каталог

1. Откройте Graylog в браузере (залогиньтесь), F12 → Console, вставьте [`graylog/detections/export-catalog.js`](../graylog/detections/export-catalog.js) целиком и выполните `await exportCatalog()`. Браузер скачает `detections-source.json`: очищенные определения без IP, MAC и белых списков.
2. Положите файл в `graylog/detections/` вместо старого.
3. Запустите `python3 graylog/detections/build_catalog.py`: обновятся эта страница и `graylog/detections/catalog.csv`.

Новое правило появится в каталоге само, как только оно создано в Graylog; тактика и техника берутся из полей `mitre_tactic`, `mitre_technique`, `mitre_techniques` в определении (см. [graylog/mitre](../graylog/mitre/README.md)).
