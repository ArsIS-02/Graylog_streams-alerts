# Каталог детектов Graylog

> Все правила (event definitions) лаборатории в одном месте: какой лог проверяется, по какому условию, как коррелируются события, к какой тактике и технике MITRE ATT&CK относятся. Всего **123** правил, из них **103** привязаны к технике ATT&CK v20 (82 разных техник). Остальные описывают здоровье сервисов и тишину в логах: атак они не ловят.

Страница собирается скриптом из выгрузки Graylog и руками не правится: [как обновить](#как-обновить-каталог). Запросы очищены: IP, MAC, отпечатки ключей и белые списки заменены на `<IP>`, `<MAC>`, `<белый список>`. Готовые определения для импорта лежат в `graylog/*-event-definitions.json`, соответствие техникам подробно описано в [graylog/mitre](../graylog/mitre/README.md).

## Содержание

- [Покрытие: тактики × платформы](#покрытие-тактики--платформы)
- [Windows](#windows) — 29
- [Linux](#linux) — 26
- [macOS (osquery и unified log)](#macos-osquery-и-unified-log) — 30
- [macOS (BI.ZONE Triage)](#macos-bizone-triage) — 9
- [Keenetic](#keenetic) — 8
- [FreeIPA и здоровье сервисов](#freeipa-и-здоровье-сервисов) — 3
- [Контейнеры](#контейнеры) — 18
- [Как читать таблицы](#как-читать-таблицы)
- [Как обновить каталог](#как-обновить-каталог)

## Покрытие: тактики × платформы

Основная тактика правила — первая из записанных в событии (поле `mitre_tactic`). Пустая ячейка означает, что правил на эту тактику на платформе нет.

| Тактика | Windows | Linux | macOS | Keenetic | FreeIPA | Контейнеры | Всего |
|---|---|---|---|---|---|---|---|
| Reconnaissance (Разведка) |  |  |  | 1 |  |  | **1** |
| Initial Access (Первоначальный доступ) | 1 | 1 | 3 | 1 |  | 1 | **7** |
| Execution (Выполнение) | 6 | 3 | 6 |  |  |  | **15** |
| Persistence (Закрепление) | 7 | 6 | 8 | 1 |  |  | **22** |
| Privilege Escalation (Повышение привилегий) |  | 3 | 6 |  |  |  | **9** |
| Stealth (Скрытность) | 3 | 2 | 2 |  |  |  | **7** |
| Defense Impairment (Подавление защиты) | 4 | 4 | 4 | 1 |  |  | **13** |
| Credential Access (Доступ к учётным данным) | 4 | 1 | 3 | 3 | 2 | 1 | **14** |
| Discovery (Исследование среды) | 1 | 1 |  |  |  |  | **2** |
| Lateral Movement (Перемещение) | 1 |  | 1 | 1 |  |  | **3** |
| Collection (Сбор данных) |  |  | 1 |  |  |  | **1** |
| Command and Control (управление, C2) | 1 | 2 | 1 |  |  |  | **4** |
| Exfiltration (Вывод данных) |  |  | 1 |  |  |  | **1** |
| Impact (Воздействие) | 1 | 2 | 1 |  |  |  | **4** |
| Без техники (служебные) |  | 1 | 2 |  | 1 | 16 | **20** |
| **Всего** | **29** | **26** | **39** | **8** | **3** | **18** | **123** |

## Windows

Sysmon, Security, PowerShell, Defender; поток WindowsLogs. Правил: 29. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Defender обнаружил угрозу или отключён | высокий | WindowsLogs<br>EventID 1116, 1117, 5001, 5010, 5012 | Defender обнаружил или обезвредил угрозу (1116, 1117) либо защита в реальном времени отключена (5001, 5010, 5012). | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Office, wscript или mshta создал исполняемый файл | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 11 | Sysmon 11: Office, wscript, cscript или mshta записал exe, dll, scr, hta, js, vbs, ps1 или bat в Temp, AppData, Public, ProgramData, Downloads, PerfLogs. powershell не включён: он… | каждое событие | Execution | `T1204.002` Malicious File<br>`T1105` |
| PowerShell с закодированной командой | высокий | WindowsLogs<br>EventID 1 | PowerShell запущен с -EncodedCommand или декодирует Base64. Так прячут вредоносные скрипты. | каждое событие | Execution | `T1059.001` PowerShell<br>`T1027.010` |
| PowerShell скачивает и исполняет код | высокий | WindowsLogs<br>EventID 4104 | Script Block Logging (4104): DownloadString, Net.WebClient, Invoke-WebRequest или IEX. Типичный загрузчик. | каждое событие | Execution | `T1059.001` PowerShell<br>`T1105` |
| wscript, cscript, mshta или regsvr32 ходит во внешнюю сеть | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 3 | Sysmon 3: исходящее соединение на внешний IP от wscript, cscript, mshta или regsvr32. Эти программы почти не ходят в сеть сами, поэтому соединение похоже на загрузчик или канал… | каждое событие | Stealth | `T1218` System Binary Proxy Execution<br>`T1071.001` |
| Вход из неизвестной сети (4624, тип 3 или 10) | высокий | WindowsLogs<br>канал Security, EventID 4624 | Сетевой вход (тип 3) или RDP (тип 10) с адреса, которого нет в справочнике homelab-subnets (поле src_zone не заполнено). Требует pipeline «homelab: windows enrichment» и обновлённую… | каждое событие | Initial Access | `T1078` Valid Accounts<br>`T1021` |
| Дамп учётных данных (reg save, comsvcs, ntdsutil) | высокий | WindowsLogs<br>EventID 1 | Выгрузка кустов SAM/SECURITY/SYSTEM через reg save, дамп памяти через comsvcs.dll MiniDump или копирование NTDS через ntdsutil. | каждое событие | Credential Access | `T1003.002` Security Account Manager<br>`T1003.001`, `T1003.003` |
| Добавление в локальные администраторы (командная строка) | высокий | WindowsLogs<br>EventID 1 | net localgroup administrators /add или Add-LocalGroupMember. Дополняет алерт по событиям 4728/4732 для случаев, когда аудит групп отключён. | каждое событие | Persistence | `T1098` Account Manipulation |
| Доступ к памяти LSASS | высокий | WindowsLogs<br>EventID 10 | Процесс открыл память lsass.exe (Sysmon 10). Типичный признак кражи учётных данных (mimikatz, procdump). | каждое событие | Credential Access | `T1003.001` LSASS Memory |
| Изменение группы «Администраторы домена» | высокий | WindowsLogs | Добавление или удаление учётной записи в группе «Администраторы домена» (net group). Критично: высшие привилегии в домене. | каждое событие | Persistence | `T1098` Account Manipulation |
| Изменение привилегированных групп и учёток | высокий | WindowsLogs<br>EventID 4720, 4726, 4728, 4732, 4756, 4740, 4724 | Создание/удаление учётки (4720, 4726), сброс пароля (4724), добавление в привилегированную группу (4728, 4732, 4756) или блокировка (4740). Требует включённого аудита управления учётными… | каждое событие | Persistence | `T1098` Account Manipulation |
| Именованные каналы C2 (Cobalt Strike и аналоги) | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 17, 18 | Sysmon 17/18: имена каналов, характерные для Cobalt Strike (msagent_*, postex_*, status_*, MSSE-*-server). Каналы нужны для связи бекона и инъекций. | каждое событие | Stealth | `T1055` Process Injection |
| Исключения или отключение защиты Defender | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1, EventID 13 | Команда Add-/Set-MpPreference с исключениями или отключением мониторинга, либо запись в ключ Windows Defender\Exclusions (Sysmon 13). | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Командная оболочка запущена через WMI | высокий | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 1 | Sysmon 1: WmiPrvSE.exe породил cmd, powershell, wscript, cscript, mshta или rundll32. Так работает удалённое выполнение через WMI (wmic /node, Impacket wmiexec). | каждое событие | Execution | `T1047` Windows Management Instrumentation |
| Отключение Firewall (netsh или PS) | высокий | WindowsLogs<br>EventID 1 | Запуск «netsh advfirewall … disable» или PowerShell «Disable-NetFirewall…». Атакующий отключает брандмауэр, чтобы открыть сетевые соединения. | каждое событие | Defense Impairment | `T1686.003` Windows Host Firewall |
| Офисное приложение запустило оболочку | высокий | WindowsLogs<br>EventID 1 | Word/Excel/Outlook/PowerPoint запустили cmd, powershell, wscript, cscript или mshta. Характерно для вредоносных макросов. | каждое событие | Execution | `T1204.002` Malicious File<br>`T1059` |
| Очистка журнала событий | высокий | WindowsLogs<br>EventID 1102, 104 | Журнал Security (1102) или System (104) очищен. Почти всегда признак заметания следов. | каждое событие | Defense Impairment | `T1685.005` Clear Windows Event Logs |
| Подбор пароля (5+ ошибок входа 4625 за 5 мин) | высокий | WindowsLogs<br>EventID 4625 | 5 и более неудачных входов (Event ID 4625) на одном хосте за 5 минут. Возможен брутфорс, в том числе учётной записи администратора. | число событий ≥ 5 за 5 мин, группировка по source | Credential Access | `T1110` Brute Force |
| Создание/удаление локального пользователя (net user) | высокий | WindowsLogs<br>EventID 1 | Создан или удалён локальный пользователь командой net user /add или /delete (Sysmon Event 1). | каждое событие | Persistence | `T1136.001` Local Account |
| Удаление теневых копий | высокий | WindowsLogs<br>EventID 1 | Удаление теневых копий или отключение восстановления (vssadmin, wmic shadowcopy, bcdedit). Типичный шаг шифровальщика. | каждое событие | Impact | `T1490` Inhibit System Recovery |
| DNS-запрос к туннелям и файлообменникам | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 22 | Sysmon 22: запрос к ngrok, pastebin, transfer.sh, trycloudflare, duckdns, anonfiles, serveo. Через них обходят периметр и забирают данные. | каждое событие | Command and Control | `T1572` Protocol Tunneling<br>`T1102` |
| LOLBins (certutil, mshta, bitsadmin, regsvr32) | средний | WindowsLogs<br>EventID 1 | Системные утилиты в роли загрузчика: certutil -urlcache, mshta, bitsadmin, regsvr32 /i:http (Squiblydoo). | каждое событие | Stealth | `T1218` System Binary Proxy Execution<br>`T1218.005`, `T1218.010`, `T1105` |
| Автозагрузка через ключ реестра Run | средний | WindowsLogs<br>EventID 13 | Запись в ключ CurrentVersion\Run (Sysmon 13) не известным приложением. Классический способ закрепления. | каждое событие | Persistence | `T1547.001` Registry Run Keys / Startup Folder |
| Закрепление через IFEO Debugger, AppInit_DLLs и Winlogon | средний | WindowsLogs<br>канал Microsoft-Windows-Sysmon/Operational, EventID 12, 13 | Sysmon 12/13: значения Debugger, GlobalFlag и VerifierDlls в Image File Execution Options, AppInit_DLLs, Winlogon Shell и Userinit. RunOnce и MitigationOptions не включены: их постоянно… | каждое событие | Persistence | `T1546.012` Image File Execution Options Injection<br>`T1546.010`, `T1547.004` |
| Новая служба | средний | WindowsLogs<br>EventID 7045, 4697 | Установлена новая служба (7045, 4697), кроме драйверов Kaspersky. Частый способ закрепления. | каждое событие | Persistence | `T1543.003` Windows Service |
| Перебор несуществующих пользователей (5+ за 10 мин) | средний | WindowsLogs<br>EventID 4625 | 5 и более неудачных входов с одного IP за 10 минут с причиной «пользователь не существует» (SubStatus 0xc0000064): перебор имён учёток. | число событий ≥ 5 за 10 мин, группировка по IpAddress | Credential Access | `T1110` Brute Force<br>`T1087` |
| Создание задачи через schtasks | средний | WindowsLogs<br>EventID 1 | Запланированная задача создана командой schtasks /create. Частый способ закрепления и запуска. | каждое событие | Execution | `T1053.005` Scheduled Task |
| Вход по RDP | низкий | WindowsLogs<br>EventID 4624 | Успешный интерактивный вход по RDP (4624, LogonType 10). | каждое событие | Lateral Movement | `T1021.001` Remote Desktop Protocol |
| Серия разведки (5+ команд за 5 мин) | низкий | WindowsLogs<br>EventID 1 | 5 и более запусков net, whoami, nltest, systeminfo, quser, arp на одном хосте за 5 минут — типичная разведка после проникновения. | число событий ≥ 5 за 5 мин, группировка по source | Discovery | `T1082` System Information Discovery |

<details><summary>Запросы Graylog (очищенные)</summary>

**Windows - Defender обнаружил угрозу или отключён**

```
win_event_id:(1116 OR 1117 OR 5001 OR 5010 OR 5012)
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

**Windows - wscript, cscript, mshta или regsvr32 ходит во внешнюю сеть**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:3 AND win_image:/.*\\(wscript|cscript|mshta|regsvr32)\.exe/ AND winlogbeat_winlog_event_data_Initiated:true AND _exists_:winlogbeat_winlog_event_data_DestinationIp AND NOT winlogbeat_winlog_event_data_DestinationIp:(10.* OR 192.168.* OR 127.* OR 169.254.* OR fe80* OR "::1" OR fc* OR fd* OR /172\.(1[6-9]|2[0-9]|3[01])\..*/)
```

**Windows - Вход из неизвестной сети (4624, тип 3 или 10)**

```
win_channel:Security AND win_event_id:4624 AND winlogbeat_winlog_event_data_LogonType:(3 OR 10) AND _exists_:winlogbeat_winlog_event_data_IpAddress AND NOT winlogbeat_winlog_event_data_IpAddress:(<белый список>) AND NOT _exists_:src_zone
```

**Windows - Дамп учётных данных (reg save, comsvcs, ntdsutil)**

```
win_event_id:1 AND (message:("reg save hklm sam" OR "reg save hklm security" OR "reg save hklm system" OR "reg.exe save hklm sam" OR "reg.exe save hklm security" OR "reg.exe save hklm system" OR "reg save hkey_local_machine sam" OR "reg save hkey_local_machine security" OR "reg save hkey_local_machine system") OR (message:"comsvcs.dll" AND message:minidump) OR (message:"ntdsutil.exe" AND message:(ifm OR ntds)))
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

**Windows - Закрепление через IFEO Debugger, AppInit_DLLs и Winlogon**

```
win_channel:"Microsoft-Windows-Sysmon/Operational" AND win_event_id:(12 OR 13) AND winlogbeat_winlog_event_data_TargetObject:/.*(Image File Execution Options\\[^\\]+\\(Debugger|GlobalFlag|VerifierDlls)|\\AppInit_DLLs|CurrentVersion\\Winlogon\\(Userinit|Shell))/
```

**Windows - Новая служба**

```
win_event_id:(7045 OR 4697) AND NOT winlogbeat_winlog_event_data_ServiceName:Kaspersky*
```

**Windows - Перебор несуществующих пользователей (5+ за 10 мин)**

```
win_event_id:4625 AND winlogbeat_winlog_event_data_SubStatus:0xc0000064
```

**Windows - Создание задачи через schtasks**

```
win_event_id:1 AND message:"schtasks" AND message:"/create"
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

auditd на RED OS; поток RedOS auditd Logs. Правил: 26. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Брутфорс SSH (5+ неудачных входов за 5 мин) | высокий | RedOS auditd Logs | 5 и более неудачных SSH-аутентификаций на одном хосте за 5 минут. Возможен подбор пароля. | число событий ≥ 5 за 5 мин, группировка по source | Credential Access | `T1110` Brute Force |
| Вход по SSH из неизвестной сети | высокий | RedOS auditd Logs<br>auditd USER_LOGIN | Успешный вход по SSH (USER_LOGIN) с адреса вне справочника homelab-subnets (поле src_zone не заполнено). Требует pipeline «homelab: linux enrichment»: он достаёт IP из addr= и ищет сеть… | каждое событие | Initial Access | `T1078` Valid Accounts<br>`T1021.004` |
| Добавление SSH-ключа в authorized_keys | высокий | RedOS auditd Logs | Запись в файл authorized_keys. Возможно добавление SSH-ключа для постоянного доступа. Проверьте, кто изменил файл и легитимен ли ключ. | число событий > 0 за 5 мин, группировка по source | Persistence | `T1098.004` SSH Authorized Keys |
| Добавление/удаление пользователя | высокий | RedOS auditd Logs<br>auditd ADD_USER, auditd DEL_USER | На хосте успешно добавлен или удалён локальный пользователь. В исходных сообщениях: учётка и инициатор (auid). | число событий > 0 за 5 мин, группировка по source | Persistence | `T1136.001` Local Account |
| Запуск из /tmp, /dev/shm, /var/tmp | высокий | RedOS auditd Logs<br>auditd EXECVE | EXECVE: программа запущена из /tmp, /dev/shm или /var/tmp, либо интерпретатор (sh, bash, dash, python, perl) исполняет оттуда скрипт. Скрипты Wazuh `execute-*.sh` исключены. Так обычно… | каждое событие | Execution | `T1059.004` Unix Shell<br>`T1036` |
| Затирание следов (shred, history, truncate логов) | высокий | RedOS auditd Logs<br>auditd EXECVE | Уничтожение файлов через shred, работа с .bash_history или обрезка логов в /var/log. Типичное заметание следов после атаки. | каждое событие | Stealth | `T1070` Indicator Removal<br>`T1070.003`, `T1685.006` |
| Изменение /etc/passwd, shadow, group | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ etcpasswd, etcgroup, opasswd | Запись или смена атрибутов файлов учётных записей (/etc/passwd, /etc/shadow, /etc/group, /etc/security/opasswd) вне штатных служб. Возможно создание скрытой учётки или смена пароля. | каждое событие | Persistence | `T1098` Account Manipulation |
| Изменение sshd_config | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ sshd | Изменение конфигурации SSH-сервера. Возможны включение входа root, паролей или подмена AuthorizedKeysFile. | каждое событие | Defense Impairment | `T1556` Modify Authentication Process |
| Массовое удаление файлов (200+ за 5 мин) | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ file_deletion | Один процесс удалил 200 и более файлов за 5 минут (обычный максимум в лаборатории около 30). Так выглядит затирание данных или шифровальщик. | число событий ≥ 200 за 5 мин, группировка по source, exe | Impact | `T1485` Data Destruction<br>`T1070.004` |
| Обратная оболочка (/dev/tcp) | высокий | RedOS auditd Logs<br>auditd EXECVE | В командной строке использован /dev/tcp — типичный приём reverse shell в bash. | каждое событие | Execution | `T1059.004` Unix Shell |
| Обратная оболочка (python, perl, nc, socat, mkfifo) | высокий | RedOS auditd Logs<br>auditd PROCTITLE | Командная строка с типовыми обратными оболочками: python -c с socket, perl -e с socket, nc -e, mkfifo, socat с exec:, bash -i с перенаправлением. Дополняет алерт на /dev/tcp. | каждое событие | Execution | `T1059.004` Unix Shell<br>`T1571` |
| Отключение аудита или удаление правил auditd | высокий | RedOS auditd Logs<br>auditd CONFIG_CHANGE | Удалено правило auditd или аудит отключён (audit_enabled=0). Атакующий может ослеплять мониторинг. | каждое событие | Defense Impairment | `T1685.004` Disable or Modify Linux Audit System Log |
| Установка setuid или setgid | высокий | RedOS auditd Logs<br>auditd SYSCALL, ключ perm_modification | chmod, fchmod, fchmodat с битом setuid (04000) или setgid (02000). Исключены systemd-tmpfiles, rpm и dnf: их установки штатно выставляют такие права. | каждое событие | Privilege Escalation | `T1548.001` Setuid and Setgid |
| SSH-туннель (-R, -L, -D) | средний | RedOS auditd Logs<br>auditd PROCTITLE | Запуск ssh с пробросом портов (-R, -L, -D). Так выводят внутренние сервисы наружу или строят прокси. | каждое событие | Command and Control | `T1572` Protocol Tunneling<br>`T1090` |
| Загрузка модуля ядра | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ kernel_modules, kernel_modules_config | Загрузка или смена конфигурации модулей ядра (init_module, finit_module, modprobe). Вредоносные модули (руткиты) загружаются так же; штатные загрузки драйверов (udev) тоже попадают сюда,… | каждое событие | Persistence | `T1547.006` Kernel Modules and Extensions |
| Закрепление через cron | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ cron_persistence | Запись в каталоги и файлы cron (crontab, /etc/cron.*, /var/spool/cron). | каждое событие | Persistence | `T1053.003` Cron |
| Закрепление через systemctl enable | средний | RedOS auditd Logs<br>auditd EXECVE | Служба добавлена в автозапуск командой systemctl enable. Проверьте, что это ожидаемая служба. | каждое событие | Persistence | `T1543.002` Systemd Service |
| Изменение прав доступа (chmod) | средний | RedOS auditd Logs<br>auditd SYSCALL | Изменение прав доступа через chmod (кроме uid 1001). В исходных сообщениях: режим, файл и пользователь. | число событий > 0 за 5 мин, группировка по source | Defense Impairment | `T1222.002` Linux and Mac Permissions |
| Исполнение из памяти (memfd_create) | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ anon_file_create | Создан анонимный файл в памяти (memfd_create). Так работают fileless-загрузчики; легитимно — некоторые AppImage. | каждое событие | Stealth | `T1620` Reflective Code Loading |
| Неудачная попытка sudo | средний | RedOS auditd Logs | Неудачная аутентификация sudo: неверный пароль или отказ PAM/SSSD. Возможен подбор пароля или ошибка пользователя. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Остановка службы (systemctl stop) | средний | RedOS auditd Logs<br>auditd EXECVE | Остановка системной службы через systemctl stop. Имя службы: аргумент a2 в исходных сообщениях. | число событий > 0 за 5 мин, группировка по source | Impact | `T1489` Service Stop |
| Подозрительные утилиты (base64, nc, socat, scp) | средний | RedOS auditd Logs<br>auditd SYSCALL, ключ susp_activity | Запуск утилит, часто используемых для передачи и кодирования данных: base64, nc, socat, scp. | каждое событие | Command and Control | `T1105` Ingress Tool Transfer<br>`T1140` |
| Изменение правил firewall (iptables, nft) | низкий | RedOS auditd Logs<br>auditd SYSCALL, ключ sbin_susp | Запуск iptables/nft. Обычно Docker или firewalld, но так же отключают защиту. | каждое событие | Defense Impairment | `T1686` Disable or Modify System Firewall |
| Использование sudo | низкий | RedOS auditd Logs<br>auditd EXECVE | Выполнение команды через sudo (кроме служебного пользователя). Команда собирается из аргументов a0 a1 a2 a3 в исходных сообщениях. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Отказ SELinux (AVC) | низкий | RedOS auditd Logs<br>auditd AVC | SELinux запретил действие процессу. Может указывать на попытку обхода политики или на ошибку настройки. | каждое событие | — | — |
| Разведка (id, whoami) | низкий | RedOS auditd Logs<br>auditd SYSCALL, ключ recon | Запуск команд разведки системы. Сами по себе безобидны, важны в связке с другими событиями. | каждое событие | Discovery | `T1033` System Owner/User Discovery |

<details><summary>Запросы Graylog (очищенные)</summary>

**LNX - Брутфорс SSH (5+ неудачных входов за 5 мин)**

```
(message:"sshd-session" AND message:"Authentication failure") OR (message:"sshd" AND message:"Failed password")
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

**LNX - Обратная оболочка (python, perl, nc, socat, mkfifo)**

```
audit_type:PROCTITLE AND proctitle:/.*(python[0-9.]* -c .*socket|perl -e .*socket|nc(at)? .* -e |mkfifo |socat .*exec:|bash -i .*>&).*/
```

**LNX - Отключение аудита или удаление правил auditd**

```
audit_type:CONFIG_CHANGE AND (op:remove_rule OR message:"audit_enabled=0")
```

**LNX - Установка setuid или setgid**

```
audit_type:SYSCALL AND key:perm_modification AND ((syscall:(53 OR 268) AND a2:/[4-9a-f][0-9a-f]{2}/) OR (syscall:(52 OR 90 OR 91) AND a1:/[4-9a-f][0-9a-f]{2}/)) AND NOT exe:("/usr/bin/systemd-tmpfiles" OR "/usr/bin/rpm" OR "/usr/bin/dnf" OR "/usr/bin/dnf5")
```

**LNX - SSH-туннель (-R, -L, -D)**

```
audit_type:PROCTITLE AND proctitle:/(.*[ \/])?ssh( .*)? -[RLD] ?[^ ]+.*/
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

**LNX - Остановка службы (systemctl stop)**

```
audit_type:EXECVE AND a0:"systemctl" AND a1:"stop"
```

**LNX - Подозрительные утилиты (base64, nc, socat, scp)**

```
key:susp_activity AND audit_type:SYSCALL AND NOT exe:("/usr/bin/netstat" OR "/usr/bin/curl" OR "/usr/bin/ssh")
```

**LNX - Изменение правил firewall (iptables, nft)**

```
key:sbin_susp AND audit_type:SYSCALL
```

**LNX - Использование sudo**

```
audit_type:EXECVE AND a0:"sudo" AND NOT uid:<служебный> AND NOT a2="<служебный агент>"
```

**LNX - Отказ SELinux (AVC)**

```
audit_type:AVC AND NOT comm:(<исключения>)
```

**LNX - Разведка (id, whoami)**

```
key:recon AND audit_type:SYSCALL AND NOT exe:(<белый список>)
```

</details>

## macOS (osquery и unified log)

osquery Endpoint Security и unified log; поток MacOS Logs. Правил: 30. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Вмешательство в TCC | высокий | MacOS Logs<br>osquery es_process_events | Сброс разрешений приватности (tccutil) или прямой доступ к базе TCC.db. | каждое событие | Privilege Escalation | `T1548.006` TCC Manipulation |
| Выгрузка паролей из Keychain | высокий | MacOS Logs<br>osquery es_process_events | Команда security читает пароли из Keychain (dump-keychain, find-generic-password, find-internet-password). Типично для стилеров. | каждое событие | Credential Access | `T1555.001` Keychain |
| Изменение /etc/sudoers | высокий | MacOS Logs<br>osquery file_events | Изменён файл /etc/sudoers, задающий права суперпользователя. Возможна эскалация привилегий. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Изменение базы авторизации (authorizationdb) | высокий | MacOS Logs<br>osquery es_process_events | security authorizationdb: правка прав на системные действия. Позволяет выполнять привилегированные операции без пароля. | каждое событие | Privilege Escalation | `T1548` Abuse Elevation Control Mechanism |
| Копирование данных браузера | высокий | MacOS Logs<br>osquery es_process_events | sqlite3, cp, cat, strings, tar, zip или python, работающие с Login Data, Cookies.binarycookies, key4.db, logins.json, Local State. Видны только команды, чтение файлов самим процессом не… | каждое событие | Credential Access | `T1555.003` Credentials from Web Browsers |
| Новый/изменённый plist в автозагрузке | высокий | MacOS Logs<br>osquery file_events | Создан, изменён или удалён plist в LaunchDaemons/LaunchAgents (кроме com.apple.*). Типичный способ закрепления (persistence). | число событий > 0 за 5 мин, группировка по source | Persistence | `T1543.004` Launch Daemon<br>`T1543.001` |
| Обратная оболочка (/dev/tcp, pty.spawn) | высокий | MacOS Logs<br>osquery es_process_events | В командной строке /dev/tcp, pty.spawn или socket.socket — признаки reverse shell. | каждое событие | Execution | `T1059.004` Unix Shell |
| Отключение SIP или Gatekeeper | высокий | MacOS Logs<br>osquery es_process_events | Попытка отключить SIP (csrutil disable) или Gatekeeper (spctl --master-disable). Резко снижает защищённость системы. | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools |
| Отключение межсетевого экрана (socketfilterfw, pfctl) | высокий | MacOS Logs<br>osquery es_process_events | socketfilterfw с --set… off либо pfctl с ключами -d, -F, -f, -e. Включение режима stealth (on) не срабатывает. | каждое событие | Defense Impairment | `T1686` Disable or Modify System Firewall |
| Очистка журналов | высокий | MacOS Logs<br>osquery es_process_events | log erase, log config, rm в /var/log или diagnostics, killall syslogd, truncate логов. Так заметают следы. | каждое событие | Stealth | `T1070.002` Clear Linux or Mac System Logs<br>`T1070` |
| Подключено мобильное устройство (не Apple) | высокий | MacOS Logs<br>журнал macos_wifi_usb | По USB подключено мобильное устройство не Apple (isApple N). Возможна попытка первоначального доступа. | каждое событие | Initial Access | `T1200` Hardware Additions |
| Подмена библиотек (DYLD_INSERT_LIBRARIES) | высокий | MacOS Logs<br>osquery es_process_events | DYLD_INSERT_LIBRARIES в окружении или командной строке процесса: внедрение динамической библиотеки. | каждое событие | Persistence | `T1574.006` Dynamic Linker Hijacking |
| Подозрительный процесс открыл TCP-порт | высокий | MacOS Logs<br>osquery listening_ports | nc/ncat/python/bash/sh начал слушать нестандартный порт. Возможен бэкдор или reverse shell. | каждое событие | Command and Control | `T1571` Non-Standard Port |
| Скачивание и запуск (curl \| sh) | высокий | MacOS Logs<br>osquery es_process_events | curl или wget с конвейером в sh, bash, zsh либо bash -c "$(curl …)". Типичный способ запустить загруженный скрипт без файла. | каждое событие | Execution | `T1059.004` Unix Shell<br>`T1105` |
| Установка или удаление профиля конфигурации | высокий | MacOS Logs<br>osquery es_process_events | Запуск profiles с install, remove, -I или -R. Профили конфигурации ставят прокси, сертификаты и VPN, отключают защиту. Штатные `profiles list` и `profiles status` не попадают. | каждое событие | Defense Impairment | `T1685` Disable or Modify Tools<br>`T1553.004` |
| Фишинговый запрос пароля через osascript | высокий | MacOS Logs<br>osquery es_process_events | osascript показывает диалог со скрытым вводом — так вредоносы выманивают пароль пользователя. | каждое событие | Collection | `T1056.002` GUI Input Capture |
| Активность AirDrop | средний | MacOS Logs<br>журнал macos_unified | Передача или приём через AirDrop (sharingd). Возможна утечка данных. | число событий ≥ 1 за 5 мин, группировка по source | — | — |
| Включение удалённого входа или Screen Sharing | средний | MacOS Logs<br>osquery es_process_events | systemsetup -setremotelogin, kickstart ARD или setremoteappleevents — открытие удалённого доступа к Маку. | каждое событие | Lateral Movement | `T1021.004` SSH<br>`T1021.005` |
| Добавление корневого сертификата | средний | MacOS Logs<br>osquery es_process_events | security add-trusted-cert, trust-settings-import или add-certificates: сертификат становится доверенным в системе. Так подготавливают перехват TLS. | каждое событие | Stealth | `T1553.004` Install Root Certificate |
| Загрузка launchd-задания (load, bootstrap, submit) | средний | MacOS Logs<br>osquery es_process_events | launchctl load, bootstrap или submit для заданий вне исключений (Apple, hostdeck, Graylog, Elastic, beszel, Homebrew, homelab, logatlas). Так запускают закреплённые задания. | каждое событие | Execution | `T1569.001` Launchctl<br>`T1543.004` |
| Загрузка расширения ядра | средний | MacOS Logs<br>osquery es_process_events | Загрузка kext через kextload или kmutil load. | каждое событие | Persistence | `T1547.006` Kernel Modules and Extensions |
| Запуск программы из /tmp или /Users/Shared | средний | MacOS Logs<br>osquery es_process_events | Исполняемый файл запущен из временного или общего каталога (кроме Bi.Zone Triage). Типично для загрузчиков. | каждое событие | Execution | `T1059` Command and Scripting Interpreter |
| Неудачная попытка sudo (неверный пароль) | средний | MacOS Logs<br>журнал macos_unified | При выполнении sudo введён неверный пароль. Возможен подбор пароля. | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Передача данных наружу (scp, rsync, nc, socat) | средний | MacOS Logs<br>osquery es_process_events | scp или rsync на user@host с точкой в имени, а также nc, ncat, socat без -l, если адрес не из частных сетей и не в monitoring.test. | каждое событие | Exfiltration | `T1048` Exfiltration Over Alternative Protocol |
| Подключено Apple-устройство (iPhone/iPad/iPod) | средний | MacOS Logs<br>журнал macos_wifi_usb | По USB подключено и распознано Apple-устройство (wifi.log, hostNotificationUSBDeviceInserted). | каждое событие | Initial Access | `T1200` Hardware Additions |
| Подключён USB-накопитель | средний | MacOS Logs<br>журнал macos_unified | Ядро распознало USB-накопитель (IOUSBMassStorageDriver): флешку или внешний диск. | число событий > 0 за 5 мин, группировка по source | Initial Access | `T1200` Hardware Additions<br>`T1052.001` |
| Создание пользователя или изменение групп | средний | MacOS Logs<br>osquery es_process_events | dscl, sysadminctl или dseditgroup создают пользователя или меняют членство в группах (в т.ч. admin). | каждое событие | Persistence | `T1136.001` Local Account<br>`T1098` |
| Элемент входа через sfltool или osascript | средний | MacOS Logs<br>osquery es_process_events | Добавление Login Items командами sfltool или osascript (System Events, login item). Закрепление без plist; дополняет алерт на LaunchAgents. | каждое событие | Persistence | `T1547.015` Login Items |
| Выполнение команды через sudo | низкий | MacOS Logs<br>osquery sudo_commands | Выполнение команды с повышенными привилегиями через sudo (не от root). | число событий > 0 за 5 мин, группировка по source | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Снятие карантина с приложения | низкий | MacOS Logs<br>osquery es_process_events | С файла снят атрибут com.apple.quarantine — Gatekeeper не проверит приложение при запуске. | каждое событие | Defense Impairment | `T1553.001` Gatekeeper Bypass |

<details><summary>Запросы Graylog (очищенные)</summary>

**macOS - Вмешательство в TCC**

```
name:es_process_events AND message:("tccutil" OR "TCC.db")
```

**macOS - Выгрузка паролей из Keychain**

```
name:es_process_events AND message:("dump-keychain" OR "find-generic-password" OR "find-internet-password" OR "export-keychain")
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

**macOS - Установка или удаление профиля конфигурации**

```
name:es_process_events AND columns_cmdline:/(.*[ \/])?profiles( .*)? (install|remove|-I|-R)( .*)?/
```

**macOS - Фишинговый запрос пароля через osascript**

```
name:es_process_events AND message:"osascript" AND message:("display dialog" OR "hidden answer")
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

**macOS - Запуск программы из /tmp или /Users/Shared**

```
name:es_process_events AND columns_path:(\/tmp\/* OR \/private\/tmp\/* OR \/Users\/Shared\/* OR \/private\/var\/tmp\/*) AND NOT columns_path:(\/private\/tmp\/bzt.* OR \/private\/tmp\/bz_triage_tmp_*)
```

**macOS - Неудачная попытка sudo (неверный пароль)**

```
log_type:macos_unified AND processImagePath:"/usr/bin/sudo" AND message:"incorrect password"
```

**macOS - Передача данных наружу (scp, rsync, nc, socat)**

```
name:es_process_events AND ((columns_cmdline:/(.*[ \/])?(scp|rsync)( .*)? [^ ]*@[^ ]*[.][^ ]*:.*/) OR (columns_cmdline:/(.*[ \/])?(nc|ncat|socat)( .*)?/ AND NOT columns_cmdline:/.* -l .*/)) AND NOT columns_cmdline:/.*(--server|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|localhost|127\.0\.0\.1|monitoring\.test).*/
```

**macOS - Подключено Apple-устройство (iPhone/iPad/iPod)**

```
log_type:macos_wifi_usb AND message:(hostNotificationUSBDeviceInserted AND (iPad OR iPhone OR iPod))
```

**macOS - Подключён USB-накопитель**

```
log_type:macos_unified AND processImagePath:\/kernel AND senderImagePath:"\/System\/Library\/Extensions\/IOUSBMassStorageDriver.kext\/Contents\/MacOS\/IOUSBMassStorageDriver"
```

**macOS - Создание пользователя или изменение групп**

```
name:es_process_events AND columns_path:("/usr/bin/dscl" OR "/usr/sbin/sysadminctl" OR "/usr/sbin/dseditgroup") AND message:("-create" OR "-append" OR "-addUser" OR "-edit")
```

**macOS - Элемент входа через sfltool или osascript**

```
name:es_process_events AND columns_cmdline:/.*(sfltool|osascript.*login item|System Events.*login item).*/
```

**macOS - Выполнение команды через sudo**

```
name:sudo_commands AND -columns_uid:0
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
| Bi.Zone: неизвестный SSH-ключ в authorized_keys | высокий | BiZone_macOS<br>BI.ZONE SSHKeyInfo | В authorized_keys появился ключ, отпечатка которого нет в белом списке (подставь отпечатки своих ключей). Возможен бэкдор-доступ по SSH. | каждое событие; повтор не чаще раза в 7 сут | Persistence | `T1098.004` SSH Authorized Keys |
| Bi.Zone: новое правило в sudoers | высокий | BiZone_macOS<br>BI.ZONE SudoersInfo | В sudoers появилось правило не из белого списка (root, %admin и свои служебные правила). Возможна эскалация привилегий. | каждое событие; повтор не чаще раза в 7 сут | Privilege Escalation | `T1548.003` Sudo and Sudo Caching |
| Bi.Zone: новый пользователь | высокий | BiZone_macOS<br>BI.ZONE UserInfo | В системе появился пользователь с uid ≥ 500, которого нет в белом списке (подставь своих пользователей). | каждое событие; повтор не чаще раза в 7 сут | Persistence | `T1136.001` Local Account |
| Bi.Zone: подозрительная запись в hosts | высокий | BiZone_macOS<br>BI.ZONE NetworkHostsFileInfo | В /etc/hosts появилась запись не из белого списка. Так перенаправляют обновления, антивирус или банк на чужой адрес. | каждое событие; повтор не чаще раза в 7 сут | Impact | `T1565.001` Stored Data Manipulation |
| Bi.Zone: процесс из /tmp или /Users/Shared | высокий | BiZone_macOS<br>BI.ZONE ProcessInfo | Работает процесс, исполняемый файл которого лежит во временном или общем каталоге (кроме Bi.Zone Triage). Типично для загрузчиков. | каждое событие; повтор не чаще раза в 7 сут | Execution | `T1059` Command and Scripting Interpreter |
| Bi.Zone: смена DNS-серверов | высокий | BiZone_macOS | В resolv.conf появился DNS-сервер не из белого списка. Возможна подмена DNS (перехват трафика, фишинг). | каждое событие; повтор не чаще раза в 7 сут | — | — |
| Bi.Zone: новый элемент автозагрузки | средний | BiZone_macOS<br>BI.ZONE AsepInfo | LaunchAgent/LaunchDaemon или другой элемент автозагрузки создан менее суток назад (кроме служб com.homelab.bzt-*). Классический способ закрепления. | каждое событие; повтор не чаще раза в 7 сут | Persistence | `T1543.004` Launch Daemon<br>`T1543.001` |
| Bi.Zone: опасная команда в истории оболочки | средний | BiZone_macOS<br>BI.ZONE ConsoleCommandInfo | В истории zsh/bash появилась новая опасная команда: curl \| sh, base64 -d, nc -l, csrutil/spctl disable, dump-keychain, dscl -create, /dev/tcp, снятие карантина, launchctl load. Команды… | каждое событие; повтор не чаще раза в 30 сут | Execution | `T1059.004` Unix Shell |
| Bi.Zone: неудачные входы по SSH | низкий | BiZone_macOS<br>BI.ZONE LogonHistoryFailure | В журнале sshd есть ошибки аутентификации (по снимку Bi.Zone). Повтор не чаще раза в сутки на хост. | каждое событие; повтор не чаще раза в 1 сут | Credential Access | `T1110` Brute Force |

<details><summary>Запросы Graylog (очищенные)</summary>

**macOS - Bi.Zone: неизвестный SSH-ключ в authorized_keys**

```
mac_bz_event_type:SSHKeyInfo AND NOT auth_key_fingerprint:(<белый список>)
```

**macOS - Bi.Zone: новое правило в sudoers**

```
mac_bz_event_type:SudoersInfo AND NOT sudoers_rule:("%admin ALL = (ALL) ALL" OR "root ALL = (ALL) ALL" OR "example-user ALL=(root) NOPASSWD: /usr/local/bin/example.sh")
```

**macOS - Bi.Zone: новый пользователь**

```
mac_bz_event_type:UserInfo AND usr_tgt_id:>=500 AND NOT mac_bz_user:("example-user" OR "nobody")
```

**macOS - Bi.Zone: подозрительная запись в hosts**

```
mac_bz_event_type:NetworkHostsFileInfo AND inventory_task_name:"LineInFileFound - Hosts Inventory" AND NOT file_match:(<белый список>)
```

**macOS - Bi.Zone: процесс из /tmp или /Users/Shared**

```
mac_bz_event_type:ProcessInfo AND proc_file_path:(\/tmp\/* OR \/private\/tmp\/* OR \/Users\/Shared\/* OR \/private\/var\/tmp\/*) AND NOT proc_file_path:(\/tmp\/bzt.* OR \/private\/tmp\/bzt.* OR \/tmp\/bz_triage_tmp_* OR \/private\/tmp\/bz_triage_tmp_*)
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
mac_bz_event_type:ConsoleCommandInfo AND ((message:"csrutil" AND message:"disable") OR (message:"spctl" AND message:"disable") OR (message:"base64" AND message:("-d" OR "--decode" OR "-D")) OR (message:"curl" AND message:("sh" OR "bash")) OR (message:"nc" AND message:"-l") OR message:"ncat" OR message:"dump-keychain" OR message:"find-generic-password" OR (message:"dscl" AND message:"-create") OR message:"/dev/tcp" OR (message:"xattr" AND message:"quarantine") OR (message:"launchctl" AND message:("load" OR "bootstrap"))) AND NOT cmdline:("curl -fsSL http://server.example.domain:8484/setup/host.sh | sudo bash" OR "nc -l 9999 > /tmp/test.out" OR "openssl base64 -d -A < /tmp/example.b64 > /tmp/example.bundle")
```

**macOS - Bi.Zone: неудачные входы по SSH**

```
mac_bz_event_type:LogonHistoryFailure
```

</details>

## Keenetic

syslog роутера; поток Syslog Logs. Правил: 8. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Вход в админку роутера (SSH) | высокий | Syslog Logs<br>событие Keenetic SSH_Connection, SSH_Success | SSH-подключение к роутеру Keenetic с адреса вне белого списка (сервер мониторинга и рабочие хосты). | каждое событие | Lateral Movement | `T1021.004` SSH |
| Отказ во входе на роутер | высокий | Syslog Logs<br>событие Keenetic Auth_Denied | Отказ в доступе к роутеру (Auth_Denied). | каждое событие | Credential Access | `T1110` Brute Force |
| ARP-конфликт на новом адресе | средний | Syslog Logs<br>событие Keenetic ARP_Conflict | Конфликт ARP (два MAC на одном IP) на адресе, которого нет среди постоянных пар. Исключены <IP>, .54, .118, .38, .117, .146, .145: у них за месяц десятки тысяч конфликтов из-за двух… | каждое событие | Credential Access | `T1557.002` ARP Cache Poisoning |
| Блокировка адреса за попытки входа в веб-интерфейс | средний | Syslog Logs | Роутер заблокировал удалённый адрес за подбор или сканирование веб-интерфейса (Netfilter Lockout, ban remote host). Адреса из интернета означают, что веб-интерфейс доступен снаружи. | каждое событие | Credential Access | `T1110` Brute Force |
| Новое устройство в сети | средний | Syslog Logs<br>событие Keenetic DHCP_Request | DHCP выдал адрес устройству, MAC которого отсутствует в белом списке. Возможно подключение нового клиента. | каждое событие; повтор не чаще раза в 7 сут | Initial Access | `T1200` Hardware Additions |
| Сканирование веб-интерфейса из интернета | средний | Syslog Logs | Запросы к веб-интерфейсу роутера несуществующих или служебных файлов (.env, readme.html и т. п.): типичное сканирование уязвимостей. | каждое событие | Reconnaissance | `T1595.002` Vulnerability Scanning<br>`T1190` |
| Сохранена конфигурация роутера | средний | Syslog Logs | Конфигурация роутера сохранена (StartupConfig: configuration saved). Событие редкое: сверьте, что это ваша правка. | каждое событие | Defense Impairment | `T1686` Disable or Modify System Firewall |
| Отказы WireGuard (ежедневная сводка) | низкий | Syslog Logs<br>событие Keenetic Wireguard_Failed | Количество неудачных WireGuard-handshake за прошедшие сутки. Высокое число (сотни или тысячи) может означать подбор ключа или сканирование извне. Проверяется раз в сутки, одно письмо в день. | число событий ≥ 1 за 1 сут, группировка по source | Persistence | `T1133` External Remote Services |

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
source:"<роутер>" AND message:"Lockout" AND message:"ban remote host"
```

**KEENETIC - Новое устройство в сети**

```
kn_event_type:DHCP_Request AND NOT kn_mac:(<белый список MAC>)
```

**KEENETIC - Сканирование веб-интерфейса из интернета**

```
source:"<роутер>" AND message:"Core::Scgi::Session" AND (message:"unsupported file path" OR message:"not found")
```

**KEENETIC - Сохранена конфигурация роутера**

```
source:"<роутер>" AND message:"StartupConfig" AND message:"configuration saved"
```

**KEENETIC - Отказы WireGuard (ежедневная сводка)**

```
kn_event_type:Wireguard_Failed
```

</details>

## FreeIPA и здоровье сервисов

аудит FreeIPA и служебные проверки. Правил: 3. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Подбор пароля (10+ PREAUTH_FAILED за 5 мин) | высокий | FreeIPA Logs | Серия отказов предварительной аутентификации Kerberos на контроллере домена. Возможен подбор пароля доменной учётной записи (password spray). | число событий ≥ 10 за 5 мин, группировка по source | Credential Access | `T1110.001` Password Guessing |
| Клиенты не могут связаться с KDC | высокий | RedOS auditd Logs | На хостах auditd/sssd сообщает «Cannot contact any KDC for realm». Признак того, что контроллер домена FreeIPA упал или недоступен по сети. | каждое событие | — | — |
| Выпуск сертификата в CA (Dogtag) | средний | FreeIPA Logs<br>приложение freeipa_389_audit | Запрос на выпуск сертификата через CA FreeIPA (Dogtag). Выпуски должны происходить только при добавлении новых сервисов или хостов. Внезапный массовый выпуск — повод проверить. | каждое событие | Credential Access | `T1649` Steal or Forge Authentication Certificates |

<details><summary>Запросы Graylog (очищенные)</summary>

**FREEIPA - Подбор пароля (10+ PREAUTH_FAILED за 5 мин)**

```
message:PREAUTH_FAILED
```

**HEALTH - Клиенты не могут связаться с KDC**

```
message:"Cannot contact any KDC"
```

**FREEIPA - Выпуск сертификата в CA (Dogtag)**

```
application_name:freeipa_389_audit AND message:cert--005frequest
```

</details>

## Контейнеры

Docker-логи через promtail и Filebeat; поток Containers. Правил: 18. Сортировка: сначала высокий приоритет.

| Правило | Приоритет | Источник логов | Что проверяет | Корреляция | Тактика | Техника |
|---|---|---|---|---|---|---|
| Контейнеры: Grafana — неудачный вход (подбор пароля) | высокий | Containers<br>контейнер grafana | Больше 5 неудачных входов в Grafana за 5 минут. | число событий > 5 за 5 мин, группировка по container_name; повтор не чаще раза в 1 ч | Credential Access | `T1110` Brute Force |
| Контейнеры: нехватка памяти или падение процесса | высокий | Containers | В логах контейнера OOM, Killed process, segfault или core dumped. | число событий > 0 за 5 мин, группировка по container_name; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: перезапуски MariaDB | высокий | Containers<br>контейнер observiumdb | Больше 2 запусков entrypoint MariaDB (контейнер observiumdb) за 15 минут — цикл перезапусков БД Observium. | число событий > 2 за 15 мин, группировка по container_name | — | — |
| Контейнеры: тишина — atrium | высокий | Containers<br>контейнер atrium | Контейнер atrium не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — grafana | высокий | Containers<br>контейнер grafana | Контейнер grafana не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — komodo_mongo_1 | высокий | Containers<br>контейнер komodo_mongo_1 | Контейнер komodo_mongo_1 не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — loki | высокий | Containers<br>контейнер loki | Контейнер loki не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — netalertx | высокий | Containers<br>контейнер netalertx | Контейнер netalertx не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — wazuh.dashboard | высокий | Containers<br>контейнер wazuh.dashboard | Контейнер wazuh.dashboard не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 1 ч; повтор не чаще раза в 1 сут | — | — |
| Контейнеры: тишина — zaslon | высокий | Containers<br>контейнер zaslon | Контейнер zaslon не прислал ни одного сообщения за 15 минут — остановлен или завис. | число событий < 1 за 15 мин; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: тишина — нет логов ни от одного контейнера | высокий | Containers | Поток Containers не получил ни одного сообщения за 10 минут — упал input «Podman Logs», Graylog или все хосты разом. | число событий < 1 за 10 мин; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: Loki — ошибки приёма | средний | Containers<br>контейнер loki | Loki пишет level=error (например, write operation failed). | число событий > 0 за 15 мин, группировка по container_name; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: MongoDB — ошибки | средний | Containers<br>контейнер komodo_mongo_1 | Сообщение уровня E (ошибка) в логе MongoDB (komodo_mongo_1). | число событий > 0 за 10 мин, группировка по container_name; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: netalertx — новое устройство в сети | средний | Containers<br>контейнер netalertx | Скан netalertx нашёл новые устройства (New Devices больше нуля). | число событий > 0 за 5 мин, группировка по container_name; повтор не чаще раза в 1 ч | Initial Access | `T1200` Hardware Additions |
| Контейнеры: promtail не доставляет логи в Loki | средний | Containers<br>контейнер promtail | Больше 15 ошибок «context deadline exceeded» за 10 минут на одном хосте — promtail не может записать в Loki. | число событий > 15 за 10 мин, группировка по source; повтор не чаще раза в 1 ч | — | — |
| Контейнеры: всплеск ошибок | средний | Containers | Больше 10 реальных ошибок за 5 минут в одном контейнере: loglevel error/warn/fatal (loki/promtail) или ключевые слова error/fatal/panic/exception/traceback в message. Исключены cadvisor,… | число событий > 10 за 5 мин, группировка по container_name | — | — |
| Контейнеры: ошибки прав доступа | средний | Containers | Больше 50 сообщений «Operation not permitted» за 10 минут в одном контейнере. | число событий > 50 за 10 мин, группировка по container_name | — | — |
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
