<#
.SYNOPSIS
    Безопасные проверки детектов Graylog для Windows и контроллера домена.

.DESCRIPTION
    Создаёт события, похожие на следы атак, чтобы убедиться, что алерты из каталога детектов срабатывают.
    Всё созданное (учётная запись DT_user, файлы, службы, ключи реестра) удаляется в конце.
    Опасные техники имитируются безвредной командной строкой. Запускайте только в лаборатории, от администратора.
    Список проверок и ожидаемых алертов: docs/15-detection-tests.md.

.EXAMPLE
    .\Invoke-DetectionTests.ps1 -List
    .\Invoke-DetectionTests.ps1 -Id WIN-01,WIN-09 -DryRun
    .\Invoke-DetectionTests.ps1 -All -Target dc01.example.test

Лицензия: GPL-3.0.
#>
[CmdletBinding()]
param(
    [switch]$List,
    [string[]]$Id,
    [switch]$All,
    [switch]$DryRun,
    [switch]$Force,
    [int]$PauseSec = 5,
    [string]$Report,
    [string]$Target = $env:COMPUTERNAME
)

# BEGIN-META
$TestsMeta = @'
[
 {
  "id": "WIN-01",
  "name": "Создание учётной записи (net user /add)",
  "risk": "низкий",
  "needs": "права администратора; на DC создаётся доменная учётка",
  "note": "Нужен аудит управления учётными записями",
  "rules": [
   "Windows - Создана учётная запись (4720)",
   "Windows - Создание/удаление локального пользователя (net user)"
  ]
 },
 {
  "id": "WIN-02",
  "name": "Сброс пароля учётной записи",
  "risk": "низкий",
  "needs": "права администратора",
  "note": "",
  "rules": [
   "Windows - Сброс пароля учётной записи (4724)"
  ]
 },
 {
  "id": "WIN-03",
  "name": "Добавление в локальные администраторы",
  "risk": "средний",
  "needs": "права администратора",
  "note": "Тестовая учётка сразу убирается из группы",
  "rules": [
   "Windows - Добавление в группу администраторов (4728, 4732, 4756)",
   "Windows - Добавление в локальные администраторы (командная строка)"
  ]
 },
 {
  "id": "WIN-04",
  "name": "Добавление в «Администраторы домена»",
  "risk": "средний",
  "needs": "запуск на контроллере домена",
  "note": "Тестовая учётка на секунды получает права администратора домена",
  "rules": [
   "Windows - Изменение группы «Администраторы домена»",
   "Windows - Изменение привилегированных групп и учёток"
  ]
 },
 {
  "id": "WIN-05",
  "name": "Неудачные входы: подбор пароля (12 попыток)",
  "risk": "низкий",
  "needs": "параметр -Target (имя DC или хоста); для Kerberos запускай с рабочей станции",
  "note": "Тестовая учётка, скорее всего, заблокируется: это и проверяется. 4771 появится на DC только при Kerberos-входе",
  "rules": [
   "Windows - Подбор пароля (5+ ошибок входа 4625 за 5 мин)",
   "Windows - Подбор пароля на DC по Kerberos (10+ ошибок 4771 за 5 мин)",
   "Windows - Подбор пароля на DC по NTLM (10+ ошибок 4776 за 5 мин)",
   "Windows - Блокировка учётной записи (4740)"
  ]
 },
 {
  "id": "WIN-06",
  "name": "Перебор несуществующих пользователей",
  "risk": "низкий",
  "needs": "параметр -Target",
  "note": "",
  "rules": [
   "Windows - Перебор несуществующих пользователей (5+ за 10 мин)"
  ]
 },
 {
  "id": "WIN-07",
  "name": "Изменение политики аудита",
  "risk": "средний",
  "needs": "права администратора",
  "note": "Политика сохраняется в файл и восстанавливается после теста",
  "rules": [
   "Windows - Изменение политики аудита (4719)"
  ]
 },
 {
  "id": "WIN-08",
  "name": "Очистка журнала событий (тестовый журнал)",
  "risk": "низкий",
  "needs": "права администратора",
  "note": "Очищается собственный журнал DetectTest, боевые журналы не затрагиваются",
  "rules": [
   "Windows - Очистка журнала событий"
  ]
 },
 {
  "id": "WIN-09",
  "name": "Задание планировщика с путём в Temp",
  "risk": "низкий",
  "needs": "права администратора",
  "note": "",
  "rules": [
   "Windows - Создание задачи через schtasks",
   "Windows - Задание планировщика с Temp, AppData или Public (4698)"
  ]
 },
 {
  "id": "WIN-10",
  "name": "Установка службы вне System32",
  "risk": "низкий",
  "needs": "права администратора",
  "note": "Служба не запускается и сразу удаляется",
  "rules": [
   "Windows - Новая служба",
   "Windows - Установка службы вне System32 и Program Files (4697)"
  ]
 },
 {
  "id": "WIN-11",
  "name": "Исключение для Defender",
  "risk": "низкий",
  "needs": "Defender включён",
  "note": "",
  "rules": [
   "Windows - Исключения или отключение защиты Defender"
  ]
 },
 {
  "id": "WIN-12",
  "name": "Тестовый файл EICAR",
  "risk": "низкий",
  "needs": "Defender включён",
  "note": "Стандартная безвредная тестовая строка антивирусов; файл будет удалён",
  "rules": [
   "Windows - Defender обнаружил угрозу или отключён"
  ]
 },
 {
  "id": "WIN-13",
  "name": "Команда удаления теневых копий (несуществующий ID)",
  "risk": "низкий",
  "needs": "права администратора",
  "note": "Команда с несуществующим идентификатором копии: реальные копии не затрагиваются",
  "rules": [
   "Windows - Удаление теневых копий"
  ]
 },
 {
  "id": "WIN-14",
  "name": "Командная строка с «firewall disable» (имитация)",
  "risk": "низкий",
  "needs": "",
  "note": "Выполняется только показ правила с подходящим именем",
  "rules": [
   "Windows - Отключение Firewall (netsh или PS)"
  ]
 },
 {
  "id": "WIN-15",
  "name": "PowerShell с закодированной командой",
  "risk": "низкий",
  "needs": "Sysmon (событие 1)",
  "note": "",
  "rules": [
   "Windows - PowerShell с закодированной командой"
  ]
 },
 {
  "id": "WIN-16",
  "name": "Скриптблок со строками DownloadString и IEX",
  "risk": "низкий",
  "needs": "включено журналирование блоков сценариев (4104)",
  "note": "Сеть не используется: строки только в тексте скрипта",
  "rules": [
   "Windows - PowerShell скачивает и исполняет код"
  ]
 },
 {
  "id": "WIN-17",
  "name": "Командная строка с LOLBins (имитация)",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "Выполняется cmd /c rem: команда ничего не делает",
  "rules": [
   "Windows - LOLBins (certutil, mshta, bitsadmin, regsvr32)"
  ]
 },
 {
  "id": "WIN-18",
  "name": "Командная строка «reg save hklm sam» (имитация)",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "Выполняется cmd /c rem: команда ничего не делает",
  "rules": [
   "Windows - Дамп учётных данных (reg save, comsvcs, ntdsutil)"
  ]
 },
 {
  "id": "WIN-19",
  "name": "Серия команд разведки",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "",
  "rules": [
   "Windows - Серия разведки (5+ команд за 5 мин)",
   "Windows - Разведка в домене (nltest, dsquery, AdFind, SharpHound)"
  ]
 },
 {
  "id": "WIN-20",
  "name": "Автозагрузка через ключ Run",
  "risk": "низкий",
  "needs": "Sysmon (события 12-14)",
  "note": "",
  "rules": [
   "Windows - Автозагрузка через ключ реестра Run"
  ]
 },
 {
  "id": "WIN-21",
  "name": "IFEO Debugger для несуществующей программы",
  "risk": "средний",
  "needs": "права администратора, Sysmon",
  "note": "Ключ создаётся для dt_test.exe и сразу удаляется",
  "rules": [
   "Windows - Закрепление через IFEO Debugger, AppInit_DLLs и Winlogon"
  ]
 },
 {
  "id": "WIN-22",
  "name": "Обход UAC через реестр (ms-settings)",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "Значение ключа создаётся и сразу удаляется, fodhelper не запускается",
  "rules": [
   "Windows - Обход UAC через реестр (fodhelper, eventvwr, ms-settings)"
  ]
 },
 {
  "id": "WIN-23",
  "name": "Постоянная подписка WMI",
  "risk": "средний",
  "needs": "права администратора, журнал WMI-Activity",
  "note": "Подписка с безвредной командой, удаляется сразу",
  "rules": [
   "Windows - Постоянная подписка WMI (5861)"
  ]
 },
 {
  "id": "WIN-24",
  "name": "Удалённая сессия WinRM",
  "risk": "низкий",
  "needs": "включён WinRM",
  "note": "Invoke-Command на localhost",
  "rules": [
   "Windows - Удалённый вход по WinRM (91)"
  ]
 },
 {
  "id": "WIN-25",
  "name": "Именованный канал в стиле C2",
  "risk": "низкий",
  "needs": "Sysmon (события 17, 18)",
  "note": "",
  "rules": [
   "Windows - Именованные каналы C2 (Cobalt Strike и аналоги)"
  ]
 },
 {
  "id": "WIN-26",
  "name": "DNS-запросы: туннель и длинное имя",
  "risk": "низкий",
  "needs": "Sysmon (событие 22)",
  "note": "",
  "rules": [
   "Windows - DNS-запрос к туннелям и файлообменникам",
   "Windows - Подозрительно длинные DNS-имена (туннель, DGA)"
  ]
 },
 {
  "id": "WIN-27",
  "name": "Файл с расширением шифровальщика",
  "risk": "низкий",
  "needs": "Sysmon (событие 11)",
  "note": "",
  "rules": [
   "Windows - Признаки шифровальщика (расширения и записки)"
  ]
 },
 {
  "id": "WIN-28",
  "name": "Процесс svchost.exe не из System32",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "Копия whoami.exe под именем svchost.exe в Temp",
  "rules": [
   "Windows - Маскировка под системный процесс (svchost, lsass, csrss вне System32)"
  ]
 },
 {
  "id": "WIN-29",
  "name": "Программы с именами ngrok и rclone",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "Копии whoami.exe под этими именами, настоящих утилит нет",
  "rules": [
   "Windows - Запуск утилит удалённого доступа и туннелей",
   "Windows - Утилиты выгрузки в облако (rclone, MEGAsync, WinSCP)"
  ]
 },
 {
  "id": "WIN-30",
  "name": "Архивация через Compress-Archive",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "",
  "rules": [
   "Windows - Архивация не из проводника (7z, WinRAR, Compress-Archive)"
  ]
 },
 {
  "id": "WIN-31",
  "name": "Поиск паролей через findstr",
  "risk": "низкий",
  "needs": "Sysmon",
  "note": "",
  "rules": [
   "Windows - Поиск паролей в файлах (findstr, Select-String)"
  ]
 },
 {
  "id": "WIN-32",
  "name": "Билет службы с RC4 (Kerberoasting)",
  "risk": "средний",
  "needs": "запуск в домене, модуль ActiveDirectory",
  "note": "Не сработает, если политика домена запрещает RC4",
  "rules": [
   "Windows - Kerberoasting: билет службы с шифрованием RC4 (4769)"
  ]
 },
 {
  "id": "WIN-33",
  "name": "Создание компьютерной учётки пользователем",
  "risk": "низкий",
  "needs": "запуск в домене, модуль ActiveDirectory",
  "note": "",
  "rules": [
   "Windows - Создана компьютерная учётная запись пользователем (4741)"
  ]
 }
]
'@ | ConvertFrom-Json
# END-META

$script:Cleanups = New-Object System.Collections.ArrayList
$script:DtUser   = 'DT_user'
$script:DtPwd    = $null
$script:DtUserCreated = $false
$script:WorkDir  = Join-Path $env:TEMP 'DT'

# ---------- Вывод ----------
function Write-Ok($t)   { Write-Host $t -ForegroundColor Green }
function Write-Err($t)  { Write-Host $t -ForegroundColor Red }
function Write-Warn($t) { Write-Host $t -ForegroundColor Yellow }
function Write-Info($t) { Write-Host $t -ForegroundColor Cyan }

# ---------- Помощники ----------
function Add-Cleanup([scriptblock]$Block) { [void]$script:Cleanups.Add($Block) }

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments)
    $script:LastError = $null
    try {
        # net.exe может задавать вопрос (Y/N): отвечаем Y, чтобы скрипт не завис в ожидании ввода
        if ($Exe -like 'net*') { $o = 'Y' | & $Exe @Arguments 2>&1 } else { $o = & $Exe @Arguments 2>&1 }
        $script:LastExit = $LASTEXITCODE
    } catch {
        # запуск не удался (например, программу заблокировала защита)
        $script:LastExit = -1
        $script:LastError = $_.Exception.Message
        $o = $null
    }
    return $o
}

# Имитация: cmd /c rem <фраза>. Каждая фраза запускается отдельно, потому что защита может блокировать часть из них.
function Invoke-Sim {
    param([string[]]$Phrases)
    $ok = 0; $blocked = 0
    foreach ($ph in $Phrases) {
        $null = Invoke-Native cmd.exe @('/c', "rem $ph")
        if ($script:LastExit -eq -1) { $blocked++; Write-Warn "Запуск заблокирован защитой: rem $ph" } else { $ok++ }
        Start-Sleep -Milliseconds 500
    }
    if ($ok -eq 0) { throw "BLOCKED: защита заблокировала все команды; смотрите событие Defender (1116/1117) и алерт «Defender обнаружил угрозу»" }
    if ($blocked -gt 0) { Write-Warn "Заблокировано команд: $blocked из $($ok + $blocked); остальные выполнены" }
}

function New-DtPassword {
    $u = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; $l = 'abcdefghijkmnopqrstuvwxyz'; $d = '23456789'; $s = '!#%+=-'
    $chars = @(($u.ToCharArray() | Get-Random), ($l.ToCharArray() | Get-Random), ($d.ToCharArray() | Get-Random), ($s.ToCharArray() | Get-Random))
    $all = ($u + $l + $d).ToCharArray()
    # не длиннее 14 символов: иначе net user задаёт скрытый вопрос и скрипт зависает
    1..9 | ForEach-Object { $chars += ($all | Get-Random) }
    return -join ($chars | Sort-Object { Get-Random })
}

function Get-DomainRole { try { return (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole } catch { return -1 } }
function Test-IsDc { return (Get-DomainRole) -ge 4 }
function Test-HasAd { return [bool](Get-Module -ListAvailable -Name ActiveDirectory) }

function Get-NameBySid([string]$Sid) {
    return (New-Object Security.Principal.SecurityIdentifier $Sid).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
}

function Initialize-WorkDir {
    if (-not (Test-Path $script:WorkDir)) { New-Item -ItemType Directory -Path $script:WorkDir | Out-Null }
    if (-not $script:WorkDirRegistered) {
        Add-Cleanup { Remove-Item -Path $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
        $script:WorkDirRegistered = $true
    }
}

function Ensure-DtUser {
    if ($script:DtUserCreated) { return }
    $script:DtPwd = New-DtPassword
    $null = Invoke-Native net.exe @('user', $script:DtUser, '/delete')
    $null = Invoke-Native net.exe @('user', $script:DtUser, $script:DtPwd, '/add', '/active:yes')
    if ($script:LastExit -ne 0) { throw "Не удалось создать учётную запись $($script:DtUser): код $($script:LastExit)" }
    $script:DtUserCreated = $true
    Add-Cleanup { $null = Invoke-Native net.exe @('user', $script:DtUser, '/delete') }
}

# ---------- Проверки ----------
function Test-WIN01 { Ensure-DtUser; Write-Host "Создана учётная запись $($script:DtUser)" }

function Test-WIN02 {
    Ensure-DtUser
    $null = Invoke-Native net.exe @('user', $script:DtUser, (New-DtPassword))
    if ($script:LastExit -ne 0) { throw "net user вернул код $($script:LastExit)" }
}

function Test-WIN03 {
    Ensure-DtUser
    $grp = Get-NameBySid 'S-1-5-32-544'
    $null = Invoke-Native net.exe @('localgroup', $grp, $script:DtUser, '/add')
    if ($script:LastExit -ne 0) { throw "Не удалось добавить в группу $grp" }
    Add-Cleanup { $null = Invoke-Native net.exe @('localgroup', $grp, $script:DtUser, '/delete') }
}

function Test-WIN04 {
    if (-not (Test-IsDc)) { throw "SKIP: нужен контроллер домена" }
    if (-not (Test-HasAd)) { throw "SKIP: нет модуля ActiveDirectory" }
    Ensure-DtUser
    $sid = (Get-ADDomain).DomainSID.Value + '-512'
    $grp = Get-NameBySid $sid
    $null = Invoke-Native net.exe @('group', $grp, $script:DtUser, '/add', '/domain')
    if ($script:LastExit -ne 0) { throw "Не удалось добавить в группу $grp" }
    Add-Cleanup { $null = Invoke-Native net.exe @('group', $grp, $script:DtUser, '/delete', '/domain') }
    Write-Warn "Правило ищет русское имя группы «Администраторы домена»; на английской системе оно не сработает."
}

function Test-WIN05 {
    Ensure-DtUser
    $acct = "$env:USERDOMAIN\$($script:DtUser)"
    foreach ($i in 1..12) {
        $null = Invoke-Native net.exe @('use', "\\$Target\IPC`$", "/user:$acct", "WrongPass-$i!")
    }
    $null = Invoke-Native net.exe @('use', '*', '/delete', '/y')
}

function Test-WIN06 {
    foreach ($i in 1..6) {
        $name = 'DT_nouser_' + (Get-Random -Maximum 99999)
        $null = Invoke-Native net.exe @('use', "\\$Target\IPC`$", "/user:$env:USERDOMAIN\$name", "WrongPass-$i!")
    }
    $null = Invoke-Native net.exe @('use', '*', '/delete', '/y')
}

function Test-WIN07 {
    $backup = Join-Path $env:TEMP 'dt_audit_backup.csv'
    Remove-Item $backup -Force -ErrorAction SilentlyContinue
    $null = Invoke-Native auditpol.exe @('/backup', "/file:$backup")
    if ($script:LastExit -ne 0) { throw "Не удалось сохранить политику аудита: код $($script:LastExit)" }
    Add-Cleanup { $null = Invoke-Native auditpol.exe @('/restore', "/file:$backup"); Remove-Item $backup -Force -ErrorAction SilentlyContinue }
    # подкатегория Other Policy Change Events
    $null = Invoke-Native auditpol.exe @('/set', '/subcategory:{0CCE9234-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')
    if ($script:LastExit -ne 0) { throw "auditpol /set вернул код $($script:LastExit)" }
}

function Test-WIN08 {
    $log = 'DetectTest'
    New-EventLog -LogName $log -Source $log -ErrorAction Stop
    Add-Cleanup { Remove-EventLog -LogName 'DetectTest' -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    Write-EventLog -LogName $log -Source $log -EventId 1 -Message 'DT test'
    Clear-EventLog -LogName $log
}

function Test-WIN09 {
    $null = Invoke-Native schtasks.exe @('/create', '/tn', 'DT_Task', '/tr', 'C:\Windows\Temp\dt.exe', '/sc', 'once', '/st', '23:59', '/f')
    if ($script:LastExit -ne 0) { throw "schtasks вернул код $($script:LastExit)" }
    Add-Cleanup { $null = Invoke-Native schtasks.exe @('/delete', '/tn', 'DT_Task', '/f') }
}

function Test-WIN10 {
    $null = Invoke-Native sc.exe @('create', 'DT_Svc', 'binPath=', 'C:\Windows\Temp\dt.exe', 'start=', 'demand')
    if ($script:LastExit -ne 0) { throw "sc create вернул код $($script:LastExit)" }
    Add-Cleanup { $null = Invoke-Native sc.exe @('delete', 'DT_Svc') }
}

function Test-WIN11 {
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) { throw "SKIP: нет командлетов Defender" }
    Add-MpPreference -ExclusionPath 'C:\DT_Exclusion' -ErrorAction Stop
    Add-Cleanup { Remove-MpPreference -ExclusionPath 'C:\DT_Exclusion' -ErrorAction SilentlyContinue }
}

function Test-WIN12 {
    Initialize-WorkDir
    # строка EICAR разбита, чтобы антивирус не срабатывал на сам скрипт
    $e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    $f = Join-Path $script:WorkDir 'eicar_test.txt'
    try { Set-Content -Path $f -Value $e -Encoding ASCII -ErrorAction Stop } catch { Write-Warn "Defender заблокировал запись файла: это тоже срабатывание" }
    Start-Sleep -Seconds 3
    Remove-Item $f -Force -ErrorAction SilentlyContinue
}

function Test-WIN13 {
    $null = Invoke-Native vssadmin.exe @('delete', 'shadows', '/shadow={00000000-0000-0000-0000-000000000000}', '/quiet')
}

function Test-WIN14 {
    $null = Invoke-Native netsh.exe @('advfirewall', 'firewall', 'show', 'rule', 'name=DT_disable_test')
}

function Test-WIN15 {
    $cmd = "Write-Output 'DT encoded test'"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    $null = Invoke-Native powershell.exe @('-NoProfile', '-EncodedCommand', $b64)
}

function Test-WIN16 {
    Initialize-WorkDir
    $f = Join-Path $script:WorkDir 'dt_download.ps1'
    Set-Content -Path $f -Value '$s = ''Net.WebClient DownloadString Invoke-Expression IEX''; Write-Output $s' -Encoding UTF8
    $null = Invoke-Native powershell.exe @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $f)
}

function Test-WIN17 { Invoke-Sim @('certutil -urlcache', 'mshta.exe', 'bitsadmin /transfer', 'scrobj.dll') }

function Test-WIN18 { Invoke-Sim @('reg save hklm sam', 'reg save hklm security', 'reg save hklm system') }

function Test-WIN19 {
    $null = Invoke-Native whoami.exe @()
    $null = Invoke-Native nltest.exe @('/domain_trusts')
    $null = Invoke-Native net.exe @('user')
    $null = Invoke-Native systeminfo.exe @()
    $null = Invoke-Native quser.exe @()
    $null = Invoke-Native arp.exe @('-a')
}

function Test-WIN20 {
    $k = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
    $null = Invoke-Native reg.exe @('add', $k, '/v', 'DT_Test', '/t', 'REG_SZ', '/d', 'C:\Windows\Temp\dt.exe', '/f')
    if ($script:LastExit -ne 0) { throw "reg add вернул код $($script:LastExit)" }
    Add-Cleanup { $null = Invoke-Native reg.exe @('delete', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', '/v', 'DT_Test', '/f') }
}

function Test-WIN21 {
    $k = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dt_test.exe'
    $null = Invoke-Native reg.exe @('add', $k, '/v', 'Debugger', '/t', 'REG_SZ', '/d', 'C:\Windows\Temp\dt.exe', '/f')
    if ($script:LastExit -ne 0) { throw "reg add вернул код $($script:LastExit)" }
    Add-Cleanup { $null = Invoke-Native reg.exe @('delete', 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dt_test.exe', '/f') }
}

function Test-WIN22 {
    $root = 'HKCU\Software\Classes\ms-settings'
    $null = Invoke-Native reg.exe @('query', $root)
    $existed = ($script:LastExit -eq 0)
    $null = Invoke-Native reg.exe @('add', "$root\Shell\Open\command", '/ve', '/t', 'REG_SZ', '/d', 'C:\Windows\Temp\dt.exe', '/f')
    if ($script:LastExit -ne 0) { throw "reg add вернул код $($script:LastExit)" }
    if ($existed) {
        Add-Cleanup { $null = Invoke-Native reg.exe @('delete', 'HKCU\Software\Classes\ms-settings\Shell\Open\command', '/f') }
    } else {
        Add-Cleanup { $null = Invoke-Native reg.exe @('delete', 'HKCU\Software\Classes\ms-settings', '/f') }
    }
}

function Test-WIN23 {
    $ns = 'root\subscription'
    $f = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{
        Name = 'DT_Filter'; EventNamespace = 'root\cimv2'; QueryLanguage = 'WQL'
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 99" } -ErrorAction Stop
    $c = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{ Name = 'DT_Consumer'; CommandLineTemplate = 'cmd.exe /c rem DT' } -ErrorAction Stop
    $null = Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{ Filter = $f; Consumer = $c } -ErrorAction Stop
    Add-Cleanup {
        $ns = 'root\subscription'
        Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter -like '*DT_Filter*' } | Remove-WmiObject
        Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='DT_Consumer'" -ErrorAction SilentlyContinue | Remove-WmiObject
        Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='DT_Filter'" -ErrorAction SilentlyContinue | Remove-WmiObject
    }
}

function Test-WIN24 {
    try { $null = Test-WSMan -ComputerName localhost -ErrorAction Stop } catch { throw "SKIP: WinRM не включён" }
    $null = Invoke-Command -ComputerName localhost -ScriptBlock { hostname } -ErrorAction Stop
}

function Test-WIN25 {
    $srv = New-Object System.IO.Pipes.NamedPipeServerStream('msagent_dt')
    try {
        $wait = $srv.WaitForConnectionAsync()
        $cli = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'msagent_dt')
        $cli.Connect(3000)
        Start-Sleep -Seconds 1
        $cli.Dispose()
    } finally { $srv.Dispose() }
}

function Test-WIN26 {
    $null = Invoke-Native nslookup.exe @('dt-test.ngrok.io')
    $null = Invoke-Native nslookup.exe @('dt-test.pastebin.com')
    $long = ('a' * 45) + '.dt-test.example.test'
    $null = Invoke-Native nslookup.exe @($long)
}

function Test-WIN27 {
    Initialize-WorkDir
    Set-Content -Path (Join-Path $script:WorkDir 'dt_document.locked') -Value 'DT test' -Encoding ASCII
}

function Test-WIN28 {
    Initialize-WorkDir
    $p = Join-Path $script:WorkDir 'svchost.exe'
    Copy-Item "$env:windir\System32\whoami.exe" $p -Force
    $null = Invoke-Native $p @()
}

function Test-WIN29 {
    Initialize-WorkDir
    foreach ($n in 'ngrok.exe', 'rclone.exe') {
        $p = Join-Path $script:WorkDir $n
        Copy-Item "$env:windir\System32\whoami.exe" $p -Force
        $null = Invoke-Native $p @()
    }
}

function Test-WIN30 {
    Initialize-WorkDir
    $src = Join-Path $script:WorkDir 'dt_archive_src.txt'
    Set-Content -Path $src -Value 'DT test' -Encoding ASCII
    Compress-Archive -Path $src -DestinationPath (Join-Path $script:WorkDir 'dt_archive.zip') -Force
}

function Test-WIN31 {
    Initialize-WorkDir
    $f = Join-Path $script:WorkDir 'dt_passwords.txt'
    Set-Content -Path $f -Value 'DT test password' -Encoding ASCII
    $null = Invoke-Native findstr.exe @('/s', '/i', 'password', (Join-Path $script:WorkDir '*.txt'))
}

function Test-WIN32 {
    if (-not (Test-HasAd)) { throw "SKIP: нет модуля ActiveDirectory" }
    if ((Get-DomainRole) -lt 1) { throw "SKIP: машина не в домене" }
    Ensure-DtUser
    $dom = (Get-ADDomain).DNSRoot
    $spn = "HTTP/dt-test.$dom"
    $null = Invoke-Native setspn.exe @('-S', $spn, $script:DtUser)
    if ($script:LastExit -ne 0) { throw "setspn вернул код $($script:LastExit)" }
    Add-Cleanup { $null = Invoke-Native setspn.exe @('-D', $spn, $script:DtUser) }
    Add-Type -AssemblyName System.IdentityModel
    $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
    Write-Warn "Если RC4 запрещён политикой домена, билет будет с AES и алерт не придёт."
}

function Test-WIN33 {
    if (-not (Test-HasAd)) { throw "SKIP: нет модуля ActiveDirectory" }
    New-ADComputer -Name 'DTTESTPC' -Enabled $false -ErrorAction Stop
    Add-Cleanup { Remove-ADComputer -Identity 'DTTESTPC' -Confirm:$false -ErrorAction SilentlyContinue }
}

# ---------- Запуск ----------
function Show-List {
    $TestsMeta | ForEach-Object {
        Write-Host ("{0,-7} [{1}] {2}" -f $_.id, $_.risk, $_.name)
        foreach ($r in $_.rules) { Write-Host ("          → {0}" -f $r) -ForegroundColor DarkGray }
    }
}

if ($List) { Show-List; return }

$selected = @()
if ($All) { $selected = @($TestsMeta) }
elseif ($Id) {
    $want = $Id | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ }
    foreach ($w in $want) {
        $m = $TestsMeta | Where-Object { $_.id -eq $w }
        if ($m) { $selected += $m } else { Write-Err "Нет проверки $w"; return }
    }
} else {
    Show-List
    $ans = Read-Host "`nВведи id через запятую или all"
    if ($ans -eq 'all') { $selected = @($TestsMeta) }
    else {
        foreach ($w in ($ans -split ',' | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ })) {
            $m = $TestsMeta | Where-Object { $_.id -eq $w }
            if ($m) { $selected += $m } else { Write-Err "Нет проверки $w"; return }
        }
    }
}
if (-not $selected.Count) { Write-Warn "Ничего не выбрано"; return }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$roleText = switch (Get-DomainRole) { 4 { 'контроллер домена' } 5 { 'контроллер домена' } 3 { 'сервер домена' } 1 { 'рабочая станция в домене' } 0 { 'автономная станция' } default { 'не определено' } }
Write-Info "АРМ: $env:COMPUTERNAME ($roleText); пользователь $env:USERDOMAIN\$env:USERNAME; администратор: $(if ($isAdmin) { 'да' } else { 'нет' }); цель входов: $Target"
if (-not $isAdmin) { Write-Warn "Скрипт запущен без прав администратора: большинство проверок завершатся ошибкой." }
Write-Warn "Правила молчат в течение периода тишины (обычно час): повторный прогон подряд новых алертов не даст."

if (-not $DryRun -and -not $Force) {
    if ((Read-Host "Выполнить проверок: $($selected.Count)? Все созданные объекты будут удалены в конце (y/n)") -ne 'y') { Write-Warn "Отменено"; return }
}

$results = New-Object System.Collections.ArrayList
$runStart = Get-Date
try {
    foreach ($t in $selected) {
        Write-Host ""
        Write-Host "== $($t.id): $($t.name) ==" -ForegroundColor Magenta
        $row = [ordered]@{ id = $t.id; name = $t.name; started = (Get-Date).ToString('s'); finished = ''; status = ''; expected = ($t.rules -join ' | '); seen_in_graylog = ''; note = '' }
        if ($DryRun) {
            Write-Host "[dry-run] ожидаются алерты: $($t.rules -join '; ')"
            $row.status = 'не выполнялось (dry-run)'
        } else {
            try {
                & "Test-$($t.id -replace '-', '')"
                $row.status = 'выполнено'
                Write-Ok "Выполнено. Ожидаются алерты: $($t.rules -join '; ')"
            } catch {
                $msg = "$_"
                if ($msg -like 'BLOCKED:*') { $row.status = 'заблокировано защитой'; $row.note = $msg.Substring(8).Trim(); Write-Warn "Заблокировано защитой: $($row.note)" }
                elseif ($msg -like 'SKIP:*') { $row.status = 'пропущено'; $row.note = $msg.Substring(5).Trim(); Write-Warn "Пропущено: $($row.note)" }
                else { $row.status = 'ошибка'; $row.note = $msg; Write-Err "Ошибка: $msg" }
            }
            Start-Sleep -Seconds $PauseSec
        }
        $row.finished = (Get-Date).ToString('s')
        [void]$results.Add([pscustomobject]$row)
    }
} finally {
    if (-not $DryRun) {
        Write-Host ""
        Write-Info "Удаляю созданное..."
        for ($i = $script:Cleanups.Count - 1; $i -ge 0; $i--) {
            try { & $script:Cleanups[$i] } catch { Write-Warn "Очистка: $_" }
        }
    }
}

$runEnd = Get-Date
if (-not $Report) { $Report = Join-Path (Get-Location) ("detection-tests-windows-{0}.csv" -f $runStart.ToString('yyyyMMdd-HHmmss')) }
$results | Export-Csv -Path $Report -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Ok "Готово. Отчёт: $Report"
Write-Host "Окно времени для Graylog (Alerts → Events): $($runStart.ToString('HH:mm:ss')) - $($runEnd.AddMinutes(10).ToString('HH:mm:ss')) ($($runStart.ToString('dd.MM.yyyy')))"
Write-Host "Алерты приходят с задержкой до 10 минут. Заполните в отчёте колонку seen_in_graylog."
$bad = @($results | Where-Object { $_.status -eq 'ошибка' })
if ($bad.Count) { Write-Warn "Ошибок выполнения: $($bad.Count): $((($bad | ForEach-Object { $_.id }) -join ', '))" }
