#!/usr/bin/env bash
# Безопасные проверки детектов Graylog для macOS (osquery, unified log, BI.ZONE Triage).
#
# Создаёт события, похожие на следы атак, чтобы убедиться, что алерты из каталога детектов срабатывают.
# Всё созданное (пользователь dt_test, файлы, LaunchAgent) удаляется в конце. Опасные техники
# имитируются безвредной командной строкой. Запускайте только в лаборатории, из сессии администратора.
# Список проверок и ожидаемых алертов: docs/15-detection-tests.md.
#
#   ./detection-tests.sh --list
#   ./detection-tests.sh --id LNX-01,LNX-05 --dry-run
#   ./detection-tests.sh --all --yes
#
# Лицензия: GPL-3.0.

set -u

# BEGIN-META
META=$(cat <<'META_EOF'
MAC-01	Создание пользователя через dscl	средний	macOS - Создана учётная запись (dscl, sysadminctl) || macOS - Создание пользователя или изменение групп || macOS - Bi.Zone: новый пользователь
MAC-02	Неверный пароль sudo	низкий	macOS - Неудачная попытка sudo (неверный пароль)
MAC-03	Команда через sudo	низкий	macOS - Выполнение команды через sudo
MAC-04	Запрос пароля из Keychain (несуществующая запись)	низкий	macOS - Выгрузка паролей из Keychain (security dump-keychain) || macOS - Выгрузка паролей из Keychain
MAC-05	Снятие карантина с файла	низкий	macOS - Снятие карантина с приложения || macOS - Снятие карантина вне Applications или отключение Gatekeeper
MAC-06	Командная строка «curl | sh» (имитация)	низкий	macOS - Скачивание и запуск (curl | sh)
MAC-07	Командные строки отключения SIP и Gatekeeper (имитация)	низкий	macOS - Отключение SIP (csrutil disable) || macOS - Отключение SIP или Gatekeeper
MAC-08	Диалог пароля через osascript	низкий	macOS - Фишинговый запрос пароля через osascript || macOS - Поддельное окно ввода пароля (osascript hidden answer)
MAC-09	Сценарий JXA через osascript	низкий	macOS - JXA-скрипт через osascript
MAC-10	Тестовый LaunchAgent: plist и load	средний	macOS - Новый/изменённый plist в автозагрузке || macOS - Загрузка launchd-задания (load, bootstrap, submit) || macOS - Bi.Zone: новый элемент автозагрузки
MAC-11	Сброс TCC для несуществующего приложения	низкий	macOS - Вмешательство в TCC
MAC-12	Смена DNS и прокси (имитация)	низкий	macOS - Смена DNS или прокси (networksetup)
MAC-13	Профили конфигурации (имитация)	низкий	macOS - Установка или удаление профиля конфигурации || macOS - Установка конфигурационного профиля (profiles install)
MAC-14	Доверенный сертификат (имитация)	низкий	macOS - Добавление корневого сертификата || macOS - Установка доверенного корневого сертификата
MAC-15	Отключение межсетевого экрана (имитация)	низкий	macOS - Отключение межсетевого экрана (socketfilterfw, pfctl)
MAC-16	Очистка журналов (имитация)	низкий	macOS - Очистка журналов
MAC-17	DYLD_INSERT_LIBRARIES в окружении процесса	низкий	macOS - Подмена библиотек (DYLD_INSERT_LIBRARIES)
MAC-18	Запуск программы из /tmp	низкий	macOS - Запуск программы из /tmp или /Users/Shared || macOS - Bi.Zone: процесс из /tmp или /Users/Shared
MAC-19	Слушающий порт у nc (60 секунд)	низкий	macOS - Подозрительный процесс открыл TCP-порт
MAC-20	Включение удалённого входа (имитация)	низкий	macOS - Включение удалённого доступа (SSH, Screen Sharing, ARD) || macOS - Включение удалённого входа или Screen Sharing
MAC-21	Строки обратной оболочки (имитация)	низкий	macOS - Обратная оболочка (/dev/tcp, pty.spawn)
MAC-22	Программы с именами ngrok, rclone, nmap	низкий	macOS - Запуск утилит удалённого доступа и туннелей || macOS - Утилиты выгрузки в облако (rclone, MEGAsync) || macOS - Сканеры сети (nmap, masscan, arp-scan)
MAC-23	Поиск паролей через grep -r	низкий	macOS - Поиск паролей в файлах (grep -r по / и ~)
MAC-24	Файл в /etc/sudoers.d	средний	macOS - Изменение /etc/sudoers || macOS - Bi.Zone: новое правило в sudoers
MAC-25	Элемент входа и launchctl bootout (имитация)	низкий	macOS - Элемент входа через sfltool или osascript || macOS - Добавление элемента входа (sfltool, osascript login item) || macOS - Остановка агентов сбора логов и защиты (launchctl)
MAC-26	Передача данных наружу (имитация)	низкий	macOS - Передача данных наружу (scp, rsync, nc, socat)
MAC-27	tmutil и diskutil (имитация)	низкий	macOS - Уничтожение резервных копий или дисков (tmutil, diskutil)
MAC-28	Копирование данных браузера (имитация)	низкий	macOS - Копирование данных браузера
MAC-29	Расширения ядра и authorizationdb (имитация)	низкий	macOS - Загрузка расширения ядра || macOS - Изменение базы авторизации (authorizationdb) || macOS - Вмешательство в TCC
META_EOF
)
# END-META

WORK=/tmp/dt_work_mac
DT_USER=dt_test
CLEANUPS=()
SKIP_REASON=""
PAUSE=5
REPORT=""
DRY=0
YES=0
ALL=0
LIST=0
IDS=""

if [ -t 1 ]; then C_G=$'\e[32m'; C_R=$'\e[31m'; C_Y=$'\e[33m'; C_C=$'\e[36m'; C_M=$'\e[35m'; C_0=$'\e[0m'; else C_G=""; C_R=""; C_Y=""; C_C=""; C_M=""; C_0=""; fi
say_ok()   { printf '%s%s%s\n' "$C_G" "$*" "$C_0"; }
say_err()  { printf '%s%s%s\n' "$C_R" "$*" "$C_0"; }
say_warn() { printf '%s%s%s\n' "$C_Y" "$*" "$C_0"; }
say_info() { printf '%s%s%s\n' "$C_C" "$*" "$C_0"; }

usage() {
  cat <<'EOF'
Использование: detection-tests.sh [параметры]
  --list            показать проверки и ожидаемые алерты
  --id ID[,ID...]   выполнить выбранные проверки
  --all             выполнить все проверки
  --dry-run         только показать, что будет сделано
  --yes             не задавать вопросов
  --pause N         пауза между проверками в секундах (по умолчанию 5)
  --report FILE     путь CSV-отчёта
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --list) LIST=1 ;;
    --id) shift; IDS="${1:-}" ;;
    --all) ALL=1 ;;
    --dry-run) DRY=1 ;;
    --yes) YES=1 ;;
    --pause) shift; PAUSE="${1:-5}" ;;
    --report) shift; REPORT="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    *) say_err "Неизвестный параметр: $1"; usage; exit 2 ;;
  esac
  shift
done

# ---------- Помощники ----------
defer() { CLEANUPS+=("$1"); }
skip() { SKIP_REASON="$1"; return 99; }
have() { command -v "$1" >/dev/null 2>&1; }
quiet() { "$@" >/dev/null 2>&1; }

ensure_work() {
  [ -d "$WORK" ] || mkdir -p "$WORK"
  if [ "${WORK_REG:-0}" = 0 ]; then defer "rm -rf '$WORK'"; WORK_REG=1; fi
}

meta_field() { # id поле(2=имя,3=риск,4=правила)
  printf '%s\n' "$META" | awk -F'\t' -v id="$1" -v f="$2" '$1==id{print $f}'
}

# ---------- Проверки ----------
# sim: выполняет bash -c с комментарием; сама команда ничего не делает, но попадает в журнал процессов
sim() { /bin/bash -c "true # $1"; }

t_MAC_01() {
  sudo -n true 2>/dev/null || sudo -v || return 1
  sudo dscl . -delete /Users/dt_test >/dev/null 2>&1
  sudo dscl . -create /Users/dt_test || return 1
  defer "sudo dscl . -delete /Users/dt_test"
  sudo dscl . -create /Users/dt_test UniqueID 599
  sudo dscl . -create /Users/dt_test PrimaryGroupID 20
  sudo dscl . -create /Users/dt_test UserShell /usr/bin/false
  sudo dscl . -create /Users/dt_test RealName "DT Test"
  return 0
}

t_MAC_02() { echo "wrong-password" | sudo -S -k -p '' true >/dev/null 2>&1; return 0; }

t_MAC_03() { sudo -n true 2>/dev/null || sudo -v || return 1; sudo true; }

t_MAC_04() { security find-generic-password -s dt_nonexistent_service_xyz -w >/dev/null 2>&1; return 0; }

t_MAC_05() {
  ensure_work
  touch "$WORK/dt_app"
  xattr -w com.apple.quarantine "0081;00000000;DT;" "$WORK/dt_app"
  xattr -d com.apple.quarantine "$WORK/dt_app"
}

t_MAC_06() { sim "curl http://127.0.0.1/dt | sh"; }

t_MAC_07() { sim "csrutil disable"; sim "spctl --master-disable"; }

t_MAC_08() {
  osascript -e 'display dialog "DT test" default answer "" with hidden answer giving up after 3' >/dev/null 2>&1
  return 0
}

t_MAC_09() { osascript -l JavaScript -e '1+1' >/dev/null 2>&1; return 0; }

t_MAC_10() {
  local p="$HOME/Library/LaunchAgents/com.dt.test.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$p" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.dt.test</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
<key>RunAtLoad</key><false/>
</dict></plist>
EOF
  defer "launchctl unload '$p' >/dev/null 2>&1; rm -f '$p'"
  launchctl load "$p" >/dev/null 2>&1
  return 0
}

t_MAC_11() { tccutil reset Camera com.dt.nonexistent >/dev/null 2>&1; return 0; }

t_MAC_12() { sim "networksetup -setdnsservers Wi-Fi 127.0.0.1"; }

t_MAC_13() { sim "profiles install -type configuration -path /dev/null"; }

t_MAC_14() { sim "security add-trusted-cert -d -r trustRoot /tmp/dt.pem"; }

t_MAC_15() { sim "socketfilterfw --setglobalstate off"; sim "pfctl -d"; }

t_MAC_16() { sim "log erase --all"; }

t_MAC_17() { DYLD_INSERT_LIBRARIES=/tmp/dt_none.dylib /usr/bin/true; return 0; }

t_MAC_18() {
  install -m 755 /usr/bin/true /tmp/dt_test_bin || return 1
  defer "rm -f /tmp/dt_test_bin /Users/Shared/dt_test_bin"
  /tmp/dt_test_bin
  install -m 755 /usr/bin/true /Users/Shared/dt_test_bin && /Users/Shared/dt_test_bin
  return 0
}

t_MAC_19() {
  nc -l 49999 >/dev/null 2>&1 &
  local pid=$!
  defer "kill $pid >/dev/null 2>&1"
  say_info "Порт 49999 открыт на 60 секунд..."
  sleep 60
  kill "$pid" >/dev/null 2>&1
  return 0
}

t_MAC_20() { sim "systemsetup -setremotelogin on"; }

t_MAC_21() { sim "python3 -c pty.spawn socket.socket /dev/tcp"; }

t_MAC_22() {
  ensure_work
  mkdir -p "$WORK/bin"
  local n
  for n in ngrok rclone nmap; do install -m 755 /usr/bin/true "$WORK/bin/$n"; done
  PATH="$WORK/bin:$PATH" ngrok
  PATH="$WORK/bin:$PATH" rclone
  PATH="$WORK/bin:$PATH" nmap
  return 0
}

t_MAC_23() {
  ensure_work
  mkdir -p "$WORK/grep"
  echo "password=DTtest" > "$WORK/grep/dt.conf"
  grep -r password "$WORK/grep" >/dev/null
  return 0
}

t_MAC_24() {
  sudo -n true 2>/dev/null || sudo -v || return 1
  sudo sh -c "echo '# dt_test' > /etc/sudoers.d/dt_test && chmod 440 /etc/sudoers.d/dt_test" || return 1
  defer "sudo rm -f /etc/sudoers.d/dt_test"
  sudo visudo -cf /etc/sudoers.d/dt_test >/dev/null 2>&1
  return 0
}

t_MAC_25() {
  sim "sfltool add-item com.apple.LSSharedFileList.SessionLoginItems dt.app"
  sim "launchctl bootout system/org.graylog.dt_test"
}

t_MAC_26() { sim "scp /tmp/dt.txt dtuser@host.example.test:/tmp"; }

t_MAC_27() { sim "tmutil disable"; }

t_MAC_28() { sim "cp Login Data /tmp/dt_login_data"; }

t_MAC_29() {
  sim "kextload /tmp/dt.kext"
  sim "security authorizationdb write system.privilege.admin allow"
  sim "sqlite3 TCC.db"
}

# ---------- Запуск ----------
show_list() {
  printf '%s\n' "$META" | while IFS=$'\t' read -r id name risk rules; do
    [ -n "$id" ] || continue
    printf '%-8s [%s] %s\n' "$id" "$risk" "$name"
    printf '%s\n' "$rules" | sed 's/ || /\n/g' | sed 's/^/           -> /'
  done
}

[ "$LIST" = 1 ] && { show_list; exit 0; }

# выбор
SELECTED=()
if [ "$ALL" = 1 ]; then
  while IFS=$'\t' read -r id _; do [ -n "$id" ] && SELECTED+=("$id"); done <<<"$META"
elif [ -n "$IDS" ]; then
  IFS=',' read -r -a want <<<"$IDS"
  for w in "${want[@]}"; do
    w="$(printf '%s' "$w" | tr -d ' ' | tr 'a-z' 'A-Z')"
    [ -n "$(meta_field "$w" 2)" ] || { say_err "Нет проверки $w"; exit 2; }
    SELECTED+=("$w")
  done
else
  show_list
  printf '\nВведи id через запятую или all: '
  read -r ans
  if [ "$ans" = "all" ]; then
    while IFS=$'\t' read -r id _; do [ -n "$id" ] && SELECTED+=("$id"); done <<<"$META"
  else
    IFS=',' read -r -a want <<<"$ans"
    for w in "${want[@]}"; do
      w="$(printf '%s' "$w" | tr -d ' ' | tr 'a-z' 'A-Z')"
      [ -n "$(meta_field "$w" 2)" ] || { say_err "Нет проверки $w"; exit 2; }
      SELECTED+=("$w")
    done
  fi
fi
[ "${#SELECTED[@]}" -gt 0 ] || { say_warn "Ничего не выбрано"; exit 0; }

if [ "$(id -u)" -eq 0 ]; then say_warn "Запуск от root: проверки рассчитаны на сессию администратора, часть событий может не совпасть."; fi
say_info "Хост: $(hostname); пользователь: $(id -un); проверок: ${#SELECTED[@]}"
say_warn "Правила молчат в течение периода тишины (обычно час): повторный прогон подряд новых алертов не даст."
if [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
  printf 'Выполнить проверки? Все созданные объекты будут удалены в конце (y/n): '
  read -r a; [ "$a" = "y" ] || { say_warn "Отменено"; exit 0; }
fi

csv() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
START_TS="$(date '+%F %T')"; START_EPOCH="$(date +%s)"
[ -n "$REPORT" ] || REPORT="detection-tests-linux-$(date +%Y%m%d-%H%M%S).csv"
printf '\xef\xbb\xbf' > "$REPORT"
echo 'id,name,started,finished,status,expected,seen_in_graylog,note' >> "$REPORT"

cleanup_all() {
  [ "$DRY" = 1 ] && return
  echo; say_info "Удаляю созданное..."
  local i
  for ((i=${#CLEANUPS[@]}-1; i>=0; i--)); do eval "${CLEANUPS[$i]}" 2>/dev/null; done
}
trap cleanup_all EXIT

BAD=()
for id in "${SELECTED[@]}"; do
  name="$(meta_field "$id" 2)"; rules="$(meta_field "$id" 4)"
  echo; printf '%s== %s: %s ==%s\n' "$C_M" "$id" "$name" "$C_0"
  st="$(date '+%F %T')"; status=""; note=""
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] ожидаются алерты: ${rules// || /; }"; status="не выполнялось (dry-run)"
  else
    SKIP_REASON=""
    "t_${id//-/_}"; rc=$?
    if [ $rc -eq 0 ]; then status="выполнено"; say_ok "Выполнено. Ожидаются алерты: ${rules// || /; }"
    elif [ $rc -eq 99 ]; then status="пропущено"; note="$SKIP_REASON"; say_warn "Пропущено: $note"
    else status="ошибка"; note="код $rc"; say_err "Ошибка выполнения (код $rc)"; BAD+=("$id"); fi
    sleep "$PAUSE"
  fi
  { csv "$id"; echo -n ,; csv "$name"; echo -n ,; csv "$st"; echo -n ,; csv "$(date '+%F %T')"; echo -n ,; csv "$status"; echo -n ,
    csv "${rules// || / | }"; echo -n ,; csv ""; echo -n ,; csv "$note"; echo; } >> "$REPORT"
done

cleanup_all; trap - EXIT
END_HM="$(date -v+10M '+%H:%M:%S' 2>/dev/null || true)"
echo; say_ok "Готово. Отчёт: $REPORT"
echo "Окно времени для Graylog (Alerts → Events): ${START_TS#* } - ${END_HM:-+10 минут} (${START_TS%% *})"
echo "Алерты приходят с задержкой до 10 минут. Заполните в отчёте колонку seen_in_graylog."
[ "${#BAD[@]}" -gt 0 ] && say_warn "Ошибок выполнения: ${#BAD[@]}: ${BAD[*]}"
exit 0
