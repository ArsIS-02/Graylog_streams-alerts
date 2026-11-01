#!/usr/bin/env bash
# Безопасные проверки детектов Graylog для Linux (auditd, правила из auditd-rules-redos).
#
# Создаёт события, похожие на следы атак, чтобы убедиться, что алерты из каталога детектов срабатывают.
# Всё созданное (пользователь dt_test, файлы, служба dt-test) удаляется в конце. Опасные техники
# имитируются безвредной командой. Запускайте только в лаборатории, от root.
# Список проверок и ожидаемых алертов: docs/15-detection-tests.md.
#
#   sudo ./detection-tests.sh --list
#   sudo ./detection-tests.sh --id LNX-01,LNX-05 --dry-run
#   sudo ./detection-tests.sh --all --yes
#
# Лицензия: GPL-3.0.

set -u

# BEGIN-META
META=$(cat <<'META_EOF'
LNX-01	Создание пользователя (useradd)	низкий	LNX - Создана локальная учётная запись (useradd) || LNX - Добавление/удаление пользователя
LNX-02	Изменение /etc/passwd (usermod)	низкий	LNX - Изменение /etc/passwd, shadow, group
LNX-03	Добавление пользователя в группу wheel	низкий	LNX - Участник добавлен в группу wheel, sudo, root, adm или docker
LNX-04	Правка sshd_config с откатом	средний	LNX - Изменение sshd_config
LNX-05	Запуск программы из /tmp	низкий	LNX - Запуск из /tmp, /dev/shm, /var/tmp
LNX-06	Затирание следов: shred и очистка своего лога	низкий	LNX - Затирание следов (shred, history, truncate логов)
LNX-07	Очистка истории (history -c, unset HISTFILE)	низкий	LNX - Очистка истории команд (history -c, unset HISTFILE)
LNX-08	Строки обратной оболочки в командной строке (имитация)	низкий	LNX - Обратная оболочка (/dev/tcp) || LNX - Обратная оболочка (bash -i, nc -e, socat exec) || LNX - Обратная оболочка (python, perl, nc, socat, mkfifo)
LNX-09	Опасный запуск контейнера (имитация) и docker с «privileged»	низкий	LNX - Опасный запуск контейнера (--privileged, -v /:/, docker.sock) || LNX - Привилегированный контейнер или docker.sock
LNX-10	Строки отключения SELinux и аудита (имитация)	низкий	LNX - Отключение SELinux или аудита (setenforce 0, auditctl -e 0)
LNX-11	Неудачные sudo (6 попыток)	низкий	LNX - Подбор пароля sudo или su (5+ ошибок за 5 мин) || LNX - Неудачная попытка sudo
LNX-12	Неудачные входы по SSH (7 попыток)	низкий	LNX - Брутфорс SSH (5+ неудачных входов за 5 мин) || LNX - Подбор пароля и успешный вход по SSH (6+ событий за 15 мин)
LNX-13	Установка бита setuid	низкий	LNX - Установка бита setuid или setgid (chmod u+s) || LNX - Установка setuid или setgid || LNX - Изменение прав доступа (chmod)
LNX-14	Закрепление через cron и crontab -e	низкий	LNX - Закрепление через cron || LNX - Правка crontab (crontab -e)
LNX-15	Служба systemd: enable и stop	низкий	LNX - Закрепление через systemctl enable || LNX - Остановка службы (systemctl stop)
LNX-16	modprobe в пробном режиме	низкий	LNX - Загрузка или выгрузка модуля ядра (insmod, modprobe, rmmod)
LNX-17	Программы с именами ngrok, nmap, rclone	низкий	LNX - Запуск утилит удалённого доступа и туннелей || LNX - Сканеры сети (nmap, masscan, arp-scan) || LNX - Утилиты выгрузки в облако (rclone, MEGAcmd)
LNX-18	Поиск паролей через grep -r	низкий	LNX - Поиск паролей в файлах (grep -r, find)
LNX-19	Установка времени той же датой	средний	LNX - Ручная смена системного времени
LNX-20	Использование sudo	низкий	LNX - Использование sudo
LNX-21	Разведка: id и whoami	низкий	LNX - Разведка (id, whoami)
LNX-22	rsync и base64 из терминала	низкий	LNX - Передача файлов наружу (scp, sftp, rsync) из терминала || LNX - Подозрительные утилиты (base64, nc, socat, scp)
LNX-23	Архивация через tar	низкий	LNX - Архивация данных пользователем (tar, zip, 7z)
LNX-24	Просмотр правил iptables и nft	низкий	LNX - Изменение правил firewall (iptables, nft)
LNX-25	Правка /etc/hosts с откатом	средний	LNX - Изменение сетевых настроек и /etc/hosts
LNX-26	memfd_create из python	низкий	LNX - Исполнение из памяти (memfd_create)
LNX-27	Файл authorized_keys у тестовой учётки	низкий	LNX - Добавление SSH-ключа в authorized_keys
LNX-28	Оболочка от имени веб-сервера	низкий	LNX - Веб-сервер запустил оболочку
LNX-29	Массовое удаление файлов (250 штук)	низкий	LNX - Массовое удаление файлов (200+ за 5 мин)
LNX-30	Строка SSH-туннеля в командной строке	низкий	LNX - SSH-туннель (-R, -L, -D)
META_EOF
)
# END-META

WORK=/tmp/dt_work
DT_USER=dt_test
DT_PWD=""
USER_CREATED=0
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

new_password() { head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16; printf 'a1!'; }

ensure_work() {
  [ -d "$WORK" ] || mkdir -p "$WORK"
  if [ "${WORK_REG:-0}" = 0 ]; then defer "rm -rf '$WORK'"; WORK_REG=1; fi
}

ensure_user() {
  [ "$USER_CREATED" = 1 ] && return 0
  DT_PWD="$(new_password)"
  quiet userdel -r "$DT_USER"
  useradd -m -s /sbin/nologin "$DT_USER" || return 1
  echo "$DT_USER:$DT_PWD" | chpasswd || return 1
  USER_CREATED=1
  defer "userdel -r '$DT_USER' >/dev/null 2>&1"
}

meta_field() { # id поле(2=имя,3=риск,4=правила)
  printf '%s\n' "$META" | awk -F'\t' -v id="$1" -v f="$2" '$1==id{print $f}'
}

# ---------- Проверки ----------
t_LNX_01() { ensure_user; }

t_LNX_02() { ensure_user && usermod -c "dt test" "$DT_USER"; }

t_LNX_03() {
  ensure_user || return 1
  local g=""
  for c in wheel sudo; do getent group "$c" >/dev/null && { g="$c"; break; }; done
  [ -n "$g" ] || { skip "нет группы wheel или sudo"; return 99; }
  usermod -aG "$g" "$DT_USER" || return 1
  defer "gpasswd -d '$DT_USER' '$g' >/dev/null 2>&1"
}

t_LNX_04() {
  [ -f /etc/ssh/sshd_config ] || { skip "нет /etc/ssh/sshd_config"; return 99; }
  ensure_work
  cp --preserve=all /etc/ssh/sshd_config "$WORK/sshd_config.bak" || return 1
  defer "cp --preserve=all '$WORK/sshd_config.bak' /etc/ssh/sshd_config"
  echo "# dt_test $(date +%s)" >> /etc/ssh/sshd_config
}

t_LNX_05() {
  install -m 755 /bin/true /tmp/dt_test_bin || return 1
  defer "rm -f /tmp/dt_test_bin /dev/shm/dt_test_bin"
  /tmp/dt_test_bin
  install -m 755 /bin/true /dev/shm/dt_test_bin && /dev/shm/dt_test_bin
  return 0
}

t_LNX_06() {
  ensure_work
  echo dt > "$WORK/dt_shred.txt"
  shred -u "$WORK/dt_shred.txt"
  echo dt > /var/log/dt_test.log
  defer "rm -f /var/log/dt_test.log"
  truncate -s 0 /var/log/dt_test.log
  bash -c "rm -f $WORK/.bash_history"
  return 0
}

t_LNX_07() { bash -c 'history -c; unset HISTFILE'; return 0; }

t_LNX_08() {
  /bin/echo "bash -i >& /dev/tcp/127.0.0.1/9 0>&1" >/dev/null
  /bin/echo "mkfifo /tmp/dt_f; nc 127.0.0.1 9 0</tmp/dt_f" >/dev/null
  /bin/echo "python3 -c import socket,subprocess,os" >/dev/null
  return 0
}

t_LNX_09() {
  /bin/echo "docker run --privileged -v /:/host dt_image" >/dev/null
  if have docker; then docker ps --filter "name=privileged_dt" >/dev/null 2>&1
  elif have podman; then podman ps --filter "name=privileged_dt" >/dev/null 2>&1
  else say_warn "Нет docker и podman: второе правило проверено не будет"; fi
  return 0
}

t_LNX_10() { /bin/echo "setenforce 0; auditctl -e 0" >/dev/null; return 0; }

t_LNX_11() {
  have sudo || { skip "нет sudo"; return 99; }
  ensure_user || return 1
  local i
  for i in 1 2 3 4 5 6; do
    runuser -u "$DT_USER" -- sh -c "echo wrong-$i | sudo -S -k true" >/dev/null 2>&1
  done
  return 0
}

t_LNX_12() {
  have ssh || { skip "нет ssh"; return 99; }
  timeout 3 bash -c '</dev/tcp/127.0.0.1/22' 2>/dev/null || { skip "sshd не слушает на 127.0.0.1:22"; return 99; }
  ensure_user || return 1
  ensure_work
  printf '#!/bin/sh\necho wrong-password\n' > "$WORK/askpass.sh"; chmod 700 "$WORK/askpass.sh"
  local i
  for i in 1 2 3 4 5 6 7; do
    SSH_ASKPASS="$WORK/askpass.sh" SSH_ASKPASS_REQUIRE=force setsid ssh \
      -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=5 "$DT_USER@127.0.0.1" true </dev/null >/dev/null 2>&1
  done
  return 0
}

t_LNX_13() {
  ensure_work
  cp /bin/true "$WORK/dt_suid" || return 1
  chmod u+s "$WORK/dt_suid"
}

t_LNX_14() {
  printf '# dt_test cron persistence\n' > /etc/cron.d/dt_test
  defer "rm -f /etc/cron.d/dt_test"
  if have crontab; then EDITOR=true crontab -e >/dev/null 2>&1; fi
  return 0
}

t_LNX_15() {
  have systemctl || { skip "нет systemd"; return 99; }
  cat > /etc/systemd/system/dt-test.service <<'EOF'
[Unit]
Description=Detection test (does nothing)
[Service]
Type=oneshot
ExecStart=/bin/true
RemainAfterExit=no
[Install]
WantedBy=multi-user.target
EOF
  defer "systemctl disable dt-test.service >/dev/null 2>&1; rm -f /etc/systemd/system/dt-test.service /etc/systemd/system/multi-user.target.wants/dt-test.service; systemctl daemon-reload"
  systemctl daemon-reload
  systemctl enable dt-test.service >/dev/null 2>&1
  systemctl stop dt-test.service >/dev/null 2>&1
  return 0
}

t_LNX_16() { have modprobe || { skip "нет modprobe"; return 99; }; modprobe -n -v dummy >/dev/null 2>&1; return 0; }

t_LNX_17() {
  ensure_work
  mkdir -p "$WORK/bin"
  local n
  for n in ngrok nmap rclone; do install -m 755 /bin/true "$WORK/bin/$n"; done
  PATH="$WORK/bin:$PATH" ngrok
  PATH="$WORK/bin:$PATH" nmap
  PATH="$WORK/bin:$PATH" rclone
  return 0
}

t_LNX_18() {
  ensure_work
  mkdir -p "$WORK/grep"
  echo "password=DTtest" > "$WORK/grep/dt.conf"
  grep -r password "$WORK/grep" >/dev/null
  return 0
}

t_LNX_19() { date -s "$(date '+%Y-%m-%d %H:%M:%S')" >/dev/null; }

t_LNX_20() { have sudo || { skip "нет sudo"; return 99; }; sudo -n true; }

t_LNX_21() { id >/dev/null; whoami >/dev/null; return 0; }

t_LNX_22() {
  have rsync || { skip "нет rsync"; return 99; }
  have script || { skip "нет утилиты script"; return 99; }
  ensure_work
  echo dt > "$WORK/a.txt"
  script -qc "rsync -a '$WORK/a.txt' '$WORK/b.txt'" /dev/null >/dev/null 2>&1
  base64 /etc/hostname >/dev/null
  return 0
}

t_LNX_23() {
  ensure_work
  echo dt > "$WORK/tar_src.txt"
  tar czf "$WORK/dt.tgz" -C "$WORK" tar_src.txt
}

t_LNX_24() {
  local ran=0
  if have iptables; then iptables -L -n >/dev/null 2>&1; ran=1; fi
  if have nft; then nft list ruleset >/dev/null 2>&1; ran=1; fi
  [ "$ran" = 1 ] || { skip "нет iptables и nft"; return 99; }
  return 0
}

t_LNX_25() {
  ensure_work
  cp --preserve=all /etc/hosts "$WORK/hosts.bak" || return 1
  defer "cp --preserve=all '$WORK/hosts.bak' /etc/hosts"
  echo "# dt_test" >> /etc/hosts
}

t_LNX_26() { have python3 || { skip "нет python3"; return 99; }; python3 -c "import os; fd=os.memfd_create('dt_test'); os.close(fd)"; }

t_LNX_27() {
  ensure_user || return 1
  mkdir -p "/home/$DT_USER/.ssh"
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT0TEST0KEY0DOES0NOT0EXIST000000000000000 dt_test" > "/home/$DT_USER/.ssh/authorized_keys"
  chown -R "$DT_USER" "/home/$DT_USER/.ssh"
}

t_LNX_28() {
  local u=""
  for c in apache nginx www-data; do id -u "$c" >/dev/null 2>&1 && { u="$c"; break; }; done
  [ -n "$u" ] || { skip "нет пользователя веб-сервера (apache, nginx, www-data)"; return 99; }
  runuser -u "$u" -- /bin/sh -c true
}

t_LNX_29() {
  ensure_work
  mkdir -p "$WORK/mass"
  local i
  for i in $(seq 1 250); do : > "$WORK/mass/f$i"; done
  for i in $(seq 1 250); do rm -f "$WORK/mass/f$i"; done
  return 0
}

t_LNX_30() {
  have ssh || { skip "нет ssh"; return 99; }
  ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -R 19999:localhost:22 dt_nouser@127.0.0.1 true >/dev/null 2>&1
  return 0
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

if [ "$DRY" = 0 ] && [ "$(id -u)" -ne 0 ]; then say_err "Нужны права root: запустите через sudo"; exit 1; fi
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
END_HM="$(date -d "@$(( $(date +%s) + 600 ))" '+%H:%M:%S' 2>/dev/null || true)"
echo; say_ok "Готово. Отчёт: $REPORT"
echo "Окно времени для Graylog (Alerts → Events): ${START_TS#* } - ${END_HM:-+10 минут} (${START_TS%% *})"
echo "Алерты приходят с задержкой до 10 минут. Заполните в отчёте колонку seen_in_graylog."
[ "${#BAD[@]}" -gt 0 ] && say_warn "Ошибок выполнения: ${#BAD[@]}: ${BAD[*]}"
exit 0
