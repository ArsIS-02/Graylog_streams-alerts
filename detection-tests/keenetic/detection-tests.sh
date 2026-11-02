#!/usr/bin/env bash
# Безопасные проверки детектов Graylog для роутера Keenetic.
#
# В отличие от других раннеров, выполняется НЕ на самой проверяемой системе: роутер не умеет
# запускать сторонние скрипты. Запускается с любой Linux-машины в той же сети, что и роутер
# (параметр --host), и действует на него по сети (SSH, веб, ARP, DHCP) — так же, как это делал бы
# настоящий пользователь или злоумышленник.
#
# Большинство проверок безопасны и обратимы. Две — КEN-07 (блокировка адреса) и KEN-08 (обрыв
# PPPoE) — ОТКЛЮЧЕНЫ ПО УМОЛЧАНИЮ и не входят в --all: первая на время бана роутера отрезает тестовую
# машину от веб-интерфейса, вторая на время переподключения рвёт интернет всей сети. Выбираются
# только явно (--id KEN-07) и требуют отдельного подтверждения словом «ДА» — флаг --yes на них не
# действует. Запускайте их в окно, когда кратковременный перерыв в доступе не критичен.
#
# Список проверок и ожидаемых алертов: docs/15-detection-tests.md.
#
#   ./detection-tests.sh --host 192.168.1.1 --list
#   ./detection-tests.sh --host 192.168.1.1 --id KEN-01,KEN-02,KEN-06 --dry-run
#   ./detection-tests.sh --host 192.168.1.1 --ssh-user admin --id KEN-06
#   ./detection-tests.sh --host 192.168.1.1 --id KEN-08 --isp ISP      # обрыв PPPoE, только явно
#
# Лицензия: GPL-3.0.

set -u

# BEGIN-META
META=$(cat <<'META_EOF'
KEN-01	SSH-подключение к роутеру с не-белого адреса	низкий	KEENETIC - Вход в админку роутера (SSH)
KEN-02	Неудачный вход на роутер (неверный пароль)	низкий	KEENETIC - Отказ во входе на роутер
KEN-03	ARP-конфликт для собственного адреса (arping)	средний	KEENETIC - ARP-конфликт на новом адресе
KEN-04	Новое устройство в сети (DHCP с чужого MAC)	низкий	KEENETIC - Новое устройство в сети
KEN-05	Неудачный WireGuard-handshake	низкий	KEENETIC - Отказы WireGuard (ежедневная сводка)
KEN-06	Сохранение конфигурации роутера	низкий	KEENETIC - Сохранена конфигурация роутера
KEN-07	Блокировка адреса в веб-интерфейсе (10 неудачных входов)	высокий	KEENETIC - Блокировка адреса за попытки входа в веб-интерфейс
KEN-08	Обрыв PPPoE-соединения	высокий	KEENETIC - Обрыв PPPoE-соединения с провайдером
META_EOF
)
# END-META
DISRUPTIVE="KEN-07 KEN-08"   # не входят в --all, требуют отдельного подтверждения «ДА»

HOST=""
SSH_USER="admin"
ISP="ISP"
WG_IFACE="wg0"
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
Использование: detection-tests.sh --host IP [параметры]
  --host IP           адрес роутера (обязателен, кроме --list)
  --ssh-user NAME     логин для SSH/CLI роутера (по умолчанию admin)
  --isp NAME          имя интерфейса провайдера в CLI роутера, для KEN-08 (по умолчанию ISP)
  --list              показать проверки и ожидаемые алерты
  --id ID[,ID...]     выполнить выбранные проверки (KEN-07, KEN-08 — только так, не через --all)
  --all               выполнить все проверки, КРОМЕ отключённых по умолчанию (KEN-07, KEN-08)
  --dry-run           только показать, что будет сделано
  --yes               не задавать обычных вопросов (на KEN-07/KEN-08 не действует)
  --pause N           пауза между проверками в секундах (по умолчанию 5)
  --report FILE       путь CSV-отчёта
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --host) shift; HOST="${1:-}" ;;
    --ssh-user) shift; SSH_USER="${1:-admin}" ;;
    --isp) shift; ISP="${1:-ISP}" ;;
    --wg-iface) shift; WG_IFACE="${1:-wg0}" ;;
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

have() { command -v "$1" >/dev/null 2>&1; }
skip() { SKIP_REASON="$1"; return 99; }
meta_field() { printf '%s\n' "$META" | awk -F'\t' -v id="$1" -v f="$2" '$1==id{print $f}'; }
is_disruptive() { case " $DISRUPTIVE " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
ssh_router() { ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "$SSH_USER@$HOST" "$@"; }

SKIP_REASON=""

# ---------- Проверки ----------
t_KEN_01() {
  have ssh || { skip "нет ssh"; return 99; }
  ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o BatchMode=no \
    -o PreferredAuthentications=none "$SSH_USER@$HOST" true >/dev/null 2>&1
  return 0   # важно само соединение (SSH_Connection), а не успешный вход
}

t_KEN_02() {
  have ssh || { skip "нет ssh"; return 99; }
  SSH_ASKPASS_REQUIRE=force SSH_ASKPASS=/bin/false setsid ssh -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new -o NumberOfPasswordPrompts=1 \
    -o PreferredAuthentications=password "wrong_dt_test@$HOST" true </dev/null >/dev/null 2>&1
  return 0
}

t_KEN_03() {
  have arping || { skip "нет пакета iputils-arping"; return 99; }
  local self_ip
  self_ip="$(ip route get "$HOST" 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
  [ -n "$self_ip" ] || { skip "не удалось определить собственный IP до роутера"; return 99; }
  local fake_mac
  fake_mac="$(printf '02:%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
  say_warn "Отправляю один ARP-пакет для собственного адреса $self_ip с другой MAC ($fake_mac): возможен секундный сбой связи у этой машины."
  timeout 3 arping -c 1 -s "$self_ip" -S "$fake_mac" "$HOST" >/dev/null 2>&1
  return 0
}

t_KEN_04() {
  have ip || { skip "нет команды ip"; return 99; }
  have dhclient || { skip "нет dhclient"; return 99; }
  local base_iface mv=dt_mv0
  base_iface="$(ip route get "$HOST" 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')"
  [ -n "$base_iface" ] || { skip "не удалось определить интерфейс до роутера"; return 99; }
  ip link add "$mv" link "$base_iface" type macvlan mode bridge 2>/dev/null || {
    skip "macvlan недоступен для $base_iface (нужны права root и поддержка ядра); надёжнее подключить тестовое устройство"; return 99; }
  ip link set "$mv" up
  ip link set "$mv" address "02:$(printf '%02x:%02x:%02x:%02x:%02x' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))"
  timeout 15 dhclient -1 -v "$mv" >/dev/null 2>&1
  dhclient -r "$mv" >/dev/null 2>&1
  ip link delete "$mv" 2>/dev/null
  return 0
}

t_KEN_05() {
  have wg || { skip "нет wireguard-tools (wg)"; return 99; }
  [ -e "/sys/class/net/$WG_IFACE" ] || { skip "интерфейс $WG_IFACE не настроен (параметр --wg-iface)"; return 99; }
  local bad_key
  bad_key="$(wg genkey 2>/dev/null | wg pubkey 2>/dev/null)"
  [ -n "$bad_key" ] || { skip "не удалось сгенерировать тестовый ключ wg"; return 99; }
  wg set "$WG_IFACE" peer "$bad_key" endpoint "$HOST:51820" allowed-ips 0.0.0.0/32 persistent-keepalive 1 2>/dev/null
  sleep 3
  wg set "$WG_IFACE" peer "$bad_key" remove 2>/dev/null
  return 0
}

t_KEN_06() {
  have ssh || { skip "нет ssh"; return 99; }
  ssh_router "system configuration save" >/dev/null 2>&1
  return 0
}

t_KEN_07() {
  have curl || { skip "нет curl"; return 99; }
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    curl -s -o /dev/null -u "dt_test_wrong:wrong-$i" "http://$HOST/" --connect-timeout 3
  done
  return 0
}

t_KEN_08() {
  have ssh || { skip "нет ssh"; return 99; }
  ssh_router "interface $ISP down" >/dev/null 2>&1
  sleep 2
  ssh_router "interface $ISP up" >/dev/null 2>&1
  return 0
}

# ---------- Запуск ----------
show_list() {
  printf '%s\n' "$META" | while IFS=$'\t' read -r id name risk rules; do
    [ -n "$id" ] || continue
    local tag=""
    is_disruptive "$id" && tag=" (отключено по умолчанию, только --id)"
    printf '%-8s [%s]%s %s\n' "$id" "$risk" "$tag" "$name"
    printf '%s\n' "$rules" | sed 's/ || /\n/g' | sed 's/^/           -> /'
  done
}

[ "$LIST" = 1 ] && { show_list; exit 0; }
[ -n "$HOST" ] || { say_err "Укажите --host IP роутера"; usage; exit 2; }

SELECTED=()
if [ "$ALL" = 1 ]; then
  while IFS=$'\t' read -r id _; do [ -n "$id" ] && ! is_disruptive "$id" && SELECTED+=("$id"); done <<<"$META"
elif [ -n "$IDS" ]; then
  IFS=',' read -r -a want <<<"$IDS"
  for w in "${want[@]}"; do
    w="$(printf '%s' "$w" | tr -d ' ' | tr 'a-z' 'A-Z')"
    [ -n "$(meta_field "$w" 2)" ] || { say_err "Нет проверки $w"; exit 2; }
    SELECTED+=("$w")
  done
else
  show_list
  printf '\nВведи id через запятую (KEN-07/KEN-08 только по id, не входят в all): '
  read -r ans
  IFS=',' read -r -a want <<<"$ans"
  for w in "${want[@]}"; do
    w="$(printf '%s' "$w" | tr -d ' ' | tr 'a-z' 'A-Z')"
    [ -n "$(meta_field "$w" 2)" ] || { say_err "Нет проверки $w"; exit 2; }
    SELECTED+=("$w")
  done
fi
[ "${#SELECTED[@]}" -gt 0 ] || { say_warn "Ничего не выбрано"; exit 0; }

say_info "Роутер: $HOST; проверок: ${#SELECTED[@]}"
say_warn "Правила молчат в течение периода тишины: повторный прогон подряд новых алертов не даст."
if [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
  printf 'Выполнить проверки? (y/n): '
  read -r a; [ "$a" = "y" ] || { say_warn "Отменено"; exit 0; }
fi

csv() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
START_TS="$(date '+%F %T')"
[ -n "$REPORT" ] || REPORT="detection-tests-keenetic-$(date +%Y%m%d-%H%M%S).csv"
printf '\xef\xbb\xbf' > "$REPORT"
echo 'id,name,started,finished,status,expected,seen_in_graylog,note' >> "$REPORT"

BAD=()
for id in "${SELECTED[@]}"; do
  name="$(meta_field "$id" 2)"; rules="$(meta_field "$id" 4)"
  echo; printf '%s== %s: %s ==%s\n' "$C_M" "$id" "$name" "$C_0"
  if [ "$DRY" = 0 ] && is_disruptive "$id"; then
    case "$id" in
      KEN-07) say_warn "KEN-07 временно банит IP этой машины в веб-интерфейсе роутера на время бана." ;;
      KEN-08) say_warn "KEN-08 рвёт интернет-соединение ВСЕЙ сети на время переподключения (обычно десятки секунд)." ;;
    esac
    printf 'Это разрушительное действие. Наберите ДА (заглавными) для подтверждения, иначе проверка будет пропущена: '
    read -r conf
    if [ "$conf" != "ДА" ]; then
      say_warn "Не подтверждено, пропускаю $id"
      { csv "$id"; echo -n ,; csv "$name"; echo -n ,; csv "$(date '+%F %T')"; echo -n ,; csv "$(date '+%F %T')"; echo -n ,
        csv "пропущено"; echo -n ,; csv "${rules// || / | }"; echo -n ,; csv ""; echo -n ,; csv "не подтверждено"; echo; } >> "$REPORT"
      continue
    fi
  fi
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

echo; say_ok "Готово. Отчёт: $REPORT"
echo "Окно времени для Graylog (Alerts → Events): с ${START_TS#* } (${START_TS%% *}), +10 минут на доставку."
[ "${#BAD[@]}" -gt 0 ] && say_warn "Ошибок выполнения: ${#BAD[@]}: ${BAD[*]}"
exit 0
