#!/usr/bin/env bash
# Безопасные проверки детектов Graylog для контейнеров home-lab (grafana, loki, mongo, netalertx,
# promtail, observiumdb и прочие сервисы потока «Containers»).
#
# Ничего не ломает: каждая проверка пишет одну или несколько строк лога напрямую в stdout контейнера
# (docker/podman exec ... > /proc/1/fd/1) — так лог попадает в тот же поток, что и настоящие сообщения
# процесса, но сам процесс и его данные не трогаются. Формат строк подобран под парсеры пайплайна
# (Loki, mongod), это имитация, а не настоящая ошибка. Если контейнер не запущен — проверка пропускается.
# Запускайте от пользователя, у которого есть доступ к docker/podman (в группе docker или через sudo).
# Список проверок и ожидаемых алертов: docs/15-detection-tests.md.
#
#   ./detection-tests.sh --list
#   ./detection-tests.sh --id CTR-01,CTR-05 --dry-run
#   ./detection-tests.sh --all
#   ./detection-tests.sh --id CTR-07 --container zaslon
#
# Лицензия: GPL-3.0.

set -u

# BEGIN-META
META=$(cat <<'META_EOF'
CTR-01	Grafana: 6 неудачных входов (подбор пароля)	низкий	Контейнеры: Grafana — неудачный вход (подбор пароля)
CTR-02	Loki: ошибка приёма	низкий	Контейнеры: Loki — ошибки приёма
CTR-03	MongoDB: запись уровня E в лог	низкий	Контейнеры: MongoDB — ошибки
CTR-04	netalertx: всплеск объёма логов (4600 строк)	низкий	Контейнеры: netalertx — всплеск объёма логов
CTR-05	netalertx: имитация находки нового устройства	низкий	Контейнеры: netalertx — новое устройство в сети
CTR-06	promtail: имитация «context deadline exceeded» (16 строк)	низкий	Контейнеры: promtail не доставляет логи в Loki
CTR-07	Контейнер: всплеск общих ошибок (11 строк)	низкий	Контейнеры: всплеск ошибок
CTR-08	Контейнер: имитация OOM ("out of memory")	низкий	Контейнеры: нехватка памяти или падение процесса
CTR-09	Контейнер: 51 строка «Operation not permitted»	низкий	Контейнеры: ошибки прав доступа
CTR-10	MariaDB (observiumdb): 3 перезапуска	низкий	Контейнеры: перезапуски MariaDB
META_EOF
)
# END-META

CLEANUPS=()
SKIP_REASON=""
PAUSE=5
REPORT=""
DRY=0
YES=0
ALL=0
LIST=0
IDS=""
CONTAINER=""
ENGINE=""

if [ -t 1 ]; then C_G=$'\e[32m'; C_R=$'\e[31m'; C_Y=$'\e[33m'; C_C=$'\e[36m'; C_M=$'\e[35m'; C_0=$'\e[0m'; else C_G=""; C_R=""; C_Y=""; C_C=""; C_M=""; C_0=""; fi
say_ok()   { printf '%s%s%s\n' "$C_G" "$*" "$C_0"; }
say_err()  { printf '%s%s%s\n' "$C_R" "$*" "$C_0"; }
say_warn() { printf '%s%s%s\n' "$C_Y" "$*" "$C_0"; }
say_info() { printf '%s%s%s\n' "$C_C" "$*" "$C_0"; }

usage() {
  cat <<'EOF'
Использование: detection-tests.sh [параметры]
  --list              показать проверки и ожидаемые алерты
  --id ID[,ID...]     выполнить выбранные проверки
  --all               выполнить все проверки
  --dry-run           только показать, что будет сделано
  --yes               не задавать вопросов
  --pause N           пауза между проверками в секундах (по умолчанию 5)
  --report FILE       путь CSV-отчёта
  --container NAME    контейнер для CTR-07/08/09 (нужны проверки с произвольным контейнером)
  --engine docker|podman  явно указать движок (по умолчанию определяется сам)
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
    --container) shift; CONTAINER="${1:-}" ;;
    --engine) shift; ENGINE="${1:-}" ;;
    -h|--help) usage; exit 0 ;;
    *) say_err "Неизвестный параметр: $1"; usage; exit 2 ;;
  esac
  shift
done

# ---------- Помощники ----------
have() { command -v "$1" >/dev/null 2>&1; }

detect_engine() {
  [ -n "$ENGINE" ] && return 0
  if have docker && docker info >/dev/null 2>&1; then ENGINE=docker
  elif have podman; then ENGINE=podman
  else say_err "Не нашёл работающий docker или podman (или не хватает прав — добавьте пользователя в группу docker)"; exit 1
  fi
}

cexists() { "$ENGINE" ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }

# пишет LINE в stdout контейнера напрямую (как настоящий процесс), повторяя N раз (по умолчанию 1)
spam() {
  local c="$1" line="$2" n="${3:-1}" i
  for ((i = 0; i < n; i++)); do
    "$ENGINE" exec "$c" sh -c "printf '%s\n' \"\$1\" > /proc/1/fd/1" sh "$line" 2>/dev/null || return 1
  done
}

# пишет N пронумерованных строк одним потоком (быстрее, чем spam в цикле) — для больших объёмов
spam_many() {
  local c="$1" prefix="$2" n="$3" i
  { for ((i = 1; i <= n; i++)); do printf '%s %d\n' "$prefix" "$i"; done; } | "$ENGINE" exec -i "$c" sh -c 'cat > /proc/1/fd/1' 2>/dev/null
}

skip() { SKIP_REASON="$1"; return 99; }
meta_field() { printf '%s\n' "$META" | awk -F'\t' -v id="$1" -v f="$2" '$1==id{print $f}'; }
ts() { date -u +%Y-%m-%dT%H:%M:%S.000Z; }

# ---------- Проверки ----------
t_CTR_01() {
  cexists grafana || { skip "контейнер grafana не запущен"; return 99; }
  spam grafana 'lvl=warn msg="Invalid username or password" logger=context.error dt_test=1' 6
}

t_CTR_02() {
  cexists loki || { skip "контейнер loki не запущен"; return 99; }
  spam loki "level=error ts=$(ts) caller=dt_test.go msg=\"dt_test simulated ingester error\""
}

t_CTR_03() {
  cexists komodo_mongo_1 || { skip "контейнер komodo_mongo_1 не запущен"; return 99; }
  spam komodo_mongo_1 "{\"t\":{\"\$date\":\"$(ts)\"},\"s\":\"E\",\"c\":\"COMMAND\",\"id\":0,\"ctx\":\"dt_test\",\"msg\":\"dt_test simulated error\"}"
}

t_CTR_04() {
  cexists netalertx || { skip "контейнер netalertx не запущен"; return 99; }
  spam_many netalertx "dt_test volume spike line" 4600
}

t_CTR_05() {
  cexists netalertx || { skip "контейнер netalertx не запущен"; return 99; }
  spam netalertx 'Scan Stats: New Devices 1, Down Devices 0, Up Devices 1 (dt_test)'
}

t_CTR_06() {
  cexists promtail || { skip "контейнер promtail не запущен"; return 99; }
  spam_many promtail "level=error ts=$(ts) caller=client.go msg=\"context deadline exceeded\" dt_test" 16
}

t_CTR_07() {
  [ -n "$CONTAINER" ] || { skip "укажите контейнер параметром --container (не cadvisor/fluent-bit/promtail)"; return 99; }
  case "$CONTAINER" in cadvisor|fluent-bit|promtail) skip "правило исключает контейнер $CONTAINER из подсчёта"; return 99 ;; esac
  cexists "$CONTAINER" || { skip "контейнер $CONTAINER не запущен"; return 99; }
  spam_many "$CONTAINER" "level=error dt_test simulated error" 11
}

t_CTR_08() {
  [ -n "$CONTAINER" ] || { skip "укажите контейнер параметром --container"; return 99; }
  cexists "$CONTAINER" || { skip "контейнер $CONTAINER не запущен"; return 99; }
  spam "$CONTAINER" 'dt_test simulated: out of memory: Killed process 1 (dt_test)'
}

t_CTR_09() {
  [ -n "$CONTAINER" ] || { skip "укажите контейнер параметром --container"; return 99; }
  cexists "$CONTAINER" || { skip "контейнер $CONTAINER не запущен"; return 99; }
  spam_many "$CONTAINER" "dt_test: Operation not permitted" 51
}

t_CTR_10() {
  cexists observiumdb || { skip "контейнер observiumdb не запущен"; return 99; }
  spam observiumdb 'Entrypoint script: dt_test simulated restart' 3
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

[ "$DRY" = 1 ] || detect_engine
say_info "Движок: ${ENGINE:-(не нужен для dry-run)}; проверок: ${#SELECTED[@]}"
say_warn "Правила молчат в течение периода тишины: повторный прогон подряд новых алертов не даст."
if [ "$DRY" = 0 ] && [ "$YES" = 0 ]; then
  printf 'Выполнить проверки? Будут добавлены тестовые строки в логи контейнеров (y/n): '
  read -r a; [ "$a" = "y" ] || { say_warn "Отменено"; exit 0; }
fi

csv() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
START_TS="$(date '+%F %T')"
[ -n "$REPORT" ] || REPORT="detection-tests-containers-$(date +%Y%m%d-%H%M%S).csv"
printf '\xef\xbb\xbf' > "$REPORT"
echo 'id,name,started,finished,status,expected,seen_in_graylog,note' >> "$REPORT"

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

echo; say_ok "Готово. Отчёт: $REPORT"
echo "Окно времени для Graylog (Alerts → Events): с ${START_TS#* } (${START_TS%% *}), +10 минут на доставку."
[ "${#BAD[@]}" -gt 0 ] && say_warn "Ошибок выполнения: ${#BAD[@]}: ${BAD[*]}"
exit 0
