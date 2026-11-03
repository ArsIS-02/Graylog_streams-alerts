#!/usr/bin/env bash
# Установка graylog-backup в rootless Podman на redos-server (запускать под обычным пользователем, из корня репозитория):
#   bash graylog-backup/deploy/install.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
APP="$HOME/graylog-backup"
ENV="$APP/graylog-backup.env"
UNIT_DIR="$HOME/.config/containers/systemd"

command -v podman >/dev/null || { echo "Нужен podman"; exit 1; }
mkdir -p "$APP" "$UNIT_DIR"

if [ ! -f "$ENV" ]; then
  install -m 600 graylog-backup/deploy/env.example "$ENV"
  echo "Создан $ENV. Заполните GRAYLOG_TOKEN, GB_MONGO_URI и GB_PASSWORD, затем запустите скрипт снова."
  exit 0
fi
for v in GRAYLOG_TOKEN GB_PASSWORD; do
  grep -Eq "^$v=.+" "$ENV" || { echo "В $ENV не заполнено $v"; exit 1; }
done

echo "Сборка образа…"
podman build -f graylog-backup/Containerfile -t localhost/graylog-backup:latest .
install -m 644 graylog-backup/deploy/graylog-backup.container "$UNIT_DIR/graylog-backup.container"

# Для полного бэкапа (аварийное восстановление): если в .env заданы HOST_SERVER_CONF/HOST_MONGOD_CONF/
# HOST_OPENSEARCH_CONF/HOST_PLUGIN_DIR, примонтировать эти файлы/каталоги с хоста в контейнер только
# для чтения и прописать туда же соответствующие GB_SERVER_CONF/GB_MONGOD_CONF/GB_OPENSEARCH_CONF/
# GB_PLUGIN_DIR — сами эти строки руками в .env заполнять не нужно.
#
# Важно: монтируем БЕЗ суффикса :Z (приватная SELinux-метка). В rootless Podman relabel (lsetxattr)
# файла/каталога, которым владеет не тот пользователь, что запускает контейнер (а эти пути почти
# всегда root/graylog, не redos), падает с «operation not permitted» — это ограничение ядра
# (нужен CAP_FOWNER или совпадение владельца), а не баг контейнера. Поэтому где SELinux enforcing,
# метку нужно один раз выставить вручную от root (semanage fcontext + restorecon) — см. ниже и
# главу 18, раздел «Если SELinux enforcing».
SELINUX_ENFORCING=0
if command -v getenforce >/dev/null && [ "$(getenforce)" = "Enforcing" ]; then
  SELINUX_ENFORCING=1
fi
relabel_hint() {  # $1 = путь на хосте (файл или каталог)
  if [ "$SELINUX_ENFORCING" = "1" ]; then
    echo "  SELinux enforcing — один раз от root: sudo semanage fcontext -a -t container_file_t \"$1(/.*)?\" && sudo restorecon -Rv \"$1\""
  fi
}
HOST_SERVER_CONF="$(sed -n 's/^HOST_SERVER_CONF=//p' "$ENV" | head -1)"
HOST_PLUGIN_DIR="$(sed -n 's/^HOST_PLUGIN_DIR=//p' "$ENV" | head -1)"
HOST_MONGOD_CONF="$(sed -n 's/^HOST_MONGOD_CONF=//p' "$ENV" | head -1)"
HOST_OPENSEARCH_CONF="$(sed -n 's/^HOST_OPENSEARCH_CONF=//p' "$ENV" | head -1)"
if [ -n "$HOST_SERVER_CONF" ]; then
  [ -r "$HOST_SERVER_CONF" ] || echo "Внимание: $HOST_SERVER_CONF не читается этим пользователем — server.conf в копию не попадёт, пока не поправите права"
  relabel_hint "$HOST_SERVER_CONF"
  sed -i "/^\[Container\]/a Volume=${HOST_SERVER_CONF}:/mnt/host/server.conf:ro\nEnvironment=GB_SERVER_CONF=/mnt/host/server.conf" "$UNIT_DIR/graylog-backup.container"
fi
if [ -n "$HOST_PLUGIN_DIR" ]; then
  [ -r "$HOST_PLUGIN_DIR" ] || echo "Внимание: $HOST_PLUGIN_DIR не читается этим пользователем — плагины в копию не попадут, пока не поправите права"
  relabel_hint "$HOST_PLUGIN_DIR"
  sed -i "/^\[Container\]/a Volume=${HOST_PLUGIN_DIR}:/mnt/host/plugins:ro\nEnvironment=GB_PLUGIN_DIR=/mnt/host/plugins" "$UNIT_DIR/graylog-backup.container"
fi
if [ -n "$HOST_MONGOD_CONF" ]; then
  [ -r "$HOST_MONGOD_CONF" ] || echo "Внимание: $HOST_MONGOD_CONF не читается этим пользователем — mongod.conf в копию не попадёт, пока не поправите права"
  relabel_hint "$HOST_MONGOD_CONF"
  sed -i "/^\[Container\]/a Volume=${HOST_MONGOD_CONF}:/mnt/host/mongod.conf:ro\nEnvironment=GB_MONGOD_CONF=/mnt/host/mongod.conf" "$UNIT_DIR/graylog-backup.container"
fi
if [ -n "$HOST_OPENSEARCH_CONF" ]; then
  [ -r "$HOST_OPENSEARCH_CONF" ] || echo "Внимание: $HOST_OPENSEARCH_CONF не читается этим пользователем — opensearch.yml в копию не попадёт, пока не поправите права"
  relabel_hint "$HOST_OPENSEARCH_CONF"
  sed -i "/^\[Container\]/a Volume=${HOST_OPENSEARCH_CONF}:/mnt/host/opensearch.yml:ro\nEnvironment=GB_OPENSEARCH_CONF=/mnt/host/opensearch.yml" "$UNIT_DIR/graylog-backup.container"
fi

systemctl --user daemon-reload
systemctl --user restart graylog-backup.service
loginctl enable-linger "$USER" 2>/dev/null || true
sleep 3
systemctl --user --no-pager status graylog-backup.service | head -8 || true
echo "Готово: интерфейс на http://127.0.0.1:8086 (выставьте наружу через Caddy: graylog-backup.apps.monitoring.test)"
echo "Перед первым реальным бэкапом проверьте «Настройки» → «Проверить соединение» (Graylog REST, mongodump, OpenSearch)."
