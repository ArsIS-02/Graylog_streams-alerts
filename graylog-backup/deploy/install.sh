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
systemctl --user daemon-reload
systemctl --user restart graylog-backup.service
loginctl enable-linger "$USER" 2>/dev/null || true
sleep 3
systemctl --user --no-pager status graylog-backup.service | head -8 || true
echo "Готово: интерфейс на http://127.0.0.1:8086 (выставьте наружу через Caddy: graylog-backup.apps.monitoring.test)"
echo "Перед первым реальным бэкапом проверьте «Настройки» → «Проверить соединение» (Graylog REST, mongodump, OpenSearch)."
