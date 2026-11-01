#!/usr/bin/env bash
# Установка rule-tester в rootless Podman на redos-server (запускать под обычным пользователем, из корня репозитория):
#   bash rule-tester/deploy/install.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
APP="$HOME/rule-tester"
ENV="$APP/rule-tester.env"
UNIT_DIR="$HOME/.config/containers/systemd"

command -v podman >/dev/null || { echo "Нужен podman"; exit 1; }
mkdir -p "$APP" "$UNIT_DIR"

if [ ! -f "$ENV" ]; then
  install -m 600 rule-tester/deploy/env.example "$ENV"
  echo "Создан $ENV. Заполните GRAYLOG_TOKEN и RT_PASSWORD (и проверьте RT_GELF, RT_STREAM), затем запустите скрипт снова."
  exit 0
fi
for v in GRAYLOG_TOKEN RT_PASSWORD; do
  grep -Eq "^$v=.+" "$ENV" || { echo "В $ENV не заполнено $v"; exit 1; }
done

echo "Сборка образа…"
podman build -f rule-tester/Containerfile -t localhost/rule-tester:latest .
install -m 644 rule-tester/deploy/rule-tester.container "$UNIT_DIR/rule-tester.container"
systemctl --user daemon-reload
systemctl --user restart rule-tester.service
loginctl enable-linger "$USER" 2>/dev/null || true
sleep 3
systemctl --user --no-pager status rule-tester.service | head -8 || true
echo "Готово: интерфейс на http://127.0.0.1:8085 (выставьте наружу через Caddy: rule-tester.apps.monitoring.test)"
