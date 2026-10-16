#!/usr/bin/env python3
"""
auditd_decoder.py — декодер auditd для Graylog.

Принимает по UDP (порт 1514) сообщения, которые rsyslog пересылает из
/var/log/audit/audit.log, разбирает пары key=value, декодирует
шестнадцатеричные поля в читаемый вид и отправляет результат в Graylog
в формате GELF (Graylog Extended Log Format) на отдельный вход.

Декодированные поля получают суффикс _decoded, чтобы в индексах сразу
было видно, что значение уже приведено к читаемому виду.

Запуск:
    sudo /usr/local/bin/auditd_decoder.py
(обычно — как systemd-демон, см. audit-decoder.service)

Настройки можно задать переменными окружения или аргументами:
    LISTEN_HOST  адрес, на котором слушаем UDP      (по умолчанию 0.0.0.0)
    LISTEN_PORT  порт, на котором слушаем UDP       (по умолчанию 1514)
    GRAYLOG_HOST адрес Graylog                       (по умолчанию 127.0.0.1)
    GRAYLOG_PORT порт GELF-входа Graylog             (по умолчанию 12201)
"""
import json
import os
import re
import socket
import sys
import time

LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "1514"))
GRAYLOG_HOST = os.environ.get("GRAYLOG_HOST", "127.0.0.1")
GRAYLOG_PORT = int(os.environ.get("GRAYLOG_PORT", "12201"))

# Поля, значения которых в auditd приходят в шестнадцатеричном виде
# (auditd кодирует их в hex, когда они содержат непечатаемые символы).
HEX_FIELDS = {
    "msg", "comm", "exe", "proctitle", "name", "cwd", "unit", "subj",
    "key", "saddr", "raddr", "laddr", "acct", "hostname", "addr",
}

# Сопоставление типов записей auditd с человекочитаемыми описаниями
RECORD_TYPES = {
    "SYSCALL": "Системный вызов",
    "EXECVE": "Аргументы execve",
    "PATH": "Объект файловой системы",
    "CWD": "Рабочий каталог процесса",
    "PROCTITLE": "Командная строка процесса",
    "SOCKADDR": "Сетевой адрес",
    "USER_LOGIN": "Вход пользователя",
    "USER_AUTH": "Аутентификация пользователя",
    "USER_ACCT": "Учётная запись пользователя",
    "USER_END": "Завершение сеанса",
    "SERVICE_START": "Запуск службы",
    "SERVICE_STOP": "Остановка службы",
    "CONFIG_CHANGE": "Изменение правил аудита",
    "ANOM_ABEND": "Аварийное завершение процесса",
    "DAEMON_START": "Запуск демона аудита",
    "DAEMON_END": "Остановка демона аудита",
}

# Поля SYSCALL, которые интересно видеть на дашбордах
SYSCALL_FIELDS = (
    "arch", "syscall", "success", "exit",
    "a0", "a1", "a2", "a3", "comm", "exe",
    "uid", "gid", "euid", "egid", "pid", "ppid",
    "ses", "tty", "proctitle",
)


def hex_to_str(value):
    """Декодирует шестнадцатеричную строку в UTF-8, если это возможно."""
    value = value.strip()
    if not value or value.startswith("("):
        return value
    if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) % 2 == 0:
        try:
            decoded = bytes.fromhex(value).decode("utf-8", errors="strict")
            if decoded.isprintable() or decoded == "":
                return decoded
        except (ValueError, UnicodeDecodeError):
            pass
    return value


def parse_audit_line(line):
    """Разбирает строку auditd на словарь полей key=value.

    Значения могут быть в кавычках и содержать пробелы.
    """
    fields = {}
    for match in re.finditer(r"([A-Za-z0-9_]+)=(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))", line):
        key = match.group(1)
        value = match.group(2) or match.group(3) or match.group(4)
        if key == "msg" and value.startswith("audit("):
            # msg=audit(1690000000.123:45): — отделяем временную метку и серийник
            m = re.match(r"audit\((\d+)\.(\d+):(\d+)\):(.*)", value, re.S)
            if m:
                fields["timestamp"] = f"{m.group(1)}.{m.group(2)}"
                fields["serial"] = m.group(3)
                value = m.group(4).strip()
        fields[key] = value
    return fields


def build_gelf(raw_line, fields, source_host):
    """Собирает GELF-сообщение из полей auditd."""
    record_type = fields.get("type", "")
    message = {
        "version": "1.1",
        "host": source_host,
        "short_message": f"auditd {record_type}" if record_type else "auditd",
        "full_message": raw_line,
        "timestamp": time.time(),
        "_type": record_type,
        "_audit_type": record_type,
        "_decoded_type": RECORD_TYPES.get(record_type, record_type),
        "_message": raw_line,
    }

    # общие поля
    for key in ("serial", "key"):
        if key in fields:
            value = fields[key]
            message[f"_{key}"] = value
            if key in HEX_FIELDS:
                message[f"_{key}_decoded"] = hex_to_str(value)

    # msg — остаток сообщения после audit(…)
    if "msg" in fields:
        message["_msg"] = fields["msg"]
        message["_msg_decoded"] = hex_to_str(fields["msg"])

    # поля конкретных типов записей
    for key, value in fields.items():
        if key in ("type", "msg", "timestamp", "serial", "key"):
            continue
        message[f"_{key}"] = value
        if key in HEX_FIELDS:
            message[f"_{key}_decoded"] = hex_to_str(value)

    return message


def send_gelf(sock, message):
    """Отправляет GELF-сообщение на вход Graylog (UDP)."""
    payload = json.dumps(message, ensure_ascii=False).encode("utf-8")
    if len(payload) > 8192:
        # GELF по UDP рекомендуют резать; режем до ~8 КБ
        payload = payload[:8000]
    sock.sendto(payload, (GRAYLOG_HOST, GRAYLOG_PORT))


def main():
    # сокет для приёма auditd-событий
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recv_sock.bind((LISTEN_HOST, LISTEN_PORT))
    recv_sock.settimeout(5.0)

    # сокет для отправки GELF
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"auditd_decoder: слушаю UDP {LISTEN_HOST}:{LISTEN_PORT}, "
          f"отправляю GELF в {GRAYLOG_HOST}:{GRAYLOG_PORT}", flush=True)

    while True:
        try:
            data, addr = recv_sock.recvfrom(65535)
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            break

        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            # syslog-префикс вида "<134>Oct 12 12:34:56 host auditd[123]:" отрезаем
            line = re.sub(r"^<\d+>\S+ \S+ \S+ [^:]+:", "", line)
            fields = parse_audit_line(line)
            if "type" not in fields:
                continue
            source_host = addr[0]
            gelf = build_gelf(line, fields, source_host)
            send_gelf(send_sock, gelf)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
