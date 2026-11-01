#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Безопасные проверки детектов Graylog для FreeIPA.

Выполняет действия через API FreeIPA и Kerberos, чтобы убедиться, что алерты из каталога детектов
срабатывают. Всё созданное (пользователь dt_user, группы dt_group и dt_pwgroup, правило dt_hbac, роль dt_role,
хост dt-host) удаляется в конце. Запускайте только в лаборатории, на сервере или клиенте IPA после kinit admin.
Список проверок и ожидаемых алертов: docs/15-detection-tests.md.

    kinit admin
    python3 ipa_detection_tests.py --list
    python3 ipa_detection_tests.py --id IPA-01,IPA-02 --dry-run
    python3 ipa_detection_tests.py --all --yes

Лицензия: GPL-3.0.
"""
import argparse
import csv
import datetime
import json
import os
import secrets
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import time

# BEGIN-META
TESTS_META = json.loads(r'''
[
 {
  "id": "IPA-01",
  "name": "Пользователь и группа через API",
  "risk": "низкий",
  "needs": "kinit admin",
  "note": "",
  "rules": [
   "FREEIPA - Изменение пользователей, групп и правил через API"
  ]
 },
 {
  "id": "IPA-02",
  "name": "Правило HBAC через API",
  "risk": "низкий",
  "needs": "kinit admin",
  "note": "",
  "rules": [
   "FREEIPA - Изменение HBAC и sudo-правил (API)"
  ]
 },
 {
  "id": "IPA-03",
  "name": "Парольная политика группы через API",
  "risk": "средний",
  "needs": "kinit admin",
  "note": "Политика создаётся для тестовой группы и удаляется",
  "rules": [
   "FREEIPA - Изменение политик паролей, Kerberos и конфигурации (API)"
  ]
 },
 {
  "id": "IPA-04",
  "name": "Роль и привилегии через API",
  "risk": "средний",
  "needs": "kinit admin",
  "note": "Создаётся тестовая роль без привилегий и удаляется",
  "rules": [
   "FREEIPA - Изменение привилегированных групп и ролей (API)"
  ]
 },
 {
  "id": "IPA-05",
  "name": "Разблокировка и включение пользователя",
  "risk": "низкий",
  "needs": "kinit admin",
  "note": "",
  "rules": [
   "FREEIPA - Разблокировка учётной записи, ключи и сертификаты пользователя (API)"
  ]
 },
 {
  "id": "IPA-06",
  "name": "Неудачные kinit: подбор пароля (12 попыток)",
  "risk": "низкий",
  "needs": "kinit admin; запуск на сервере или клиенте IPA",
  "note": "Тестовый пользователь заблокируется по политике: это и проверяется",
  "rules": [
   "FREEIPA - Подбор пароля (10+ PREAUTH_FAILED за 5 мин)",
   "FREEIPA - Kerberos: вход отключённой, заблокированной или просроченной учётной записи"
  ]
 },
 {
  "id": "IPA-07",
  "name": "Неудачный вход в веб-интерфейс",
  "risk": "низкий",
  "needs": "curl; доступ к https серверу IPA",
  "note": "",
  "rules": [
   "FREEIPA - Неудачный вход в веб-интерфейс"
  ]
 },
 {
  "id": "IPA-08",
  "name": "Успешный вход в веб-интерфейс",
  "risk": "средний",
  "needs": "kinit admin, curl",
  "note": "Нужна смена временного пароля тестового пользователя через kinit; если не получится, проверка пропускается",
  "rules": [
   "FREEIPA - Успешный вход в веб-интерфейс"
  ]
 },
 {
  "id": "IPA-09",
  "name": "Выпуск сертификата в Dogtag",
  "risk": "средний",
  "needs": "kinit admin, openssl",
  "note": "Для тестового хоста выдаётся сертификат, затем он отзывается, хост удаляется",
  "rules": [
   "FREEIPA - Выпуск сертификата в CA (Dogtag)"
  ]
 },
 {
  "id": "IPA-10",
  "name": "Массовая выгрузка из каталога (100+ записей)",
  "risk": "низкий",
  "needs": "kinit admin; в домене 100 и более пользователей",
  "note": "Столько пользователей даёт наполнение из tools/ipa_manager.py",
  "rules": [
   "FREEIPA - Массовая выгрузка из каталога LDAP (100+ записей за запрос)"
  ]
 },
 {
  "id": "IPA-11",
  "name": "Билет службы с RC4 (best effort)",
  "risk": "низкий",
  "needs": "kinit admin",
  "note": "Сработает, только если KDC ещё разрешает RC4 для службы",
  "rules": [
   "FREEIPA - Kerberos: билет службы с шифрованием RC4 (Kerberoasting)"
  ]
 }
]
''')
# END-META

DT_USER, DT_GROUP, DT_PWGROUP, DT_HBAC, DT_ROLE = "dt_user", "dt_group", "dt_pwgroup", "dt_hbac", "dt_role"
C = {"g": "\033[32m", "r": "\033[31m", "y": "\033[33m", "c": "\033[36m", "m": "\033[35m", "0": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


class Skip(Exception):
    """Проверка пропущена: причина в сообщении."""


class State:
    api = None
    errors = None
    cleanups = []
    password = None
    user_ready = False
    group_ready = False
    tmp = None


def say(color, text):
    print(f"{C[color]}{text}{C['0']}")


def defer(fn):
    State.cleanups.append(fn)


def quiet(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception:
        return None


def new_password():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(14)) + "a1!"


def cmd(name, *args, **kw):
    return getattr(State.api.Command, name)(*args, **kw)


def connect():
    if shutil.which("klist") and subprocess.call(["klist", "-s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        sys.exit("Нет билета Kerberos. Сначала выполни: kinit admin")
    try:
        from ipalib import api, errors
    except ImportError:
        sys.exit("Нет модуля ipalib: запускай на сервере или клиенте FreeIPA")
    api.bootstrap(context="cli")
    api.finalize()
    try:
        api.Backend.rpcclient.connect()
    except Exception as e:
        sys.exit(f"Не удалось подключиться к IPA: {e}\nСначала выполни: kinit admin")
    State.api, State.errors = api, errors
    State.tmp = tempfile.mkdtemp(prefix="dt_ipa_")
    defer(lambda: shutil.rmtree(State.tmp, ignore_errors=True))


def ensure_user():
    if State.user_ready:
        return
    State.password = new_password()
    quiet(cmd, "user_del", DT_USER)
    cmd("user_add", DT_USER, givenname="DT", sn="User", userpassword=State.password)
    State.user_ready = True
    defer(lambda: quiet(cmd, "user_del", DT_USER))


def ensure_group():
    if State.group_ready:
        return
    quiet(cmd, "group_del", DT_GROUP)
    cmd("group_add", DT_GROUP, description="Detection test (удаляется)")
    State.group_ready = True
    defer(lambda: quiet(cmd, "group_del", DT_GROUP))


def server_name():
    return getattr(State.api.env, "server", None) or State.api.env.host


def ccache_env(name):
    env = dict(os.environ)
    env["KRB5CCNAME"] = "FILE:" + os.path.join(State.tmp, name)
    return env


# ---------- Проверки ----------
def test_IPA_01():
    ensure_user()
    ensure_group()
    cmd("user_mod", DT_USER, description="DT test")
    cmd("group_add_member", DT_GROUP, user=[DT_USER])
    cmd("group_remove_member", DT_GROUP, user=[DT_USER])


def test_IPA_02():
    ensure_user()
    quiet(cmd, "hbacrule_del", DT_HBAC)
    cmd("hbacrule_add", DT_HBAC, description="Detection test (удаляется)")
    defer(lambda: quiet(cmd, "hbacrule_del", DT_HBAC))
    cmd("hbacrule_add_user", DT_HBAC, user=[DT_USER])
    cmd("hbacrule_mod", DT_HBAC, description="DT test 2")
    cmd("hbacrule_disable", DT_HBAC)


def test_IPA_03():
    quiet(cmd, "pwpolicy_del", DT_PWGROUP)
    quiet(cmd, "group_del", DT_PWGROUP)
    cmd("group_add", DT_PWGROUP, description="Detection test (удаляется)")
    defer(lambda: quiet(cmd, "group_del", DT_PWGROUP))
    cmd("pwpolicy_add", DT_PWGROUP, cospriority=9999, krbmaxpwdlife=90, krbminpwdlife=1)
    defer(lambda: quiet(cmd, "pwpolicy_del", DT_PWGROUP))
    cmd("pwpolicy_mod", DT_PWGROUP, krbmaxpwdlife=91)


def test_IPA_04():
    ensure_group()
    quiet(cmd, "role_del", DT_ROLE)
    cmd("role_add", DT_ROLE, description="Detection test (удаляется)")
    defer(lambda: quiet(cmd, "role_del", DT_ROLE))
    cmd("role_add_member", DT_ROLE, group=[DT_GROUP])
    cmd("role_remove_member", DT_ROLE, group=[DT_GROUP])


def test_IPA_05():
    ensure_user()
    cmd("user_disable", DT_USER)
    cmd("user_enable", DT_USER)
    try:
        cmd("user_unlock", DT_USER)
    except Exception:
        pass


def test_IPA_06():
    ensure_user()
    if not shutil.which("kinit"):
        raise Skip("нет kinit")
    env = ccache_env("fail_cc")
    for i in range(12):
        subprocess.run(["kinit", DT_USER], input=f"wrong-{i}\n", text=True, env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def _login_post(user, password):
    if not shutil.which("curl"):
        raise Skip("нет curl")
    host = server_name()
    ca = "/etc/ipa/ca.crt"
    args = ["curl", "-sS", "-o", os.devnull, "-w", "%{http_code}", "-X", "POST",
            "-H", f"Referer: https://{host}/ipa", "-H", "Content-Type: application/x-www-form-urlencoded",
            "-H", "Accept: text/plain", "--data-urlencode", f"user={user}", "--data-urlencode", f"password={password}"]
    args += ["--cacert", ca] if os.path.exists(ca) else ["-k"]
    args.append(f"https://{host}/ipa/session/login_password")
    return subprocess.run(args, capture_output=True, text=True, timeout=30).stdout.strip()


def test_IPA_07():
    code = _login_post(DT_USER, "wrong-password")
    print(f"Ответ веб-интерфейса: HTTP {code}")


def test_IPA_08():
    ensure_user()
    if not shutil.which("kinit"):
        raise Skip("нет kinit")
    new_pw = new_password()
    r = subprocess.run(["kinit", DT_USER], input=f"{State.password}\n{new_pw}\n{new_pw}\n", text=True,
                       env=ccache_env("login_cc"), capture_output=True, timeout=30)
    if r.returncode != 0:
        raise Skip("не удалось сменить временный пароль через kinit")
    code = _login_post(DT_USER, new_pw)
    print(f"Ответ веб-интерфейса: HTTP {code}")
    if code != "200":
        raise Exception(f"вход не удался: HTTP {code}")


def test_IPA_09():
    for tool in ("ipa", "openssl"):
        if not shutil.which(tool):
            raise Skip(f"нет {tool}")
    domain = State.api.env.domain
    host = f"dt-host.{domain}"
    key, csr = os.path.join(State.tmp, "dt.key"), os.path.join(State.tmp, "dt.csr")
    quiet(cmd, "host_del", host)
    cmd("host_add", host, force=True)
    defer(lambda: quiet(cmd, "host_del", host))
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-subj", f"/CN={host}",
                    "-out", csr], check=True, capture_output=True)
    r = subprocess.run(["ipa", "cert-request", csr, "--principal", f"host/{host}"], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise Exception(r.stderr.strip() or "ipa cert-request завершилась с ошибкой")
    serial = next((ln.split(":", 1)[1].strip() for ln in r.stdout.splitlines() if "Serial number" in ln and "hex" not in ln.lower()), None)
    if serial:
        defer(lambda: subprocess.run(["ipa", "cert-revoke", serial, "--revocation-reason=0"], capture_output=True))


def test_IPA_10():
    n = cmd("user_find", sizelimit=0, timelimit=0).get("count", 0)
    if n < 100:
        raise Skip(f"в домене {n} пользователей, нужно не меньше 100")
    cmd("group_find", sizelimit=0, timelimit=0)
    print(f"Выгружено пользователей: {n}")


def test_IPA_11():
    if not shutil.which("kvno"):
        raise Skip("нет kvno")
    princ = f"HTTP/{server_name()}"
    for enc in ("rc4-hmac", "arcfour-hmac"):
        r = subprocess.run(["kvno", "-e", enc, princ], capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            return
    say("y", "KDC не выдал билет с RC4: алерт, скорее всего, не придёт (RC4 запрещён).")


# ---------- Запуск ----------
def show_list():
    for t in TESTS_META:
        print(f"{t['id']:<8}[{t['risk']}] {t['name']}")
        for r in t["rules"]:
            print(f"           -> {r}")


def main():
    ap = argparse.ArgumentParser(description="Проверки детектов Graylog для FreeIPA")
    ap.add_argument("--list", action="store_true", help="показать проверки")
    ap.add_argument("--id", default="", help="id проверок через запятую")
    ap.add_argument("--all", action="store_true", help="все проверки")
    ap.add_argument("--dry-run", action="store_true", help="только показать, что будет сделано")
    ap.add_argument("--yes", action="store_true", help="не задавать вопросов")
    ap.add_argument("--pause", type=int, default=5, help="пауза между проверками, секунды")
    ap.add_argument("--report", default="", help="путь CSV-отчёта")
    a = ap.parse_args()

    if a.list:
        show_list()
        return
    by_id = {t["id"]: t for t in TESTS_META}
    if a.all:
        chosen = list(TESTS_META)
    elif a.id:
        chosen = []
        for w in (x.strip().upper() for x in a.id.split(",") if x.strip()):
            if w not in by_id:
                sys.exit(f"Нет проверки {w}")
            chosen.append(by_id[w])
    else:
        show_list()
        ans = input("\nВведи id через запятую или all: ").strip()
        if ans.lower() == "all":
            chosen = list(TESTS_META)
        else:
            chosen = []
            for w in (x.strip().upper() for x in ans.split(",") if x.strip()):
                if w not in by_id:
                    sys.exit(f"Нет проверки {w}")
                chosen.append(by_id[w])
    if not chosen:
        say("y", "Ничего не выбрано")
        return

    say("c", f"Хост: {socket.gethostname()}; проверок: {len(chosen)}")
    say("y", "Правила молчат в течение периода тишины (обычно час): повторный прогон подряд новых алертов не даст.")
    if not a.dry_run:
        if not a.yes and input("Выполнить проверки? Все созданные объекты будут удалены в конце (y/n): ").strip().lower() != "y":
            say("y", "Отменено")
            return
        connect()
        say("c", f"Домен: {State.api.env.domain}; сервер: {server_name()}")

    started = datetime.datetime.now()
    rows, bad = [], []
    try:
        for t in chosen:
            print()
            say("m", f"== {t['id']}: {t['name']} ==")
            row = dict(id=t["id"], name=t["name"], started=datetime.datetime.now().isoformat(timespec="seconds"),
                       finished="", status="", expected=" | ".join(t["rules"]), seen_in_graylog="", note="")
            if a.dry_run:
                print("[dry-run] ожидаются алерты: " + "; ".join(t["rules"]))
                row["status"] = "не выполнялось (dry-run)"
            else:
                try:
                    globals()["test_" + t["id"].replace("-", "_")]()
                    row["status"] = "выполнено"
                    say("g", "Выполнено. Ожидаются алерты: " + "; ".join(t["rules"]))
                except Skip as e:
                    row["status"], row["note"] = "пропущено", str(e)
                    say("y", f"Пропущено: {e}")
                except Exception as e:
                    row["status"], row["note"] = "ошибка", str(e)
                    bad.append(t["id"])
                    say("r", f"Ошибка: {e}")
                time.sleep(a.pause)
            row["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
            rows.append(row)
    finally:
        if not a.dry_run:
            print()
            say("c", "Удаляю созданное...")
            for fn in reversed(State.cleanups):
                try:
                    fn()
                except Exception as e:
                    say("y", f"Очистка: {e}")

    ended = datetime.datetime.now()
    report = a.report or f"detection-tests-ipa-{started.strftime('%Y%m%d-%H%M%S')}.csv"
    with open(report, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print()
    say("g", f"Готово. Отчёт: {report}")
    until = (ended + datetime.timedelta(minutes=10)).strftime("%H:%M:%S")
    print(f"Окно времени для Graylog (Alerts → Events): {started.strftime('%H:%M:%S')} - {until} ({started.strftime('%d.%m.%Y')})")
    print("Алерты приходят с задержкой до 10 минут. Заполните в отчёте колонку seen_in_graylog.")
    if bad:
        say("y", f"Ошибок выполнения: {len(bad)}: {', '.join(bad)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        say("y", "Прервано")
