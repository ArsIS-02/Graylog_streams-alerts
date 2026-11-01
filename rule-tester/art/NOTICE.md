# Источник тестов

Тесты в `plan.json` отобраны вручную из проекта Atomic Red Team
(https://github.com/redcanaryco/atomic-red-team), Copyright (c) Red Canary, Inc., лицензия MIT.

Из каждого теста взяты номер техники MITRE ATT&CK, название, команда и очистка; значения аргументов
подставлены, опасные тесты (отключение журналов и защиты, удаление теневых копий, остановка служб) не включены.
План пересобирается командой `python3 -I art_build.py <путь к atomics>`.

Текст лицензии MIT: https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt
