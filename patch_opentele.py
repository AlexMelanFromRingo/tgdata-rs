#!/usr/bin/env python3
"""
Патч для opentele — совместимость с Telegram Desktop 5.x/6.x.

Проблема 1: Unknown key type 23 в map-файле (добавлен в новых версиях TG Desktop).
Проблема 2: Бесконечная рекурсия в Account.api setter.

Запуск: python patch_opentele.py
"""

import sys
import importlib
from pathlib import Path


def find_opentele_path() -> Path:
    try:
        import opentele.td.account as m
        return Path(m.__file__)
    except ImportError:
        print("opentele не установлен. Запустите setup.bat / setup.sh", file=sys.stderr)
        sys.exit(1)


def patch_file(path: Path, replacements: list[tuple[str, str]]) -> bool:
    content = path.read_text(encoding="utf-8")
    changed = False
    for old, new, name in replacements:
        if new in content:
            print(f"  [{name}] уже применён — пропускаем")
            continue
        if old in content:
            content = content.replace(old, new)
            print(f"  [{name}] применён")
            changed = True
        else:
            print(f"  [{name}] ⚠️  паттерн не найден (другая версия opentele?)")
    if changed:
        path.write_text(content, encoding="utf-8")
    return changed


def main():
    account_py = find_opentele_path()
    print(f"Патчим: {account_py}")

    replacements = [
        (
            # Патч 1: неизвестный тип ключа в map → break вместо exception
            '            else:\n'
            '                raise TDataReadMapDataFailed(\n'
            '                    f"Unknown key type in encrypted map: {keyType}"\n'
            '                )',
            '            else:\n'
            '                # Key type added in newer TG Desktop versions — skip.\n'
            '                break',
            "unknown-key-type→break",
        ),
        (
            # Патч 2: рекурсия в api setter → убираем проброс наверх
            '    @api.setter\n'
            '    def api(self, value) -> None:\n'
            '        self.__api = value\n'
            '        if self.owner.api != self.api:\n'
            '            self.owner.api = self.api',
            '    @api.setter\n'
            '    def api(self, value) -> None:\n'
            '        self.__api = value',
            "api-recursion-fix",
        ),
    ]

    patch_file(account_py, replacements)
    print("Готово.")


if __name__ == "__main__":
    main()
