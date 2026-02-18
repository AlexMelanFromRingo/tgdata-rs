#!/usr/bin/env python3
"""
Telegram Account Manager
Обработка tdata-аккаунтов: спамблок (через API), сессии, облачный пароль

Установка:
  python -m venv .venv
  .venv/Scripts/pip install opentele telethon   (Windows)
  .venv/bin/pip  install opentele telethon       (Linux)

Запуск:
  .venv/Scripts/python tg_tool.py --path "L:\\Programs\\Telegram Desktop"
  .venv/Scripts/python tg_tool.py --path "L:\\Programs\\Telegram Desktop" \\
      --terminate-sessions --set-password "Pass123!" --threads 10
"""

from __future__ import annotations

import asyncio
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

# Убираем лишние логи
for _l in ("telethon", "opentele", "asyncio"):
    logging.getLogger(_l).setLevel(logging.ERROR)

# ─── Telegram DC → (ip, port) ──────────────────────────────────────────────
DC_ADDRESSES = {
    1: ("149.154.175.53",  443),
    2: ("149.154.167.51",  443),
    3: ("149.154.175.100", 443),
    4: ("149.154.167.92",  443),
    5: ("91.108.56.130",   443),
}

# ANSI-цвета
GREEN = "\033[92m"
RED   = "\033[91m"
GRAY  = "\033[90m"
RESET = "\033[0m"

_print_lock = asyncio.Lock()


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


async def _log(thread: int, phone: str, msg: str, color: str = "") -> None:
    c = {"green": GREEN, "red": RED, "gray": GRAY}.get(color, "")
    line = f"{c}[{_ts()}] [Поток {thread}] [{phone}] {msg}{RESET if c else ''}"
    async with _print_lock:
        print(line, flush=True)


# ─── Telegram операции ─────────────────────────────────────────────────────

async def check_spam(client) -> bool:
    """
    Спамблок через Telegram API: contacts.Search → PEER_FLOOD.
    НЕ отправляет сообщения. True = аккаунт заспамлен.
    """
    from telethon.errors import PeerFloodError
    from telethon.tl.functions.contacts import SearchRequest

    try:
        await client(SearchRequest(q="telegram", limit=1))
        return False
    except PeerFloodError:
        return True


async def get_sessions_count(client) -> tuple[int, int]:
    """Возвращает (всего, чужих) сессий."""
    from telethon.tl.functions.account import GetAuthorizationsRequest
    result = await client(GetAuthorizationsRequest())
    total = len(result.authorizations)
    other = sum(1 for a in result.authorizations if not a.current)
    return total, other


async def terminate_other_sessions(client) -> int:
    """Завершает все сессии кроме текущей. Возвращает кол-во."""
    from telethon.tl.functions.account import (
        GetAuthorizationsRequest,
        ResetAuthorizationRequest,
    )
    result = await client(GetAuthorizationsRequest())
    closed = 0
    for auth in result.authorizations:
        if not auth.current and auth.hash != 0:
            try:
                await client(ResetAuthorizationRequest(hash=auth.hash))
                closed += 1
            except Exception:
                pass
    return closed


async def set_cloud_password(client, password: str) -> tuple[bool, str]:
    """
    Ставит облачный пароль 2FA.
    Возвращает (успех, причина_если_нет).
    """
    from telethon.tl.functions.account import GetPasswordRequest
    info = await client(GetPasswordRequest())
    if info.has_password:
        return False, "уже установлен"
    try:
        await client.edit_2fa(new_password=password, hint="")
        return True, ""
    except Exception as e:
        return False, str(e)


# ─── Обработка одного аккаунта ─────────────────────────────────────────────

async def process_account(
    thread:    int,
    idx:       int,
    account,
    *,
    semaphore: asyncio.Semaphore,
    results:   dict,
    terminate: bool,
    password:  Optional[str],
) -> None:
    from opentele.api import UseCurrentSession, API
    from telethon.errors import (
        AuthKeyUnregisteredError,
        UserDeactivatedBanError,
        UserDeactivatedError,
        SessionRevokedError,
        FloodWaitError,
    )

    async with semaphore:
        phone = f"акк{idx + 1}"
        try:
            client = await account.ToTelethon(
                flag=UseCurrentSession,
                api=API.TelegramDesktop.Generate(),
            )

            # Определяем DC до подключения
            dc_id = getattr(client.session, "dc_id", 2) or 2
            ip, port = DC_ADDRESSES.get(dc_id, ("unknown", 443))
            await _log(thread, phone, f"Подключается через {ip}:{port}", "gray")

            await client.connect()

            try:
                me = await client.get_me()
                phone = me.phone or f"id{me.id}"

                # ── Спамблок (API, без сообщений) ─────────────────────
                spam_blocked = await check_spam(client)

                if spam_blocked:
                    await _log(thread, phone, "СПАМБЛОК!", "red")
                    results["spam"] += 1
                    return

                # ── Аккаунт чистый ────────────────────────────────────
                parts: list[str] = ["Аккаунт жив. Без спамблока."]

                # Сессии
                total_s, other_s = await get_sessions_count(client)

                if terminate and other_s > 0:
                    closed = await terminate_other_sessions(client)
                    parts.append(f"закрыто {closed} сессий")
                elif other_s > 0:
                    parts.append(f"сессий {total_s} (чужих: {other_s})")

                # Пароль
                if password:
                    ok, reason = await set_cloud_password(client, password)
                    parts.append("пароль ✓" if ok else f"пароль: {reason}")

                await _log(thread, phone, " | ".join(parts), "green")
                results["clean"] += 1

            finally:
                await client.disconnect()

        except (UserDeactivatedBanError, UserDeactivatedError):
            await _log(thread, phone, "Аккаунт ЗАБАНЕН", "red")
            results["banned"] += 1

        except AuthKeyUnregisteredError:
            await _log(thread, phone, "Сессия недействительна", "gray")
            results["errors"] += 1

        except SessionRevokedError:
            await _log(thread, phone, "Сессия отозвана", "gray")
            results["errors"] += 1

        except FloodWaitError as e:
            await _log(thread, phone, f"FloodWait {e.seconds}s — пропущен", "gray")
            results["errors"] += 1

        except Exception as e:
            await _log(thread, phone, f"Ошибка: {e}", "red")
            results["errors"] += 1


# ─── Точка входа ───────────────────────────────────────────────────────────

def _win_to_wsl(path: str) -> str:
    """Конвертирует 'L:\\foo' → '/mnt/l/foo' при запуске под WSL2."""
    import platform
    if (
        platform.system() == "Linux"
        and len(path) >= 2
        and path[1] == ":"
    ):
        drive = path[0].lower()
        rest = path[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return path


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Telegram Account Manager — tdata (multi-account)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python tg_tool.py --path "L:\\Programs\\Telegram Desktop"
  python tg_tool.py --path "L:\\Programs\\Telegram Desktop" --terminate-sessions
  python tg_tool.py --path "L:\\Programs\\Telegram Desktop" --set-password "Qwerty123!"
  python tg_tool.py --path "L:\\Programs\\Telegram Desktop" --terminate-sessions \\
      --set-password "Qwerty123!" --accounts 20 --threads 10
""",
    )
    parser.add_argument(
        "--path",
        default=r"L:\Programs\Telegram Desktop",
        metavar="PATH",
        help='Путь к папке Telegram Desktop (default: "L:\\Programs\\Telegram Desktop")',
    )
    parser.add_argument(
        "--terminate-sessions",
        action="store_true",
        help="Закрыть все чужие сессии",
    )
    parser.add_argument(
        "--set-password",
        metavar="PASS",
        default=None,
        help="Установить облачный пароль 2FA (если не стоит)",
    )
    parser.add_argument(
        "--accounts",
        metavar="N",
        type=int,
        default=None,
        help="Обрабатывать только первые N аккаунтов",
    )
    parser.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=5,
        help="Параллельных потоков (default: 5)",
    )
    args = parser.parse_args()

    # ── Путь ──────────────────────────────────────────────────
    base = Path(_win_to_wsl(args.path))
    if not base.exists():
        print(f"[{_ts()}] ❌ Путь не найден: {base}", file=sys.stderr)
        sys.exit(1)
    if not (base / "tdata").exists():
        print(f"[{_ts()}] ❌ tdata/ не найден в {base}", file=sys.stderr)
        sys.exit(1)

    # ── opentele ──────────────────────────────────────────────
    try:
        from opentele.td import TDesktop
    except ImportError:
        print(
            f"[{_ts()}] ❌ opentele не установлен.\n"
            "  Запустите:  python -m venv .venv\n"
            "              .venv/Scripts/pip install opentele telethon",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[{_ts()}] Загружаем аккаунты: {base}")
    # opentele требует путь к tdata/, а не к родительской папке
    tdesk = TDesktop(str(base / "tdata"))

    if not tdesk.isLoaded():
        print(f"[{_ts()}] ❌ Не удалось загрузить tdata", file=sys.stderr)
        sys.exit(1)

    accounts = tdesk.accounts
    if not accounts:
        print(f"[{_ts()}] ❌ Аккаунты не найдены", file=sys.stderr)
        sys.exit(1)

    total   = len(accounts)
    limit   = min(args.accounts, total) if args.accounts else total
    threads = min(args.threads, limit)

    print(f"[{_ts()}] Аккаунтов: {total} | Обрабатываем: {limit} | Потоков: {threads}")
    if args.terminate_sessions:
        print(f"[{_ts()}] Чужие сессии будут закрыты")
    if args.set_password:
        print(f"[{_ts()}] Облачный пароль будет установлен")
    print()

    # ── Параллельная обработка ────────────────────────────────
    semaphore = asyncio.Semaphore(threads)
    results   = {"clean": 0, "spam": 0, "banned": 0, "errors": 0}

    tasks = [
        process_account(
            thread    = (i % threads) + 1,
            idx       = i,
            account   = acc,
            semaphore = semaphore,
            results   = results,
            terminate = args.terminate_sessions,
            password  = args.set_password,
        )
        for i, acc in enumerate(accounts[:limit])
    ]

    await asyncio.gather(*tasks)

    # ── Итоги ─────────────────────────────────────────────────
    print(f"\n[{_ts()}] Результаты проверки:")
    if results["clean"]:
        print(f"[{_ts()}]     {GREEN}Без спамблока: {results['clean']}{RESET}")
    if results["spam"]:
        print(f"[{_ts()}]     {RED}Спамблок:      {results['spam']}{RESET}")
    if results["banned"]:
        print(f"[{_ts()}]     {RED}Забанено:      {results['banned']}{RESET}")
    if results["errors"]:
        print(f"[{_ts()}]     Ошибок:        {results['errors']}")
    print(f"\n[{_ts()}] Выполнение задачи завершено!")


if __name__ == "__main__":
    asyncio.run(main())
