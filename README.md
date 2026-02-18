# tgdata-rs

Rust CLI tool for managing [Telegram Desktop](https://desktop.telegram.org/) accounts
directly from the `tdata` session directory — without re-authentication.

## Features

| Flag | Description |
|------|-------------|
| _(no flags)_ | Spam-block check + session count for every account |
| `--terminate-sessions` | Log out all foreign sessions |
| `--set-password PASS` | Set a cloud 2FA password (skips if already set) |
| `--remove-password PASS` | Remove an existing cloud 2FA password |
| `--export FILE` | Dump auth keys to JSON (offline, no network required) |
| `--import FILE` | Create a new `tdata` from a JSON export |
| `--only N,N,...` | Process only the listed accounts (1-based) |
| `--skip N,N,...` | Skip the listed accounts |
| `--accounts N` | Process at most N accounts |
| `--threads N` | Parallelism level (default: 5) |

## Build

### Linux / WSL

```bash
cargo build --release
./target/release/tgdata-rs --help
```

### Windows cross-compile (from Linux/WSL)

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu
# → target/x86_64-pc-windows-gnu/release/tgdata-rs.exe
```

## Usage

### Spam check (default)

```
tgdata-rs --path "C:\Users\User\AppData\Roaming\Telegram Desktop"
```

```
[12:00:00] Загружаем аккаунты: C:\Users\User\AppData\Roaming\Telegram Desktop
[12:00:00] Аккаунтов: 2 | Обрабатываем: 2 | Потоков: 2

[12:00:01] [Поток 1] [79001234567] Аккаунт жив. Без спамблока. | сессий 3 (чужих: 2)
[12:00:01] [Поток 2] [79007654321] СПАМБЛОК!

[12:00:01] Результаты проверки:
[12:00:01]     Без спамблока: 1
[12:00:01]     Спамблок:      1
```

### Terminate other sessions

```
tgdata-rs --path "C:\..." --terminate-sessions
```

```
[12:00:01] [Поток 1] [79001234567] Аккаунт жив. Без спамблока. | закрыто сессий: 2
[12:00:01] [Поток 1] [79001234567]   ↳ отключено: iPhone 15 Telegram iOS (iOS, Moscow, Russia)
[12:00:01] [Поток 1] [79001234567]   ↳ отключено: Samsung Galaxy S24 Telegram Android (Android, Kyiv, Ukraine)
```

### Set 2FA cloud password

```
tgdata-rs --path "C:\..." --set-password "MySecretPass123!"
```

```
[12:00:01] [Поток 1] [79001234567] Аккаунт жив. Без спамблока. | пароль ✓
```

### Remove 2FA cloud password

```
tgdata-rs --path "C:\..." --remove-password "MySecretPass123!"
```

### Export sessions to JSON (no network)

```
tgdata-rs --path "C:\..." --export sessions.json
```

```json
[
  {
    "index": 0,
    "user_id": 123456789,
    "dc_id": 2,
    "auth_key": "a1b2c3d4...512 hex chars..."
  }
]
```

### Import sessions → create new tdata

Creates the target directory if it does not exist. Useful for migrating
sessions to another machine without re-logging in.

```
tgdata-rs --path "D:\NewPC\Telegram Desktop" --import sessions.json
```

### Filter accounts

```bash
# Only accounts 1 and 3
tgdata-rs --path "C:\..." --only 1,3

# Skip account 2
tgdata-rs --path "C:\..." --skip 2

# First 10 accounts, 10 parallel threads
tgdata-rs --path "C:\..." --accounts 10 --threads 10
```

## tdata location

| OS | Default path |
|----|-------------|
| Windows | `%APPDATA%\Telegram Desktop` |
| Linux | `~/.local/share/TelegramDesktop` |
| macOS | `~/Library/Application Support/Telegram Desktop` |

When run from WSL, Windows paths are converted automatically
(`L:\Programs\Telegram Desktop` → `/mnt/l/Programs/Telegram Desktop`).

## How it works

Telegram Desktop stores sessions in an encrypted binary format inside `tdata/`.

1. **Key derivation** — derives the 256-byte local key via `PBKDF2-HMAC-SHA512`
   from a per-installation salt stored in `key_datas` (empty passcode assumed).
2. **Decryption** — reads per-account files, decrypts MTP authorization blocks
   with `AES-256-IGE` (old-MTProto key schedule).
3. **Connection** — uses the extracted auth keys to connect directly to
   Telegram's MTProto API via [grammers](https://github.com/Lonami/grammers).
4. **Operations** — performs the requested checks / mutations, then disconnects.

See [`TDATA_INTERNALS.md`](TDATA_INTERNALS.md) for a detailed breakdown of
the `tdata` file format.

## Python alternative

`tg_tool.py` is a simpler Python implementation using
[opentele](https://github.com/thedemons/opentele) + telethon.
See `setup.bat` / `setup.sh` for install instructions and `patch_opentele.py`
for required compatibility patches (needed for Telegram Desktop ≥ 5.x).

## Disclaimer

This tool is intended **for use on Telegram accounts you own and control**.
Accessing another person's session data without authorization may violate
applicable law and Telegram's [Terms of Service](https://telegram.org/tos).

## License

MIT
