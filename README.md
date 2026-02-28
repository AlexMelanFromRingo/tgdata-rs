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
| `--check-groups GROUP,...` | Resolve groups/channels: title, type, member count |
| `--parse-group GROUP` | Scrape all members to CSV (supergroups only) |
| `--join-group GROUP` | Join a group/channel (username or `t.me/+HASH` invite link) |
| `--leave-group GROUP` | Leave a group/channel |
| `--check-username USER` | Check if a Telegram username is available (free to register) |
| `--set-name "First\|Last"` | Set account first and/or last name |
| `--set-bio TEXT` | Set account bio / about text |
| `--ping` | Send "." to Saved Messages (session keep-alive) |
| `--view-stories USER,...` | View and mark stories of given users as seen |
| `--react LINK` | React to a message link (`t.me/username/123`) |
| `--react-emoji EMOJI` | Emoji for `--react` (default: 👍) |
| `--proxy URL` | SOCKS5 proxy: `socks5://[user:pass@]host:port` |
| `--parse-messages GROUP` | Scrape messages to CSV |
| `--msg-limit N` | Max messages for `--parse-messages` (default: 1000) |
| `--list-joined-channels` | List channels/supergroups available in one selected account |
| `--dump-channel SOURCE` | Full dump (text + media) from channel source (`@`, `t.me/...`, invite, or `joined:N`) |
| `--dump-dir DIR` | Output directory for `--dump-channel` (default: `channel_dump`) |
| `--dump-limit N` | Message limit for `--dump-channel` (`0` = no limit) |
| `--dump-account N` | Account index (1-based) used for `--dump-channel` and `--list-joined-channels` |
| `--invite-to GROUP` | Invite users to a channel |
| `--invite-from FILE` | CSV source for `--invite-to` (from `--parse-group` output) |
| `--output FILE` | CSV destination (default: `members.csv` / `messages.csv`) |
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

### Check groups / channels

```
tgdata-rs --path "C:\..." --check-groups "@durov,t.me/telegram,@somegroup"
```

```
[12:00:01] [79001234567] группы (3):
[12:00:01] [79001234567]   ↳ @durov — «Pavel Durov» (10 583 524 уч.) [канал] ✓
[12:00:01] [79001234567]   ↳ @telegram — «Telegram News» (11 385 781 уч.) [канал] ✓
[12:00:01] [79001234567]   ↳ @somegroup — «Some Group» (1 204 уч.) [супергруппа] ✓
```

Member count is fetched via `channels.getFullChannel` for accurate results.

### Parse group members

```
tgdata-rs --path "C:\..." --parse-group @somegroup --output members.csv
```

```
[12:00:01] [79001234567] парсинг @somegroup...
[12:00:30] [79001234567] Аккаунт жив. | спарсено 1198/1200
✓ Сохранено 1200 участников (с телефонами: 43) → members.csv
```

Uses all selected accounts in parallel — different accounts have different mutual
contacts, so using multiple accounts yields more visible phone numbers.
Results are merged by `user_id`.

**Output CSV columns:** `user_id`, `access_hash`, `username`, `first_name`, `last_name`, `phone`, `is_bot`, `is_premium`

> Works for supergroups. Broadcast channels require admin rights.

### Join / leave groups

```
tgdata-rs --path "C:\..." --join-group @somegroup
tgdata-rs --path "C:\..." --join-group "t.me/+AbCdEfGhIjKl"
tgdata-rs --path "C:\..." --leave-group @somegroup
```

### Check username availability

```
tgdata-rs --path "C:\..." --check-username coolname
```

```
[12:00:01] [Поток 1] [79001234567] Аккаунт жив. Без спамблока. | @coolname: свободен ✓
```

### Set name and bio

```
tgdata-rs --path "C:\..." --set-name "Ivan|Petrov" --set-bio "Crypto trader"
```

```
[12:00:01] [Поток 1] [79001234567] Аккаунт жив. Без спамблока. | имя, bio обновлено ✓
```

### Ping (session keep-alive)

```
tgdata-rs --path "C:\..." --ping
```

Sends a silent "." to Saved Messages on every account.

### View stories

```
tgdata-rs --path "C:\..." --view-stories "@durov,@telegram"
```

```
[12:00:01] [Поток 1] [79001234567] Аккаунт жив. | stories: просмотрено 3 шт.
[12:00:01] [Поток 1] [79001234567]   ↳ @durov: 2 историй
[12:00:01] [Поток 1] [79001234567]   ↳ @telegram: 1 историй
```

### React to a message

```
tgdata-rs --path "C:\..." --react "t.me/durov/123" --react-emoji "❤️"
```

### Using SOCKS5 proxy

```
tgdata-rs --path "C:\..." --proxy "socks5://user:pass@192.168.1.100:1080"
tgdata-rs --path "C:\..." --proxy "socks5://192.168.1.100:1080"
```

Each account gets its own relay through the proxy.

### Parse messages

```
tgdata-rs --path "C:\..." --parse-messages @somegroup --msg-limit 5000 --output messages.csv
```

**Output CSV columns:** `msg_id`, `date`, `from_id`, `text`, `reply_to_id`, `views`, `forwards`

### Full channel dump (text + media)

Pick the account explicitly with `--dump-account`:

```bash
# 1) Show channels available in account #2
tgdata-rs --path "C:\..." --dump-account 2 --list-joined-channels

# 2) Dump by joined index from previous list
tgdata-rs --path "C:\..." --dump-account 2 --dump-channel joined:3 --dump-dir channel_dump

# 3) Dump by public username/link
tgdata-rs --path "C:\..." --dump-account 2 --dump-channel @telegram --dump-limit 10000
tgdata-rs --path "C:\..." --dump-account 2 --dump-channel "t.me/telegram"

# 4) Dump by invite link (tool joins first if needed)
tgdata-rs --path "C:\..." --dump-account 2 --dump-channel "t.me/+AbCdEfGhIjKl"
```

Output files:
- `channel_dump/messages.csv`
- `channel_dump/media/*`

**Output CSV columns:** `msg_id`, `date`, `from_id`, `text`, `reply_to_id`, `views`, `forwards`, `media_kind`, `media_file`

### Invite members to a channel

First parse members from a source group, then invite them:

```
tgdata-rs --path "C:\..." --parse-group @sourcegroup --output members.csv
tgdata-rs --path "C:\..." --invite-to @targetgroup --invite-from members.csv
```

The invite list is split evenly across all accounts to avoid per-account rate limits.

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
