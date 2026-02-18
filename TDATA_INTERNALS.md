# Telegram Desktop tdata — Формат и математика

Документ описывает внутреннее устройство папки `tdata` Telegram Desktop и
алгоритмы, необходимые для извлечения MTP-ключей авторизации без запуска самого
приложения. Всё описанное было получено методом реверс-инжиниринга исходников
opentele и Telegram Desktop.

---

## Общая структура папки `tdata`

```
tdata/
├── key_datas          ← главный ключевой файл (один на всё приложение)
├── <hash>s            ← MTP-данные аккаунта 0
├── <hash2>s           ← MTP-данные аккаунта 1
├── <hash3>s           ← MTP-данные аккаунта 2
└── ...
```

Все файлы в `tdata` — это **TDF-файлы** (Telegram Data File).

Помимо файлов сессий, в `tdata` встречаются служебные файлы:

| Файл | Содержимое |
|------|------------|
| `key_datas` | Главный ключ + список аккаунтов (разобран в этом документе) |
| `settings` | Настройки приложения (тема, язык, окно) — TDF, не шифруется |
| `prefix` | URL сервера обновлений (`https://td.telegram.org/`) — plaintext |
| `maps` | Кэш access_hash для пользователей/каналов — TDF, зашифрован localKey |
| `<hash>` / `<hash>s` | MTP-данные аккаунтов (описаны ниже) |

> **`maps`:** не нужен для авторизации, но используется для парсинга
> кэшированных сообщений — в нём хранится маппинг `peer_id → access_hash`,
> без которого многие API-запросы к конкретным чатам вернут ошибку.

---

## 1. Формат TDF-файла

> **Версионность:** Magic `TDF$` и базовая структура стабильны с версий ~2.x.
> Telegram Desktop меняет формат крайне редко, но при крупных обновлениях
> (переход с 4.x на 5.x/6.x) иногда добавляют новые типы ключей внутри блоков.
> Если парсер падает с «unknown key type», это признак нового подтипа данных —
> достаточно сделать `break` вместо исключения и пропустить неизвестный блок.

> **Кроссплатформенность:** Формат TDF специфичен для **Telegram Desktop (Qt/C++)**.
> macOS Native, Android и iOS используют другие хранилища:
> CoreData, SQLite (`account.db`), Realm — несовместимы с этим форматом.

## 1. Формат TDF-файла

Каждый файл состоит из:

```
┌──────────────┬─────────────────────┬──────────┬──────────────┐
│  Magic (4)   │   Version LE32 (4)  │  Data …  │  MD5(16)     │
└──────────────┴─────────────────────┴──────────┴──────────────┘
b"TDF$"        LE u32                raw bytes   контрольная сумма
```

**Проверка MD5:**

```
MD5( Data || LE32(len(Data)) || LE32(version) || b"TDF$" )
```

Результат должен совпасть с последними 16 байтами файла.

**Суффиксы файлов:** `s`, `1`, `0`. Читается первый существующий.

---

## 2. QDataStream

Данные внутри TDF-файлов сериализованы в формате Qt `QDataStream` (big-endian):

| Тип           | Размер     | Кодирование                              |
|---------------|------------|------------------------------------------|
| `i32`         | 4 байта    | big-endian знаковое                      |
| `u32`         | 4 байта    | big-endian беззнаковое                   |
| `u64`         | 8 байт     | big-endian беззнаковое                   |
| `QByteArray`  | 4 + N байт | `BE_u32(len)` + `N байт`; `0xFFFFFFFF` = null/пусто |

---

## 3. Файл `key_datas` — главный ключ

`key_datas` содержит один QByteArray с тремя вложенными QByteArray:

```
QByteArray(
    QByteArray salt           ← случайная соль (32 байта)
    QByteArray keyEncrypted   ← зашифрованный локальный ключ
    QByteArray infoEncrypted  ← зашифрованный список аккаунтов
)
```

---

## 4. Криптография: `CreateLocalKey`

Из соли и кодового слова (passcode) Telegram вычисляет ключ шифрования:

```
hashKey  = SHA-512( salt || passcode || salt )
localKey = PBKDF2-HMAC-SHA512(
               password   = hashKey,
               salt       = salt,
               iterations = 1,          ← если passcode пустой
               dkLen      = 256         ← 256 байт = 2048 бит
           )
```

> **Примечание:** При непустом passcode используется 100 000 итераций.
> При пустом (большинство установок без кодового слова) — 1 итерация.

Результат `localKey` — 256-байтный ключ. Он используется как «auth_key»
в схеме MTP-шифрования (описана ниже).

---

## 5. `decrypt_local` — дешифровка блоков

Все зашифрованные блоки (`keyEncrypted`, `infoEncrypted`, MTP-данные) имеют
одинаковую структуру:

```
encrypted = msg_key(16) || ciphertext(N×16)
```

**Алгоритм:**

1. `msg_key` = первые 16 байт
2. Вычислить AES-ключ и AES-IV через `prepareAES_oldmtp(msg_key, auth_key, x=8)`
3. Расшифровать `ciphertext` алгоритмом **AES-256-IGE**
4. Проверить: `SHA1(plaintext)[:16] == msg_key`
5. Вернуть `plaintext[4 .. 4 + LE32(plaintext[0..4])]`

---

### 5.1 `prepareAES_oldmtp` (x = 8 для дешифровки)

Из `msg_key` (16 байт) и `auth_key` (256 байт) строятся 32-байтный AES-ключ и
32-байтный AES-IV по схеме MTProto 1.0:

```
sha1_a = SHA1( msg_key[0..16]  ||  auth_key[x .. x+32]  )
sha1_b = SHA1( auth_key[x+32..x+48]  ||  msg_key[0..16]  ||  auth_key[x+48..x+64] )
sha1_c = SHA1( auth_key[x+64..x+96]  ||  msg_key[0..16]  )
sha1_d = SHA1( msg_key[0..16]  ||  auth_key[x+96..x+128] )

aes_key[0..8]   = sha1_a[0..8]
aes_key[8..20]  = sha1_b[8..20]
aes_key[20..32] = sha1_c[4..16]

aes_iv[0..12]   = sha1_a[8..20]
aes_iv[12..20]  = sha1_b[0..8]
aes_iv[20..24]  = sha1_c[16..20]
aes_iv[24..32]  = sha1_d[0..8]
```

---

### 5.2 AES-256-IGE (Infinite Garble Extension)

Нестандартный режим AES, используемый в MTProto. Отличается от CBC порядком XOR:

```
P[i] = AES_decrypt_block(C[i] XOR P[i-1]) XOR C[i-1]
```

Начальные значения (конвенция tgcrypto):

```
C[-1] (prev_cipher) = iv[0..16]
P[-1] (prev_plain)  = iv[16..32]
```

> **Частая ошибка:** перепутать местами `C[-1]` и `P[-1]` из IV.
> В tgcrypto `iv[0..16]` — это предыдущий **шифртекст**, а не открытый текст.

---

## 6. Расшифровка `keyEncrypted` → `localKey`

```python
passcode_key = CreateLocalKey(salt, passcode=b"")
key_inner    = decrypt_local(keyEncrypted, passcode_key)
local_key    = key_inner[0:256]   # первые 256 байт
```

`local_key` — мастер-ключ, которым зашифровано всё остальное.

---

## 7. Расшифровка `infoEncrypted` → список аккаунтов

```python
info_data = decrypt_local(infoEncrypted, local_key)
# QDataStream:
count   = i32.read()          # количество аккаунтов
indices = [i32.read() for _ in range(count)]   # индексы (0, 1, 2 ...)
```

---

## 8. Имена файлов аккаунтов

Для каждого индекса `idx` имя файла вычисляется так:

```python
def compose_data_string(idx):
    return "data" if idx == 0 else f"data#{idx + 1}"
    # idx=0 → "data", idx=1 → "data#2", idx=2 → "data#3"

def compute_data_name_key(name):
    md5 = MD5(name.encode())
    return int.from_bytes(md5[:8], 'little')   # u64 little-endian

def to_file_part(val):
    result = ""
    for _ in range(16):
        nibble = val & 0xF
        result += str(nibble) if nibble < 10 else chr(ord('A') + nibble - 10)
        val >>= 4
    return result  # LSB-nibble first, 16 символов

file_part = to_file_part(compute_data_name_key(compose_data_string(idx)))
# читать: tdata/<file_part>s
```

Пример (idx=0, name="data"):

```
MD5("data") = 8d777f385d3dfec8815d20f7496026dc (hex)
первые 8 байт LE: 0x8d 0x77 0x7f 0x38 0x5d 0x3d 0xfe 0xc8
→ u64 LE = 0xc8fe3d5d387f778d
→ to_file_part → "D877F385D3DFEC8C"  (nibble-LSB)
→ файл: tdata/D877F385D3DFEC8Cs
```

---

## 9. MTP Authorization Block

Внутри файла аккаунта — TDF-файл, данные которого содержат один `QByteArray`
с зашифрованным блоком:

```python
encrypted_mtp = QByteArray.read()          # из TDF-данных
mtp_dec       = decrypt_local(encrypted_mtp, local_key)
```

Расшифрованный блок:

```
i32  block_id          = 75  (LSK_MTP_AUTHORIZATION)
QByteArray serialized        ← собственно MTP-данные
```

Внутри `serialized` (QDataStream):

```
# Заголовок: определяем формат (Legacy vs Wide IDs)
i32  legacy_user_id
i32  legacy_dc_id
combined = (legacy_user_id << 32) | legacy_dc_id

если combined == 0xFFFFFFFF_FFFFFFFF  (kWideIdsTag):
    u64  user_id    ← 64-битный ID пользователя
    i32  main_dc_id ← основной дата-центр

иначе (устаревший формат):
    user_id    = legacy_user_id
    main_dc_id = legacy_dc_id

# Ключи авторизации
i32  key_count
for _ in range(key_count):
    i32    dc_id     ← номер дата-центра (1..5)
    bytes  auth_key  ← 256 байт «сырого» MTProto ключа

# Нужен ключ для main_dc_id
```

---

## 10. Использование ключа: Session для MTProto

Полученный 256-байтный `auth_key` для `main_dc_id` вставляется в сессию
MTProto-клиента:

```rust
let mut data = SessionData::default();
data.home_dc = dc_id;
data.dc_options.get_mut(&dc_id).unwrap().auth_key = Some(auth_key);
let session = MemorySession::from(data);
```

После чего клиент может вызывать любые MTProto API-методы от имени аккаунта
без логина/пароля — ключ уже авторизован.

> **Риски параллельного использования:**
> Если использовать тот же `auth_key` одновременно с запущенным Telegram Desktop
> и с той же парой `api_id/api_hash`, сервер ведёт общий счётчик `seq_no`
> обновлений (updates). Два клиента будут конфликтовать за него:
> каждый получит только часть обновлений, один из них в итоге получит
> `AUTH_KEY_UNREGISTERED` и будет разлогинен. Безопаснее:
> - использовать другой `api_id` (например, собственный, зарегистрированный на my.telegram.org), или
> - не держать TG Desktop открытым во время работы инструмента, или
> - работать только с «снапшотными» операциями (спам-чек, 2FA, сессии) и сразу отключаться.

---

## 11. Проверка спам-блокировки

```
contacts.Search { q: "telegram", limit: 1 }
  → OK                → аккаунт чистый
  → RPC 420 PEER_FLOOD → спам-блокировка активна
```

---

## 12. Установка облачного пароля 2FA

**Получение параметров от сервера:**

```
account.GetPassword
  → new_algo: PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow {
        salt1: bytes   ← серверная соль (обычно 8 байт)
        salt2: bytes   ← серверная соль (обычно 16 байт)
        g:     int     ← генератор DH-группы (3 или 7)
        p:     bytes   ← простое число DH (2048 бит, 256 байт)
    }
```

**Вычисление верификатора:**

```
# Добавляем клиентский random ТОЛЬКО к salt1
client_random = os.urandom(32)
salt1 = server_new_algo.salt1 + client_random   # соль1 = серверная + клиентская
salt2 = server_new_algo.salt2                    # соль2 без изменений!

# PH2 — функция деривации ключа
H(x)            = SHA256(x)
SH(data, salt)  = H(salt || data || salt)
PH1(pwd, s1, s2) = SH( SH(pwd, s1), s2 )
PH2(pwd, s1, s2) = SH( PBKDF2-HMAC-SHA512(PH1(pwd, s1, s2), s1, 100000, 64B), s2 )

x        = PH2(password.encode(), salt1, salt2)
verifier = pow(g, x, p)          # g^x mod p — 256 байт
```

**Отправка:**

```
account.UpdatePasswordSettings {
    password: InputCheckPasswordEmpty,   # нет текущего пароля
    new_settings: PasswordInputSettings {
        new_algo: { salt1, salt2, g, p },  # модифицированный algo с нашим salt1
        new_password_hash: verifier,       # g^x mod p, 256 байт
        hint: "",
    }
}
```

> **Критично:** добавление клиентского случайного к `salt2` вызывает ошибку
> `NEW_SALT_INVALID`. Клиентский random добавляется **только к `salt1`**.

---

## Схема потока данных

```
tdata/key_datas
    │
    ├─[TDF parse]─► raw bytes
    │
    └─[QDataStream]─► salt, keyEncrypted, infoEncrypted
                          │
              CreateLocalKey(salt, "")
                          │
                     passcode_key (256B)
                          │
              decrypt_local(keyEncrypted, passcode_key)
                          │
                      local_key (256B)
                          │
              decrypt_local(infoEncrypted, local_key)
                          │
                  [count, idx0, idx1, ...]
                          │
             ┌────────────┴───────────────────┐
         idx=0                            idx=1, 2...
    compose("data")               compose("data#2"), ("data#3")...
    MD5[:8] as u64 LE             same
    to_file_part(u64)             same
         │
    tdata/<hash>s
         │
    [TDF parse]─► QByteArray(encrypted_mtp)
         │
    decrypt_local(encrypted_mtp, local_key)
         │
    blockId(75) + QByteArray(serialized)
         │
    parse: user_id, main_dc_id, keys[(dc_id, auth_key[256])]
         │
    auth_key[256] for main_dc_id
         │
    MTProto session → API calls
```

---

## Использованные источники

- [opentele](https://github.com/thedemons/opentele) — Python-библиотека для работы с tdata (реверс-анализ)
- [grammers](https://github.com/Lonami/grammers) — Rust MTProto-клиент
- [Telegram MTProto 1.0 spec](https://core.telegram.org/mtproto/description_v1) — официальная документация по AES-IGE и prepareAES
- [Telegram SRP (2FA)](https://core.telegram.org/api/srp) — официальный алгоритм PH2/SRP для 2FA
- Telegram Desktop C++ source — `storage.cpp`, `core_cloud_password.cpp`
