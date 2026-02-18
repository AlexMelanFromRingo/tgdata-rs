/// Parses Telegram Desktop tdata format to extract MTP authorization keys.
///
/// Flow (per opentele source):
/// 1. Read `tdata/key_datas` → (salt, keyEncrypted, infoEncrypted)
/// 2. passcodeKey = CreateLocalKey(salt, passcode="")
/// 3. localKey = decrypt_local(keyEncrypted, passcodeKey)[0..256]
/// 4. infoData = decrypt_local(infoEncrypted, localKey)
///    → count i32, then count × index i32
/// 5. For each account index:
///    - file name = ToFilePart(ComputeDataNameKey(ComposeDataString("data", idx)))
///    - Read tdata/<name>s → QByteArray → decrypt_local → blockId(75) + QByteArray(MTP auth)
///    - Parse MTP auth → userId, mainDcId, keys[(dcId, authKey[256])]

use anyhow::{anyhow, bail, Result};
use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use rand::RngCore;
use md5::{Digest as _, Md5};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha512;
use std::path::Path;

pub struct AccountInfo {
    pub index: usize,
    pub dc_id: i32,
    pub user_id: i64,
    pub auth_key: Box<[u8; 256]>,
}

const TDF_MAGIC: &[u8; 4] = b"TDF$";
const LSK_MTP_AUTHORIZATION: i32 = 75;
// kWideIdsTag = ~0 as i64 = 0xFFFFFFFF_FFFFFFFF (all bits set)
// Detected by reading two i32s and checking combined i64 == -1
const K_WIDE_IDS_TAG: i64 = -1_i64;

// ─── TDF file format ─────────────────────────────────────────────────────────
// Layout: magic(4) | version_LE(4) | data | md5(16)
// MD5 = MD5(data || LE32(data_len) || LE32(version) || magic)

fn read_tdf(path: &Path) -> Result<(u32, Vec<u8>)> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow!("Cannot read {}: {}", path.display(), e))?;

    if bytes.len() < 8 + 16 {
        bail!("TDF file too short: {}", path.display());
    }
    if &bytes[0..4] != TDF_MAGIC {
        bail!("Invalid TDF magic in {}", path.display());
    }

    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let data_len = bytes.len() - 8 - 16;
    let data = bytes[8..8 + data_len].to_vec();
    let stored_md5 = &bytes[bytes.len() - 16..];

    let mut h = Md5::new();
    h.update(&data);
    h.update(&(data_len as u32).to_le_bytes());
    h.update(&version.to_le_bytes());
    h.update(TDF_MAGIC);
    let computed = h.finalize();

    if computed.as_slice() != stored_md5 {
        bail!("TDF MD5 mismatch in {}", path.display());
    }

    Ok((version, data))
}

fn read_tdf_with_suffix(base: &Path, name: &str) -> Result<(u32, Vec<u8>)> {
    for suffix in ["s", "1", "0"] {
        let path = base.join(format!("{}{}", name, suffix));
        if path.exists() {
            return read_tdf(&path);
        }
    }
    bail!("File not found: {}/{}", base.display(), name)
}

// ─── QDataStream reader (big-endian) ─────────────────────────────────────────

struct QStream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> QStream<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!(
                "QStream underflow: need {}, have {}",
                n,
                self.data.len() - self.pos
            );
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    }

    fn read_i32(&mut self) -> Result<i32> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_be_bytes(b.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }

    /// Read QByteArray: BE u32 length + raw bytes (0xFFFFFFFF = null/empty)
    fn read_bytearray(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()?;
        if len == 0xFFFF_FFFF {
            return Ok(vec![]);
        }
        Ok(self.read_bytes(len as usize)?.to_vec())
    }

    fn read_raw(&mut self, n: usize) -> Result<Vec<u8>> {
        Ok(self.read_bytes(n)?.to_vec())
    }
}

// ─── Crypto ──────────────────────────────────────────────────────────────────

/// CreateLocalKey(salt, passcode) from opentele:
///   hashKey = SHA512(salt || passcode || salt)
///   key     = PBKDF2-HMAC-SHA512(hashKey, salt, iterations, 256)
///   iterations = 1 for empty passcode, 100_000 otherwise
fn create_local_key(salt: &[u8], passcode: &[u8]) -> [u8; 256] {
    let mut h = Sha512::new();
    h.update(salt);
    h.update(passcode);
    h.update(salt);
    let hash_key = h.finalize();

    let iters = if passcode.is_empty() { 1u32 } else { 100_000u32 };
    let mut out = [0u8; 256];
    pbkdf2_hmac::<Sha512>(&hash_key, salt, iters, &mut out);
    out
}

/// SHA1 of concatenated parts
fn sha1_parts(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// prepareAES_oldmtp: x=0 for encrypt (sending), x=8 for decrypt (receiving)
fn prepare_aes_oldmtp(msg_key: &[u8], auth_key: &[u8; 256], x: usize) -> ([u8; 32], [u8; 32]) {
    let sha1_a = sha1_parts(&[&msg_key[..16], &auth_key[x..x + 32]]);
    let sha1_b = sha1_parts(&[
        &auth_key[x + 32..x + 48],
        &msg_key[..16],
        &auth_key[x + 48..x + 64],
    ]);
    let sha1_c = sha1_parts(&[&auth_key[x + 64..x + 96], &msg_key[..16]]);
    let sha1_d = sha1_parts(&[&msg_key[..16], &auth_key[x + 96..x + 128]]);

    let mut aes_key = [0u8; 32];
    aes_key[..8].copy_from_slice(&sha1_a[..8]);
    aes_key[8..20].copy_from_slice(&sha1_b[8..20]);
    aes_key[20..32].copy_from_slice(&sha1_c[4..16]);

    let mut aes_iv = [0u8; 32];
    aes_iv[..12].copy_from_slice(&sha1_a[8..20]);
    aes_iv[12..20].copy_from_slice(&sha1_b[..8]);
    aes_iv[20..24].copy_from_slice(&sha1_c[16..20]);
    aes_iv[24..32].copy_from_slice(&sha1_d[..8]);

    (aes_key, aes_iv)
}

fn prepare_aes_decrypt(msg_key: &[u8], auth_key: &[u8; 256]) -> ([u8; 32], [u8; 32]) {
    prepare_aes_oldmtp(msg_key, auth_key, 8)
}

fn prepare_aes_encrypt_local(msg_key: &[u8], auth_key: &[u8; 256]) -> ([u8; 32], [u8; 32]) {
    prepare_aes_oldmtp(msg_key, auth_key, 8)
}

/// AES-256-IGE decrypt (tgcrypto convention)
/// P[i] = D_key(C[i] XOR prev_plain) XOR prev_cipher
/// iv[0..16] = C[-1] = prev_cipher, iv[16..32] = P[-1] = prev_plain
fn aes_ige_decrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        bail!("AES-IGE input not 16-byte aligned ({})", data.len());
    }
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut result = vec![0u8; data.len()];
    let mut prev_plain = [0u8; 16];
    let mut prev_cipher = [0u8; 16];
    // tgcrypto: iv[0..16] = xprev = C[-1], iv[16..32] = yprev = P[-1]
    prev_cipher.copy_from_slice(&iv[..16]);
    prev_plain.copy_from_slice(&iv[16..32]);

    for (i, chunk) in data.chunks_exact(16).enumerate() {
        let mut block = [0u8; 16];
        for j in 0..16 {
            block[j] = chunk[j] ^ prev_plain[j];
        }
        let mut ga = GenericArray::from(block);
        cipher.decrypt_block(&mut ga);
        let dec: [u8; 16] = ga.into();
        let mut plain = [0u8; 16];
        for j in 0..16 {
            plain[j] = dec[j] ^ prev_cipher[j];
        }
        result[i * 16..(i + 1) * 16].copy_from_slice(&plain);
        prev_plain = plain;
        prev_cipher.copy_from_slice(chunk);
    }
    Ok(result)
}

/// DecryptLocal(encrypted, authKey):
///   msg_key = encrypted[0..16]
///   AES-256-IGE decrypt rest using SHA1-derived key+iv
///   verify SHA1(plain)[:16] == msg_key
///   return plain[4 .. 4 + LE32(plain[0..4])]
fn decrypt_local(encrypted: &[u8], auth_key: &[u8; 256]) -> Result<Vec<u8>> {
    if encrypted.len() < 16 || (encrypted.len() - 16) % 16 != 0 {
        bail!("Bad encrypted size: {}", encrypted.len());
    }
    let msg_key = &encrypted[..16];
    let ciphertext = &encrypted[16..];

    let (aes_key, aes_iv) = prepare_aes_decrypt(msg_key, auth_key);
    let decrypted = aes_ige_decrypt(ciphertext, &aes_key, &aes_iv)?;

    let check = sha1_parts(&[&decrypted]);
    if &check[..16] != msg_key {
        bail!("decrypt_local: SHA1 mismatch (wrong key or corrupt data)");
    }

    if decrypted.len() < 4 {
        bail!("decrypt_local: decrypted too short");
    }
    let data_len = u32::from_le_bytes(decrypted[..4].try_into().unwrap()) as usize;
    if data_len < 4 || data_len > decrypted.len() {
        bail!("decrypt_local: bad data_len {}", data_len);
    }

    Ok(decrypted[4..data_len].to_vec())
}

// ─── File name computation ────────────────────────────────────────────────────

fn compute_data_name_key(name: &str) -> u64 {
    let hash = Md5::digest(name.as_bytes());
    u64::from_le_bytes(hash[..8].try_into().unwrap())
}

fn to_file_part(mut val: u64) -> String {
    let mut s = String::with_capacity(16);
    for _ in 0..16 {
        let nibble = (val & 0xF) as u8;
        s.push(if nibble < 10 {
            (b'0' + nibble) as char
        } else {
            (b'A' + nibble - 10) as char
        });
        val >>= 4;
    }
    s
}

/// ComposeDataString("data", 0) = "data"
/// ComposeDataString("data", 1) = "data#2"
/// ComposeDataString("data", 2) = "data#3"
fn compose_data_string(index: usize) -> String {
    if index == 0 {
        "data".to_string()
    } else {
        format!("data#{}", index + 1)
    }
}

// ─── Main extraction ──────────────────────────────────────────────────────────

pub fn extract_all_accounts(tdata_path: &Path) -> Result<Vec<AccountInfo>> {
    // ── Step 1: Read key_datas ─────────────────────────────────────────────
    let (_ver, kd_bytes) = read_tdf_with_suffix(tdata_path, "key_data")?;
    let mut kd = QStream::new(&kd_bytes);

    let salt = kd.read_bytearray()?;
    let key_encrypted = kd.read_bytearray()?;
    let info_encrypted = kd.read_bytearray()?;

    // ── Step 2: Derive passcodeKey (empty passcode) ────────────────────────
    let passcode_key = create_local_key(&salt, b"");

    // ── Step 3: Decrypt keyEncrypted → actual 256-byte localKey ───────────
    let key_inner = decrypt_local(&key_encrypted, &passcode_key)?;
    if key_inner.len() < 256 {
        bail!("key inner data too short: {}", key_inner.len());
    }
    let mut local_key = [0u8; 256];
    local_key.copy_from_slice(&key_inner[..256]);

    // ── Step 4: Decrypt infoEncrypted → account indices ───────────────────
    let info_data = decrypt_local(&info_encrypted, &local_key)?;
    let mut info_qs = QStream::new(&info_data);
    let count = info_qs.read_i32()? as usize;
    let mut indices = Vec::with_capacity(count);
    for _ in 0..count {
        indices.push(info_qs.read_i32()? as usize);
    }

    // ── Step 5: For each account index, read MTP auth data ────────────────
    let mut accounts = Vec::new();

    for idx in indices {
        let data_name = compose_data_string(idx);
        let hash_key = compute_data_name_key(&data_name);
        let file_part = to_file_part(hash_key);

        let (_ver2, mtp_raw) = match read_tdf_with_suffix(tdata_path, &file_part) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  [skip] account idx={}: {}", idx, e);
                continue;
            }
        };

        // TDF data is one QByteArray containing the encrypted MTP block
        let mut mtp_qs = QStream::new(&mtp_raw);
        let encrypted_mtp = match mtp_qs.read_bytearray() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  [skip] account idx={}: read bytearray failed: {}", idx, e);
                continue;
            }
        };

        let mtp_dec = match decrypt_local(&encrypted_mtp, &local_key) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  [skip] account idx={}: decrypt failed: {}", idx, e);
                continue;
            }
        };

        // Decrypted block: i32 blockId + QByteArray serialized
        let mut d = QStream::new(&mtp_dec);
        let block_id = match d.read_i32() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  [skip] account idx={}: read blockId: {}", idx, e);
                continue;
            }
        };
        if block_id != LSK_MTP_AUTHORIZATION {
            eprintln!(
                "  [skip] account idx={}: unexpected blockId {} (expected {})",
                idx, block_id, LSK_MTP_AUTHORIZATION
            );
            continue;
        }

        let serialized = match d.read_bytearray() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  [skip] account idx={}: read serialized: {}", idx, e);
                continue;
            }
        };

        // Parse MTP authorization (from Account._setMtpAuthorization)
        match parse_mtp_authorization(&serialized, idx) {
            Ok(info) => accounts.push(info),
            Err(e) => eprintln!("  [skip] account idx={}: parse auth: {}", idx, e),
        }
    }

    Ok(accounts)
}

fn parse_mtp_authorization(data: &[u8], index: usize) -> Result<AccountInfo> {
    let mut s = QStream::new(data);

    // kWideIdsTag detection:
    // Read two i32 values; if combined as i64 == -1, it's a wide IDs format
    let legacy_user_id = s.read_i32()? as i64;
    let legacy_dc_id = s.read_i32()? as i64;
    let combined = (legacy_user_id << 32) | (legacy_dc_id & 0xFFFF_FFFF);

    let (user_id, main_dc_id) = if combined == K_WIDE_IDS_TAG {
        // Wide IDs: next u64 = user_id, next i32 = dc_id
        let uid = s.read_u64()? as i64;
        let dc = s.read_i32()?;
        (uid, dc)
    } else {
        (legacy_user_id, legacy_dc_id as i32)
    };

    // Read keys: i32 count, then (i32 dcId + 256 raw bytes) each
    let key_count = s.read_i32()? as usize;
    let mut auth_key_opt: Option<[u8; 256]> = None;

    for _ in 0..key_count {
        let dc_id = s.read_i32()?;
        let key_bytes = s.read_raw(256)?;
        if dc_id == main_dc_id && auth_key_opt.is_none() {
            let mut k = [0u8; 256];
            k.copy_from_slice(&key_bytes);
            auth_key_opt = Some(k);
        }
    }

    let auth_key = auth_key_opt.ok_or_else(|| {
        anyhow!(
            "no auth key for main DC {} (user {})",
            main_dc_id,
            user_id
        )
    })?;

    Ok(AccountInfo {
        index,
        dc_id: main_dc_id,
        user_id,
        auth_key: Box::new(auth_key),
    })
}

// ─── QDataStream writer ───────────────────────────────────────────────────────

fn write_i32_be(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn write_u64_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// QByteArray: BE u32 length + raw bytes
fn write_qbytearray(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

// ─── AES-256-IGE encrypt ──────────────────────────────────────────────────────
// C[i] = E_key(P[i] XOR C[i-1]) XOR P[i-1]
// iv[0..16] = C[-1] = prev_cipher, iv[16..32] = P[-1] = prev_plain

fn aes_ige_encrypt(data: &[u8], key: &[u8; 32], iv: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        bail!("AES-IGE encrypt: input not 16-byte aligned ({})", data.len());
    }
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut result = vec![0u8; data.len()];
    let mut prev_cipher = [0u8; 16];
    let mut prev_plain  = [0u8; 16];
    prev_cipher.copy_from_slice(&iv[..16]);
    prev_plain.copy_from_slice(&iv[16..32]);

    for (i, chunk) in data.chunks_exact(16).enumerate() {
        let mut block = [0u8; 16];
        for j in 0..16 { block[j] = chunk[j] ^ prev_cipher[j]; }
        let mut ga = GenericArray::from(block);
        cipher.encrypt_block(&mut ga);
        let enc: [u8; 16] = ga.into();
        let mut cipher_block = [0u8; 16];
        for j in 0..16 { cipher_block[j] = enc[j] ^ prev_plain[j]; }
        result[i * 16..(i + 1) * 16].copy_from_slice(&cipher_block);
        prev_plain.copy_from_slice(chunk);
        prev_cipher = cipher_block;
    }
    Ok(result)
}

// ─── encrypt_local ────────────────────────────────────────────────────────────
// Inverse of decrypt_local.
// plain = LE32(4 + len(data)) || data || random_padding → 16-byte aligned
// msg_key = SHA1(plain)[0..16]
// result  = msg_key || AES_IGE_encrypt(plain, x=0)

fn encrypt_local(data: &[u8], auth_key: &[u8; 256]) -> Result<Vec<u8>> {
    let data_len_field = 4 + data.len();            // includes the 4-byte length itself
    let padded_len     = (data_len_field + 15) & !15; // round up to 16 bytes

    let mut plain = vec![0u8; padded_len];
    plain[..4].copy_from_slice(&(data_len_field as u32).to_le_bytes());
    plain[4..4 + data.len()].copy_from_slice(data);
    rand::thread_rng().fill_bytes(&mut plain[data_len_field..]); // random padding

    let sha = sha1_parts(&[&plain]);
    let msg_key: [u8; 16] = sha[..16].try_into().unwrap();

    let (aes_key, aes_iv) = prepare_aes_encrypt_local(&msg_key, auth_key);
    let ciphertext = aes_ige_encrypt(&plain, &aes_key, &aes_iv)?;

    let mut result = Vec::with_capacity(16 + ciphertext.len());
    result.extend_from_slice(&msg_key);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

// ─── TDF writer ───────────────────────────────────────────────────────────────

fn write_tdf(path: &Path, version: u32, data: &[u8]) -> Result<()> {
    let mut h = Md5::new();
    h.update(data);
    h.update(&(data.len() as u32).to_le_bytes());
    h.update(&version.to_le_bytes());
    h.update(TDF_MAGIC);
    let md5 = h.finalize();

    let mut bytes = Vec::with_capacity(4 + 4 + data.len() + 16);
    bytes.extend_from_slice(TDF_MAGIC);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&md5);

    std::fs::write(path, &bytes)
        .map_err(|e| anyhow!("write_tdf {}: {}", path.display(), e))
}

// ─── MTP block builder ────────────────────────────────────────────────────────

fn build_mtp_block(user_id: i64, dc_id: i32, auth_key: &[u8; 256]) -> Vec<u8> {
    // serialized QDataStream (wide IDs format)
    let mut ser = Vec::new();
    write_i32_be(&mut ser, -1i32);               // kWideIdsTag high word
    write_i32_be(&mut ser, -1i32);               // kWideIdsTag low word
    write_u64_be(&mut ser, user_id as u64);      // user_id (64-bit)
    write_i32_be(&mut ser, dc_id);               // main_dc_id
    write_i32_be(&mut ser, 1);                   // key_count = 1
    write_i32_be(&mut ser, dc_id);               // dc_id of this key
    ser.extend_from_slice(auth_key);             // 256 raw bytes

    // outer block: blockId(75) + QByteArray(serialized)
    let mut block = Vec::new();
    write_i32_be(&mut block, LSK_MTP_AUTHORIZATION);
    write_qbytearray(&mut block, &ser);
    block
}

// ─── Export / Import ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct ExportedAccount {
    /// Position in the tdata account list (0-based)
    pub index: usize,
    /// Telegram user ID
    pub user_id: i64,
    /// Home datacenter (1..5)
    pub dc_id: i32,
    /// 256-byte MTProto auth key, hex-encoded (512 hex characters)
    pub auth_key: String,
}

pub fn accounts_to_export(accounts: &[AccountInfo]) -> Vec<ExportedAccount> {
    accounts.iter().map(|a| ExportedAccount {
        index:    a.index,
        user_id:  a.user_id,
        dc_id:    a.dc_id,
        auth_key: hex::encode(a.auth_key.as_ref()),
    }).collect()
}

/// Create a fresh tdata directory from exported accounts.
/// The target directory must not be an existing TG Desktop installation,
/// or the caller should confirm overwrite before calling this.
pub fn create_tdata(tdata_path: &Path, accounts: &[ExportedAccount]) -> Result<()> {
    if accounts.is_empty() {
        bail!("No accounts to import");
    }

    std::fs::create_dir_all(tdata_path)
        .map_err(|e| anyhow!("Cannot create {}: {}", tdata_path.display(), e))?;

    // Sort by original index, then re-number from 0
    let mut sorted = accounts.to_vec();
    sorted.sort_by_key(|a| a.index);
    for (i, acc) in sorted.iter_mut().enumerate() {
        acc.index = i;
    }

    // Random salt + localKey
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut local_key = [0u8; 256];
    rand::thread_rng().fill_bytes(&mut local_key);
    let passcode_key = create_local_key(&salt, b"");

    // Write per-account MTP data files
    for acc in &sorted {
        let key_bytes = hex::decode(&acc.auth_key)
            .map_err(|e| anyhow!("Invalid hex auth_key at index {}: {}", acc.index, e))?;
        if key_bytes.len() != 256 {
            bail!("auth_key at index {} must be 256 bytes, got {}", acc.index, key_bytes.len());
        }
        let mut auth_key = [0u8; 256];
        auth_key.copy_from_slice(&key_bytes);

        let mtp_block = build_mtp_block(acc.user_id, acc.dc_id, &auth_key);
        let encrypted  = encrypt_local(&mtp_block, &local_key)?;

        // TDF data = QByteArray(encrypted_mtp)
        let mut tdf_data = Vec::new();
        write_qbytearray(&mut tdf_data, &encrypted);

        let file_part = to_file_part(compute_data_name_key(&compose_data_string(acc.index)));
        write_tdf(&tdata_path.join(format!("{}s", file_part)), 1, &tdf_data)?;
    }

    // infoEncrypted: i32(count) + i32(index) × count
    let mut info_data = Vec::new();
    write_i32_be(&mut info_data, sorted.len() as i32);
    for acc in &sorted {
        write_i32_be(&mut info_data, acc.index as i32);
    }
    let info_enc = encrypt_local(&info_data, &local_key)?;

    // keyEncrypted: payload = raw 256-byte localKey
    let key_enc = encrypt_local(&local_key, &passcode_key)?;

    // key_datas TDF: QByteArray(salt) + QByteArray(keyEncrypted) + QByteArray(infoEncrypted)
    let mut kd_data = Vec::new();
    write_qbytearray(&mut kd_data, &salt);
    write_qbytearray(&mut kd_data, &key_enc);
    write_qbytearray(&mut kd_data, &info_enc);
    write_tdf(&tdata_path.join("key_datas"), 1, &kd_data)?;

    Ok(())
}
