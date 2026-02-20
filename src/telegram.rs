/// Telegram API operations using grammers-client.
///
/// For each account we:
/// 1. Build an in-memory session with the known auth key and DC.
/// 2. Run SenderPool + Client on a tokio task.
/// 3. Perform operations (spam check, sessions, 2FA).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use grammers_client::Client;
use grammers_mtsender::{InvocationError, SenderPool};
use grammers_session::{
    SessionData,
    storages::MemorySession,
    types::DcOption,
};
use grammers_tl_types as tl;
use grammers_crypto::two_factor_auth::calculate_2fa;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest as _, Sha256};

use crate::tdata::AccountInfo;

// Telegram Desktop API credentials (well-known public values)
const API_ID: i32 = 2040;

// DC addresses (production)
const DC_IPS: [(i32, [u8; 4]); 5] = [
    (1, [149, 154, 175, 53]),
    (2, [149, 154, 167, 41]),
    (3, [149, 154, 175, 100]),
    (4, [149, 154, 167, 92]),
    (5, [91, 108, 56, 104]),
];

fn make_session(info: &AccountInfo) -> MemorySession {
    let mut data = SessionData::default();
    data.home_dc = info.dc_id;

    // Set auth key for the account's home DC
    if let Some(dc_opt) = data.dc_options.get_mut(&info.dc_id) {
        dc_opt.auth_key = Some(*info.auth_key);
    } else {
        // DC not in default list – construct it from our known list
        if let Some(&(_, octets)) = DC_IPS.iter().find(|&&(id, _)| id == info.dc_id) {
            let ipv4 = SocketAddrV4::new(Ipv4Addr::from(octets), 443);
            let ipv6 = SocketAddrV6::new(
                Ipv6Addr::from(Ipv4Addr::from(octets).to_ipv6_compatible()),
                443,
                0,
                0,
            );
            data.dc_options.insert(
                info.dc_id,
                DcOption {
                    id: info.dc_id,
                    ipv4,
                    ipv6,
                    auth_key: Some(*info.auth_key),
                },
            );
        }
    }

    MemorySession::from(data)
}

pub fn dc_ip(dc_id: i32) -> String {
    DC_IPS
        .iter()
        .find(|&&(id, _)| id == dc_id)
        .map(|&(_, o)| format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Returns (client, pool_task_handle)
pub async fn connect(info: &AccountInfo) -> Result<(Client, tokio::task::JoinHandle<()>)> {
    let session = Arc::new(make_session(info));
    let SenderPool { runner, handle, .. } = SenderPool::new(Arc::clone(&session), API_ID);
    let client = Client::new(handle);
    let task = tokio::spawn(async move { runner.run().await });
    Ok((client, task))
}

pub fn disconnect(client: Client, task: tokio::task::JoinHandle<()>) {
    client.disconnect();
    drop(client);
    task.abort();
}

// ─── Telegram operations ──────────────────────────────────────────────────────

/// Spam check via contacts.Search → PEER_FLOOD means spam-blocked.
/// Returns true if the account is spam-blocked.
pub async fn check_spam(client: &Client) -> Result<bool> {
    match client
        .invoke(&tl::functions::contacts::Search {
            q: "telegram".to_string(),
            limit: 1,
        })
        .await
    {
        Ok(_) => Ok(false),
        Err(InvocationError::Rpc(ref e)) if e.is("PEER_FLOOD") => Ok(true),
        Err(e) => Err(anyhow!("contacts.Search failed: {}", e)),
    }
}

/// Returns (total_sessions, other_sessions_count)
pub async fn get_sessions(client: &Client) -> Result<(usize, usize)> {
    let result = client
        .invoke(&tl::functions::account::GetAuthorizations {})
        .await
        .map_err(|e| anyhow!("GetAuthorizations failed: {}", e))?;

    let auths = match result {
        tl::enums::account::Authorizations::Authorizations(a) => a.authorizations,
    };

    let total = auths.len();
    let other = auths
        .iter()
        .filter(|a| match a {
            tl::enums::Authorization::Authorization(x) => !x.current,
        })
        .count();

    Ok((total, other))
}

/// Terminates all non-current sessions.
/// Returns list of descriptions of terminated sessions.
pub async fn terminate_other_sessions(client: &Client) -> Result<Vec<String>> {
    let result = client
        .invoke(&tl::functions::account::GetAuthorizations {})
        .await
        .map_err(|e| anyhow!("GetAuthorizations failed: {}", e))?;

    let auths = match result {
        tl::enums::account::Authorizations::Authorizations(a) => a.authorizations,
    };

    let mut terminated = Vec::new();
    for auth in auths {
        let a = match auth {
            tl::enums::Authorization::Authorization(a) => a,
        };
        if !a.current && a.hash != 0 {
            match client
                .invoke(&tl::functions::account::ResetAuthorization { hash: a.hash })
                .await
            {
                Ok(_) => {
                    let desc = format!(
                        "{} {} ({}, {})",
                        a.device_model, a.app_name, a.platform, a.country
                    );
                    terminated.push(desc);
                }
                Err(e) => {
                    terminated.push(format!("[ошибка: {}]", e));
                }
            }
        }
    }
    Ok(terminated)
}

/// Set a cloud 2FA password if none is currently set.
/// Returns Ok(true) if set, Ok(false) if already has password.
pub async fn set_cloud_password(client: &Client, password: &str) -> Result<bool> {
    let pwd_info = client
        .invoke(&tl::functions::account::GetPassword {})
        .await
        .map_err(|e| anyhow!("GetPassword failed: {}", e))?;

    let pwd = match pwd_info {
        tl::enums::account::Password::Password(ref p) => p,
    };

    if pwd.has_password {
        return Ok(false); // already set
    }

    // Extract the new_algo offered by the server
    let new_algo = match &pwd.new_algo {
        tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(a) => a.clone(),
        tl::enums::PasswordKdfAlgo::Unknown => return Err(anyhow!("Unsupported new_algo from server")),
    };

    // Add 32 bytes of client random to salt1 only (salt2 stays as server sent it).
    // This matches what TDesktop and telethon do.
    let mut client_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_salt);

    let salt1 = [new_algo.salt1.as_slice(), client_salt.as_slice()].concat();
    let salt2 = new_algo.salt2.clone();

    // Compute password verifier: g^PH2(password, salt1, salt2) mod p
    let x = ph2(password.as_bytes(), &salt1, &salt2);
    let g_val = BigUint::from(new_algo.g as u32);
    let p_val = BigUint::from_bytes_be(&new_algo.p);
    let x_val = BigUint::from_bytes_be(&x);
    let verifier = g_val.modpow(&x_val, &p_val);
    let new_password_hash = pad_to_256(&verifier.to_bytes_be());

    let algo_with_salts = tl::types::PasswordKdfAlgoSha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow {
        salt1: salt1.clone(),
        salt2: salt2.clone(),
        g: new_algo.g,
        p: new_algo.p.clone(),
    };

    let new_settings = tl::types::account::PasswordInputSettings {
        new_algo: Some(tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(
            algo_with_salts,
        )),
        new_password_hash: Some(new_password_hash.to_vec()),
        hint: Some(String::new()),
        email: None,
        new_secure_settings: None,
    };

    client
        .invoke(&tl::functions::account::UpdatePasswordSettings {
            password: tl::enums::InputCheckPasswordSrp::InputCheckPasswordEmpty,
            new_settings: tl::enums::account::PasswordInputSettings::Settings(new_settings),
        })
        .await
        .map_err(|e| anyhow!("UpdatePasswordSettings failed: {}", e))?;

    Ok(true)
}

/// Remove the existing cloud 2FA password.
/// Returns Ok(true) if removed, Ok(false) if no password was set.
pub async fn remove_cloud_password(client: &Client, password: &str) -> Result<bool> {
    let pwd_info = client
        .invoke(&tl::functions::account::GetPassword {})
        .await
        .map_err(|e| anyhow!("GetPassword failed: {}", e))?;

    let pwd = match pwd_info {
        tl::enums::account::Password::Password(ref p) => p,
    };

    if !pwd.has_password {
        return Ok(false); // nothing to remove
    }

    // Get current algo and SRP parameters
    let current_algo = match &pwd.current_algo {
        Some(tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(a)) => a.clone(),
        _ => return Err(anyhow!("Unsupported or missing current_algo")),
    };
    let srp_b  = pwd.srp_b.clone().ok_or_else(|| anyhow!("No srp_B in GetPassword response"))?;
    let srp_id = pwd.srp_id.ok_or_else(|| anyhow!("No srp_id in GetPassword response"))?;

    // Random secret 'a' for DH
    let mut a_bytes = vec![0u8; 256];
    rand::thread_rng().fill_bytes(&mut a_bytes);

    let (m1, g_a) = calculate_2fa(
        &current_algo.salt1,
        &current_algo.salt2,
        &current_algo.p,
        &current_algo.g,
        srp_b,
        a_bytes,
        password.as_bytes(),
    );

    let check_password = tl::enums::InputCheckPasswordSrp::Srp(tl::types::InputCheckPasswordSrp {
        srp_id,
        a: g_a.to_vec(),
        m1: m1.to_vec(),
    });

    // To remove: send empty new_password_hash; new_algo and hint must still be present (same flag bit)
    let new_settings = tl::types::account::PasswordInputSettings {
        new_algo: Some(pwd.new_algo.clone()),
        new_password_hash: Some(vec![]),  // empty = remove password
        hint: Some(String::new()),
        email: None,
        new_secure_settings: None,
    };

    client
        .invoke(&tl::functions::account::UpdatePasswordSettings {
            password: check_password,
            new_settings: tl::enums::account::PasswordInputSettings::Settings(new_settings),
        })
        .await
        .map_err(|e| anyhow!("UpdatePasswordSettings (remove) failed: {}", e))?;

    Ok(true)
}

// ─── SRP helper functions ─────────────────────────────────────────────────────
// H(data)         := SHA256(data)
// SH(data, salt)  := H(salt | data | salt)
// PH1(pass, s1, s2) := SH(SH(pass, s1), s2)
// PH2(pass, s1, s2) := SH(PBKDF2-SHA512(PH1, s1, 100000, 64), s2)

fn h_sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

fn sh(data: &[u8], salt: &[u8]) -> [u8; 32] {
    h_sha256(&[salt, data, salt])
}

fn ph1(password: &[u8], salt1: &[u8], salt2: &[u8]) -> [u8; 32] {
    sh(&sh(password, salt1), salt2)
}

fn ph2(password: &[u8], salt1: &[u8], salt2: &[u8]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha512;

    let hash1 = ph1(password, salt1, salt2);
    let mut dk = [0u8; 64];
    pbkdf2_hmac::<Sha512>(&hash1, salt1, 100_000, &mut dk);
    sh(&dk, salt2)
}

fn pad_to_256(data: &[u8]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let start = out.len().saturating_sub(data.len());
    out[start..].copy_from_slice(&data[data.len().saturating_sub(256)..]);
    out
}

// ─── Group check ──────────────────────────────────────────────────────────────

pub struct GroupInfo {
    pub input:   String,
    pub title:   String,
    pub kind:    &'static str, // "канал" | "супергруппа" | "группа"
    pub members: i32,
    pub error:   Option<String>,
}

/// Resolve and describe each group/channel.
/// Never fails: errors are stored in GroupInfo::error.
pub async fn check_groups(client: &Client, groups: &[String]) -> Vec<GroupInfo> {
    let mut out = Vec::with_capacity(groups.len());
    for raw in groups {
        out.push(resolve_group(client, raw).await);
    }
    out
}

async fn resolve_group(client: &Client, raw: &str) -> GroupInfo {
    let username = normalize_username(raw);
    let resolved = client
        .invoke(&tl::functions::contacts::ResolveUsername { username, referer: None })
        .await;

    let r = match resolved {
        Ok(tl::enums::contacts::ResolvedPeer::Peer(r)) => r,
        Err(e) => {
            return GroupInfo {
                input: raw.to_string(), title: String::new(),
                kind: "?", members: 0,
                error: Some(rpc_name(&e)),
            };
        }
    };

    for chat in &r.chats {
        match chat {
            tl::enums::Chat::Channel(ch) => {
                let kind = if ch.megagroup { "супергруппа" } else { "канал" };

                // participants_count is absent in ResolveUsername for most channels —
                // fetch it explicitly via GetFullChannel.
                let members = match ch.participants_count {
                    Some(n) if n > 0 => n,
                    _ => {
                        let input = tl::enums::InputChannel::Channel(tl::types::InputChannel {
                            channel_id:  ch.id,
                            access_hash: ch.access_hash.unwrap_or(0),
                        });
                        match client
                            .invoke(&tl::functions::channels::GetFullChannel { channel: input })
                            .await
                        {
                            Ok(tl::enums::messages::ChatFull::Full(f)) => match f.full_chat {
                                tl::enums::ChatFull::ChannelFull(cf) => cf.participants_count.unwrap_or(0),
                                _ => 0,
                            },
                            Err(_) => 0,
                        }
                    }
                };

                return GroupInfo {
                    input: raw.to_string(),
                    title: ch.title.clone(),
                    kind,
                    members,
                    error: None,
                };
            }
            tl::enums::Chat::Chat(ch) => {
                return GroupInfo {
                    input: raw.to_string(),
                    title: ch.title.clone(),
                    kind: "группа",
                    members: ch.participants_count,
                    error: None,
                };
            }
            _ => {}
        }
    }

    GroupInfo {
        input: raw.to_string(), title: String::new(),
        kind: "?", members: 0,
        error: Some("не удалось получить информацию".to_string()),
    }
}

fn normalize_username(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("t.me/")
        .trim_start_matches('@')
        .to_string()
}

fn rpc_name(e: &grammers_mtsender::InvocationError) -> String {
    match e {
        InvocationError::Rpc(r) => r.name.clone(),
        other => other.to_string(),
    }
}

// ─── Group parser ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberInfo {
    pub user_id:    i64,
    pub username:   Option<String>,
    pub first_name: String,
    pub last_name:  Option<String>,
    pub phone:      Option<String>,
    pub is_bot:     bool,
    pub is_premium: bool,
}

/// Parse all members of a supergroup/channel.
/// Returns (members, total_declared_by_server).
/// Caller should print progress before/after.
pub async fn parse_group_members(
    client: &Client,
    group:  &str,
) -> Result<(Vec<MemberInfo>, i32)> {
    let username = normalize_username(group);

    let resolved = client
        .invoke(&tl::functions::contacts::ResolveUsername { username, referer: None })
        .await
        .map_err(|e| anyhow!("ResolveUsername: {}", rpc_name(&e)))?;

    let r = match resolved {
        tl::enums::contacts::ResolvedPeer::Peer(r) => r,
    };

    let input_channel = peer_to_input_channel(&r.peer, &r.chats)?;

    let mut members: HashMap<i64, MemberInfo> = HashMap::new();
    let mut offset = 0i32;
    let mut total  = 0i32;

    loop {
        let res = client
            .invoke(&tl::functions::channels::GetParticipants {
                channel: input_channel.clone(),
                filter: tl::enums::ChannelParticipantsFilter::ChannelParticipantsRecent,
                offset,
                limit: 200,
                hash: 0,
            })
            .await;

        let batch = match res {
            Ok(tl::enums::channels::ChannelParticipants::Participants(p)) => {
                total = p.count;
                p
            }
            Ok(tl::enums::channels::ChannelParticipants::NotModified) => break,
            Err(InvocationError::Rpc(ref e)) if e.name == "FLOOD_WAIT" => {
                let secs = e.value.unwrap_or(60) as u64;
                tokio::time::sleep(tokio::time::Duration::from_secs(secs + 1)).await;
                continue;
            }
            Err(e) => return Err(anyhow!("GetParticipants: {}", e)),
        };

        if batch.participants.is_empty() {
            break;
        }

        let users_map: HashMap<i64, &tl::types::User> = batch
            .users
            .iter()
            .filter_map(|u| match u {
                tl::enums::User::User(u) => Some((u.id, u)),
                _ => None,
            })
            .collect();

        let batch_len = batch.participants.len() as i32;

        for p in &batch.participants {
            if let Some(uid) = participant_uid(p) {
                if let Some(user) = users_map.get(&uid) {
                    let info = user_to_member(*user);
                    let entry = members.entry(uid).or_insert_with(|| info.clone());
                    // prefer entry with phone number
                    if entry.phone.is_none() && info.phone.is_some() {
                        *entry = info;
                    }
                }
            }
        }

        offset += batch_len;
        if offset >= total {
            break;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(800)).await;
    }

    let list: Vec<MemberInfo> = members.into_values().collect();
    Ok((list, total))
}

fn peer_to_input_channel(
    peer:  &tl::enums::Peer,
    chats: &[tl::enums::Chat],
) -> Result<tl::enums::InputChannel> {
    let channel_id = match peer {
        tl::enums::Peer::Channel(c) => c.channel_id,
        tl::enums::Peer::Chat(_) => {
            // Regular group — GetParticipants not supported; caller should use GetFullChat
            return Err(anyhow!("Обычные группы не поддерживаются для парсинга (нужна супергруппа)"));
        }
        tl::enums::Peer::User(_) => return Err(anyhow!("Это пользователь, а не группа")),
    };

    for chat in chats {
        if let tl::enums::Chat::Channel(ch) = chat {
            if ch.id == channel_id {
                return Ok(tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id,
                    access_hash: ch.access_hash.unwrap_or(0),
                }));
            }
        }
    }

    Err(anyhow!("Канал {} не найден в resolved chats", channel_id))
}

fn participant_uid(p: &tl::enums::ChannelParticipant) -> Option<i64> {
    match p {
        tl::enums::ChannelParticipant::Participant(x) => Some(x.user_id),
        tl::enums::ChannelParticipant::ParticipantSelf(x) => Some(x.user_id),
        tl::enums::ChannelParticipant::Admin(x)       => Some(x.user_id),
        tl::enums::ChannelParticipant::Creator(x)     => Some(x.user_id),
        tl::enums::ChannelParticipant::Banned(_)      => None,
        tl::enums::ChannelParticipant::Left(_)        => None,
    }
}

fn user_to_member(u: &tl::types::User) -> MemberInfo {
    MemberInfo {
        user_id:    u.id,
        username:   u.username.clone(),
        first_name: u.first_name.clone().unwrap_or_default(),
        last_name:  u.last_name.clone(),
        phone:      u.phone.clone(),
        is_bot:     u.bot,
        is_premium: u.premium,
    }
}
