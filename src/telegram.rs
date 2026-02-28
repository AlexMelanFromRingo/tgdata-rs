/// Telegram API operations using grammers-client.
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use grammers_client::Client;
use grammers_client::media::{Document, Media};
use grammers_client::peer::Peer;
use grammers_crypto::two_factor_auth::calculate_2fa;
use grammers_mtsender::{InvocationError, SenderPool};
use grammers_session::{
    SessionData,
    storages::MemorySession,
    types::{DcOption, PeerKind, PeerRef},
};
use grammers_tl_types as tl;
use num_bigint::BigUint;
use rand::RngCore;
use sha2::{Digest as _, Sha256};
use tokio_socks::tcp::Socks5Stream;

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

// ─── Session building ─────────────────────────────────────────────────────────

fn make_session_data(info: &AccountInfo) -> SessionData {
    let mut data = SessionData::default();
    data.home_dc = info.dc_id;

    if let Some(dc_opt) = data.dc_options.get_mut(&info.dc_id) {
        dc_opt.auth_key = Some(*info.auth_key);
    } else {
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
    data
}

pub fn dc_ip(dc_id: i32) -> String {
    DC_IPS
        .iter()
        .find(|&&(id, _)| id == dc_id)
        .map(|&(_, o)| format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
        .unwrap_or_else(|| "unknown".to_string())
}

// ─── Proxy support ────────────────────────────────────────────────────────────

pub struct ProxyConfig {
    pub addr: String, // "host:port"
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Parse a SOCKS5 proxy URL: "socks5://user:pass@host:port" or "socks5://host:port"
pub fn parse_proxy_url(url: &str) -> Result<ProxyConfig> {
    let s = url
        .trim()
        .trim_start_matches("socks5://")
        .trim_start_matches("socks4://");

    if let Some(at) = s.rfind('@') {
        let creds = &s[..at];
        let addr = s[at + 1..].to_string();
        if let Some(colon) = creds.find(':') {
            return Ok(ProxyConfig {
                addr,
                username: Some(creds[..colon].to_string()),
                password: Some(creds[colon + 1..].to_string()),
            });
        }
        return Ok(ProxyConfig {
            addr,
            username: Some(creds.to_string()),
            password: None,
        });
    }
    Ok(ProxyConfig {
        addr: s.to_string(),
        username: None,
        password: None,
    })
}

/// Start a SOCKS5 relay for one DC target. Returns (local_port, relay_task).
async fn start_dc_relay(
    proxy: &ProxyConfig,
    target: String,
) -> Result<(u16, tokio::task::JoinHandle<()>)> {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    let proxy_addr = proxy.addr.clone();
    let username = proxy.username.clone();
    let password = proxy.password.clone();

    let task = tokio::spawn(async move {
        loop {
            let (mut local_conn, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let proxy_addr = proxy_addr.clone();
            let target = target.clone();
            let username = username.clone();
            let password = password.clone();
            tokio::spawn(async move {
                let stream = if let (Some(u), Some(p)) = (&username, &password) {
                    Socks5Stream::connect_with_password(
                        proxy_addr.as_str(),
                        target.as_str(),
                        u.as_str(),
                        p.as_str(),
                    )
                    .await
                } else {
                    Socks5Stream::connect(proxy_addr.as_str(), target.as_str()).await
                };
                let mut remote = match stream {
                    Ok(s) => s,
                    Err(_) => return,
                };
                tokio::io::copy_bidirectional(&mut local_conn, &mut remote)
                    .await
                    .ok();
            });
        }
    });

    Ok((local_port, task))
}

// ─── Connect / disconnect ─────────────────────────────────────────────────────

/// Returns (client, pool_task, relay_tasks).
pub async fn connect(
    info: &AccountInfo,
    proxy: Option<&ProxyConfig>,
) -> Result<(
    Client,
    tokio::task::JoinHandle<()>,
    Vec<tokio::task::JoinHandle<()>>,
)> {
    let mut data = make_session_data(info);
    let mut relay_tasks = Vec::new();

    if let Some(prx) = proxy {
        if let Some(&(_, octets)) = DC_IPS.iter().find(|&&(id, _)| id == info.dc_id) {
            let target = format!(
                "{}.{}.{}.{}:443",
                octets[0], octets[1], octets[2], octets[3]
            );
            if let Ok((port, task)) = start_dc_relay(prx, target).await {
                if let Some(dc_opt) = data.dc_options.get_mut(&info.dc_id) {
                    dc_opt.ipv4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port);
                }
                relay_tasks.push(task);
            }
        }
    }

    let session = Arc::new(MemorySession::from(data));
    let SenderPool { runner, handle, .. } = SenderPool::new(Arc::clone(&session), API_ID);
    let client = Client::new(handle);
    let task = tokio::spawn(async move { runner.run().await });
    Ok((client, task, relay_tasks))
}

pub fn disconnect(
    client: Client,
    task: tokio::task::JoinHandle<()>,
    relay_tasks: Vec<tokio::task::JoinHandle<()>>,
) {
    client.disconnect();
    drop(client);
    task.abort();
    for t in relay_tasks {
        t.abort();
    }
}

// ─── Spam check / sessions ────────────────────────────────────────────────────

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

/// Returns (total_sessions, other_sessions_count).
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

/// Terminates all non-current sessions. Returns descriptions of terminated ones.
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
                Ok(_) => terminated.push(format!(
                    "{} {} ({}, {})",
                    a.device_model, a.app_name, a.platform, a.country
                )),
                Err(e) => terminated.push(format!("[ошибка: {}]", e)),
            }
        }
    }
    Ok(terminated)
}

// ─── 2FA ──────────────────────────────────────────────────────────────────────

/// Set a cloud 2FA password. Returns Ok(true) if set, Ok(false) if already set.
pub async fn set_cloud_password(client: &Client, password: &str) -> Result<bool> {
    let pwd_info = client
        .invoke(&tl::functions::account::GetPassword {})
        .await
        .map_err(|e| anyhow!("GetPassword failed: {}", e))?;
    let pwd = match pwd_info {
        tl::enums::account::Password::Password(ref p) => p,
    };
    if pwd.has_password {
        return Ok(false);
    }

    let new_algo = match &pwd.new_algo {
        tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(a) => {
            a.clone()
        }
        tl::enums::PasswordKdfAlgo::Unknown => return Err(anyhow!("Unsupported new_algo")),
    };

    let mut client_salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_salt);
    let salt1 = [new_algo.salt1.as_slice(), client_salt.as_slice()].concat();
    let salt2 = new_algo.salt2.clone();

    let x = ph2(password.as_bytes(), &salt1, &salt2);
    let g_val = BigUint::from(new_algo.g as u32);
    let p_val = BigUint::from_bytes_be(&new_algo.p);
    let x_val = BigUint::from_bytes_be(&x);
    let verifier = g_val.modpow(&x_val, &p_val);
    let new_password_hash = pad_to_256(&verifier.to_bytes_be());

    let algo_with_salts =
        tl::types::PasswordKdfAlgoSha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow {
            salt1: salt1.clone(),
            salt2: salt2.clone(),
            g: new_algo.g,
            p: new_algo.p.clone(),
        };
    let new_settings = tl::types::account::PasswordInputSettings {
        new_algo: Some(
            tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(
                algo_with_salts,
            ),
        ),
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

/// Remove the existing cloud 2FA password. Returns Ok(false) if none was set.
pub async fn remove_cloud_password(client: &Client, password: &str) -> Result<bool> {
    let pwd_info = client
        .invoke(&tl::functions::account::GetPassword {})
        .await
        .map_err(|e| anyhow!("GetPassword failed: {}", e))?;
    let pwd = match pwd_info {
        tl::enums::account::Password::Password(ref p) => p,
    };
    if !pwd.has_password {
        return Ok(false);
    }

    let current_algo = match &pwd.current_algo {
        Some(tl::enums::PasswordKdfAlgo::Sha256Sha256Pbkdf2Hmacsha512iter100000Sha256ModPow(a)) => {
            a.clone()
        }
        _ => return Err(anyhow!("Unsupported or missing current_algo")),
    };
    let srp_b = pwd.srp_b.clone().ok_or_else(|| anyhow!("No srp_B"))?;
    let srp_id = pwd.srp_id.ok_or_else(|| anyhow!("No srp_id"))?;

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
    let new_settings = tl::types::account::PasswordInputSettings {
        new_algo: Some(pwd.new_algo.clone()),
        new_password_hash: Some(vec![]),
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

// ─── SRP helpers ──────────────────────────────────────────────────────────────

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
    pub input: String,
    pub title: String,
    pub kind: &'static str,
    pub members: i32,
    pub error: Option<String>,
}

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
        .invoke(&tl::functions::contacts::ResolveUsername {
            username,
            referer: None,
        })
        .await;

    let r = match resolved {
        Ok(tl::enums::contacts::ResolvedPeer::Peer(r)) => r,
        Err(e) => {
            return GroupInfo {
                input: raw.to_string(),
                title: String::new(),
                kind: "?",
                members: 0,
                error: Some(rpc_name(&e)),
            };
        }
    };

    for chat in &r.chats {
        match chat {
            tl::enums::Chat::Channel(ch) => {
                let kind = if ch.megagroup {
                    "супергруппа"
                } else {
                    "канал"
                };
                let members = match ch.participants_count {
                    Some(n) if n > 0 => n,
                    _ => {
                        let input = tl::enums::InputChannel::Channel(tl::types::InputChannel {
                            channel_id: ch.id,
                            access_hash: ch.access_hash.unwrap_or(0),
                        });
                        match client
                            .invoke(&tl::functions::channels::GetFullChannel { channel: input })
                            .await
                        {
                            Ok(tl::enums::messages::ChatFull::Full(f)) => match f.full_chat {
                                tl::enums::ChatFull::ChannelFull(cf) => {
                                    cf.participants_count.unwrap_or(0)
                                }
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
        input: raw.to_string(),
        title: String::new(),
        kind: "?",
        members: 0,
        error: Some("не удалось получить информацию".to_string()),
    }
}

// ─── Group parser ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberInfo {
    pub user_id: i64,
    pub access_hash: i64,
    pub username: Option<String>,
    pub first_name: String,
    pub last_name: Option<String>,
    pub phone: Option<String>,
    pub is_bot: bool,
    pub is_premium: bool,
}

/// Parse all members of a supergroup/channel.
pub async fn parse_group_members(client: &Client, group: &str) -> Result<(Vec<MemberInfo>, i32)> {
    let username = normalize_username(group);
    let resolved = client
        .invoke(&tl::functions::contacts::ResolveUsername {
            username,
            referer: None,
        })
        .await
        .map_err(|e| anyhow!("ResolveUsername: {}", rpc_name(&e)))?;
    let r = match resolved {
        tl::enums::contacts::ResolvedPeer::Peer(r) => r,
    };
    let input_channel = peer_to_input_channel(&r.peer, &r.chats)?;

    let mut members: HashMap<i64, MemberInfo> = HashMap::new();
    let mut offset = 0i32;
    let mut total = 0i32;

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

    Ok((members.into_values().collect(), total))
}

// ─── Level 1: Basic operations ────────────────────────────────────────────────

/// Join a group/channel. Accepts @username, t.me/username, or t.me/+HASH invite links.
pub async fn join_group(client: &Client, group: &str) -> Result<String> {
    let trimmed = group
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("t.me/");

    // Invite links: +HASH or joinchat/HASH
    if let Some(hash) = trimmed.strip_prefix('+') {
        client
            .invoke(&tl::functions::messages::ImportChatInvite {
                hash: hash.to_string(),
            })
            .await
            .map_err(|e| anyhow!("ImportChatInvite: {}", rpc_name(&e)))?;
        return Ok(format!("вступил по invite ссылке"));
    }
    if let Some(rest) = trimmed.strip_prefix("joinchat/") {
        client
            .invoke(&tl::functions::messages::ImportChatInvite {
                hash: rest.to_string(),
            })
            .await
            .map_err(|e| anyhow!("ImportChatInvite: {}", rpc_name(&e)))?;
        return Ok(format!("вступил по joinchat ссылке"));
    }

    let username = trimmed.trim_start_matches('@');
    let input_channel = resolve_to_input_channel(client, username).await?;
    client
        .invoke(&tl::functions::channels::JoinChannel {
            channel: input_channel,
        })
        .await
        .map_err(|e| anyhow!("JoinChannel: {}", rpc_name(&e)))?;
    Ok(format!("вступил в @{}", username))
}

/// Leave a group/channel by username.
pub async fn leave_group(client: &Client, group: &str) -> Result<String> {
    let username = normalize_username(group);
    let input_channel = resolve_to_input_channel(client, &username).await?;
    client
        .invoke(&tl::functions::channels::LeaveChannel {
            channel: input_channel,
        })
        .await
        .map_err(|e| anyhow!("LeaveChannel: {}", rpc_name(&e)))?;
    Ok(format!("вышел из @{}", username))
}

/// Check if a username is available (not taken). Returns true if available.
pub async fn check_username_available(client: &Client, username: &str) -> Result<bool> {
    let un = username.trim().trim_start_matches('@').to_string();
    client
        .invoke(&tl::functions::account::CheckUsername { username: un })
        .await
        .map_err(|e| anyhow!("CheckUsername: {}", rpc_name(&e)))
}

/// Update profile fields. Pass None to leave a field unchanged.
pub async fn update_profile(
    client: &Client,
    first_name: Option<&str>,
    last_name: Option<&str>,
    about: Option<&str>,
) -> Result<()> {
    client
        .invoke(&tl::functions::account::UpdateProfile {
            first_name: first_name.map(String::from),
            last_name: last_name.map(String::from),
            about: about.map(String::from),
        })
        .await
        .map_err(|e| anyhow!("UpdateProfile: {}", rpc_name(&e)))?;
    Ok(())
}

// ─── Level 2: Warming / activity ─────────────────────────────────────────────

/// Send a "." to Saved Messages to keep the session alive.
pub async fn ping_saved_messages(client: &Client) -> Result<()> {
    client
        .invoke(&tl::functions::messages::SendMessage {
            no_webpage: false,
            silent: true,
            background: false,
            clear_draft: false,
            noforwards: false,
            update_stickersets_order: false,
            invert_media: false,
            allow_paid_floodskip: false,
            peer: tl::enums::InputPeer::PeerSelf,
            reply_to: None,
            message: ".".to_string(),
            random_id: rand::random::<i64>(),
            reply_markup: None,
            entities: None,
            schedule_date: None,
            schedule_repeat_period: None,
            send_as: None,
            quick_reply_shortcut: None,
            effect: None,
            allow_paid_stars: None,
            suggested_post: None,
        })
        .await
        .map_err(|e| anyhow!("SendMessage: {}", rpc_name(&e)))?;
    Ok(())
}

/// View stories for each user. Returns (display_name, viewed_count) pairs.
pub async fn view_stories(client: &Client, users: &[String]) -> Result<Vec<(String, usize)>> {
    let mut results = Vec::new();
    for raw in users {
        let username = raw.trim().trim_start_matches('@');
        match view_user_stories(client, username).await {
            Ok(n) => results.push((username.to_string(), n)),
            Err(e) => results.push((format!("{} [{}]", username, e), 0)),
        }
    }
    Ok(results)
}

async fn view_user_stories(client: &Client, username: &str) -> Result<usize> {
    let peer = resolve_to_input_peer(client, username).await?;

    let res = client
        .invoke(&tl::functions::stories::GetPeerStories { peer: peer.clone() })
        .await
        .map_err(|e| anyhow!("GetPeerStories: {}", rpc_name(&e)))?;

    let inner = match res {
        tl::enums::stories::PeerStories::Stories(s) => s,
    };
    let ps = match inner.stories {
        tl::enums::PeerStories::Stories(p) => p,
    };

    let ids: Vec<i32> = ps
        .stories
        .iter()
        .filter_map(|s| match s {
            tl::enums::StoryItem::Item(item) => Some(item.id),
            _ => None,
        })
        .collect();

    if ids.is_empty() {
        return Ok(0);
    }

    client
        .invoke(&tl::functions::stories::IncrementStoryViews {
            peer,
            id: ids.clone(),
        })
        .await
        .map_err(|e| anyhow!("IncrementStoryViews: {}", rpc_name(&e)))?;

    Ok(ids.len())
}

/// React to a message. Link format: "t.me/username/123" or "t.me/c/CHANNEL_ID/123".
pub async fn react_to_message(client: &Client, link: &str, emoji: &str) -> Result<()> {
    let (peer, msg_id) = parse_link_to_peer(client, link).await?;
    client
        .invoke(&tl::functions::messages::SendReaction {
            big: false,
            add_to_recent: true,
            peer,
            msg_id,
            reaction: Some(vec![tl::enums::Reaction::Emoji(tl::types::ReactionEmoji {
                emoticon: emoji.to_string(),
            })]),
        })
        .await
        .map_err(|e| anyhow!("SendReaction: {}", rpc_name(&e)))?;
    Ok(())
}

// ─── Level 3: Advanced ────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageInfo {
    pub msg_id: i32,
    pub date: i32,
    pub from_id: Option<i64>,
    pub text: String,
    pub reply_to_id: Option<i32>,
    pub views: Option<i32>,
    pub forwards: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct JoinedChannelInfo {
    pub index: usize, // 1-based index for --dump-channel joined:N
    pub title: String,
    pub username: Option<String>,
    pub kind: &'static str,
    pub peer_ref: PeerRef,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DumpMessageInfo {
    pub msg_id: i32,
    pub date: i64,
    pub from_id: Option<i64>,
    pub text: String,
    pub reply_to_id: Option<i32>,
    pub views: Option<i32>,
    pub forwards: Option<i32>,
    pub media_kind: Option<String>,
    pub media_file: Option<String>, // relative path like "media/msg_123_photo.jpg"
}

#[derive(Debug, Clone)]
pub struct ChannelDumpResult {
    pub source_label: String,
    pub messages: Vec<DumpMessageInfo>,
    pub media_saved: usize,
    pub media_failed: usize,
    pub media_detected: usize,
}

/// List channels and supergroups available in dialogs of the current account.
pub async fn list_joined_channels(client: &Client) -> Result<Vec<JoinedChannelInfo>> {
    let mut dialogs = client.iter_dialogs();
    let mut out = Vec::new();

    while let Some(dialog) = dialogs
        .next()
        .await
        .map_err(|e| anyhow!("iter_dialogs: {}", rpc_name(&e)))?
    {
        let peer = dialog.peer();
        match peer {
            Peer::Channel(ch) => {
                if let Some(peer_ref) = peer.to_ref().await {
                    out.push(JoinedChannelInfo {
                        index: 0,
                        title: ch.title().to_string(),
                        username: ch.username().map(str::to_string),
                        kind: "канал",
                        peer_ref,
                    });
                }
            }
            Peer::Group(g) if g.is_megagroup() => {
                if let Some(peer_ref) = peer.to_ref().await {
                    out.push(JoinedChannelInfo {
                        index: 0,
                        title: g.title().unwrap_or_default().to_string(),
                        username: g.username().map(str::to_string),
                        kind: "супергруппа",
                        peer_ref,
                    });
                }
            }
            _ => {}
        }
    }

    out.sort_by(|a, b| {
        let by_title = a.title.to_lowercase().cmp(&b.title.to_lowercase());
        if by_title.is_eq() {
            a.username.cmp(&b.username)
        } else {
            by_title
        }
    });

    for (i, ch) in out.iter_mut().enumerate() {
        ch.index = i + 1;
    }

    Ok(out)
}

/// Dump messages and downloadable media from a channel/supergroup.
///
/// `source` supports:
/// - `@username`
/// - `t.me/username`
/// - invite links (`t.me/+HASH`, `t.me/joinchat/HASH`)
/// - `joined:N` from `list_joined_channels`.
/// `limit = 0` means no limit.
pub async fn dump_channel_content(
    client: &Client,
    source: &str,
    dump_dir: &Path,
    limit: usize,
) -> Result<ChannelDumpResult> {
    let (peer_ref, source_label) = resolve_dump_source(client, source).await?;

    std::fs::create_dir_all(dump_dir)
        .map_err(|e| anyhow!("create_dir_all({}): {}", dump_dir.display(), e))?;
    let media_dir = dump_dir.join("media");
    std::fs::create_dir_all(&media_dir)
        .map_err(|e| anyhow!("create_dir_all({}): {}", media_dir.display(), e))?;

    let mut iter = if limit == 0 {
        client.iter_messages(peer_ref)
    } else {
        client.iter_messages(peer_ref).limit(limit)
    };

    let mut messages = Vec::new();
    let mut media_saved = 0usize;
    let mut media_failed = 0usize;
    let mut media_detected = 0usize;

    while let Some(msg) = iter
        .next()
        .await
        .map_err(|e| anyhow!("iter_messages: {}", rpc_name(&e)))?
    {
        let mut media_kind_value: Option<String> = None;
        let mut media_file: Option<String> = None;

        if let Some(media) = msg.media() {
            let kind = media_kind(&media).to_string();
            media_kind_value = Some(kind.clone());
            media_detected += 1;

            if media_is_downloadable(&media) {
                let ext = media_extension(&media, &kind);
                let filename = format!("msg_{:010}_{}{}", msg.id(), kind, ext);
                let full_path = media_dir.join(&filename);
                match client.download_media(&media, &full_path).await {
                    Ok(()) => {
                        media_saved += 1;
                        media_file = Some(format!("media/{}", filename));
                    }
                    Err(_) => {
                        media_failed += 1;
                    }
                }
            }
        }

        let from_id = msg.sender_id().and_then(|id| match id.kind() {
            PeerKind::UserSelf => None,
            _ => Some(id.bare_id()),
        });

        messages.push(DumpMessageInfo {
            msg_id: msg.id(),
            date: msg.date().timestamp(),
            from_id,
            text: msg.text().to_string(),
            reply_to_id: msg.reply_to_message_id(),
            views: msg.view_count(),
            forwards: msg.forward_count(),
            media_kind: media_kind_value,
            media_file,
        });
    }

    Ok(ChannelDumpResult {
        source_label,
        messages,
        media_saved,
        media_failed,
        media_detected,
    })
}

async fn resolve_dump_source(client: &Client, source: &str) -> Result<(PeerRef, String)> {
    let source = source.trim();
    if let Some(idx_raw) = source.strip_prefix("joined:") {
        let idx: usize = idx_raw
            .parse()
            .map_err(|_| anyhow!("Некорректный формат joined:N (пример: joined:3)"))?;
        let joined = list_joined_channels(client).await?;
        if joined.is_empty() {
            return Err(anyhow!("Список joined-каналов пуст"));
        }
        let picked = joined
            .iter()
            .find(|c| c.index == idx)
            .ok_or_else(|| anyhow!("joined:{} вне диапазона 1..{}", idx, joined.len()))?;
        let label = if let Some(un) = &picked.username {
            format!("{} (@{})", picked.title, un)
        } else {
            picked.title.clone()
        };
        return Ok((picked.peer_ref, label));
    }

    if let Some(hash) = invite_hash_from_source(source) {
        return resolve_dump_source_invite(client, &hash).await;
    }

    let username = username_from_source(source);
    if username.is_empty() {
        return Err(anyhow!(
            "Не удалось извлечь username из источника: {}",
            source
        ));
    }

    let peer = client
        .resolve_username(&username)
        .await
        .map_err(|e| anyhow!("ResolveUsername: {}", rpc_name(&e)))?
        .ok_or_else(|| anyhow!("Username не найден: {}", username))?;

    let peer_ref = peer
        .to_ref()
        .await
        .ok_or_else(|| anyhow!("Не удалось получить peer_ref для {}", username))?;

    Ok((peer_ref, peer_label(&peer)))
}

async fn resolve_dump_source_invite(client: &Client, hash: &str) -> Result<(PeerRef, String)> {
    let checked = client
        .invoke(&tl::functions::messages::CheckChatInvite {
            hash: hash.to_string(),
        })
        .await
        .map_err(|e| anyhow!("CheckChatInvite: {}", rpc_name(&e)))?;

    match checked {
        tl::enums::ChatInvite::Already(already) => peer_ref_from_chat(client, already.chat).await,
        tl::enums::ChatInvite::Invite(_) | tl::enums::ChatInvite::Peek(_) => {
            if let Err(e) = client
                .invoke(&tl::functions::messages::ImportChatInvite {
                    hash: hash.to_string(),
                })
                .await
            {
                if rpc_name(&e) != "USER_ALREADY_PARTICIPANT" {
                    return Err(anyhow!("ImportChatInvite: {}", rpc_name(&e)));
                }
            }

            let checked_again = client
                .invoke(&tl::functions::messages::CheckChatInvite {
                    hash: hash.to_string(),
                })
                .await
                .map_err(|e| anyhow!("CheckChatInvite(after import): {}", rpc_name(&e)))?;

            match checked_again {
                tl::enums::ChatInvite::Already(already) => {
                    peer_ref_from_chat(client, already.chat).await
                }
                tl::enums::ChatInvite::Invite(_) | tl::enums::ChatInvite::Peek(_) => Err(anyhow!(
                    "Invite принят, но канал не появился в доступных диалогах"
                )),
            }
        }
    }
}

async fn peer_ref_from_chat(client: &Client, chat: tl::enums::Chat) -> Result<(PeerRef, String)> {
    let peer = Peer::from_raw(client, chat);
    let label = peer_label(&peer);
    let peer_ref = peer
        .to_ref()
        .await
        .ok_or_else(|| anyhow!("Не удалось получить peer_ref после invite"))?;
    Ok((peer_ref, label))
}

fn peer_label(peer: &Peer) -> String {
    let name = peer.name().unwrap_or("без названия");
    let username = peer
        .username()
        .map(|u| format!(" (@{})", u))
        .unwrap_or_default();
    format!("{}{}", name, username)
}

fn invite_hash_from_source(raw: &str) -> Option<String> {
    let s = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("t.me/");

    if let Some(hash) = s.strip_prefix('+') {
        let clean = hash.split('?').next().unwrap_or_default();
        if !clean.is_empty() {
            return Some(clean.to_string());
        }
    }
    if let Some(rest) = s.strip_prefix("joinchat/") {
        let clean = rest
            .split('/')
            .next()
            .unwrap_or_default()
            .split('?')
            .next()
            .unwrap_or_default();
        if !clean.is_empty() {
            return Some(clean.to_string());
        }
    }
    None
}

fn username_from_source(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("t.me/")
        .trim_start_matches("s/")
        .trim_start_matches('@');

    trimmed
        .split('/')
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn media_kind(media: &Media) -> &'static str {
    match media {
        Media::Photo(_) => "photo",
        Media::Sticker(_) => "sticker",
        Media::Document(d) => {
            if d.raw.voice {
                "voice"
            } else if d.raw.round {
                "video_note"
            } else if d.raw.video {
                "video"
            } else {
                "document"
            }
        }
        Media::Contact(_) => "contact",
        Media::Poll(_) => "poll",
        Media::Geo(_) => "geo",
        Media::Dice(_) => "dice",
        Media::Venue(_) => "venue",
        Media::GeoLive(_) => "geo_live",
        Media::WebPage(_) => "web_page",
        _ => "media",
    }
}

fn media_is_downloadable(media: &Media) -> bool {
    matches!(
        media,
        Media::Photo(_) | Media::Document(_) | Media::Sticker(_)
    )
}

fn media_extension(media: &Media, kind: &str) -> String {
    match media {
        Media::Photo(_) => ".jpg".to_string(),
        Media::Document(doc) => document_extension(doc, kind),
        Media::Sticker(sticker) => document_extension(&sticker.document, "sticker"),
        _ => String::new(),
    }
}

fn document_extension(doc: &Document, kind: &str) -> String {
    if let Some(name) = doc.name() {
        if let Some(ext) = extension_from_file_name(name) {
            return ext;
        }
    }
    if let Some(ext) = extension_from_mime(doc.mime_type()) {
        return ext;
    }
    match kind {
        "voice" => ".ogg".to_string(),
        "video" | "video_note" => ".mp4".to_string(),
        "sticker" => ".webp".to_string(),
        "photo" => ".jpg".to_string(),
        _ => ".bin".to_string(),
    }
}

fn extension_from_file_name(name: &str) -> Option<String> {
    let ext = Path::new(name).extension()?.to_str()?.trim();
    if ext.is_empty() {
        return None;
    }
    let clean: String = ext.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if clean.is_empty() {
        None
    } else {
        Some(format!(".{}", clean.to_lowercase()))
    }
}

fn extension_from_mime(mime_type: Option<&str>) -> Option<String> {
    let mime = mime_type?.split(';').next()?.trim();
    let subtype = mime.split('/').nth(1)?;
    let mut clean = subtype.split('+').next().unwrap_or(subtype).to_lowercase();
    if clean == "jpeg" {
        clean = "jpg".to_string();
    }
    if clean == "quicktime" {
        clean = "mov".to_string();
    }
    if clean == "plain" {
        clean = "txt".to_string();
    }
    if clean.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(format!(".{}", clean))
    } else {
        None
    }
}

/// Fetch messages from a group/channel. Up to `limit` messages (newest first).
pub async fn parse_messages(client: &Client, group: &str, limit: i32) -> Result<Vec<MessageInfo>> {
    let username = normalize_username(group);
    let peer = resolve_to_input_peer(client, &username).await?;

    let mut messages: Vec<MessageInfo> = Vec::new();
    let mut offset_id = 0i32;

    loop {
        let batch_limit = 100.min(limit - messages.len() as i32).max(1);

        let res = client
            .invoke(&tl::functions::messages::GetHistory {
                peer: peer.clone(),
                offset_id,
                offset_date: 0,
                add_offset: 0,
                limit: batch_limit,
                max_id: 0,
                min_id: 0,
                hash: 0,
            })
            .await
            .map_err(|e| anyhow!("GetHistory: {}", rpc_name(&e)))?;

        let raw_msgs = extract_messages_from_result(res);
        if raw_msgs.is_empty() {
            break;
        }

        if let Some(last) = raw_msgs.last() {
            offset_id = last.msg_id;
        }
        let done = (raw_msgs.len() as i32) < batch_limit;
        messages.extend(raw_msgs);

        if done || messages.len() as i32 >= limit {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    Ok(messages)
}

fn extract_messages_from_result(res: tl::enums::messages::Messages) -> Vec<MessageInfo> {
    let raw = match res {
        tl::enums::messages::Messages::Messages(m) => m.messages,
        tl::enums::messages::Messages::Slice(m) => m.messages,
        tl::enums::messages::Messages::ChannelMessages(m) => m.messages,
        tl::enums::messages::Messages::NotModified(_) => return vec![],
    };
    raw.into_iter()
        .filter_map(|m| match m {
            tl::enums::Message::Message(msg) => Some(MessageInfo {
                msg_id: msg.id,
                date: msg.date,
                from_id: msg.from_id.as_ref().and_then(peer_to_user_id),
                text: msg.message,
                reply_to_id: extract_reply_to_id(msg.reply_to.as_ref()),
                views: msg.views,
                forwards: msg.forwards,
            }),
            _ => None,
        })
        .collect()
}

/// Invite users (as user_id + access_hash pairs) to a channel.
/// Returns (invited_count, failed_count).
pub async fn invite_to_channel(
    client: &Client,
    channel: &str,
    users: &[(i64, i64)],
) -> Result<(usize, usize)> {
    let username = normalize_username(channel);
    let input_channel = resolve_to_input_channel(client, &username).await?;

    let mut invited = 0usize;
    let mut failed = 0usize;

    for chunk in users.chunks(5) {
        let make_users = |chunk: &[(i64, i64)]| -> Vec<tl::enums::InputUser> {
            chunk
                .iter()
                .map(|&(user_id, access_hash)| {
                    tl::enums::InputUser::User(tl::types::InputUser {
                        user_id,
                        access_hash,
                    })
                })
                .collect()
        };

        match client
            .invoke(&tl::functions::channels::InviteToChannel {
                channel: input_channel.clone(),
                users: make_users(chunk),
            })
            .await
        {
            Ok(_) => invited += chunk.len(),
            Err(InvocationError::Rpc(ref e)) if e.name == "FLOOD_WAIT" => {
                let secs = e.value.unwrap_or(60) as u64;
                tokio::time::sleep(tokio::time::Duration::from_secs(secs + 1)).await;
                match client
                    .invoke(&tl::functions::channels::InviteToChannel {
                        channel: input_channel.clone(),
                        users: make_users(chunk),
                    })
                    .await
                {
                    Ok(_) => invited += chunk.len(),
                    Err(_) => failed += chunk.len(),
                }
            }
            Err(_) => failed += chunk.len(),
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok((invited, failed))
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

pub fn normalize_username(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("t.me/")
        .trim_start_matches('@')
        .to_string()
}

pub fn rpc_name(e: &grammers_mtsender::InvocationError) -> String {
    match e {
        InvocationError::Rpc(r) => r.name.clone(),
        other => other.to_string(),
    }
}

/// Resolve a username and return InputChannel.
async fn resolve_to_input_channel(
    client: &Client,
    username: &str,
) -> Result<tl::enums::InputChannel> {
    let resolved = client
        .invoke(&tl::functions::contacts::ResolveUsername {
            username: username.to_string(),
            referer: None,
        })
        .await
        .map_err(|e| anyhow!("ResolveUsername: {}", rpc_name(&e)))?;
    let r = match resolved {
        tl::enums::contacts::ResolvedPeer::Peer(r) => r,
    };
    peer_to_input_channel(&r.peer, &r.chats)
}

/// Resolve a username to InputPeer (user or channel or chat).
async fn resolve_to_input_peer(client: &Client, username: &str) -> Result<tl::enums::InputPeer> {
    let resolved = client
        .invoke(&tl::functions::contacts::ResolveUsername {
            username: username.to_string(),
            referer: None,
        })
        .await
        .map_err(|e| anyhow!("ResolveUsername: {}", rpc_name(&e)))?;
    let r = match resolved {
        tl::enums::contacts::ResolvedPeer::Peer(r) => r,
    };

    match &r.peer {
        tl::enums::Peer::User(pu) => {
            for u in &r.users {
                if let tl::enums::User::User(user) = u {
                    if user.id == pu.user_id {
                        return Ok(tl::enums::InputPeer::User(tl::types::InputPeerUser {
                            user_id: user.id,
                            access_hash: user.access_hash.unwrap_or(0),
                        }));
                    }
                }
            }
            Err(anyhow!("User not found in resolved peers"))
        }
        tl::enums::Peer::Channel(pc) => {
            for chat in &r.chats {
                if let tl::enums::Chat::Channel(ch) = chat {
                    if ch.id == pc.channel_id {
                        return Ok(tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                            channel_id: ch.id,
                            access_hash: ch.access_hash.unwrap_or(0),
                        }));
                    }
                }
            }
            Err(anyhow!("Channel not found in resolved peers"))
        }
        tl::enums::Peer::Chat(pc) => Ok(tl::enums::InputPeer::Chat(tl::types::InputPeerChat {
            chat_id: pc.chat_id,
        })),
    }
}

fn peer_to_input_channel(
    peer: &tl::enums::Peer,
    chats: &[tl::enums::Chat],
) -> Result<tl::enums::InputChannel> {
    let channel_id = match peer {
        tl::enums::Peer::Channel(c) => c.channel_id,
        tl::enums::Peer::Chat(_) => {
            return Err(anyhow!(
                "Обычные группы не поддерживаются (нужна супергруппа/канал)"
            ));
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
        tl::enums::ChannelParticipant::Admin(x) => Some(x.user_id),
        tl::enums::ChannelParticipant::Creator(x) => Some(x.user_id),
        tl::enums::ChannelParticipant::Banned(_) => None,
        tl::enums::ChannelParticipant::Left(_) => None,
    }
}

fn user_to_member(u: &tl::types::User) -> MemberInfo {
    MemberInfo {
        user_id: u.id,
        access_hash: u.access_hash.unwrap_or(0),
        username: u.username.clone(),
        first_name: u.first_name.clone().unwrap_or_default(),
        last_name: u.last_name.clone(),
        phone: u.phone.clone(),
        is_bot: u.bot,
        is_premium: u.premium,
    }
}

fn peer_to_user_id(peer: &tl::enums::Peer) -> Option<i64> {
    match peer {
        tl::enums::Peer::User(u) => Some(u.user_id),
        _ => None,
    }
}

fn extract_reply_to_id(reply: Option<&tl::enums::MessageReplyHeader>) -> Option<i32> {
    if let Some(tl::enums::MessageReplyHeader::Header(h)) = reply {
        h.reply_to_msg_id
    } else {
        None
    }
}

/// Parse a t.me message link into (InputPeer, msg_id).
async fn parse_link_to_peer(client: &Client, link: &str) -> Result<(tl::enums::InputPeer, i32)> {
    let s = link
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("t.me/");

    let parts: Vec<&str> = s.split('/').collect();

    if parts.len() >= 3 && parts[0] == "c" {
        // Private channel: t.me/c/CHANNEL_ID/MSG_ID
        let channel_id: i64 = parts[1]
            .parse()
            .map_err(|_| anyhow!("Invalid channel ID in link: {}", link))?;
        let msg_id: i32 = parts[2]
            .parse()
            .map_err(|_| anyhow!("Invalid message ID in link: {}", link))?;
        return Ok((
            tl::enums::InputPeer::Channel(tl::types::InputPeerChannel {
                channel_id,
                access_hash: 0,
            }),
            msg_id,
        ));
    }

    if parts.len() >= 2 {
        let username = parts[0].trim_start_matches('@');
        let msg_id: i32 = parts[1]
            .parse()
            .map_err(|_| anyhow!("Invalid message ID in link: {}", link))?;
        let peer = resolve_to_input_peer(client, username).await?;
        return Ok((peer, msg_id));
    }

    Err(anyhow!(
        "Не удалось разобрать ссылку на сообщение: {}",
        link
    ))
}
