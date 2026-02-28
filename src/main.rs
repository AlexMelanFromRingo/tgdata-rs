mod tdata;
mod telegram;

use anyhow::{Result, anyhow};
use chrono::Local;
use clap::Parser;
use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

// ANSI colours
const GREEN: &str = "\x1b[92m";
const RED: &str = "\x1b[91m";
const GRAY: &str = "\x1b[90m";
const YELLOW: &str = "\x1b[93m";
const RESET: &str = "\x1b[0m";

fn ts() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

/// Telegram Account Manager — tdata (multi-account)
#[derive(Parser, Debug)]
#[command(name = "tgdata-rs", about = "Управление Telegram-аккаунтами из tdata")]
struct Cli {
    /// Путь к папке Telegram Desktop (содержит tdata/)
    #[arg(long, default_value = r"L:\Programs\Telegram Desktop")]
    path: String,

    // ── Existing operations ─────────────────────────────────────────────────
    /// Закрыть все чужие сессии
    #[arg(long, action = clap::ArgAction::SetTrue)]
    terminate_sessions: bool,

    /// Установить облачный пароль 2FA
    #[arg(long, value_name = "PASS")]
    set_password: Option<String>,

    /// Снять облачный пароль 2FA
    #[arg(long, value_name = "CURRENT_PASS")]
    remove_password: Option<String>,

    /// Экспортировать ключи в JSON (без сети)
    #[arg(long, value_name = "FILE")]
    export: Option<String>,

    /// Импортировать ключи из JSON и создать новую tdata
    #[arg(long, value_name = "FILE")]
    import: Option<String>,

    /// Проверить доступность групп/каналов
    #[arg(long, value_name = "GROUP,...", value_delimiter = ',')]
    check_groups: Vec<String>,

    /// Спарсить участников группы (супергруппа)
    #[arg(long, value_name = "GROUP")]
    parse_group: Option<String>,

    // ── Level 1: Basic operations ──────────────────────────────────────────
    /// Вступить в группу/канал (username или t.me/+HASH)
    #[arg(long, value_name = "GROUP_OR_LINK")]
    join_group: Option<String>,

    /// Покинуть группу/канал
    #[arg(long, value_name = "GROUP")]
    leave_group: Option<String>,

    /// Проверить доступность username (свободен ли?)
    #[arg(long, value_name = "USERNAME")]
    check_username: Option<String>,

    /// Установить имя аккаунта. Формат: "Имя" или "Имя|Фамилия"
    #[arg(long, value_name = "FIRST[|LAST]")]
    set_name: Option<String>,

    /// Установить описание (bio) аккаунта
    #[arg(long, value_name = "TEXT")]
    set_bio: Option<String>,

    // ── Level 2: Warming ───────────────────────────────────────────────────
    /// Отправить "." в Избранное (поддержание активности)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    ping: bool,

    /// Просмотреть истории пользователей (через запятую)
    #[arg(long, value_name = "USER,...", value_delimiter = ',')]
    view_stories: Vec<String>,

    /// Поставить реакцию на сообщение по ссылке (t.me/username/123)
    #[arg(long, value_name = "LINK")]
    react: Option<String>,

    /// Эмодзи для реакции (default: 👍)
    #[arg(long, value_name = "EMOJI", default_value = "👍")]
    react_emoji: String,

    // ── Level 3: Advanced ──────────────────────────────────────────────────
    /// SOCKS5 прокси: socks5://[user:pass@]host:port
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Спарсить сообщения группы/канала в CSV
    #[arg(long, value_name = "GROUP")]
    parse_messages: Option<String>,

    /// Лимит сообщений при --parse-messages (default: 1000)
    #[arg(long, value_name = "N", default_value_t = 1000)]
    msg_limit: i32,

    /// Пригласить участников в канал
    #[arg(long, value_name = "GROUP")]
    invite_to: Option<String>,

    /// CSV-файл с user_id и access_hash для --invite-to
    #[arg(long, value_name = "FILE")]
    invite_from: Option<String>,

    /// Показать каналы/супергруппы, где состоит выбранный аккаунт
    #[arg(long, action = clap::ArgAction::SetTrue)]
    list_joined_channels: bool,

    /// Источник канала для полного дампа:
    /// @username | t.me/username | t.me/+HASH | t.me/joinchat/HASH | joined:N
    #[arg(long, value_name = "SOURCE")]
    dump_channel: Option<String>,

    /// Директория для --dump-channel (default: channel_dump)
    #[arg(long, value_name = "DIR", default_value = "channel_dump")]
    dump_dir: String,

    /// Лимит сообщений для --dump-channel (0 = без лимита)
    #[arg(long, value_name = "N", default_value_t = 0)]
    dump_limit: usize,

    /// Конкретный аккаунт для --dump-channel/--list-joined-channels (1-based)
    #[arg(long, value_name = "N")]
    dump_account: Option<usize>,

    // ── Filters / output ────────────────────────────────────────────────────
    /// Файл для CSV-вывода (default: members.csv)
    #[arg(long, value_name = "FILE", default_value = "members.csv")]
    output: String,

    /// Обрабатывать только первые N аккаунтов
    #[arg(long, value_name = "N")]
    accounts: Option<usize>,

    /// Только указанные аккаунты (1-based: --only 1,3)
    #[arg(long, value_name = "N,N,...", value_delimiter = ',')]
    only: Vec<usize>,

    /// Пропустить аккаунты (1-based: --skip 2)
    #[arg(long, value_name = "N,N,...", value_delimiter = ',')]
    skip: Vec<usize>,

    /// Число параллельных потоков (default: 5)
    #[arg(long, value_name = "N", default_value_t = 5)]
    threads: usize,
}

fn win_to_wsl(path: &str) -> String {
    if cfg!(target_os = "linux") && path.len() >= 2 && path.chars().nth(1) == Some(':') {
        let drive = path.chars().next().unwrap().to_ascii_lowercase();
        let rest = path[2..].replace('\\', "/");
        return format!("/mnt/{}{}", drive, rest);
    }
    path.to_string()
}

struct Results {
    clean: u32,
    spam: u32,
    banned: u32,
    errors: u32,
}
impl Results {
    fn new() -> Self {
        Self {
            clean: 0,
            spam: 0,
            banned: 0,
            errors: 0,
        }
    }
}

type SharedResults = Arc<Mutex<Results>>;
type PrintLock = Arc<Mutex<()>>;

async fn log(lock: &PrintLock, thread: usize, phone: &str, msg: &str, color: &str) {
    let _g = lock.lock().await;
    println!(
        "{}[{}] [Поток {}] [{}] {}{}",
        color,
        ts(),
        thread,
        phone,
        msg,
        if color.is_empty() { "" } else { RESET }
    );
}

// All per-account options bundled together to keep process_account tidy
struct AccountOpts {
    terminate: bool,
    password: Option<String>,
    remove_password: Option<String>,
    check_groups: Vec<String>,
    parse_group: Option<String>,
    join_group: Option<String>,
    leave_group: Option<String>,
    check_username: Option<String>,
    set_name: Option<String>,
    set_bio: Option<String>,
    ping: bool,
    view_stories: Vec<String>,
    react: Option<String>,
    react_emoji: String,
    parse_messages: Option<String>,
    msg_limit: i32,
    invite_to: Option<String>,
    invite_users: Vec<(i64, i64)>, // pre-split slice for this account
    proxy: Option<Arc<telegram::ProxyConfig>>,
}

struct AccountResult {
    members: Vec<telegram::MemberInfo>,
    messages: Vec<telegram::MessageInfo>,
}

async fn process_account(
    thread: usize,
    info: tdata::AccountInfo,
    semaphore: Arc<Semaphore>,
    results: SharedResults,
    opts: AccountOpts,
    plock: PrintLock,
) -> AccountResult {
    let _permit = semaphore.acquire().await.unwrap();

    let phone = format!("акк{}", info.index + 1);
    let dc_ip = telegram::dc_ip(info.dc_id);

    log(
        &plock,
        thread,
        &phone,
        &format!("Подключается через {}:443", dc_ip),
        GRAY,
    )
    .await;

    let proxy_ref = opts.proxy.as_deref();
    let (client, pool_task, relay_tasks) = match telegram::connect(&info, proxy_ref).await {
        Ok(v) => v,
        Err(e) => {
            log(
                &plock,
                thread,
                &phone,
                &format!("Ошибка подключения: {}", e),
                RED,
            )
            .await;
            results.lock().await.errors += 1;
            return AccountResult {
                members: vec![],
                messages: vec![],
            };
        }
    };

    // ── Identify account ────────────────────────────────────────────────────
    let me_result = client
        .invoke(&grammers_tl_types::functions::users::GetUsers {
            id: vec![grammers_tl_types::enums::InputUser::UserSelf],
        })
        .await;

    let display_phone = match me_result {
        Ok(users) => extract_phone_from_users(&users).unwrap_or_else(|| phone.clone()),
        Err(e) => {
            telegram::disconnect(client, pool_task, relay_tasks);
            let msg = e.to_string();
            if msg.contains("AUTH_KEY_UNREGISTERED")
                || msg.contains("SESSION_REVOKED")
                || msg.contains("USER_DEACTIVATED")
            {
                log(&plock, thread, &phone, "Сессия недействительна", GRAY).await;
            } else if msg.contains("USER_DEACTIVATED_BAN") {
                log(&plock, thread, &phone, "Аккаунт ЗАБАНЕН", RED).await;
                results.lock().await.banned += 1;
                return AccountResult {
                    members: vec![],
                    messages: vec![],
                };
            } else {
                log(&plock, thread, &phone, &format!("Ошибка: {}", e), RED).await;
            }
            results.lock().await.errors += 1;
            return AccountResult {
                members: vec![],
                messages: vec![],
            };
        }
    };

    // ── Spam check ──────────────────────────────────────────────────────────
    let spam_blocked = match telegram::check_spam(&client).await {
        Ok(v) => v,
        Err(e) => {
            log(
                &plock,
                thread,
                &display_phone,
                &format!("Ошибка спам-проверки: {}", e),
                RED,
            )
            .await;
            telegram::disconnect(client, pool_task, relay_tasks);
            results.lock().await.errors += 1;
            return AccountResult {
                members: vec![],
                messages: vec![],
            };
        }
    };

    if spam_blocked {
        log(&plock, thread, &display_phone, "СПАМБЛОК!", RED).await;
        telegram::disconnect(client, pool_task, relay_tasks);
        results.lock().await.spam += 1;
        return AccountResult {
            members: vec![],
            messages: vec![],
        };
    }

    // ── Operations ──────────────────────────────────────────────────────────
    let mut parts: Vec<String> = vec!["Аккаунт жив. Без спамблока.".to_string()];
    let mut out_members: Vec<telegram::MemberInfo> = vec![];
    let mut out_messages: Vec<telegram::MessageInfo> = vec![];

    // Sessions
    if let Ok((total, other)) = telegram::get_sessions(&client).await {
        if opts.terminate && other > 0 {
            match telegram::terminate_other_sessions(&client).await {
                Ok(terminated) if !terminated.is_empty() => {
                    parts.push(format!("закрыто сессий: {}", terminated.len()));
                    for desc in &terminated {
                        log(
                            &plock,
                            thread,
                            &display_phone,
                            &format!("  ↳ отключено: {}", desc),
                            GRAY,
                        )
                        .await;
                    }
                }
                Ok(_) => {}
                Err(e) => parts.push(format!("сессии: {}", e)),
            }
        } else if other > 0 {
            parts.push(format!("сессий {} (чужих: {})", total, other));
        }
    }

    // 2FA
    if let Some(ref pass) = opts.password {
        match telegram::set_cloud_password(&client, pass).await {
            Ok(true) => parts.push("пароль ✓".to_string()),
            Ok(false) => parts.push("пароль: уже установлен".to_string()),
            Err(e) => parts.push(format!("пароль: {}", e)),
        }
    }
    if let Some(ref pass) = opts.remove_password {
        match telegram::remove_cloud_password(&client, pass).await {
            Ok(true) => parts.push("пароль снят ✓".to_string()),
            Ok(false) => parts.push("пароль: не был установлен".to_string()),
            Err(e) => parts.push(format!("снятие пароля: {}", e)),
        }
    }

    // Check groups
    if !opts.check_groups.is_empty() {
        let infos = telegram::check_groups(&client, &opts.check_groups).await;
        log(
            &plock,
            thread,
            &display_phone,
            &format!("группы ({}):", infos.len()),
            GREEN,
        )
        .await;
        for g in &infos {
            let line = if let Some(ref err) = g.error {
                format!("  ↳ {} — недоступна ✗ ({})", g.input, err)
            } else {
                format!(
                    "  ↳ {} — «{}» ({} уч.) [{}] ✓",
                    g.input, g.title, g.members, g.kind
                )
            };
            log(&plock, thread, &display_phone, &line, GRAY).await;
        }
    }

    // Parse group members
    if let Some(ref group) = opts.parse_group {
        log(
            &plock,
            thread,
            &display_phone,
            &format!("парсинг {}...", group),
            GRAY,
        )
        .await;
        match telegram::parse_group_members(&client, group).await {
            Ok((members, total)) => {
                parts.push(format!("спарсено {}/{}", members.len(), total));
                out_members = members;
            }
            Err(e) => parts.push(format!("парсинг: {}", e)),
        }
    }

    // ── Level 1 ─────────────────────────────────────────────────────────────

    if let Some(ref group) = opts.join_group {
        match telegram::join_group(&client, group).await {
            Ok(msg) => parts.push(msg),
            Err(e) => parts.push(format!("join: {}", e)),
        }
    }

    if let Some(ref group) = opts.leave_group {
        match telegram::leave_group(&client, group).await {
            Ok(msg) => parts.push(msg),
            Err(e) => parts.push(format!("leave: {}", e)),
        }
    }

    if let Some(ref username) = opts.check_username {
        match telegram::check_username_available(&client, username).await {
            Ok(true) => parts.push(format!("@{}: свободен ✓", username.trim_start_matches('@'))),
            Ok(false) => parts.push(format!("@{}: занят ✗", username.trim_start_matches('@'))),
            Err(e) => parts.push(format!("check-username: {}", e)),
        }
    }

    if opts.set_name.is_some() || opts.set_bio.is_some() {
        let (first_name, last_name) = parse_name_arg(opts.set_name.as_deref());
        match telegram::update_profile(&client, first_name, last_name, opts.set_bio.as_deref())
            .await
        {
            Ok(()) => {
                let mut what = Vec::new();
                if first_name.is_some() || last_name.is_some() {
                    what.push("имя");
                }
                if opts.set_bio.is_some() {
                    what.push("bio");
                }
                parts.push(format!("{} обновлено ✓", what.join(", ")));
            }
            Err(e) => parts.push(format!("update-profile: {}", e)),
        }
    }

    // ── Level 2 ─────────────────────────────────────────────────────────────

    if opts.ping {
        match telegram::ping_saved_messages(&client).await {
            Ok(()) => parts.push("ping ✓".to_string()),
            Err(e) => parts.push(format!("ping: {}", e)),
        }
    }

    if !opts.view_stories.is_empty() {
        match telegram::view_stories(&client, &opts.view_stories).await {
            Ok(viewed) => {
                let total: usize = viewed.iter().map(|(_, n)| n).sum();
                parts.push(format!("stories: просмотрено {} шт.", total));
                for (user, n) in &viewed {
                    log(
                        &plock,
                        thread,
                        &display_phone,
                        &format!("  ↳ @{}: {} историй", user, n),
                        GRAY,
                    )
                    .await;
                }
            }
            Err(e) => parts.push(format!("view-stories: {}", e)),
        }
    }

    if let Some(ref link) = opts.react {
        match telegram::react_to_message(&client, link, &opts.react_emoji).await {
            Ok(()) => parts.push(format!("реакция {} ✓", opts.react_emoji)),
            Err(e) => parts.push(format!("react: {}", e)),
        }
    }

    // ── Level 3 ─────────────────────────────────────────────────────────────

    if let Some(ref group) = opts.parse_messages {
        log(
            &plock,
            thread,
            &display_phone,
            &format!("парсинг сообщений {}...", group),
            GRAY,
        )
        .await;
        match telegram::parse_messages(&client, group, opts.msg_limit).await {
            Ok(msgs) => {
                parts.push(format!("сообщений: {}", msgs.len()));
                out_messages = msgs;
            }
            Err(e) => parts.push(format!("parse-messages: {}", e)),
        }
    }

    if let Some(ref channel) = opts.invite_to {
        if !opts.invite_users.is_empty() {
            log(
                &plock,
                thread,
                &display_phone,
                &format!("приглашаем {} в {}...", opts.invite_users.len(), channel),
                GRAY,
            )
            .await;
            match telegram::invite_to_channel(&client, channel, &opts.invite_users).await {
                Ok((inv, fail)) => parts.push(format!("приглашено: {} / ошибок: {}", inv, fail)),
                Err(e) => parts.push(format!("invite: {}", e)),
            }
        }
    }

    // ── Done ────────────────────────────────────────────────────────────────
    log(&plock, thread, &display_phone, &parts.join(" | "), GREEN).await;
    telegram::disconnect(client, pool_task, relay_tasks);
    results.lock().await.clean += 1;

    AccountResult {
        members: out_members,
        messages: out_messages,
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn parse_name_arg(arg: Option<&str>) -> (Option<&str>, Option<&str>) {
    match arg {
        None => (None, None),
        Some(s) => {
            if let Some(sep) = s.find('|') {
                let first = s[..sep].trim();
                let last = s[sep + 1..].trim();
                (
                    if first.is_empty() { None } else { Some(first) },
                    if last.is_empty() { None } else { Some(last) },
                )
            } else {
                let t = s.trim();
                (if t.is_empty() { None } else { Some(t) }, None)
            }
        }
    }
}

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn write_members_csv(path: &str, members: &[telegram::MemberInfo]) -> Result<()> {
    let file =
        std::fs::File::create(path).map_err(|e| anyhow!("Не удалось создать {}: {}", path, e))?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(
        w,
        "user_id,access_hash,username,first_name,last_name,phone,is_bot,is_premium"
    )?;
    for m in members {
        writeln!(
            w,
            "{},{},{},{},{},{},{},{}",
            m.user_id,
            m.access_hash,
            escape_csv(m.username.as_deref().unwrap_or("")),
            escape_csv(&m.first_name),
            escape_csv(m.last_name.as_deref().unwrap_or("")),
            m.phone.as_deref().unwrap_or(""),
            m.is_bot,
            m.is_premium,
        )?;
    }
    Ok(())
}

fn write_messages_csv(path: &str, messages: &[telegram::MessageInfo]) -> Result<()> {
    let file =
        std::fs::File::create(path).map_err(|e| anyhow!("Не удалось создать {}: {}", path, e))?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(w, "msg_id,date,from_id,text,reply_to_id,views,forwards")?;
    for m in messages {
        writeln!(
            w,
            "{},{},{},{},{},{},{}",
            m.msg_id,
            m.date,
            m.from_id.map(|id| id.to_string()).unwrap_or_default(),
            escape_csv(&m.text),
            m.reply_to_id.map(|id| id.to_string()).unwrap_or_default(),
            m.views.map(|v| v.to_string()).unwrap_or_default(),
            m.forwards.map(|f| f.to_string()).unwrap_or_default(),
        )?;
    }
    Ok(())
}

fn write_dump_messages_csv(path: &str, messages: &[telegram::DumpMessageInfo]) -> Result<()> {
    let file =
        std::fs::File::create(path).map_err(|e| anyhow!("Не удалось создать {}: {}", path, e))?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(
        w,
        "msg_id,date,from_id,text,reply_to_id,views,forwards,media_kind,media_file"
    )?;
    for m in messages {
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{}",
            m.msg_id,
            m.date,
            m.from_id.map(|id| id.to_string()).unwrap_or_default(),
            escape_csv(&m.text),
            m.reply_to_id.map(|id| id.to_string()).unwrap_or_default(),
            m.views.map(|v| v.to_string()).unwrap_or_default(),
            m.forwards.map(|f| f.to_string()).unwrap_or_default(),
            m.media_kind.as_deref().unwrap_or(""),
            escape_csv(m.media_file.as_deref().unwrap_or("")),
        )?;
    }
    Ok(())
}

fn filtered_account_numbers(cli: &Cli, total_accounts: usize) -> Vec<usize> {
    (1..=total_accounts)
        .filter(|n| {
            if !cli.only.is_empty() {
                cli.only.contains(n)
            } else if !cli.skip.is_empty() {
                !cli.skip.contains(n)
            } else {
                true
            }
        })
        .take(cli.accounts.unwrap_or(usize::MAX))
        .collect()
}

fn extract_phone_from_users(users: &[grammers_tl_types::enums::User]) -> Option<String> {
    for u in users {
        if let grammers_tl_types::enums::User::User(user) = u {
            if let Some(ref phone) = user.phone {
                return Some(phone.clone());
            }
            return Some(format!("id{}", user.id));
        }
    }
    None
}

/// Read (user_id, access_hash) pairs from a members CSV file.
fn read_invite_users_from_csv(path: &str) -> Result<Vec<(i64, i64)>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("Не удалось прочитать {}: {}", path, e))?;
    let mut lines = content.lines();
    let header = lines
        .next()
        .ok_or_else(|| anyhow!("Пустой CSV файл: {}", path))?;
    let cols: Vec<&str> = header.split(',').collect();

    let uid_col = cols
        .iter()
        .position(|&c| c.trim() == "user_id")
        .ok_or_else(|| anyhow!("Нет колонки user_id в {}", path))?;
    let ah_col = cols
        .iter()
        .position(|&c| c.trim() == "access_hash")
        .ok_or_else(|| {
            anyhow!(
                "Нет колонки access_hash в {} (используйте файл из --parse-group)",
                path
            )
        })?;

    let max_col = uid_col.max(ah_col);
    let mut users = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() <= max_col {
            continue;
        }
        if let (Ok(uid), Ok(ah)) = (
            parts[uid_col].trim().parse::<i64>(),
            parts[ah_col].trim().parse::<i64>(),
        ) {
            users.push((uid, ah));
        }
    }
    Ok(users)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Resolve path ────────────────────────────────────────────────────────
    let base_str = win_to_wsl(&cli.path);
    let base = PathBuf::from(&base_str);
    let tdata_path = base.join("tdata");

    // ── --import ────────────────────────────────────────────────────────────
    if let Some(ref import_file) = cli.import {
        let json = std::fs::read_to_string(import_file)
            .map_err(|e| anyhow!("Не удалось прочитать {}: {}", import_file, e))?;
        let imported: Vec<tdata::ExportedAccount> =
            serde_json::from_str(&json).map_err(|e| anyhow!("Ошибка разбора JSON: {}", e))?;
        if tdata_path.exists() {
            eprintln!(
                "[{}] ⚠  {} уже существует — будет перезаписана.",
                ts(),
                tdata_path.display()
            );
        }
        println!(
            "[{}] Импорт {} аккаунтов → {}",
            ts(),
            imported.len(),
            tdata_path.display()
        );
        tdata::create_tdata(&tdata_path, &imported)
            .map_err(|e| anyhow!("Ошибка создания tdata: {}", e))?;
        println!("[{}] ✓ tdata создана успешно", ts());
        return Ok(());
    }

    // All other operations need an existing tdata
    if !base.exists() {
        eprintln!("[{}] ❌ Путь не найден: {}", ts(), base.display());
        std::process::exit(1);
    }
    if !tdata_path.exists() {
        eprintln!("[{}] ❌ tdata/ не найден в {}", ts(), base.display());
        std::process::exit(1);
    }

    // ── Load accounts ────────────────────────────────────────────────────────
    println!("[{}] Загружаем аккаунты: {}", ts(), base.display());
    let accounts = match tdata::extract_all_accounts(&tdata_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[{}] ❌ Не удалось загрузить tdata: {}", ts(), e);
            std::process::exit(1);
        }
    };

    // ── --export ─────────────────────────────────────────────────────────────
    if let Some(ref export_file) = cli.export {
        let exported = tdata::accounts_to_export(&accounts);
        let json = serde_json::to_string_pretty(&exported)?;
        std::fs::write(export_file, &json)
            .map_err(|e| anyhow!("Не удалось записать {}: {}", export_file, e))?;
        println!(
            "[{}] ✓ Экспортировано {} аккаунтов → {}",
            ts(),
            exported.len(),
            export_file
        );
        return Ok(());
    }

    if accounts.is_empty() {
        eprintln!("[{}] ❌ Аккаунты не найдены", ts());
        std::process::exit(1);
    }

    // ── Parse proxy ──────────────────────────────────────────────────────────
    let proxy: Option<Arc<telegram::ProxyConfig>> = match &cli.proxy {
        Some(url) => match telegram::parse_proxy_url(url) {
            Ok(cfg) => {
                println!("[{}] Прокси: {}", ts(), cfg.addr);
                Some(Arc::new(cfg))
            }
            Err(e) => {
                eprintln!("[{}] ❌ Некорректный прокси URL: {}", ts(), e);
                std::process::exit(1);
            }
        },
        None => None,
    };

    // ── Precompute selected account numbers (1-based) ──────────────────────
    let account_numbers = filtered_account_numbers(&cli, accounts.len());
    if account_numbers.is_empty() {
        eprintln!("[{}] ❌ После фильтрации не осталось аккаунтов", ts());
        std::process::exit(1);
    }

    // ── Single-account channel dump/list mode ───────────────────────────────
    if cli.list_joined_channels || cli.dump_channel.is_some() {
        let selected_num = match cli.dump_account {
            Some(n) => {
                if n == 0 || n > accounts.len() {
                    eprintln!(
                        "[{}] ❌ --dump-account={} вне диапазона 1..{}",
                        ts(),
                        n,
                        accounts.len()
                    );
                    std::process::exit(1);
                }
                if !account_numbers.contains(&n) {
                    eprintln!(
                        "[{}] ❌ --dump-account={} отфильтрован параметрами --only/--skip/--accounts",
                        ts(),
                        n
                    );
                    std::process::exit(1);
                }
                n
            }
            None => account_numbers[0],
        };

        println!("[{}] Режим дампа канала: аккаунт #{}", ts(), selected_num);
        let account = &accounts[selected_num - 1];
        let proxy_ref = proxy.as_deref();

        let (client, pool_task, relay_tasks) = match telegram::connect(account, proxy_ref).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[{}] ❌ Ошибка подключения: {}", ts(), e);
                std::process::exit(1);
            }
        };

        let mode_result: Result<()> = async {
            if cli.list_joined_channels {
                let channels = telegram::list_joined_channels(&client).await?;
                if channels.is_empty() {
                    println!("[{}] joined-каналы не найдены", ts());
                } else {
                    println!("[{}] joined-каналы ({}):", ts(), channels.len());
                    for ch in &channels {
                        let uname = ch
                            .username
                            .as_deref()
                            .map(|u| format!("@{}", u))
                            .unwrap_or_else(|| "-".to_string());
                        println!(
                            "[{}]   joined:{}  {}  [{}] {}",
                            ts(),
                            ch.index,
                            ch.title,
                            ch.kind,
                            uname
                        );
                    }
                }
            }

            if let Some(source) = cli.dump_channel.as_deref() {
                let dump_dir = PathBuf::from(&cli.dump_dir);
                println!(
                    "[{}] Дамп канала: {} | лимит: {} | папка: {}",
                    ts(),
                    source,
                    if cli.dump_limit == 0 {
                        "без лимита".to_string()
                    } else {
                        cli.dump_limit.to_string()
                    },
                    dump_dir.display()
                );

                let dump =
                    telegram::dump_channel_content(&client, source, &dump_dir, cli.dump_limit)
                        .await?;

                let csv_path = dump_dir.join("messages.csv");
                let csv_path_str = csv_path.to_string_lossy().to_string();
                write_dump_messages_csv(&csv_path_str, &dump.messages)?;

                println!("[{}] Источник: {}", ts(), dump.source_label);
                println!(
                    "[{}] ✓ Сообщений: {} | медиа найдено: {} | скачано: {} | ошибок: {}",
                    ts(),
                    dump.messages.len(),
                    dump.media_detected,
                    dump.media_saved,
                    dump.media_failed
                );
                println!("[{}] ✓ CSV: {}", ts(), csv_path.display());
                println!("[{}] ✓ Медиа: {}", ts(), dump_dir.join("media").display());
            }
            Ok(())
        }
        .await;

        telegram::disconnect(client, pool_task, relay_tasks);

        if let Err(e) = mode_result {
            eprintln!("[{}] ❌ {}", ts(), e);
            std::process::exit(1);
        }
        return Ok(());
    }

    // ── Read invite users list ───────────────────────────────────────────────
    let invite_users_all: Vec<(i64, i64)> = if cli.invite_to.is_some() {
        match &cli.invite_from {
            Some(f) => match read_invite_users_from_csv(f) {
                Ok(users) => {
                    println!(
                        "[{}] Загружено {} пользователей для приглашения из {}",
                        ts(),
                        users.len(),
                        f
                    );
                    users
                }
                Err(e) => {
                    eprintln!("[{}] ❌ {}", ts(), e);
                    std::process::exit(1);
                }
            },
            None => {
                eprintln!("[{}] ❌ --invite-to требует --invite-from FILE", ts());
                std::process::exit(1);
            }
        }
    } else {
        vec![]
    };

    let total = accounts.len();

    // ── Apply filters ────────────────────────────────────────────────────────
    let selected: std::collections::HashSet<usize> = account_numbers.iter().copied().collect();
    let accounts: Vec<_> = accounts
        .into_iter()
        .enumerate()
        .map(|(i, acc)| (i + 1, acc))
        .filter(|(n, _)| selected.contains(n))
        .collect();

    let limit = accounts.len();
    let threads = cli.threads.min(limit.max(1));

    if limit == 0 {
        eprintln!("[{}] ❌ После фильтрации не осталось аккаунтов", ts());
        std::process::exit(1);
    }

    // ── Split invite list across accounts ────────────────────────────────────
    let invite_chunks: Vec<Vec<(i64, i64)>> = if !invite_users_all.is_empty() {
        let chunk_size = (invite_users_all.len() + limit - 1) / limit;
        invite_users_all
            .chunks(chunk_size)
            .map(|c| c.to_vec())
            .collect()
    } else {
        vec![vec![]; limit]
    };

    // ── Print summary ────────────────────────────────────────────────────────
    println!(
        "[{}] Аккаунтов: {} | Обрабатываем: {} | Потоков: {}",
        ts(),
        total,
        limit,
        threads
    );
    if !cli.only.is_empty() {
        println!("[{}] Фильтр --only: {:?}", ts(), cli.only);
    }
    if !cli.skip.is_empty() {
        println!("[{}] Фильтр --skip: {:?}", ts(), cli.skip);
    }
    if cli.terminate_sessions {
        println!("[{}] Закрытие чужих сессий: да", ts());
    }
    if cli.set_password.is_some() {
        println!("[{}] Установка 2FA пароля: да", ts());
    }
    if cli.remove_password.is_some() {
        println!("[{}] Снятие 2FA пароля: да", ts());
    }
    if !cli.check_groups.is_empty() {
        println!("[{}] Проверка групп: {}", ts(), cli.check_groups.join(", "));
    }
    if let Some(ref g) = cli.parse_group {
        println!("[{}] Парсинг участников: {}", ts(), g);
    }
    if let Some(ref g) = cli.join_group {
        println!("[{}] Вступление в: {}", ts(), g);
    }
    if let Some(ref g) = cli.leave_group {
        println!("[{}] Выход из: {}", ts(), g);
    }
    if cli.ping {
        println!("[{}] Ping Saved Messages: да", ts());
    }
    if !cli.view_stories.is_empty() {
        println!(
            "[{}] Просмотр историй: {}",
            ts(),
            cli.view_stories.join(", ")
        );
    }
    if let Some(ref l) = cli.react {
        println!("[{}] Реакция {} на: {}", ts(), cli.react_emoji, l);
    }
    if let Some(ref g) = cli.parse_messages {
        println!(
            "[{}] Парсинг сообщений: {} (лимит: {})",
            ts(),
            g,
            cli.msg_limit
        );
    }
    if let Some(ref g) = cli.invite_to {
        println!(
            "[{}] Приглашение в: {} ({} уч.)",
            ts(),
            g,
            invite_users_all.len()
        );
    }
    println!();

    // ── Determine output path ────────────────────────────────────────────────
    let output_path = if cli.parse_messages.is_some() && cli.output == "members.csv" {
        "messages.csv".to_string()
    } else {
        cli.output.clone()
    };

    // ── Spawn tasks ──────────────────────────────────────────────────────────
    let semaphore = Arc::new(Semaphore::new(threads));
    let results = Arc::new(Mutex::new(Results::new()));
    let print_lock = Arc::new(Mutex::new(()));

    let mut tasks = Vec::with_capacity(limit);

    for (i, (_num, account)) in accounts.into_iter().enumerate() {
        let thread = (i % threads) + 1;
        let sem = Arc::clone(&semaphore);
        let res = Arc::clone(&results);
        let plock = Arc::clone(&print_lock);
        let proxy_arc = proxy.clone();

        let opts = AccountOpts {
            terminate: cli.terminate_sessions,
            password: cli.set_password.clone(),
            remove_password: cli.remove_password.clone(),
            check_groups: cli.check_groups.clone(),
            parse_group: cli.parse_group.clone(),
            join_group: cli.join_group.clone(),
            leave_group: cli.leave_group.clone(),
            check_username: cli.check_username.clone(),
            set_name: cli.set_name.clone(),
            set_bio: cli.set_bio.clone(),
            ping: cli.ping,
            view_stories: cli.view_stories.clone(),
            react: cli.react.clone(),
            react_emoji: cli.react_emoji.clone(),
            parse_messages: cli.parse_messages.clone(),
            msg_limit: cli.msg_limit,
            invite_to: cli.invite_to.clone(),
            invite_users: invite_chunks.get(i).cloned().unwrap_or_default(),
            proxy: proxy_arc,
        };

        let task = tokio::spawn(process_account(thread, account, sem, res, opts, plock));
        tasks.push(task);
    }

    // ── Collect results ──────────────────────────────────────────────────────
    let mut all_members: HashMap<i64, telegram::MemberInfo> = HashMap::new();
    let mut all_messages: HashMap<i32, telegram::MessageInfo> = HashMap::new();

    for t in tasks {
        if let Ok(acc_result) = t.await {
            for m in acc_result.members {
                let entry = all_members.entry(m.user_id);
                match entry {
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(m);
                    }
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        if e.get().phone.is_none() && m.phone.is_some() {
                            e.insert(m);
                        }
                    }
                }
            }
            for msg in acc_result.messages {
                all_messages.entry(msg.msg_id).or_insert(msg);
            }
        }
    }

    // ── Write CSVs ───────────────────────────────────────────────────────────
    if cli.parse_group.is_some() && !all_members.is_empty() {
        let mut sorted: Vec<_> = all_members.into_values().collect();
        sorted.sort_by_key(|m| m.user_id);
        let with_phone = sorted.iter().filter(|m| m.phone.is_some()).count();
        match write_members_csv(&output_path, &sorted) {
            Ok(()) => println!(
                "[{}] ✓ Сохранено {} участников (с телефонами: {}) → {}",
                ts(),
                sorted.len(),
                with_phone,
                output_path
            ),
            Err(e) => eprintln!("[{}] ❌ Ошибка записи CSV: {}", ts(), e),
        }
    } else if cli.parse_group.is_some() {
        eprintln!("[{}] ⚠ Не удалось получить ни одного участника", ts());
    }

    if cli.parse_messages.is_some() && !all_messages.is_empty() {
        let mut sorted: Vec<_> = all_messages.into_values().collect();
        sorted.sort_by_key(|m| -(m.msg_id as i64)); // newest first
        match write_messages_csv(&output_path, &sorted) {
            Ok(()) => println!(
                "[{}] {} Сохранено {} сообщений → {}",
                ts(),
                YELLOW,
                sorted.len(),
                output_path
            ),
            Err(e) => eprintln!("[{}] ❌ Ошибка записи CSV: {}", ts(), e),
        }
    } else if cli.parse_messages.is_some() {
        eprintln!("[{}] ⚠ Сообщений не получено", ts());
    }

    // ── Summary ──────────────────────────────────────────────────────────────
    let r = results.lock().await;
    println!("\n[{}] Результаты проверки:", ts());
    if r.clean > 0 {
        println!(
            "[{}]     {}Без спамблока: {}{}",
            ts(),
            GREEN,
            r.clean,
            RESET
        );
    }
    if r.spam > 0 {
        println!("[{}]     {}Спамблок:      {}{}", ts(), RED, r.spam, RESET);
    }
    if r.banned > 0 {
        println!("[{}]     {}Забанено:      {}{}", ts(), RED, r.banned, RESET);
    }
    if r.errors > 0 {
        println!("[{}]     Ошибок:        {}", ts(), r.errors);
    }
    println!("\n[{}] Выполнение задачи завершено!", ts());

    Ok(())
}
