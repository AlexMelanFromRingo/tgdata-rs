mod tdata;
mod telegram;

use anyhow::{anyhow, Result};
use chrono::Local;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

// ANSI colours
const GREEN: &str = "\x1b[92m";
const RED:   &str = "\x1b[91m";
const GRAY:  &str = "\x1b[90m";
const RESET: &str = "\x1b[0m";

fn ts() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

/// Telegram Account Manager — tdata (multi-account)
///
/// Examples:
///   tgdata-rs --path "C:\Users\User\AppData\Roaming\Telegram Desktop"
///   tgdata-rs --path "C:\..." --terminate-sessions
///   tgdata-rs --path "C:\..." --set-password "Qwerty123!"
///   tgdata-rs --path "C:\..." --export sessions.json
///   tgdata-rs --path "D:\NewPC\Telegram Desktop" --import sessions.json
#[derive(Parser, Debug)]
#[command(name = "tgdata-rs", about = "Управление Telegram-аккаунтами из tdata")]
struct Cli {
    /// Путь к папке Telegram Desktop (содержит tdata/)
    #[arg(
        long,
        default_value = r"L:\Programs\Telegram Desktop",
        help = "Путь к папке Telegram Desktop (содержит tdata/)"
    )]
    path: String,

    /// Закрыть все чужие сессии
    #[arg(long, action = clap::ArgAction::SetTrue)]
    terminate_sessions: bool,

    /// Установить облачный пароль 2FA (если не установлен)
    #[arg(long, value_name = "PASS")]
    set_password: Option<String>,

    /// Снять облачный пароль 2FA (нужен текущий пароль)
    #[arg(long, value_name = "CURRENT_PASS")]
    remove_password: Option<String>,

    /// Экспортировать ключи аккаунтов в JSON (без подключения к Telegram)
    #[arg(long, value_name = "FILE")]
    export: Option<String>,

    /// Импортировать ключи из JSON и создать новую tdata по --path
    #[arg(long, value_name = "FILE")]
    import: Option<String>,

    /// Обрабатывать только первые N аккаунтов
    #[arg(long, value_name = "N")]
    accounts: Option<usize>,

    /// Обрабатывать ТОЛЬКО указанные аккаунты (1-based, через запятую: --only 1,3)
    #[arg(long, value_name = "N,N,...", value_delimiter = ',')]
    only: Vec<usize>,

    /// Пропустить указанные аккаунты (1-based, через запятую: --skip 2)
    #[arg(long, value_name = "N,N,...", value_delimiter = ',')]
    skip: Vec<usize>,

    /// Число параллельных потоков (default: 5)
    #[arg(long, value_name = "N", default_value_t = 5)]
    threads: usize,
}

fn win_to_wsl(path: &str) -> String {
    // Convert "L:\foo\bar" → "/mnt/l/foo/bar" when running on Linux
    if cfg!(target_os = "linux")
        && path.len() >= 2
        && path.chars().nth(1) == Some(':')
    {
        let drive = path.chars().next().unwrap().to_ascii_lowercase();
        let rest = path[2..].replace('\\', "/");
        return format!("/mnt/{}{}", drive, rest);
    }
    path.to_string()
}

struct Results {
    clean:  u32,
    spam:   u32,
    banned: u32,
    errors: u32,
}

impl Results {
    fn new() -> Self {
        Self { clean: 0, spam: 0, banned: 0, errors: 0 }
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

async fn process_account(
    thread:          usize,
    info:            tdata::AccountInfo,
    semaphore:       Arc<Semaphore>,
    results:         SharedResults,
    terminate:       bool,
    password:        Option<String>,
    remove_password: Option<String>,
    print_lock:      PrintLock,
) {
    let _permit = semaphore.acquire().await.unwrap();

    let phone = format!("акк{}", info.index + 1);
    let dc_ip = telegram::dc_ip(info.dc_id);

    log(&print_lock, thread, &phone,
        &format!("Подключается через {}:443", dc_ip), GRAY).await;

    let (client, pool_task) = match telegram::connect(&info).await {
        Ok(v) => v,
        Err(e) => {
            log(&print_lock, thread, &phone,
                &format!("Ошибка подключения: {}", e), RED).await;
            results.lock().await.errors += 1;
            return;
        }
    };

    // ── Get account info ───────────────────────────────────────────────────
    let me_result = client.invoke(&grammers_tl_types::functions::users::GetUsers {
        id: vec![grammers_tl_types::enums::InputUser::UserSelf],
    }).await;

    let display_phone = match me_result {
        Ok(users) => {
            extract_phone_from_users(&users).unwrap_or_else(|| phone.clone())
        }
        Err(e) => {
            telegram::disconnect(client, pool_task);
            let msg = e.to_string();
            if msg.contains("AUTH_KEY_UNREGISTERED")
                || msg.contains("SESSION_REVOKED")
                || msg.contains("USER_DEACTIVATED")
            {
                log(&print_lock, thread, &phone, "Сессия недействительна", GRAY).await;
            } else if msg.contains("USER_DEACTIVATED_BAN") {
                log(&print_lock, thread, &phone, "Аккаунт ЗАБАНЕН", RED).await;
                results.lock().await.banned += 1;
                return;
            } else {
                log(&print_lock, thread, &phone, &format!("Ошибка: {}", e), RED).await;
            }
            results.lock().await.errors += 1;
            return;
        }
    };

    // ── Spam check ─────────────────────────────────────────────────────────
    let spam_blocked = match telegram::check_spam(&client).await {
        Ok(v) => v,
        Err(e) => {
            log(&print_lock, thread, &display_phone,
                &format!("Ошибка спам-проверки: {}", e), RED).await;
            telegram::disconnect(client, pool_task);
            results.lock().await.errors += 1;
            return;
        }
    };

    if spam_blocked {
        log(&print_lock, thread, &display_phone, "СПАМБЛОК!", RED).await;
        telegram::disconnect(client, pool_task);
        results.lock().await.spam += 1;
        return;
    }

    // ── Clean account ──────────────────────────────────────────────────────
    let mut parts: Vec<String> = vec!["Аккаунт жив. Без спамблока.".to_string()];

    // Sessions
    if let Ok((total, other)) = telegram::get_sessions(&client).await {
        if terminate && other > 0 {
            match telegram::terminate_other_sessions(&client).await {
                Ok(terminated) if !terminated.is_empty() => {
                    parts.push(format!("закрыто сессий: {}", terminated.len()));
                    for desc in &terminated {
                        log(&print_lock, thread, &display_phone,
                            &format!("  ↳ отключено: {}", desc), GRAY).await;
                    }
                }
                Ok(_) => {}
                Err(e) => parts.push(format!("сессии: {}", e)),
            }
        } else if other > 0 {
            parts.push(format!("сессий {} (чужих: {})", total, other));
        }
    }

    // Set 2FA password
    if let Some(ref pass) = password {
        match telegram::set_cloud_password(&client, pass).await {
            Ok(true)  => parts.push("пароль ✓".to_string()),
            Ok(false) => parts.push("пароль: уже установлен".to_string()),
            Err(e)    => parts.push(format!("пароль: {}", e)),
        }
    }

    // Remove 2FA password
    if let Some(ref pass) = remove_password {
        match telegram::remove_cloud_password(&client, pass).await {
            Ok(true)  => parts.push("пароль снят ✓".to_string()),
            Ok(false) => parts.push("пароль: не был установлен".to_string()),
            Err(e)    => parts.push(format!("снятие пароля: {}", e)),
        }
    }

    log(&print_lock, thread, &display_phone, &parts.join(" | "), GREEN).await;
    telegram::disconnect(client, pool_task);
    results.lock().await.clean += 1;
}

fn extract_phone_from_users(users: &[grammers_tl_types::enums::User]) -> Option<String> {
    use grammers_tl_types::enums::User;
    for u in users {
        if let User::User(user) = u {
            if let Some(ref phone) = user.phone {
                return Some(phone.clone());
            }
            return Some(format!("id{}", user.id));
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Resolve path ───────────────────────────────────────────────────────
    let base_str = win_to_wsl(&cli.path);
    let base = PathBuf::from(&base_str);
    let tdata_path = base.join("tdata");

    // ── --import: create new tdata, does not need existing path ───────────
    if let Some(ref import_file) = cli.import {
        let json = std::fs::read_to_string(import_file)
            .map_err(|e| anyhow!("Не удалось прочитать {}: {}", import_file, e))?;
        let imported: Vec<tdata::ExportedAccount> = serde_json::from_str(&json)
            .map_err(|e| anyhow!("Ошибка разбора JSON: {}", e))?;

        if tdata_path.exists() {
            eprintln!("[{}] ⚠  {} уже существует — будет перезаписана.", ts(), tdata_path.display());
        }

        println!("[{}] Импорт {} аккаунтов → {}", ts(), imported.len(), tdata_path.display());
        tdata::create_tdata(&tdata_path, &imported)
            .map_err(|e| anyhow!("Ошибка создания tdata: {}", e))?;
        println!("[{}] ✓ tdata создана успешно", ts());
        return Ok(());
    }

    // All other operations require an existing tdata
    if !base.exists() {
        eprintln!("[{}] ❌ Путь не найден: {}", ts(), base.display());
        std::process::exit(1);
    }
    if !tdata_path.exists() {
        eprintln!("[{}] ❌ tdata/ не найден в {}", ts(), base.display());
        std::process::exit(1);
    }

    // ── Load accounts from tdata ───────────────────────────────────────────
    println!("[{}] Загружаем аккаунты: {}", ts(), base.display());
    let accounts = match tdata::extract_all_accounts(&tdata_path) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[{}] ❌ Не удалось загрузить tdata: {}", ts(), e);
            std::process::exit(1);
        }
    };

    // ── --export: dump keys to JSON, no API needed ─────────────────────────
    if let Some(ref export_file) = cli.export {
        let exported = tdata::accounts_to_export(&accounts);
        let json = serde_json::to_string_pretty(&exported)?;
        std::fs::write(export_file, &json)
            .map_err(|e| anyhow!("Не удалось записать {}: {}", export_file, e))?;
        println!("[{}] ✓ Экспортировано {} аккаунтов → {}", ts(), exported.len(), export_file);
        return Ok(());
    }

    if accounts.is_empty() {
        eprintln!("[{}] ❌ Аккаунты не найдены", ts());
        std::process::exit(1);
    }

    let total = accounts.len();

    // Apply --only / --skip / --accounts filters (1-based indexing for the user)
    let accounts: Vec<_> = accounts
        .into_iter()
        .enumerate()
        .map(|(i, acc)| (i + 1, acc))          // (1-based_num, AccountInfo)
        .filter(|(n, _)| {
            if !cli.only.is_empty() {
                cli.only.contains(n)
            } else if !cli.skip.is_empty() {
                !cli.skip.contains(n)
            } else {
                true
            }
        })
        .take(cli.accounts.unwrap_or(usize::MAX))
        .collect();

    let limit   = accounts.len();
    let threads = cli.threads.min(limit.max(1));

    if limit == 0 {
        eprintln!("[{}] ❌ После фильтрации --only/--skip не осталось аккаунтов", ts());
        std::process::exit(1);
    }

    println!("[{}] Аккаунтов: {} | Обрабатываем: {} | Потоков: {}", ts(), total, limit, threads);
    if !cli.only.is_empty() {
        println!("[{}] Фильтр --only: {:?}", ts(), cli.only);
    }
    if !cli.skip.is_empty() {
        println!("[{}] Фильтр --skip: {:?}", ts(), cli.skip);
    }
    if cli.terminate_sessions {
        println!("[{}] Чужие сессии будут закрыты", ts());
    }
    if cli.set_password.is_some() {
        println!("[{}] Облачный пароль будет установлен", ts());
    }
    if cli.remove_password.is_some() {
        println!("[{}] Облачный пароль будет снят", ts());
    }
    println!();

    // ── Concurrent processing ──────────────────────────────────────────────
    let semaphore  = Arc::new(Semaphore::new(threads));
    let results    = Arc::new(Mutex::new(Results::new()));
    let print_lock = Arc::new(Mutex::new(()));

    let mut tasks = Vec::with_capacity(limit);

    for (i, (_num, account)) in accounts.into_iter().enumerate() {
        let thread          = (i % threads) + 1;
        let sem             = Arc::clone(&semaphore);
        let res             = Arc::clone(&results);
        let plock           = Arc::clone(&print_lock);
        let terminate       = cli.terminate_sessions;
        let password        = cli.set_password.clone();
        let remove_password = cli.remove_password.clone();

        let task = tokio::spawn(process_account(
            thread, account, sem, res, terminate, password, remove_password, plock,
        ));
        tasks.push(task);
    }

    for t in tasks {
        let _ = t.await;
    }

    // ── Summary ────────────────────────────────────────────────────────────
    let r = results.lock().await;
    println!("\n[{}] Результаты проверки:", ts());
    if r.clean  > 0 { println!("[{}]     {}Без спамблока: {}{}", ts(), GREEN, r.clean,  RESET); }
    if r.spam   > 0 { println!("[{}]     {}Спамблок:      {}{}", ts(), RED,   r.spam,   RESET); }
    if r.banned > 0 { println!("[{}]     {}Забанено:      {}{}", ts(), RED,   r.banned, RESET); }
    if r.errors > 0 { println!("[{}]     Ошибок:        {}", ts(), r.errors); }
    println!("\n[{}] Выполнение задачи завершено!", ts());

    Ok(())
}
