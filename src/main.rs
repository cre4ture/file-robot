use clap::Parser;
use notify::{
    Event, EventKind, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher,
};
use std::{collections::BTreeMap, sync::Mutex};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc::channel;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to watch
    #[arg(short, long)]
    path: String,

    /// Command to run on new files (use {file} for the file path)
    #[arg(short, long)]
    command: String,

    /// User to run the command as
    #[arg(short, long)]
    user: String,
}

#[tokio::main]
async fn main() -> NotifyResult<()> {
    let args = Args::parse();
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())?;
    watcher.watch(args.path.as_ref(), RecursiveMode::NonRecursive)?;

    println!("Watching path: {}", args.path);
    println!("Will run command: {} as user: {}", args.command, args.user);

    let event_handler = Arc::new(move |path: PathBuf| {
        println!("Handling file: {:?}", path);
        handle_new_file(&path, &args.command, &args.user);
    });

    let event_queue = EventQueue {
        handle_event_delay: std::time::Duration::from_secs(5),
        files_check_again: BTreeMap::new(),
    };
    let queue = Arc::new(Box::new(Mutex::new(event_queue)));

    // Spawn the event loop
    tokio::spawn(run_event_queue(queue.clone(), event_handler));

    for res in rx {
        match res {
            Ok(event) => queue.lock()?.add_event(&event),
            Err(e) => eprintln!("watch error: {:?}", e),
        }
    }
    Ok(())
}

use tokio::time::{sleep_until, Instant as TokioInstant};
use std::sync::Arc;

struct EventQueue {
    handle_event_delay: std::time::Duration,
    files_check_again: BTreeMap<std::time::Instant, PathBuf>,
}

impl EventQueue {
    pub fn add_event(&mut self, event: &Event) {
        if let EventKind::Create(_) = event.kind {
            for path in &event.paths {
                if path.is_file() {
                    self.handle_file_created_event(path);
                }
            }
        }
    }

    pub fn handle_file_created_event(&mut self, path: &PathBuf) {
        let check_at_future_time = std::time::Instant::now() + self.handle_event_delay;
        self.files_check_again.insert(check_at_future_time, path.clone());
    }
}


/// Start the async event loop to process delayed events
async fn run_event_queue(
    protected_q: Arc<Box<Mutex<EventQueue>>>,
    event_handler: Arc<dyn Fn(PathBuf) + Send + Sync>,
) {
    loop {
        let mut next_instant = None;
        let mut to_handle = Vec::new();
        {
            let gq = protected_q.lock();
            if gq.is_err() {
                eprintln!("Mutex poisoned, exiting event loop.");
                return;
            }
            let q = &mut *gq.unwrap();
            let now = std::time::Instant::now();
            let mut to_check = Vec::new();
            for (&instant, path) in &q.files_check_again {
                if instant <= now {
                    to_check.push(path.clone());
                } else {
                    next_instant = Some(instant);
                    break;
                }
            }
            for path in &to_check {
                q.files_check_again.retain(|_, p| p != path);
            }
            for path in to_check {
                let Ok(m) = path.metadata() else {
                    continue;
                };
                let Ok(mtime) = m.modified() else {
                    continue;
                };
                let last_modification_age = std::time::SystemTime::now()
                    .duration_since(mtime)
                    .unwrap_or_default();
                if last_modification_age >= q.handle_event_delay {
                    to_handle.push(path);
                } else {
                    let new_check_time = std::time::Instant::now() + (q.handle_event_delay - last_modification_age);
                    q.files_check_again.insert(new_check_time, path.clone());
                }
            }
        }
        for path in to_handle {
            event_handler(path);
        }
        if let Some(instant) = next_instant {
            let delay = instant.saturating_duration_since(std::time::Instant::now());
            sleep_until(TokioInstant::now() + delay).await;
        } else {
            // No events to handle, sleep for a short time
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
    }
}

fn handle_new_file(path: &PathBuf, command: &str, user: &str) {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use users::{get_group_by_gid, get_user_by_name};

    if path.is_file() {
        let cmd = command.replace("{file}", &path.to_string_lossy());
        println!("Preparing to run as user '{}': {}", user, cmd);

        // Get original permissions and ownership
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Failed to get metadata: {}", e);
                return;
            }
        };
        let orig_mode = metadata.permissions().mode();
        let orig_uid = metadata.uid();
        let orig_gid = metadata.gid();

        // Get target user info
        let user_info = match get_user_by_name(user) {
            Some(u) => u,
            None => {
                eprintln!("User not found: {}", user);
                return;
            }
        };
        let group_info = match get_group_by_gid(
                user_info.primary_group_id()) {
            Some(g) => g,
            None => {
                eprintln!("Group not found for user: {}", user);
                return;
            }
        };

        // Change ownership and permissions
        if let Err(e) = std::os::unix::fs::chown(
            path,
            Some(user_info.uid()),
            Some(group_info.gid()),
        ) {
            eprintln!("Failed to chown: {}", e);
            return;
        }
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
            eprintln!("Failed to set permissions: {}", e);
            return;
        }

        // Run command as user
        let status = Command::new(
            "sudo")
            .arg("-u")
            .arg(user)
            .arg("sh")
            .arg("-c")
            .arg(&cmd)
            .status();
        match status {
            Ok(s) => println!("Command exited with: {}", s),
            Err(e) => eprintln!("Failed to run command: {}", e),
        }

        // Restore original ownership and permissions
        if let Err(e) = std::os::unix::fs::chown(
            path,
            Some(orig_uid),
            Some(orig_gid),
        ) {
            eprintln!("Failed to restore chown: {}", e);
        }
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(orig_mode)) {
            eprintln!("Failed to restore permissions: {}", e);
        }
    }
}
