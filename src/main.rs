use clap::Parser;
use notify::{
    Event, EventKind, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher,
};
use std::collections::BTreeMap;
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

fn main() -> NotifyResult<()> {
    let args = Args::parse();
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())?;
    watcher.watch(args.path.as_ref(), RecursiveMode::NonRecursive)?;

    println!("Watching path: {}", args.path);
    println!("Will run command: {} as user: {}", args.command, args.user);

    let event_handler = Arc::new(|path: PathBuf| {
        println!("Handling file: {:?}", path);
        // Place your file handling logic here
    });

    let mut event_queue = EventQueue {
        handle_event_delay: std::time::Duration::from_secs(5),
        events_input: Vec::new(),
        files_check_again: BTreeMap::new(),
        event_handler,
    };

    // Spawn the event loop
    tokio::spawn(event_queue.run());

    for res in rx {
        match res {
            Ok(event) => event_queue.add_event(&event),
            Err(e) => eprintln!("watch error: {:?}", e),
        }
    }
    Ok(())
}

use tokio::time::{sleep_until, Instant as TokioInstant};
use std::sync::Arc;

struct EventQueue {
    handle_event_delay: std::time::Duration,
    events_input: Vec<Event>,
    files_check_again: BTreeMap<std::time::Instant, PathBuf>,
    event_handler: Arc<dyn Fn(PathBuf) + Send + Sync>,
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

    /// Start the async event loop to process delayed events
    pub async fn run(mut self) {
        loop {
            let now = std::time::Instant::now();
            let mut to_handle = Vec::new();
            let mut next_instant = None;
            for (&instant, path) in &self.files_check_again {
                if instant <= now {
                    to_handle.push(path.clone());
                } else {
                    next_instant = Some(instant);
                    break;
                }
            }
            for path in &to_handle {
                (self.event_handler)(path.clone());
            }
            for path in &to_handle {
                self.files_check_again.retain(|_, p| p != path);
            }
            if let Some(instant) = next_instant {
                let delay = instant.saturating_duration_since(now);
                sleep_until(TokioInstant::now() + delay).await;
            } else {
                // No events to handle, sleep for a short time
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

fn handle_event(event: &Event, command: &str, user: &str) {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use users::{get_group_by_gid, get_user_by_name};

    if let EventKind::Create(_) = event.kind {
        for path in &event.paths {
            if path.is_file() {
                let cmd = command.replace("{file}", &path.to_string_lossy());
                println!("Preparing to run as user '{}': {}", user, cmd);

                // Get original permissions and ownership
                let metadata = match fs::metadata(path) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("Failed to get metadata: {}", e);
                        continue;
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
                        continue;
                    }
                };
                let group_info = match get_group_by_gid(
                        user_info.primary_group_id()) {
                    Some(g) => g,
                    None => {
                        eprintln!("Group not found for user: {}", user);
                        continue;
                    }
                };

                // Change ownership and permissions
                if let Err(e) = std::os::unix::fs::chown(
                    path,
                    Some(user_info.uid()),
                    Some(group_info.gid()),
                ) {
                    eprintln!("Failed to chown: {}", e);
                    continue;
                }
                if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
                    eprintln!("Failed to set permissions: {}", e);
                    continue;
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
    }
}
