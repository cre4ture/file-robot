



use clap::Parser;
use notify::{RecommendedWatcher, RecursiveMode, Result as NotifyResult, Watcher, Event, EventKind};
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
}

fn main() -> NotifyResult<()> {
    let args = Args::parse();
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, notify::Config::default())?;
    watcher.watch(args.path.as_ref(), RecursiveMode::NonRecursive)?;

    println!("Watching path: {}", args.path);
    println!("Will run command: {}", args.command);

    for res in rx {
        match res {
            Ok(event) => handle_event(&event, &args.command),
            Err(e) => eprintln!("watch error: {:?}", e),
        }
    }
    Ok(())
}

fn handle_event(event: &Event, command: &str) {
    if let EventKind::Create(_) = event.kind {
        for path in &event.paths {
            if path.is_file() {
                let cmd = command.replace("{file}", &path.to_string_lossy());
                println!("Running: {}", cmd);
                let status = Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .status();
                match status {
                    Ok(s) => println!("Command exited with: {}", s),
                    Err(e) => eprintln!("Failed to run command: {}", e),
                }
            }
        }
    }
}
