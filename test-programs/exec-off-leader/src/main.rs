use std::os::unix::process::CommandExt;
use std::process::Command;
use std::thread::{sleep, spawn};
use std::time::Duration;

fn main() {
    let mut cmd = Command::new("/bin/true");
    spawn(|| sleep(Duration::from_secs(60)));
    sleep(Duration::from_millis(100));  // Hack, sorry.
    spawn(move || cmd.exec()).join().unwrap();
}
