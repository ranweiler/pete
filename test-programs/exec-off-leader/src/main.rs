use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let mut cmd = Command::new("/bin/true");
    std::thread::spawn(move || cmd.exec()).join().unwrap();
}
