extern crate nix;

use nix::sys::signal::{kill, signal};
use nix::unistd::Pid;

fn main() {
    println!("Hello, world!");
}
