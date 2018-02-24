extern crate kernel32;

mod debugger;
mod win32;

use std::io::prelude::*;
use std::io;

fn main() {
    let mut debugger = debugger::Debugger::new();
    let mut input = String::new();
    print!("Enter PID to which to attach: ");
    io::stdout().flush();
    let _ = io::stdin().read_line(&mut input);
    let pid = str::parse::<u32>(&input[..].trim()).unwrap();
    debugger::attach(&mut debugger, pid);
    debugger::detach(debugger);
}
