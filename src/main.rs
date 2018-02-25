#![feature(repr_simd)]
#![feature(untagged_unions)]

extern crate either;
extern crate kernel32;

mod debugger;
mod win32;

use std::io::prelude::*;
use std::io;

fn main() {
    let mut debugger = debugger::Debugger::new();
    let mut input = String::new();
    print!("Enter PID to which to attach: ");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut input);
    let pid = str::parse::<u32>(&input[..].trim()).unwrap();
    debugger::attach(&mut debugger, pid);
    let printf_address = debugger::resolve_function("msvcrt.dll", "printf");
    println!("Address of printf: {}", printf_address as u32);
    debugger::bp_set(&mut debugger, printf_address);
    debugger::debug(&mut debugger);
    debugger::detach(&mut debugger);
}
