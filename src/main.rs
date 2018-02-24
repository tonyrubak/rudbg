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
    let threads = match debugger::enumerate_threads(&debugger) {
        Ok(v) => v,
        Err(e) => {
            println!("Error enumerating threads!");
            println!("Error code: {}", e);
            return;
        }
    };

    for thread in threads {
        let ctx = match debugger::get_thread_context(&debugger, thread) {
            Ok(c) => c,
            Err(e) => {
                println!("Error getting thread context!");
                println!("Error code: {}", e);
                return;
            }
        };
        
        println!("Dumping attached process registers");
        println!("EIP: {}", ctx.Eip);
        println!("ESP: {}", ctx.Esp);
        println!("EBP: {}", ctx.Ebp);
    }
    debugger::detach(debugger);
}
