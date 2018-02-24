extern crate kernel32;

mod debugger;
mod win32;

fn main() {
    let mut debugger = debugger::Debugger::new();
    debugger::load(&mut debugger, "c:\\windows\\system32\\calc.exe");
}
