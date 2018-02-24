extern crate kernel32;

mod debugger;
mod win32;

fn main() {
    debugger::load("c:\\windows\\system32\\calc.exe");
}
