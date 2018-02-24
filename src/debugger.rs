use win32;

use std::mem;
use std::ptr;

pub struct Debugger {
    creation_flags: win32::DWORD,
    startup_info: win32::StartupInfo,
    process_info: win32::ProcessInformation
}

impl Debugger {
    pub fn new() -> Debugger {
        let dbg = Debugger {
            creation_flags: 0x0,
            startup_info: win32::StartupInfo {
                cb: 0,
                lpReserved: &mut 0,
                lpDesktop: &mut 0,
                lpTitle: &mut 0,
                dwX: 0,
                dwY: 0,
                dwXSize: 0,
                dwYSize: 0,
                dwXCountChars: 0,
                dwYCountChars: 0,
                dwFillAttribute: 0,
                dwFlags: 0,
                wShowWindow: 0,
                cbReserved2: 0,
                lpReserved2: &mut 0,
                hStdInput: ptr::null_mut(),
                hStdOutput: ptr::null_mut(),
                hStdError: ptr::null_mut()
            },
            
            process_info: win32::ProcessInformation {
                hProcess: ptr::null_mut(),
                hThread: ptr::null_mut(),
                dwProcessId: 0,
                dwThreadId: 0
            }
        };
        dbg
    }
}


pub fn load(path: &str) {
    let mut debug = Debugger::new();

    /* Set process creation and startup flags */
    debug.creation_flags = win32::DEBUG_PROCESS;
    debug.startup_info.dwFlags = 0x1; // Start up the process with the current process as the debugger
    debug.startup_info.wShowWindow = 0x0;

    debug.startup_info.cb = mem::size_of::<win32::StartupInfo>() as u32;

    let return_code: win32::BOOL;
    let error_code: win32::DWORD;

    unsafe {
        return_code = win32::CreateProcessA(path.as_ptr(),
                             ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0,
                             debug.creation_flags, ptr::null_mut(), ptr::null(),
                             &mut debug.startup_info as *mut _ as win32::LPVOID,
                             &mut debug.process_info as *mut _ as win32::LPVOID);
        error_code = win32::GetLastError();      
    }
    
    if return_code == 0 {
        println!("Process failed to launch :(");
        println!("Error code: {}", error_code);
        return;
    }
    
    println!("Process launched successfully.");
    println!("PID: {}", debug.process_info.dwProcessId);
}
