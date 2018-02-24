use win32;

use std::io;
use std::mem;
use std::ptr;

pub struct Debugger {
    creation_flags: win32::DWORD,
    startup_info: win32::StartupInfo,
    process_info: win32::ProcessInformation,
    pid: win32::DWORD,
    process: win32::HANDLE,
    attached: bool
}

impl Debugger {
    pub fn new() -> Debugger {
        let dbg = Debugger {
            creation_flags: 0x0,
            pid: 0,
            process: ptr::null_mut(),
            attached: false,
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

/* Load runs a new process and sets the debugger pid to the run process,
you must still attach(debugger, pid) to actually run the debugger */
pub fn load(debugger: &mut Debugger, path: &str) {
    
    /* Set process creation and startup flags */
    debugger.creation_flags = win32::DEBUG_PROCESS;
    debugger.startup_info.dwFlags = 0x1; // Start up the process with the current process as the debugger
    debugger.startup_info.wShowWindow = 0x0;
    
    debugger.startup_info.cb = mem::size_of::<win32::StartupInfo>() as u32;
    
    let return_code: win32::BOOL;
    let error_code: win32::DWORD;
    
    unsafe {
        return_code = win32::CreateProcessA(path.as_ptr(),
                                            ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), 0,
                                            debugger.creation_flags, ptr::null_mut(), ptr::null(),
                                            &mut debugger.startup_info as *mut _ as win32::LPVOID,
                                            &mut debugger.process_info as *mut _ as win32::LPVOID);
        error_code = win32::GetLastError();      
    }
    
    if return_code == 0 {
        println!("Process failed to launch :(");
        println!("Error code: {}", error_code);
        return;
    }

    debugger.pid = debugger.process_info.dwProcessId;
    
    println!("Process launched successfully.");
    println!("PID: {}", debugger.pid);

    debugger.process = unsafe { win32::OpenProcess(win32::PROCESS_ALL_ACCESS, 0, debugger.pid) };
}

pub fn attach(debugger: &mut Debugger, pid: win32::DWORD) {
    debugger.pid = pid;
    debugger.process = unsafe { win32::OpenProcess(win32::PROCESS_ALL_ACCESS, 0, pid) };
    let res = unsafe { win32::DebugActiveProcess(debugger.pid) };
    if res != 0 {
        debugger.attached = true;
        debug(debugger);
    }
    else {
        let err = unsafe { win32::GetLastError() };
        println!("Attaching to process {} failed.", pid);
        println!("Error code: {}", err);
    }
}

pub fn debug(debugger: &mut Debugger) {
    while debugger.attached {
        get_debug_event(debugger);
    }
}

pub fn get_debug_event(debugger: &mut Debugger) {
    let mut event = win32::DebugEvent {
        dwDebugEventCode: 0,
        dwProcessId: 0,
        dwThreadId: 0,
        u: [0u8; 160]
    };
    let status = win32::DBG_CONTINUE;

    if unsafe { win32::WaitForDebugEvent(&mut event as *mut _ as win32::LPVOID, win32::INFINITE) } != 0 {
        let _ = unsafe { win32::ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) };
    }
}

pub fn detach(debugger: Debugger) -> bool {
    let res = unsafe { win32::DebugActiveProcessStop(debugger.pid) };
    if res != 0 {
        println!("Finished debugging");
        true
    }
    else {
        let err = unsafe { win32::GetLastError() };
        println!("Something went wrong!");
        println!("Error code: {}", err);
        false
    }
}
