use win32;

use either;
use std::mem;
use std::ptr;

pub struct Debugger {
    creation_flags: win32::DWORD,
    startup_info: win32::StartupInfo,
    process_info: win32::ProcessInformation,
    pid: win32::DWORD,
    process: win32::HANDLE,
    thread: win32::HANDLE,
    context32: win32::WOW64_CONTEXT,
    context64: win32::CONTEXT,
    wow64: win32::BOOL,
    attached: bool,
}

impl Debugger {
    pub fn new() -> Debugger {
        let dbg = Debugger {
            creation_flags: 0x0,
            pid: 0,
            process: ptr::null_mut(),
            thread: ptr::null_mut(),
            context32: win32::WOW64_CONTEXT::new(),
            context64: win32::CONTEXT::new(),
            wow64: 0,
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
        let mut wow64 = 0i16;
        let res = unsafe { win32::IsWow64Process(debugger.process, &mut wow64 as win32::PBOOL) };
        debugger.wow64 = wow64;
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
    let mut event = win32::DEBUG_EVENT {
        dwDebugEventCode: 0,
        dwProcessId: 0,
        dwThreadId: 0,
        u: [0u8; 160]
    };
    let status = win32::DBG_CONTINUE;

    if unsafe { win32::WaitForDebugEvent(&mut event as win32::LPDEBUG_EVENT, win32::INFINITE) } != 0 {
        debugger.thread = match open_thread(event.dwThreadId) {
            Ok(t) => t,
            Err(_) => { return; }
        };
        if debugger.wow64 == 1 {
            debugger.context32 = match get_thread_context32(event.dwThreadId) {
                Ok(ctx) => ctx,
                Err(_) => { return; }
            };
        } else {
            debugger.context64 = match get_thread_context64(event.dwThreadId) {
                Ok(ctx) => ctx,
                Err(_) => { return; }
                };
        }
        println!("Event code: {evcode} Thread ID: {thread}", evcode = event.dwDebugEventCode,
                 thread = event.dwThreadId);
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

pub fn enumerate_threads(debugger: &Debugger) -> Result<Vec<win32::DWORD>, win32::DWORD> {
    let mut thread_entry = win32::THREADENTRY32 {
        dwSize: 0,
        cntUsage: 0,
        th32ThreadId: 0,
        th32OwnerProcessId: 0,
        tpBasePri: 0,
        tpDeltaPri: 0,
        dwFlags: 0,
    };

    let mut thread_list: Vec<win32::DWORD> = Vec::new();

    let snapshot = unsafe { win32::CreateToolhelp32Snapshot(win32::TH32CS_SNAPTHREAD, debugger.pid) };

    if ptr::eq(snapshot, ptr::null()) {
        let err = unsafe { win32::GetLastError() };
        Err(err)
    }
    else {
        thread_entry.dwSize = mem::size_of::<win32::THREADENTRY32>() as u32;
        let mut success = unsafe { win32::Thread32First(snapshot, &mut thread_entry as *mut _) };
        while success != 0 {
            if thread_entry.th32OwnerProcessId == debugger.pid {
                thread_list.push(thread_entry.th32ThreadId);
            }
            success = unsafe { win32::Thread32Next(snapshot, &mut thread_entry as *mut _) };
        }
        unsafe { win32::CloseHandle(snapshot) };
        Ok(thread_list)
    }
}

pub fn get_thread_context(debugger: &Debugger, thread_id: win32::DWORD) ->
    Result<either::Either<win32::CONTEXT,win32::WOW64_CONTEXT>, win32::DWORD> {
    if is_wow64_process(&debugger) {
        match get_thread_context32(thread_id) {
            Ok(ctx) => Ok(either::Right(ctx)),
            Err(err) => Err(err)
        }
    } else {
        match get_thread_context64(thread_id) {
            Ok(ctx) => Ok(either::Left(ctx)),
            Err(err) => Err(err)
        }
    }
}

fn get_thread_context64(thread_id: win32::DWORD) -> Result<win32::CONTEXT, win32::DWORD> {
    let mut ctx = win32::CONTEXT::new();
    ctx.ContextFlags = win32::CONTEXT_DEBUG_REGISTERS | win32::CONTEXT_FULL;
    let thread = match open_thread(thread_id) {
        Ok(t) => t,
        Err(e) => { return Err(e); }
    };
    if unsafe { win32::GetThreadContext(thread, &mut ctx as win32::LPCONTEXT) } != 0 {
        unsafe { win32::CloseHandle(thread) };
        Ok(ctx)
    } else {
        let err = unsafe { win32::GetLastError() };
        Err(err)
    }    
}

fn get_thread_context32(thread_id: win32::DWORD) -> Result<win32::WOW64_CONTEXT, win32::DWORD> {
    let mut ctx = win32::WOW64_CONTEXT::new();
    ctx.ContextFlags = win32::CONTEXT_DEBUG_REGISTERS | win32::CONTEXT_FULL;
    let thread = match open_thread(thread_id) {
        Ok(t) => t,
        Err(e) => { return Err(e); }
    };
    if unsafe { win32::Wow64GetThreadContext(thread, &mut ctx as win32::PWOW64_CONTEXT) } != 0 {
        unsafe { win32::CloseHandle(thread) };
        Ok(ctx)
    } else {
        let err = unsafe { win32::GetLastError() };
        Err(err)
    }
}

fn is_wow64_process(debugger: &Debugger) -> bool {
    let mut res: win32::BOOL = 0;

    if ptr::eq(debugger.process,ptr::null_mut()) {
        return false;
    } else {
        let rv = unsafe { win32::IsWow64Process(debugger.process, &mut res as win32::PBOOL) };
        if rv == 0 {
            let err = unsafe { win32::GetLastError() };
            println!("Error code: {}", err);
            panic!("IsWow64Process failed.");
        }
    }

    if res != 0 {
        true
    } else {
        false
    }
}

fn open_thread(thread_id: win32::DWORD) -> Result<win32::HANDLE, win32::DWORD> {
    let thread = unsafe { win32::OpenThread(win32::THREAD_ALL_ACCESS, 0, thread_id) };
    if ptr::eq(thread, ptr::null_mut()) {
        let err = unsafe { win32::GetLastError() };
        Err(err)
    } else {
        Ok(thread)
    }
}
