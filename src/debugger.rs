use win32;

use either;
use std::collections::HashMap;
use std::ffi;
use std::mem;
use std::ptr;
use std::slice;

pub struct Debugger {
    creation_flags: win32::DWORD,
    startup_info: win32::StartupInfo,
    process_info: win32::ProcessInformation,
    pid: win32::DWORD,
    process: win32::HANDLE,
    thread_id: win32::DWORD,
    context32: win32::WOW64_CONTEXT,
    context64: win32::CONTEXT,
    wow64: win32::BOOL,
    exception_code: win32::DWORD,
    exception_address: win32::PVOID,
    attached: bool,
    breakpoints: HashMap<win32::LPCVOID, Vec<u8>>,
    sys_first_breakpoint: bool,
    hw_breakpoints: [win32::LPCVOID; 4],
    system_info: win32::SYSTEM_INFO,
    page_size: win32::DWORD,
    guarded_pages: Vec<win32::PVOID>,
    memory_breakpoints: HashMap<win32::LPCVOID, (win32::SIZE_T, win32::MEMORY_BASIC_INFORMATION)>,
}

impl Debugger {
    pub fn new() -> Debugger {
        let mut dbg = Debugger {
            creation_flags: 0x0,
            pid: 0,
            process: ptr::null_mut(),
            thread_id: 0,
            context32: win32::WOW64_CONTEXT::new(),
            context64: win32::CONTEXT::new(),
            wow64: 0,
            exception_code: 0,
            exception_address: ptr::null_mut(),
            attached: false,
            breakpoints: HashMap::new(),
            sys_first_breakpoint: true,
            hw_breakpoints: [ptr::null_mut(); 4],
            page_size: 0,
            guarded_pages: Vec::new(),
            memory_breakpoints: HashMap::new(),
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
            },
            system_info: win32::SYSTEM_INFO::new(),
        };
        let _ = unsafe { win32::GetSystemInfo(&mut dbg.system_info as win32::LPSYSTEM_INFO) };
        dbg.page_size = dbg.system_info.dwPageSize;
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

pub fn attach(debugger: &mut Debugger, pid: win32::DWORD) -> u32 {
    let retval: u32;
    debugger.process = unsafe { win32::OpenProcess(win32::PROCESS_ALL_ACCESS, 0, pid) };
    if ptr::eq(debugger.process,ptr::null_mut()) {
        retval = unsafe { win32::GetLastError() };
    } else {
        let res = unsafe { win32::DebugActiveProcess(pid) };
        if res != 0 {
            debugger.attached = true;
            debugger.pid = pid;
            let mut wow64 = 0i16;
            let _ = unsafe { win32::IsWow64Process(debugger.process, &mut wow64 as win32::PBOOL) };
            debugger.wow64 = wow64;
            retval = 0;
        }
        else {
            retval = unsafe { win32::GetLastError() };
            println!("Attaching to process {} failed.", pid);
            println!("Error code: {}", retval);
        }
    }
    retval
}

pub fn debug(debugger: &mut Debugger) {
    while debugger.attached {
        get_debug_event(debugger);
    }
}

pub fn get_debug_event(mut debugger: &mut Debugger) {
    let mut event = win32::DEBUG_EVENT {
        dwDebugEventCode: 0,
        dwProcessId: 0,
        dwThreadId: 0,
        u: win32::DEBUG_EVENT_UNION { blob: [0u8; 160] },
    };
    let mut status = win32::DBG_CONTINUE;

    if unsafe { win32::WaitForDebugEvent(&mut event as win32::LPDEBUG_EVENT, win32::INFINITE) } != 0 {
        let thread = match open_thread(event.dwThreadId) {
            Ok(t) => t,
            Err(_) => { panic!("Could not get handle to thread"); }
        };
        debugger.thread_id = event.dwThreadId;
        if debugger.wow64 == 1 {
            debugger.context32 = match get_thread_context32(event.dwThreadId) {
                Ok(ctx) => ctx,
                Err(_) => { return; }
            };
        } else {
            debugger.context64 = match get_thread_context64(thread) {
                Ok(ctx) => ctx,
                Err(_) => { panic!("Could not get thread context"); }
            };
        }

        if event.dwDebugEventCode == win32::EXCEPTION_DEBUG_EVENT {
            unsafe {
                debugger.exception_code = event.u.Exception.ExceptionRecord.ExceptionCode;
                debugger.exception_address = event.u.Exception.ExceptionRecord.ExceptionAddress;
            }
            if debugger.exception_code == win32::EXCEPTION_ACCESS_VIOLATION {
                println!("Access violation detected");
            } else if debugger.exception_code == win32::EXCEPTION_BREAKPOINT {
                status = exception_handler_breakpoint(&mut debugger);
            } else if debugger.exception_code == win32::EXCEPTION_GUARD_PAGE {
                println!("Guard page access detected");
            } else if debugger.exception_code == win32::EXCEPTION_SINGLE_STEP {
                status = exception_handler_single_step(&mut debugger);;
            }
        }
        
        println!("Event code: {evcode} Thread ID: {thread}", evcode = event.dwDebugEventCode,
                 thread = event.dwThreadId);
        let _ = unsafe { win32::ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) };
        let _ = unsafe { win32::CloseHandle(thread) };
    }
}

pub fn detach(debugger: &mut Debugger) -> bool {
    let retval: bool;
    if debugger.attached {
        let res = unsafe { win32::DebugActiveProcessStop(debugger.pid) };
        if res != 0 {
            debugger.attached = false;
            println!("Finished debugging");
            retval = true;
        }
        else {
            let err = unsafe { win32::GetLastError() };
            eprintln!("Something went wrong detaching!");
            eprintln!("Error code: {}", err);
            retval = false;
        }
    } else {
        retval = false;
    }
    return retval;
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

pub fn get_thread_context(thread_id: win32::DWORD, wow64: win32::BOOL) ->
    Result<either::Either<win32::CONTEXT,win32::WOW64_CONTEXT>, win32::DWORD> {
    if wow64 != 0 {
        match get_thread_context32(thread_id) {
            Ok(ctx) => Ok(either::Right(ctx)),
            Err(err) => Err(err)
        }
    } else {
        match get_thread_context64_from_id(thread_id) {
            Ok(ctx) => Ok(either::Left(ctx)),
            Err(err) => Err(err)
        }
    }
}
fn get_thread_context64(thread: win32::HANDLE) -> Result<win32::CONTEXT, win32::DWORD> {
    let mut ctx = win32::CONTEXT::new();
    ctx.ContextFlags = win32::CONTEXT_DEBUG_REGISTERS | win32::CONTEXT_FULL;
    if unsafe { win32::GetThreadContext(thread, &mut ctx as win32::LPCONTEXT) } != 0 {
        unsafe { win32::CloseHandle(thread) };
        Ok(ctx)
    } else {
        let err = unsafe { win32::GetLastError() };
        Err(err)
    }    
}


fn get_thread_context64_from_id(thread_id: win32::DWORD) -> Result<win32::CONTEXT, win32::DWORD> {
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

fn exception_handler_breakpoint(debugger: &mut Debugger) -> win32::DWORD {
    let retval: win32::DWORD;
    println!("Handling breakpoint");
    println!("Exception address: 0x{:x}", debugger.exception_address as u32);
    
    if !debugger.breakpoints.contains_key(&(debugger.exception_address as win32::LPCVOID)) {
        if debugger.sys_first_breakpoint {
            println!("{:x}: System break exception (first chance)",
                     debugger.exception_address as u32);
            debugger.sys_first_breakpoint = false;
            retval = win32::DBG_CONTINUE;
        }
        else {
            println!("{:x}: Unexpected break exception. Terminating debugging.",
                     debugger.exception_address as u32);
            retval = win32::DBG_TERMINATE_PROCESS;
        }
    } else {
        println!("Breakpoint hit.");
        let instr = &debugger.breakpoints[&(debugger.exception_address as win32::LPCVOID)];
        let _ = write_process_memory(&debugger, debugger.exception_address,
                             instr.as_slice());
        
        debugger.context64 = match get_thread_context64_from_id(debugger.thread_id) {
            Ok(ctx) => ctx,
            Err(e) => {
                println!("Error code: {}", e);
                panic!("Could not get thread context");
            }
        };
        
        debugger.context64.Rip -= 1;

        let thread = match open_thread(debugger.thread_id) {
            Ok(th) => th,
            Err(n) => {
                eprintln!("Error code: {}", n);
                panic!("Couldn't get a handle to the thread");
            }
        };
        
        let res = unsafe { win32::SetThreadContext(thread,
                                                   &mut debugger.context64 as win32::LPCONTEXT) };
        if res == 0 {
            let err = unsafe { win32::GetLastError() };
            println!("Error code: {}", err);
            panic!("Error setting thread context.");
        }
        let _ = unsafe { win32::CloseHandle(thread) };
        retval = win32::DBG_CONTINUE;
    }
    retval
}

fn exception_handler_single_step(mut debugger: &mut Debugger) -> win32::DWORD {
    if debugger.wow64 != 0 {
        panic!("Exception handling not supported for WOW64 images");
    }

    // Get a thread context and see if this was one of our breakpoints
    let ctx = match get_thread_context64_from_id(debugger.thread_id) {
        Ok(ctx) => ctx,
        Err(_) => { panic!("Error getting thread context"); }
    };

    let slot = if ctx.Dr6 & 0x1 == 1 && !ptr::eq(debugger.hw_breakpoints[0], ptr::null_mut()) {
        0
    } else if ctx.Dr6 & 0x2 == 1 && !ptr::eq(debugger.hw_breakpoints[1], ptr::null_mut()) {
        1
    } else if ctx.Dr6 & 0x4 == 1 && !ptr::eq(debugger.hw_breakpoints[2], ptr::null_mut()) {
        2
    }  else if ctx.Dr6 & 0x2 == 8 && !ptr::eq(debugger.hw_breakpoints[3], ptr::null_mut()) {
        3
    } else { // Not my breakpoint, not my problem
        return win32::DBG_EXCEPTION_NOT_HANDLED;
    };

    let _ = delete_hw_bp(&mut debugger, slot);
    println!("Deleted hardware breakpoint");

    // Remove hardware breakpoint
    win32::DBG_CONTINUE
}

fn read_process_memory(debugger: &Debugger, address: win32::LPCVOID, length: usize)
                       -> Result<Vec<u8>,win32::DWORD> {
    let mut read = 0usize;
    let res: win32::BOOL;
    
    let mut read_buf = Vec::<u8>::with_capacity(length);

    for _ in 0..length {
        read_buf.push(0);
    }
        
    res = unsafe { win32::ReadProcessMemory(debugger.process,
                                            address,
                                            read_buf.as_mut_ptr() as win32::LPVOID,
                                            length,
                                            &mut read as *mut win32::SIZE_T) };

    if res == 0 {
        let err = unsafe { win32::GetLastError() };
        Err(err)
    } else {
        Ok(read_buf)
    }
}

fn write_process_memory(debugger: &Debugger, address: win32::LPCVOID, data: &[u8])
                        -> win32::DWORD {
    let mut written = 0usize;
    let length = data.len();

    let res = unsafe { win32::WriteProcessMemory(debugger.process,
                                                 address,
                                                 data.as_ptr() as win32::LPCVOID,
                                                 length,
                                                 &mut written as *mut win32::SIZE_T) };
    
    if res == 0 {
        unsafe { win32::GetLastError() }
    } else {
        0
    }
}

pub fn bp_set(debugger: &mut Debugger, address: win32::LPCVOID) -> win32::DWORD {
    if !debugger.breakpoints.contains_key(&address) {
        let b = match read_process_memory(&debugger, address, 1) {
            Ok(buf) => buf,
            Err(n) => { return n; }
        };
        let _ = write_process_memory(&debugger, address, b"\xCC");
        debugger.breakpoints.insert(address, b);
    }
    0
}

pub fn bp_set_hw(debugger: &mut Debugger, address: win32::LPCVOID,
                 length: usize, condition: win32::DWORD) -> bool {
    
    let available_reg: usize;

    let mut m_length = length;

    if debugger.wow64 != 0 {
        println!("Hardware breakpoints not implemented for WOW64 images.");
        return false;
    }
    
    // Check to make sure the length is legal
    if length != 1 && length != 2 && length != 4 {
        return false;
    } else { m_length -= 1; }

    // Check to make sure the passed condition code is legal
    if condition != win32::HW_ACCESS && condition != win32::HW_EXECUTE && condition != win32::HW_WRITE {
        return false;
    }

    // Get an available hardware breakpoint slot

    if ptr::eq(debugger.hw_breakpoints[0], ptr::null_mut()) {
        available_reg = 0;
    } else if ptr::eq(debugger.hw_breakpoints[1], ptr::null_mut()) {
        available_reg = 1;
    } else if ptr::eq(debugger.hw_breakpoints[2], ptr::null_mut()) {
        available_reg = 2;
    } else if ptr::eq(debugger.hw_breakpoints[3], ptr::null_mut()) {
        available_reg = 3;
    } else { return false; }

    // Register the hardware breakpoint in all threads
    let threads = match enumerate_threads(&debugger) {
        Ok(ts) => ts,
        Err(_) => { return false; }
    };

    for thread_id in threads {
        let mut ctx = match get_thread_context64_from_id(thread_id) {
            Ok(c) => c,
            Err(_) => { return false; }
        };
        
        ctx.Dr7 = ctx.Dr7 | (1 << (available_reg * 2));
        
        match available_reg {
            0 => ctx.Dr0 = address as u64,
            1 => ctx.Dr1 = address as u64,
            2 => ctx.Dr2 = address as u64,
            3 => ctx.Dr3 = address as u64,
            _ => { return false; }
        };

        // Set condition
        ctx.Dr7 = ctx.Dr7 | ((condition << ((available_reg * 4) + 16)) as u64);

        // Set length
        ctx.Dr7 = ctx.Dr7 | ((m_length << ((available_reg * 4) + 18)) as u64);

        // Get thread handle and set context
        let mut thread = match open_thread(thread_id) {
            Ok(t) => t,
            Err(_) => { return false; }
        };

        let _ = unsafe { win32::SetThreadContext(thread, &mut ctx as win32::LPCONTEXT) };

        debugger.hw_breakpoints[available_reg] = address;

        let _ = unsafe { win32::CloseHandle(thread) };
    }
    return true;
}

pub fn bp_set_mem(debugger: &mut Debugger, address: win32::LPCVOID, size: win32::SIZE_T) -> bool {
    let mut mbi = win32::MEMORY_BASIC_INFORMATION {
        BaseAddress: ptr::null_mut(),
        AllocationBase: ptr::null_mut(),
        AllocationProtect: 0,
        RegionSize: 0,
        State: 0,
        Protect: 0,
        Type: 0,
    };

    if unsafe { win32::VirtualQueryEx(debugger.process, address, &mut mbi as *mut _,
                             mem::size_of::<win32::MEMORY_BASIC_INFORMATION>()) } <
        mem::size_of::<win32::MEMORY_BASIC_INFORMATION>() {
            return false;
        }

    let mut current_page = mbi.BaseAddress as usize;

    while current_page <= (address as usize) + size {
        debugger.guarded_pages.push(current_page as win32::PVOID);

        let mut old_prot = 0u32;

        if unsafe { win32::VirtualProtectEx(debugger.process, current_page as win32::PVOID, size,
                                   mbi.Protect | win32::PAGE_GUARD, &mut old_prot as *mut _) } == 0 {
            return false;
        }
        current_page += debugger.page_size as usize;
    }

    debugger.memory_breakpoints.insert(address,(size,mbi));
    
    return true;
}

pub fn resolve_function(dll_name: &str, function_name: &str) -> win32::FARPROC {
    let address: win32::FARPROC;
    unsafe {
        let handle = win32::GetModuleHandleA(ffi::CString::new(dll_name).unwrap().as_ptr());
        address = win32::GetProcAddress(handle, ffi::CString::new(function_name).unwrap().as_ptr());
    }
    address
}

fn delete_hw_bp(debugger: &mut Debugger, slot: usize) -> bool {
    let threads = match enumerate_threads(&debugger) {
        Ok(ts) => ts,
        Err(_) => { panic!("Error getting threads");}
    };
    for thread_id in threads {
        let mut ctx = match get_thread_context64_from_id(thread_id) {
            Ok(ctx) => ctx,
            Err(_) => { panic!("Error getting thread context"); }
        };

        ctx.Dr7 = ctx.Dr7 & !(1 << (slot * 2));

        match slot {
            0 => ctx.Dr0 = 0,
            1 => ctx.Dr1 = 0,
            2 => ctx.Dr2 = 0,
            3 => ctx.Dr3 = 0,
            _ => { return false; }
        };

        ctx.Dr7 = ctx.Dr7 & !(3 << ((slot * 4) + 16));
        ctx.Dr7 = ctx.Dr7 & !(3 << ((slot * 4) + 18));

        let thread = match open_thread(thread_id) {
            Ok(t) => t,
            Err(_) => { panic!("Failed to open thread"); }
        };
                                 
        let _ = unsafe { win32::SetThreadContext(thread, &mut ctx as win32::LPCONTEXT) };
    }
    debugger.hw_breakpoints[slot] = ptr::null_mut();
    true
}
