/* Types */

type HANDLE = *mut std::os::raw::c_void;
type LPBYTE = *mut u8;
type LPSTR = *mut i8;
type DWORD = u32;
type WORD = u16;

const DEBUG_PROCESS = 0x1;
const CREATE_NEW_CONSOLE = 0x10;


/* StartupInfo structure for CreateProcessA() */
struct StartupInfo {
    cb: DWORD,
    lpReserved: LPSTR,
    lpDesktop: LPSTR,
    lpTitle: LPSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: WORD,
    cbReserved2: WORD,
    lpReserved2: LPBYTE,
    hSTdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE
    
}

/* ProcessInformation structure for CreateProcessA() */
struct ProcessInformation {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD
}
