#![allow(non_snake_case)]
use std::os::raw;
/* Types */

pub type BOOL = i16;
pub type HANDLE = *mut raw::c_void;
pub type LPBYTE = *mut u8;
pub type LPSECURITY_ATTRIBUTES = *mut raw::c_void;
pub type LPTSTR = *mut u8;
pub type LPVOID = *mut raw::c_void;
pub type LPCTSTR = *const u8;
pub type DWORD = u32;
pub type WORD = u16;

pub const DEBUG_PROCESS: DWORD = 0x1;
pub const CREATE_NEW_CONSOLE: DWORD = 0x10;


/* StartupInfo structure for CreateProcessA() */
pub struct StartupInfo {
    pub cb: DWORD,
    pub lpReserved: LPTSTR,
    pub lpDesktop: LPTSTR,
    pub lpTitle: LPTSTR,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: WORD,
    pub cbReserved2: WORD,
    pub lpReserved2: LPBYTE,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE
    
}

/* ProcessInformation structure for CreateProcessA() */
pub struct ProcessInformation {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD
}

pub struct SecurityAttributes {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL
}

#[link(name = "kernel32")]
extern "stdcall" {
    pub fn CreateProcessA(lpApplicationName: LPCTSTR,
                         lpCommandLine: LPTSTR,
                         lpProcessAttributes: LPSECURITY_ATTRIBUTES,
                         lpThreadAttributes: LPSECURITY_ATTRIBUTES,
                         bInheritHandles: BOOL,
                         dwCreationFlags: DWORD,
                         lpEnvironment: LPVOID,
                         lpCurrentDirectory: LPCTSTR,
                         lpStartupInfo: LPVOID,
                         lpProcessInformation: LPVOID
                         ) -> BOOL;
    pub fn GetLastError() -> DWORD;
}
