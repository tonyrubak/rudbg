#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use std::os::raw;
/* Types */

pub type BOOL = i16;
pub type BYTE = u8;
pub type HANDLE = *mut raw::c_void;
pub type LONG = i32;
pub type LPBYTE = *mut u8;
pub type LPCONTEXT = *mut Context;
pub type LPSECURITY_ATTRIBUTES = *mut raw::c_void;
pub type LPTHREADENTRY32 = *mut THREADENTRY32;
pub type LPTSTR = *mut u8;
pub type LPVOID = *mut raw::c_void;
pub type LPCTSTR = *const u8;
pub type UCHAR = u8;
pub type ULONG = u32;
pub type ULONG_PTR = *mut u32;
pub type DWORD = u32;
pub type WORD = u16;

pub const DEBUG_PROCESS: DWORD = 0x1;
pub const CONTEXT_DEBUG_REGISTERS: DWORD =  0x00010010;
pub const CONTEXT_FULL: DWORD = 0x00010007;
pub const CREATE_NEW_CONSOLE: DWORD = 0x10;
pub const DBG_CONTINUE: DWORD = 0x00010002;
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const MAXIMUM_SUPPORTED_EXTENSION: usize = 512;
pub const PROCESS_ALL_ACCESS: DWORD = (0x000F0000 | 0x00100000 | 0xFFF);
pub const TH32CS_SNAPTHREAD: DWORD = 0x00000004;
pub const THREAD_ALL_ACCESS: DWORD = 0x001F03FF;

#[repr(C)]
pub struct Context {
    pub ContextFlags: DWORD,
    pub Dr0: DWORD,
    pub Dr1: DWORD,
    pub Dr2: DWORD,
    pub Dr3: DWORD,
    pub Dr6: DWORD,
    pub Dr7: DWORD,
    pub FloatSave: FLOATING_SAVE_AREA,
    pub SegGs: DWORD,
    pub SegFs: DWORD,
    pub SegEs: DWORD,
    pub SegDs: DWORD,
    pub Edi: DWORD,
    pub Esi: DWORD,
    pub Ebx: DWORD,
    pub Edx: DWORD,
    pub Ecx: DWORD,
    pub Eax: DWORD,
    pub Ebp: DWORD,
    pub Eip: DWORD,
    pub SegCs: DWORD,
    pub Esp: DWORD,
    pub SegSs: DWORD,
    pub ExtendedRegisters: [BYTE; MAXIMUM_SUPPORTED_EXTENSION],
}

#[repr(C)]
pub struct THREADENTRY32 {
    pub dwSize: DWORD,
    pub cntUsage: DWORD,
    pub th32ThreadId: DWORD,
    pub th32OwnerProcessId: DWORD,
    pub tpBasePri: LONG,
    pub tpDeltaPri: LONG,
    pub dwFlags: DWORD,
}

#[repr(C)]
pub struct FLOATING_SAVE_AREA {
    pub ControlWord: ULONG,
    pub StatusWord: ULONG,
    pub TagWord: ULONG,
    pub ErrorOffset: ULONG,
    pub ErrorSelector: ULONG,
    pub DataOffset: ULONG,
    pub DataSelector: ULONG,
    pub RegisterArea: [UCHAR; 80],
    pub Cr0NpxState: ULONG,
}
    

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

pub struct DebugEvent {
    pub dwDebugEventCode: DWORD,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
    pub u: [u8; 160]
}

/* Import the functions from kernel32.dll that we need */
#[link(name = "kernel32")]
extern "stdcall" {
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
    pub fn ContinueDebugEvent(dwProcessId: DWORD,
                              dwThreadId: DWORD,
                              dwContinueStatus: DWORD) -> BOOL;
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
    pub fn CreateToolhelp32Snapshot(dwFlags: DWORD,
                                    th32ProcessId: DWORD) -> HANDLE;
    pub fn DebugActiveProcess(dwProcessId: DWORD) -> BOOL;
    pub fn DebugActiveProcessStop(dwProcessId: DWORD) -> BOOL;
    pub fn GetLastError() -> DWORD;
    pub fn GetThreadContext(hThread: HANDLE,
                            lpContext: LPCONTEXT) -> BOOL;
    pub fn OpenProcess(dwDesiredAccess: DWORD,
                       bInheritHandle: BOOL,
                       dwProcessId: DWORD) -> HANDLE;
    pub fn OpenThread(dwDesiredAccess: DWORD,
                      bInheritHandle: BOOL,
                      dwThreadId: DWORD) -> HANDLE;
    pub fn SetThreadContext(hThread: HANDLE,
                            lpContext: LPCONTEXT) -> BOOL;
    pub fn Thread32First(hSnapshot: HANDLE,
                         lpte: LPTHREADENTRY32) -> BOOL;
    pub fn Thread32Next(hSnapshot: HANDLE,
                        lpte: LPTHREADENTRY32) -> BOOL;
    pub fn WaitForDebugEvent(lpDebugEvent: LPVOID,
                             dwMilliseconds: DWORD) -> BOOL;
}
