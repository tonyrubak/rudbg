#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use std::os::raw;
/* Types */

pub type BOOL = i16;
pub type BYTE = u8;
pub type DWORD = u32;
pub type DWORD64 = u64;
pub type HANDLE = *mut raw::c_void;
pub type LONG = i32;
pub type LONGLONG = i64;
pub type LPBYTE = *mut u8;
pub type LPCONTEXT = *mut CONTEXT;
pub type LPSECURITY_ATTRIBUTES = *mut raw::c_void;
pub type LPTHREADENTRY32 = *mut THREADENTRY32;
pub type LPTSTR = *mut u8;
pub type LPVOID = *mut raw::c_void;
pub type LPCTSTR = *const u8;
pub type PBOOL = *mut BOOL;
pub type PWOW64_CONTEXT = *mut WOW64_CONTEXT;
pub type UCHAR = u8;
pub type ULONG = u32;
pub type ULONGLONG = u64;
pub type ULONG_PTR = *mut u32;
pub type WORD = u16;
pub type XMM_SAVE_AREA32 = XSAVE_FORMAT;

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
pub struct CONTEXT {
    pub P1Home: DWORD64,
    pub P2Home: DWORD64,
    pub P3Home: DWORD64,
    pub P4Home: DWORD64,
    pub P5Home: DWORD64,
    pub P6Home: DWORD64,
    pub ContextFlags: DWORD,
    pub MxCsr: DWORD,
    pub SegCs: WORD,
    pub SegDs: WORD,
    pub SegEs: WORD,
    pub SegFs: WORD,
    pub SegGs: WORD,
    pub SegSs: WORD,
    pub EFlags: DWORD,
    pub Dr0: DWORD64,
    pub Dr1: DWORD64,
    pub Dr2: DWORD64,
    pub Dr3: DWORD64,
    pub Dr6: DWORD64,
    pub Dr7: DWORD64,
    pub Rax: DWORD64,
    pub Rcx: DWORD64,
    pub Rdx: DWORD64,
    pub Rbx: DWORD64,
    pub Rsp: DWORD64,
    pub Rbp: DWORD64,
    pub Rsi: DWORD64,
    pub Rdi: DWORD64,
    pub R8: DWORD64,
    pub R9: DWORD64,
    pub R10: DWORD64,
    pub R11: DWORD64,
    pub R12: DWORD64,
    pub R13: DWORD64,
    pub R14: DWORD64,
    pub R15: DWORD64,
    pub Rip: DWORD64,
    pub FltSave: XMM_SAVE_AREA32,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: DWORD64,
    pub DebugControl: DWORD64,
    pub LastBranchToRip: DWORD64,
    pub LastBranchFromRip: DWORD64,
    pub LastExceptionToRip: DWORD64,
    pub LastExceptionFromRip: DWORD64,
}

#[repr(C)]
pub struct XSAVE_FORMAT {
    pub ControlWord: WORD,
    pub StatusWord: WORD,
    pub TagWord: BYTE,
    pub Reserved1: BYTE,
    pub ErrorOpcode: WORD,
    pub ErrorOffset: DWORD,
    pub ErrorSelector: WORD,
    pub Reserved2: WORD,
    pub DataOffset: DWORD,
    pub DataSelector: WORD,
    pub Reserved3: WORD,
    pub MxCsr: DWORD,
    pub MxCsr_Mask: DWORD,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [BYTE; 96],
}

#[repr(C)]
pub struct M128A {
    pub Low: ULONGLONG,
    pub High: LONGLONG,
}

#[repr(C)]
pub struct WOW64_CONTEXT {
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
    pub fn IsWow64Process(hProcess: HANDLE,
                          Wow64Process: PBOOL) -> BOOL;
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
    pub fn Wow64GetThreadContext(hThread: HANDLE,
                                 lpContext: PWOW64_CONTEXT) -> BOOL;
}
