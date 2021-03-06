#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use std::os::raw;
use std::ptr;
/* Types */

pub type BOOL = i16;
pub type BYTE = u8;
pub type DWORD = u32;
pub type DWORD64 = u64;
pub type DWORD_PTR = ULONG_PTR;
pub type FARPROC = *const raw::c_void;
pub type HANDLE = *mut raw::c_void;
pub type LONG = i32;
pub type LONGLONG = i64;
pub type LPBYTE = *mut u8;
pub type LPCONTEXT = *mut CONTEXT;
pub type LPCSTR = *const i8;
pub type LPCVOID = *const raw::c_void;
pub type LPDEBUG_EVENT = *mut DEBUG_EVENT;
pub type LPSECURITY_ATTRIBUTES = *mut raw::c_void;
pub type LPSYSTEM_INFO = *mut SYSTEM_INFO;
pub type LPTHREADENTRY32 = *mut THREADENTRY32;
pub type LPTSTR = *mut u8;
pub type LPVOID = *mut raw::c_void;
pub type LPCTSTR = *const u8;
pub type PBOOL = *mut BOOL;
pub type PDWORD = *mut DWORD;
pub type PMEMORY_BASIC_INFORMATION = *mut MEMORY_BASIC_INFORMATION;
pub type PVOID = *mut raw::c_void;
pub type PWOW64_CONTEXT = *mut WOW64_CONTEXT;
pub type SIZE_T = usize;
pub type UCHAR = u8;
pub type ULONG = u32;
pub type ULONGLONG = u64;
pub type ULONG_PTR = u64;
pub type WORD = u16;
pub type XMM_SAVE_AREA32 = XSAVE_FORMAT;

pub const DEBUG_PROCESS: DWORD = 0x1;
pub const CONTEXT_DEBUG_REGISTERS: DWORD =  0x00010010;
pub const CONTEXT_FULL: DWORD = 0x00010007;
pub const CREATE_NEW_CONSOLE: DWORD = 0x10;
pub const DBG_CONTINUE: DWORD = 0x00010002;
pub const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x80010001;
pub const DBG_TERMINATE_PROCESS: DWORD = 0x40010004;
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const MAXIMUM_SUPPORTED_EXTENSION: usize = 512;
pub const PROCESS_ALL_ACCESS: DWORD = (0x000F0000 | 0x00100000 | 0xFFF);
pub const TH32CS_SNAPTHREAD: DWORD = 0x00000004;
pub const THREAD_ALL_ACCESS: DWORD = 0x001F03FF;

// Debugging event codes
pub const EXCEPTION_DEBUG_EVENT: DWORD = 0x1;
pub const CREATE_THREAD_DEBUG_EVENT: DWORD = 0x2;
pub const CREATE_PROCESS_DEBUG_EVENT: DWORD = 0x3;
pub const EXIT_THREAD_DEBUG_EVENT: DWORD = 0x4;
pub const EXIT_PROCESS_DEBUG_EVENT: DWORD = 0x5;
pub const LOAD_DLL_DEBUG_EVENT: DWORD = 0x6;
pub const UNLOAD_DLL_DEBUG_EVENT: DWORD = 0x7;
pub const OUTPUT_DEBUG_STRING_EVENT: DWORD = 0x8;
pub const RIP_EVENT: DWORD = 0x9;

// Debug exception codes
pub const EXCEPTION_ACCESS_VIOLATION: DWORD = 0xC0000005;
pub const EXCEPTION_BREAKPOINT: DWORD = 0x80000003;
pub const EXCEPTION_GUARD_PAGE: DWORD = 0x80000001;
pub const EXCEPTION_SINGLE_STEP: DWORD = 0x80000004;

// HW breakpoint codes
pub const HW_ACCESS: DWORD = 0x00000003;
pub const HW_EXECUTE: DWORD = 0x00000000;
pub const HW_WRITE: DWORD = 0x00000001;

// Memory page permissions
pub const PAGE_NOACCESS: DWORD = 0x00000001;
pub const PAGE_READONLY: DWORD = 0x00000002;
pub const PAGE_READWRITE: DWORD = 0x00000004;
pub const PAGE_WRITECOPY: DWORD = 0x00000008;
pub const PAGE_EXECUTE: DWORD = 0x00000010;
pub const PAGE_EXECUTE_READ: DWORD = 0x00000020;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x00000040;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x00000080;
pub const PAGE_GUARD: DWORD = 0x00000100;
pub const PAGE_NOCACHE: DWORD = 0x00000200;
pub const PAGE_WRITECOMBINE: DWORD = 0x00000400;

// This type is needed to force CONTEXT to align to 16 bytes
#[repr(simd)]
pub struct ALIGNMENT(pub u64, pub u64);

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
    pub _align: [ALIGNMENT; 0] // Aligment to 16 bytes for CONTEXT
}

impl CONTEXT {
    pub fn new() -> CONTEXT {
        let ctx = CONTEXT {
            P1Home: 0,
            P2Home: 0,
            P3Home: 0,
            P4Home: 0,
            P5Home: 0,
            P6Home: 0,
            ContextFlags: 0,
            MxCsr: 0,
            SegCs: 0,
            SegDs: 0,
            SegEs: 0,
            SegFs: 0,
            SegGs: 0,
            SegSs: 0,
            EFlags: 0,
            Dr0: 0,
            Dr1: 0,
            Dr2: 0,
            Dr3: 0,
            Dr6: 0,
            Dr7: 0,
            Rax: 0,
            Rcx: 0,
            Rdx: 0,
            Rbx: 0,
            Rsp: 0,
            Rbp: 0,
            Rsi: 0,
            Rdi: 0,
            R8: 0,
            R9: 0,
            R10: 0,
            R11: 0,
            R12: 0,
            R13: 0,
            R14: 0,
            R15: 0,
            Rip: 0,
            FltSave: XMM_SAVE_AREA32 {
                ControlWord: 0,
                StatusWord: 0,
                TagWord: 0,
                Reserved1: 0,
                ErrorOpcode: 0,
                ErrorOffset: 0,
                ErrorSelector: 0,
                Reserved2: 0,
                DataOffset: 0,
                DataSelector: 0,
                Reserved3: 0,
                MxCsr: 0,
                MxCsr_Mask: 0,
                FloatRegisters: [M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                                 M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                                 M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                                 M128A {Low: 0, High: 0},M128A {Low: 0, High: 0}],
                XmmRegisters: [M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                               M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                               M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                               M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                               M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                               M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                               M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                               M128A {Low: 0, High: 0},M128A {Low: 0, High: 0}],
                Reserved4: [0u8; 96],
            },
            VectorRegister: [M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0},
                             M128A {Low: 0, High: 0},M128A {Low: 0, High: 0}],
            VectorControl: 0,
            DebugControl: 0,
            LastBranchToRip: 0,
            LastBranchFromRip: 0,
            LastExceptionToRip: 0,
            LastExceptionFromRip: 0,
            _align: [ ALIGNMENT{0:0,1:0}; 0]
        };
        ctx
    }
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

impl WOW64_CONTEXT {
    pub fn new() -> WOW64_CONTEXT {
        let ctx = WOW64_CONTEXT {
            ContextFlags: 0,
            Dr0: 0,
            Dr1: 0,
            Dr2: 0,
            Dr3: 0,
            Dr6: 0,
            Dr7: 0,
            FloatSave: FLOATING_SAVE_AREA {
                ControlWord: 0,
                StatusWord: 0,
                TagWord: 0,
                ErrorOffset: 0,
                ErrorSelector: 0,
                DataOffset: 0,
                DataSelector: 0,
                RegisterArea: [0u8; 80],
                Cr0NpxState: 0,
            },
            SegGs: 0,
            SegFs: 0,
            SegEs: 0,
            SegDs: 0,
            Edi: 0,
            Esi: 0,
            Ebx: 0,
            Edx: 0,
            Ecx: 0,
            Eax: 0,
            Ebp: 0,
            Eip: 0,
            SegCs: 0,
            Esp: 0,
            SegSs: 0,
            ExtendedRegisters: [0u8; MAXIMUM_SUPPORTED_EXTENSION],
        };
        ctx
    }
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

#[repr(C)]
pub struct EXCEPTION_DEBUG_INFO {
    pub ExceptionRecord: EXCEPTION_RECORD,
    pub dwFirstChance: DWORD,
}

impl EXCEPTION_DEBUG_INFO {
    pub fn new() -> EXCEPTION_DEBUG_INFO {
        EXCEPTION_DEBUG_INFO {
            ExceptionRecord: EXCEPTION_RECORD::new(),
            dwFirstChance: 0,
        }
    }
}

#[repr(C)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: DWORD,
    pub ExceptionFlags: DWORD,
    pub ExceptionRecord: *const EXCEPTION_RECORD,
    pub ExceptionAddress: PVOID,
    pub NumberParameters: DWORD,
    pub ExceptionInformation: [ULONG_PTR; EXCEPTION_MAXIMUM_PARAMETERS],
}

impl EXCEPTION_RECORD {
    pub fn new() -> EXCEPTION_RECORD {
        EXCEPTION_RECORD {
            ExceptionCode: 0,
            ExceptionFlags: 0,
            ExceptionRecord: ptr::null(),
            ExceptionAddress: ptr::null_mut(),
            NumberParameters: 0,
            ExceptionInformation: [0; EXCEPTION_MAXIMUM_PARAMETERS],
        }
    }
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

#[repr(C)]
pub struct DEBUG_EVENT {
    pub dwDebugEventCode: DWORD,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
    pub u: DEBUG_EVENT_UNION, //[u8; 160]
}

#[repr(C)]
pub union DEBUG_EVENT_UNION {
    pub blob: [u8; 160],
    pub Exception: EXCEPTION_DEBUG_INFO,
}

#[repr(C)]
pub struct SYSTEM_INFO {
    pub u: SYSTEM_INFO_UNION,
    pub dwPageSize: DWORD,
    pub lpMinimumApplicationAddress: LPVOID,
    pub lpMaximumApplicationAddress: LPVOID,
    pub dwActiveProcessorMask: DWORD_PTR,
    pub dwNumberOfProcessors: DWORD,
    pub dwProcessorType: DWORD,
    pub dwAllocationGranularity: DWORD,
    pub wProcessorLevel: WORD,
    pub wProcessorRevision: WORD,
}

impl SYSTEM_INFO {
    pub fn new() -> SYSTEM_INFO {
        let sysinf = SYSTEM_INFO {
            u: SYSTEM_INFO_UNION { dwOemId: 0 },
            dwPageSize: 0,
            lpMinimumApplicationAddress: ptr::null_mut(),
            lpMaximumApplicationAddress: ptr::null_mut(),
            dwActiveProcessorMask: 0,
            dwNumberOfProcessors: 0,
            dwProcessorType: 0,
            dwAllocationGranularity: 0,
            wProcessorLevel: 0,
            wProcessorRevision: 0,
        };
        sysinf
    }
}

#[repr(C)]
pub union SYSTEM_INFO_UNION {
    dwOemId: DWORD,
    s: _INNER_SYSTEM_INFO,
}

#[repr(C)]
pub struct _INNER_SYSTEM_INFO {
    pub wProcessorArchitecture: WORD,
    pub wReserved: WORD,
}

#[repr(C)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: PVOID,
    pub AllocationBase: PVOID,
    pub AllocationProtect: DWORD,
    pub RegionSize: SIZE_T,
    pub State: DWORD,
    pub Protect: DWORD,
    pub Type: DWORD,
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
    pub fn GetModuleHandleA(lpModuleName: LPCSTR) -> HANDLE;
    pub fn GetProcAddress(hModule: HANDLE,
                          lpProcName: LPCSTR) -> FARPROC;
    pub fn GetSystemInfo(lpSystemInfo: LPSYSTEM_INFO);
    pub fn GetThreadContext(hThread: HANDLE,
                            lpContext: LPCONTEXT) -> BOOL;
    pub fn IsWow64Process(hProcess: HANDLE,
                          Wow64Process: PBOOL) -> BOOL;
    pub fn OpenProcess(dwDesiredAccess: DWORD,
                       bInheritHandle: BOOL,
                       dwProcessId: DWORD) -> HANDLE;
    pub fn OpenThread(dwDesiredAccess: DWORD,
                      bInheritHandle: BOOL,
                      dwThreadId: DWORD) -> HANDLE;
    pub fn ReadProcessMemory(hProcess: HANDLE,
                             lpBaseAddress: LPCVOID,
                             lpBuffer: LPVOID,
                             nSize: SIZE_T,
                             lpNumberOfBytesRead: *mut SIZE_T) -> BOOL;
    pub fn SetThreadContext(hThread: HANDLE,
                            lpContext: LPCONTEXT) -> BOOL;
    pub fn Thread32First(hSnapshot: HANDLE,
                         lpte: LPTHREADENTRY32) -> BOOL;
    pub fn Thread32Next(hSnapshot: HANDLE,
                        lpte: LPTHREADENTRY32) -> BOOL;
    pub fn VirtualProtectEx(hProcess: HANDLE, lpAddress: LPVOID,
                            dwSize: SIZE_T, flNewProtect: DWORD,
                            lpflOldProtect: PDWORD) -> BOOL;
    pub fn VirtualQueryEx(hProcess: HANDLE, lpAddress: LPCVOID,
                          lpBuffer: PMEMORY_BASIC_INFORMATION,
                          dwLength: SIZE_T) -> SIZE_T;
    pub fn WaitForDebugEvent(lpDebugEvent: LPDEBUG_EVENT,
                             dwMilliseconds: DWORD) -> BOOL;
    pub fn Wow64GetThreadContext(hThread: HANDLE,
                                 lpContext: PWOW64_CONTEXT) -> BOOL;
    pub fn WriteProcessMemory(hProcess: HANDLE,
                              lpBaseAddress: LPCVOID,
                              lpBuffer: LPCVOID,
                              nSize: SIZE_T,
                              lpNumberOfBytesWritten: *mut SIZE_T) -> BOOL;
}
