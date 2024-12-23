use std::{
    fs::File,
    mem,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows::{
    core::{self, Free, PCWSTR},
    Win32::{
        Foundation, Security,
        System::{Diagnostics::Debug, Memory, Threading},
    },
};

pub unsafe fn inspect(pid: i32, catch_exc: bool, catch_exit: bool, output: &mut File) {
    let process_id = pid as u32;

    if !catch_exc && !catch_exit {
        minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(
            crash_context::CrashContext {
                process_id,
                thread_id: 0,
                exception_code: 0,
                exception_pointers: ptr::null(),
            },
            None,
            output,
        )
        .unwrap();
        return;
    }

    let mut process_h = Threading::OpenProcess(
        Threading::PROCESS_VM_OPERATION | Threading::PROCESS_VM_WRITE,
        false,
        process_id,
    )
    .unwrap();

    if wow(process_h) != wow(Threading::GetCurrentProcess()) {
        panic!("process arch mismatch");
    }

    let _ = enable_privileges(Security::SE_DEBUG_NAME);

    Debug::DebugActiveProcess(process_id).unwrap();
    let mut event = Debug::DEBUG_EVENT::default();
    println!("inspecting process: {}", pid);
    while let Ok(_) = Debug::WaitForDebugEvent(&mut event, Threading::INFINITE) {
        match event.dwDebugEventCode {
            Debug::EXCEPTION_DEBUG_EVENT
                if event.u.Exception.ExceptionRecord.ExceptionCode
                    != Foundation::EXCEPTION_BREAKPOINT =>
            {
                let thread_h = Threading::OpenThread(
                    Threading::THREAD_GET_CONTEXT,
                    Foundation::FALSE,
                    event.dwThreadId,
                )
                .unwrap();
                let mut ctx: crash_context::CONTEXT = mem::zeroed();
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.ContextFlags = Debug::CONTEXT_FULL_AMD64.0;
                }
                #[cfg(target_arch = "x86")]
                {
                    ctx.ContextFlags = Debug::CONTEXT_FULL_X86.0;
                }
                Debug::GetThreadContext(thread_h, &mut ctx as *mut _ as _).unwrap();

                minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(
                    crash_context::CrashContext {
                        process_id: event.dwProcessId,
                        thread_id: event.dwThreadId,
                        exception_code: event.u.Exception.ExceptionRecord.ExceptionCode.0,
                        exception_pointers: transfer_remote_exception_pointers(
                            process_h,
                            &event.u.Exception.ExceptionRecord,
                            &ctx,
                        ) as _,
                    },
                    None,
                    output,
                )
                .unwrap();
                let _ = Debug::ContinueDebugEvent(
                    event.dwProcessId,
                    event.dwThreadId,
                    Foundation::DBG_EXCEPTION_NOT_HANDLED,
                );
                break;
            }
            Debug::EXIT_PROCESS_DEBUG_EVENT => {
                if catch_exit {
                    minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(
                        crash_context::CrashContext {
                            process_id: event.dwProcessId,
                            thread_id: event.dwThreadId,
                            exception_code: 0,
                            exception_pointers: ptr::null(),
                        },
                        None,
                        output,
                    )
                    .unwrap();
                }
                let _ = Debug::ContinueDebugEvent(
                    event.dwProcessId,
                    event.dwThreadId,
                    Foundation::DBG_EXCEPTION_NOT_HANDLED,
                );
                break;
            }
            _ => {
                Debug::ContinueDebugEvent(
                    event.dwProcessId,
                    event.dwThreadId,
                    Foundation::DBG_CONTINUE,
                )
                .unwrap();
            }
        }
    }
    let _ = Debug::DebugActiveProcessStop(process_id);
    process_h.free();
}

fn wow(h: Foundation::HANDLE) -> bool {
    let mut r = Foundation::BOOL::default();
    unsafe {
        Threading::IsWow64Process(h, &mut r).unwrap();
    }
    r.as_bool()
}

fn transfer_remote_exception_pointers(
    h: Foundation::HANDLE,
    record: &Debug::EXCEPTION_RECORD,
    context: &crash_context::CONTEXT,
) -> *mut Debug::EXCEPTION_POINTERS {
    unsafe {
        let record_size = mem::size_of_val(record);
        let record_remote_ptr = Memory::VirtualAllocEx(
            h,
            None,
            record_size,
            Memory::MEM_COMMIT | Memory::MEM_RESERVE,
            Memory::PAGE_READWRITE,
        );
        assert!(!record_remote_ptr.is_null());
        Debug::WriteProcessMemory(
            h,
            record_remote_ptr,
            record as *const _ as _,
            record_size,
            None,
        )
        .unwrap();

        let context_size = mem::size_of_val(context);
        let context_remote_ptr = Memory::VirtualAllocEx(
            h,
            None,
            context_size,
            Memory::MEM_COMMIT | Memory::MEM_RESERVE,
            Memory::PAGE_READWRITE,
        );
        assert!(!context_remote_ptr.is_null());
        Debug::WriteProcessMemory(
            h,
            context_remote_ptr,
            context as *const _ as _,
            context_size,
            None,
        )
        .unwrap();

        let exception_pointers = Debug::EXCEPTION_POINTERS {
            ExceptionRecord: record_remote_ptr as _,
            ContextRecord: context_remote_ptr as _,
        };
        let exception_pointers_size = mem::size_of_val(&exception_pointers);
        let exception_pointers_remote_ptr = Memory::VirtualAllocEx(
            h,
            None,
            exception_pointers_size,
            Memory::MEM_COMMIT | Memory::MEM_RESERVE,
            Memory::PAGE_READWRITE,
        );
        assert!(!exception_pointers_remote_ptr.is_null());
        Debug::WriteProcessMemory(
            h,
            exception_pointers_remote_ptr,
            &exception_pointers as *const _ as _,
            exception_pointers_size,
            None,
        )
        .unwrap();

        exception_pointers_remote_ptr as _
    }
}

fn enable_privileges(name: PCWSTR) -> core::Result<()> {
    unsafe {
        let mut token_handle: Foundation::HANDLE = mem::zeroed();
        Threading::OpenProcessToken(
            Threading::GetCurrentProcess(),
            Security::TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        )?;
        let token_handle = OwnedHandle::from_raw_handle(token_handle.0 as _);

        let mut luid: Foundation::LUID = mem::zeroed();
        Security::LookupPrivilegeValueW(None, name, &mut luid)?;

        let mut new_state: Security::TOKEN_PRIVILEGES = mem::zeroed();
        new_state.PrivilegeCount = 1;
        new_state.Privileges[0].Luid = luid;
        new_state.Privileges[0].Attributes = Security::SE_PRIVILEGE_ENABLED;

        Security::AdjustTokenPrivileges(
            Foundation::HANDLE(token_handle.as_raw_handle()),
            false,
            Some(&mut new_state),
            mem::size_of::<Security::TOKEN_PRIVILEGES>() as _,
            None,
            None,
        )
    }
}
