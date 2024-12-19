use std::{
    fs::File,
    mem,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation, Security,
        System::{Diagnostics::Debug, Threading},
    },
};

pub unsafe fn inspect(pid: i32, catch_exit: bool, output: &mut File) {
    let process_id = pid as u32;

    enable_privileges(Security::SE_DEBUG_NAME);

    Debug::DebugActiveProcess(process_id).unwrap();
    let mut event = Debug::DEBUG_EVENT::default();
    println!("inspecting process: {}", pid);
    loop {
        Debug::WaitForDebugEvent(&mut event, Threading::INFINITE).unwrap();
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
                ctx.ContextFlags = Debug::CONTEXT_FULL_AMD64.0;
                Debug::GetThreadContext(thread_h, &mut ctx as *mut _ as _).unwrap();

                minidump_writer::minidump_writer::MinidumpWriter::dump_crash_context(
                    crash_context::CrashContext {
                        process_id: event.dwProcessId,
                        thread_id: event.dwThreadId,
                        exception_code: event.u.Exception.ExceptionRecord.ExceptionCode.0,
                        exception_pointers: &mut crash_context::EXCEPTION_POINTERS {
                            ExceptionRecord: &mut event.u.Exception.ExceptionRecord as *mut _ as _,
                            ContextRecord: &mut ctx,
                        },
                    },
                    None,
                    output,
                )
                .unwrap();
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
}

fn enable_privileges(name: PCWSTR) {
    unsafe {
        let mut token_handle: Foundation::HANDLE = mem::zeroed();
        Threading::OpenProcessToken(
            Threading::GetCurrentProcess(),
            Security::TOKEN_ADJUST_PRIVILEGES,
            &mut token_handle,
        )
        .unwrap();
        let token_handle = OwnedHandle::from_raw_handle(token_handle.0 as _);

        let mut luid: Foundation::LUID = mem::zeroed();
        Security::LookupPrivilegeValueW(None, name, &mut luid).unwrap();

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
        .unwrap();
    }
}
