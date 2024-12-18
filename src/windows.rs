use std::{fs::File, mem, ptr};
use windows::Win32::{
    Foundation,
    System::{Diagnostics::Debug, Threading},
};

pub unsafe fn inspect(pid: i32, catch_exit: bool, output: &mut File) {
    let process_id = pid as u32;

    Debug::DebugActiveProcess(process_id).unwrap();
    let mut event = Debug::DEBUG_EVENT::default();
    println!("inspecting process: {}", pid);
    loop {
        Debug::WaitForDebugEvent(&mut event, Threading::INFINITE).unwrap();
        match event.dwDebugEventCode {
            Debug::EXCEPTION_DEBUG_EVENT => {
                let thread_h = Threading::OpenThread(
                    Threading::THREAD_GET_CONTEXT,
                    Foundation::FALSE,
                    event.dwThreadId,
                )
                .unwrap();
                let mut ctx: crash_context::CONTEXT = mem::zeroed();
                ctx.ContextFlags = Debug::CONTEXT_ALL_AMD64.0;
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
