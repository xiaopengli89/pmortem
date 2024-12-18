use mach2::{
    exception_types, kern_return, mach_port, mach_types, message, ndr, port, structs, task,
    task_info, thread_act, thread_status, traps, vm, vm_types,
};
use std::{
    ffi,
    io::{Seek, Write},
    mem,
    os::fd::{self, AsRawFd, FromRawFd},
    process, ptr, thread,
    time::Duration,
};

#[allow(
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    non_camel_case_types
)]
mod dyld_images;
#[allow(
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    non_camel_case_types
)]
mod loader;
#[allow(
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    non_camel_case_types
)]
mod nlist;

pub unsafe fn inspect(pid: i32, catch_exit: bool, output: &mut (impl Write + Seek)) {
    let mut r;

    let task = {
        let mut task_name = 0;
        r = traps::task_for_pid(traps::mach_task_self(), pid, &mut task_name);
        assert_eq!(r, kern_return::KERN_SUCCESS);
        Task {
            port: Port { name: task_name },
        }
    };

    let exc_port = {
        let mut notify_name = 0;
        r = mach_port::mach_port_allocate(
            traps::mach_task_self(),
            port::MACH_PORT_RIGHT_RECEIVE,
            &mut notify_name,
        );
        assert_eq!(r, kern_return::KERN_SUCCESS);
        Port { name: notify_name }
    };
    r = mach_port::mach_port_insert_right(
        traps::mach_task_self(),
        exc_port.name,
        exc_port.name,
        message::MACH_MSG_TYPE_MAKE_SEND,
    );
    assert_eq!(r, kern_return::KERN_SUCCESS);

    if catch_exit {
        thread::spawn(move || {
            let _ = process::Command::new("lldb")
                .args([
                    "-p",
                    &pid.to_string(),
                    "-o",
                    "breakpoint set --name __exit",
                    "-o",
                    "c",
                    "-o",
                    "quit",
                ])
                .output()
                .unwrap();
        });
        thread::sleep(Duration::from_secs(1));
    }

    let _old_exc_port = {
        let mut old_mask = 0;
        let mut old_mask_cnt = 1;
        let mut old_exc_port_name = port::MACH_PORT_NULL;
        let mut old_behaviors = 0;
        let mut old_flavors = 0;
        r = dyld_images::task_swap_exception_ports(
            task.port.name,
            exception_types::EXC_MASK_ALL,
            exc_port.name,
            exception_types::EXCEPTION_DEFAULT as _,
            thread_status::THREAD_STATE_NONE,
            &mut old_mask,
            &mut old_mask_cnt,
            &mut old_exc_port_name,
            &mut old_behaviors,
            &mut old_flavors,
        );
        assert_eq!(r, kern_return::KERN_SUCCESS);
        Port {
            name: old_exc_port_name,
        }
    };

    println!("inspecting process: {}", pid);
    let wait_r = wait_for(pid, &exc_port);

    match wait_r {
        Event::Exit(code) => {
            let _ = code;
        }
        Event::Exception => {
            let mut msg: ExceptionMessage = mem::zeroed();
            r = message::mach_msg(
                &mut msg.header,
                message::MACH_RCV_MSG,
                0,
                mem::size_of_val(&msg) as _,
                exc_port.name,
                message::MACH_MSG_TIMEOUT_NONE,
                port::MACH_PORT_NULL,
            );
            assert_eq!(r, kern_return::KERN_SUCCESS);

            let exc_task_port = Port {
                name: msg.task.name,
            };
            let exc_thread_port = Port {
                name: msg.thread.name,
            };

            minidump_writer::minidump_writer::MinidumpWriter::with_crash_context(
                crash_context::CrashContext {
                    task: exc_task_port.name,
                    thread: exc_thread_port.name,
                    handler_thread: port::MACH_PORT_NULL,
                    exception: (msg.exception != dyld_images::EXC_BREAKPOINT as i32).then_some(
                        crash_context::ExceptionInfo {
                            kind: msg.exception as _,
                            code: msg.code[0] as _,
                            subcode: (msg.code_count > 1).then_some(msg.code[1] as u64),
                        },
                    ),
                },
            )
            .dump(output)
            .unwrap();
        }
    }
}

struct Port {
    name: port::mach_port_t,
}

impl Drop for Port {
    fn drop(&mut self) {
        unsafe {
            let r = mach_port::mach_port_deallocate(traps::mach_task_self(), self.name);
            assert_eq!(r, kern_return::KERN_SUCCESS);
        }
    }
}

struct Task {
    port: Port,
}

impl Task {
    unsafe fn read<T>(&self, ptr: *const T) -> T {
        let mut v = mem::zeroed();
        let mut cnt = 0;
        let r = vm::mach_vm_read_overwrite(
            self.port.name,
            ptr as _,
            mem::size_of_val(&v) as _,
            &mut v as *mut _ as _,
            &mut cnt,
        );
        assert_eq!(r, kern_return::KERN_SUCCESS);
        v
    }

    unsafe fn read_str(&self, addr: *const ffi::c_char) -> String {
        let mut s = vec![];
        let mut c: ffi::c_char = 0;
        let mut cnt = 0;
        let mut r;
        let mut i = 0;
        loop {
            r = vm::mach_vm_read_overwrite(
                self.port.name,
                addr.offset(i) as _,
                1,
                &mut c as *mut _ as _,
                &mut cnt,
            );
            assert_eq!(r, kern_return::KERN_SUCCESS);

            s.push(c);
            if c == 0 {
                break;
            }
            i += 1;
        }
        ffi::CStr::from_ptr(s.as_ptr())
            .to_string_lossy()
            .into_owned()
    }

    #[allow(dead_code)]
    fn threads(&self, modules: &[super::Module]) -> Vec<super::Thread> {
        unsafe {
            let mut threads_ptr: mach_types::thread_act_array_t = ptr::null_mut();
            let mut cnt = 0;
            let mut r = task::task_threads(self.port.name, &mut threads_ptr, &mut cnt);
            assert_eq!(r, kern_return::KERN_SUCCESS);

            let threads: Vec<_> = (0..cnt)
                .map(|i| {
                    let thread_port = Port {
                        name: *threads_ptr.offset(i as _),
                    };

                    let thread_id_info = {
                        let mut id_info: libc::thread_identifier_info = mem::zeroed();
                        let mut cnt = libc::THREAD_IDENTIFIER_INFO_COUNT;
                        r = libc::thread_info(
                            thread_port.name,
                            libc::THREAD_IDENTIFIER_INFO as _,
                            &mut id_info as *mut _ as _,
                            &mut cnt,
                        );
                        assert_eq!(r, kern_return::KERN_SUCCESS);
                        id_info
                    };

                    let mut pc;
                    let mut fp;

                    #[cfg(target_arch = "aarch64")]
                    {
                        let mut state = structs::arm_thread_state64_t::new();
                        let mut count = structs::arm_thread_state64_t::count();
                        r = thread_act::thread_get_state(
                            thread_port.name,
                            thread_status::ARM_THREAD_STATE64,
                            &mut state as *mut _ as _,
                            &mut count,
                        );
                        assert_eq!(r, kern_return::KERN_SUCCESS);

                        pc = state.__pc;
                        fp = state.__fp;
                    }
                    #[cfg(target_arch = "x86_64")]
                    {
                        let mut state = structs::x86_thread_state64_t::new();
                        let mut count = structs::x86_thread_state64_t::count();
                        r = thread_act::thread_get_state(
                            thread_port.name,
                            thread_status::x86_THREAD_STATE64,
                            &mut state as *mut _ as _,
                            &mut count,
                        );
                        assert_eq!(r, kern_return::KERN_SUCCESS);

                        pc = state.__rip;
                        fp = state.__rbp;
                    }

                    let mut thread = super::Thread {
                        id: thread_id_info.thread_id,
                        exception: None,
                        backtrace: vec![],
                    };
                    let mut depth = 0;
                    thread
                        .backtrace
                        .push(super::Backtrace::new(depth, pc, modules));

                    while fp > 0 {
                        pc = self.read((fp as *const u64).offset(1));
                        if pc == 0 {
                            break;
                        }
                        depth += 1;
                        thread
                            .backtrace
                            .push(super::Backtrace::new(depth, pc, &modules));
                        fp = self.read(fp as *const u64);
                    }
                    thread
                })
                .collect();

            r = dyld_images::vm_deallocate(
                traps::mach_task_self(),
                threads_ptr as _,
                cnt as vm_types::vm_size_t
                    * mem::size_of::<mach_types::thread_act_t>() as vm_types::vm_size_t,
            );
            assert_eq!(r, kern_return::KERN_SUCCESS);

            threads
        }
    }

    #[allow(dead_code)]
    unsafe fn modules(&self) -> Vec<super::Module> {
        let mut info = task_info::task_dyld_info::default();
        let mut info_cnt = (mem::size_of_val(&info) / mem::size_of::<ffi::c_int>())
            as message::mach_msg_type_number_t;
        let r = task::task_info(
            self.port.name,
            task_info::TASK_DYLD_INFO,
            &mut info as *mut _ as _,
            &mut info_cnt,
        );
        assert_eq!(r, kern_return::KERN_SUCCESS);

        let all_image_infos =
            self.read(info.all_image_info_addr as *const dyld_images::dyld_all_image_infos);

        let parse_module =
            |path_ptr: *const ffi::c_char, load_address: *const dyld_images::mach_header| {
                let path = self.read_str(path_ptr);

                let mut slide = 0;
                let mut text_segment = None;

                let header_ptr = load_address as *const loader::mach_header_64;
                let header = self.read(header_ptr);
                let mut lc_ptr = header_ptr.offset(1) as *const libc::load_command;
                let mut offset = 0;
                let mut exit_address = None;

                for _ in 0..header.sizeofcmds {
                    let lc = self.read(lc_ptr);
                    if lc.cmd == loader::LC_SEGMENT_64 {
                        let seg = self.read(lc_ptr as *const libc::segment_command_64);
                        let seg_name = ffi::CStr::from_ptr(seg.segname.as_ptr());
                        if seg_name == c"__TEXT" {
                            slide = load_address as u64 - seg.vmaddr;
                            text_segment = Some(super::Range {
                                start: slide + seg.vmaddr,
                                end: slide + seg.vmaddr + seg.vmsize,
                            });
                        } else if seg_name == c"__LINKEDIT" {
                            offset = seg.vmaddr - seg.fileoff;
                        }
                    } else if lc.cmd == loader::LC_SYMTAB {
                        let sym_tab_cmd = self.read(lc_ptr as *const loader::symtab_command);
                        let fixed = offset + slide;
                        let sym_tab_ptr =
                            (sym_tab_cmd.symoff as u64 + fixed) as *const nlist::nlist_64;
                        let sym_str_ptr = (sym_tab_cmd.stroff as u64 + fixed) as *const ffi::c_char;
                        for i in 0..sym_tab_cmd.nsyms {
                            let sym = self.read(sym_tab_ptr.offset(i as _));
                            if (sym.n_type as u32 & (nlist::N_STAB | nlist::N_PEXT)) > 0
                                || (sym.n_type as u32 & nlist::N_SECT) == 0
                            {
                                continue;
                            }
                            let sym_name =
                                self.read_str(sym_str_ptr.offset(sym.n_un.n_strx as isize));
                            if sym_name == "__exit" {
                                exit_address = Some(sym.n_value + slide);
                            }
                        }
                    }
                    lc_ptr = (lc_ptr as usize + lc.cmdsize as usize) as _;
                }

                super::Module {
                    path,
                    load_address: load_address as _,
                    text_segment,
                    exit_address,
                }
            };

        let mut modules = Vec::with_capacity(1 + all_image_infos.infoArrayCount as usize);

        modules.push(parse_module(
            all_image_infos.dyldPath,
            all_image_infos.dyldImageLoadAddress,
        ));
        for i in 0..all_image_infos.infoArrayCount {
            let image_info = self.read(all_image_infos.infoArray.offset(i as _));
            modules.push(parse_module(
                image_info.imageFilePath,
                image_info.imageLoadAddress,
            ));
        }

        modules
    }
}

fn wait_for(pid: i32, exc_port: &Port) -> Event {
    unsafe {
        let fd = libc::kqueue();
        assert_ne!(fd, -1);
        let fd = fd::OwnedFd::from_raw_fd(fd);

        let mut r;
        {
            let event = libc::kevent {
                ident: pid as _,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ENABLE,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: ptr::null_mut(),
            };
            r = libc::kevent(fd.as_raw_fd(), &event, 1, ptr::null_mut(), 0, ptr::null());
            assert_ne!(r, -1);
        }

        {
            let event = libc::kevent {
                ident: exc_port.name as _,
                filter: libc::EVFILT_MACHPORT,
                flags: libc::EV_ADD | libc::EV_RECEIPT,
                fflags: 0,
                data: 0,
                udata: ptr::null_mut(),
            };
            r = libc::kevent(fd.as_raw_fd(), &event, 1, ptr::null_mut(), 0, ptr::null());
            assert_ne!(r, -1);
        }

        let mut event: libc::kevent = mem::zeroed();
        loop {
            let n = libc::kevent(fd.as_raw_fd(), ptr::null(), 0, &mut event, 1, ptr::null());
            if n > 0 {
                if event.filter == libc::EVFILT_PROC {
                    break Event::Exit(event.data as _);
                } else if event.filter == libc::EVFILT_MACHPORT {
                    break Event::Exception;
                }
            }
        }
    }
}

enum Event {
    Exit(i32),
    Exception,
}

#[repr(C)]
struct ExceptionMessage {
    header: message::mach_msg_header_t,
    body: message::mach_msg_body_t,
    thread: message::mach_msg_port_descriptor_t,
    task: message::mach_msg_port_descriptor_t,
    ndr: ndr::NDR_record_t,
    exception: exception_types::exception_type_t,
    code_count: message::mach_msg_type_number_t,
    code: [exception_types::exception_data_type_t; 2],
    trailer: message::mach_msg_trailer_t,
}
