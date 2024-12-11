use mach2::{
    exception_types, kern_return, mach_port, mach_types, message, ndr, port, structs, task,
    task_info, thread_act, thread_status, traps, vm,
};
use std::{ffi, mem};

#[allow(
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    non_camel_case_types
)]
mod dyld_images;

pub unsafe fn inspect(pid: i32) -> super::Snapshot {
    let mut target = 0;
    let mut r = traps::task_for_pid(traps::mach_task_self(), pid, &mut target);
    assert_eq!(r, kern_return::KERN_SUCCESS);

    let mut notify = 0;
    r = mach_port::mach_port_allocate(
        traps::mach_task_self(),
        port::MACH_PORT_RIGHT_RECEIVE,
        &mut notify,
    );
    assert_eq!(r, kern_return::KERN_SUCCESS);
    r = mach_port::mach_port_insert_right(
        traps::mach_task_self(),
        notify,
        notify,
        message::MACH_MSG_TYPE_MAKE_SEND,
    );
    assert_eq!(r, kern_return::KERN_SUCCESS);

    r = task_set_exception_ports(
        target,
        exception_types::EXC_MASK_ALL,
        notify,
        exception_types::EXCEPTION_DEFAULT as _,
        thread_status::THREAD_STATE_NONE,
    );
    assert_eq!(r, kern_return::KERN_SUCCESS);

    let mut msg: ExceptionMessage = mem::zeroed();
    r = message::mach_msg(
        &mut msg.header,
        message::MACH_RCV_MSG,
        0,
        mem::size_of_val(&msg) as _,
        notify,
        message::MACH_MSG_TIMEOUT_NONE,
        port::MACH_PORT_NULL,
    );
    assert_eq!(r, kern_return::KERN_SUCCESS);

    dbg!(
        msg.task.name,
        msg.thread.name,
        msg.exception,
        msg.code_count,
        msg.code
    );

    // TODO: x86_THREAD_STATE64
    let mut state = structs::arm_thread_state64_t::new();
    let mut count = structs::arm_thread_state64_t::count();
    r = thread_act::thread_get_state(
        msg.thread.name,
        thread_status::ARM_THREAD_STATE64,
        &mut state as *mut _ as _,
        &mut count,
    );
    assert_eq!(r, kern_return::KERN_SUCCESS);

    dbg!(state.__pc, state.__sp, state.__fp);

    let task = Task {
        task_name: msg.task.name,
    };
    let modules = task.modules();

    let mut pc = state.__pc;
    let mut fp = state.__fp;

    let mut thread = super::Thread { backtrace: vec![] };
    let mut depth = 0;
    thread
        .backtrace
        .push(super::Backtrace::new(depth, pc, &modules));

    while fp > 0 {
        pc = task.read((fp as *const u64).offset(1));
        if pc == 0 {
            break;
        }
        depth += 1;
        thread
            .backtrace
            .push(super::Backtrace::new(depth, pc, &modules));
        fp = task.read(fp as *const u64);
    }

    super::Snapshot {
        threads: vec![thread],
        modules,
    }
}

struct Task {
    task_name: port::mach_port_t,
}

impl Task {
    unsafe fn read<T>(&self, ptr: *const T) -> T {
        let mut v = mem::zeroed();
        let mut cnt = 0;
        let r = vm::mach_vm_read_overwrite(
            self.task_name,
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
                self.task_name,
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

    unsafe fn modules(&self) -> Vec<super::Module> {
        let mut info = task_info::task_dyld_info::default();
        let mut info_cnt = (mem::size_of_val(&info) / mem::size_of::<ffi::c_int>())
            as message::mach_msg_type_number_t;
        let r = task::task_info(
            self.task_name,
            task_info::TASK_DYLD_INFO,
            &mut info as *mut _ as _,
            &mut info_cnt,
        );
        assert_eq!(r, kern_return::KERN_SUCCESS);

        let all_image_infos =
            self.read(info.all_image_info_addr as *const dyld_images::dyld_all_image_infos);

        (0..all_image_infos.infoArrayCount)
            .into_iter()
            .map(|index| {
                let image_info = self.read(all_image_infos.infoArray.offset(index as _));
                let path = self.read_str(image_info.imageFilePath);

                let mut end_address = 0;
                let mut slide = 0;

                #[allow(deprecated)]
                let header_ptr = image_info.imageLoadAddress as *const libc::mach_header_64;
                let header = self.read(header_ptr);
                let mut lc_ptr = header_ptr.offset(1) as *const libc::load_command;

                #[allow(deprecated)]
                for _ in 0..header.sizeofcmds {
                    let lc = self.read(lc_ptr);
                    if lc.cmd == libc::LC_SEGMENT_64 {
                        let seg = self.read(lc_ptr as *const libc::segment_command_64);
                        if libc::strcmp(seg.segname.as_ptr(), c"__TEXT".as_ptr()) == 0 {
                            slide = image_info.imageLoadAddress as u64 - seg.vmaddr;
                        }
                        end_address = end_address.max(slide + seg.vmaddr + seg.vmsize);
                    }
                    lc_ptr = (lc_ptr as usize + lc.cmdsize as usize) as _;
                }

                super::Module {
                    index,
                    path,
                    load_address: image_info.imageLoadAddress as _,
                    end_address,
                }
            })
            .collect()
    }
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

extern "C" {
    fn task_set_exception_ports(
        task: mach_types::task_t,
        exception_mask: exception_types::exception_mask_t,
        port: port::mach_port_t,
        behavior: exception_types::exception_behavior_t,
        flavor: thread_status::thread_state_flavor_t,
    ) -> kern_return::kern_return_t;
}
