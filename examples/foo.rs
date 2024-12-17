use std::{ffi, hint, io, process, ptr};

fn main() {
    println!("pid: {}", process::id());

    foo();
}

fn foo() {
    unsafe {
        let mut buf = ptr::null_mut();
        let sz = libc::backtrace(&mut buf, 64);
        let mut sym = libc::backtrace_symbols(&buf, sz);
        for _ in 0..sz {
            let s = ffi::CStr::from_ptr(*sym).to_string_lossy();
            println!("{s}");
            sym = sym.offset(1);
        }
    }
    io::stdin().read_line(&mut String::new()).unwrap();

    let _ = hint::black_box(unsafe { *ptr::null_mut::<i32>().offset(1) });
    process::exit(0);
}
