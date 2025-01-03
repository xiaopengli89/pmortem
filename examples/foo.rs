use std::{io, process, ptr};

fn main() {
    println!("pid: {}", process::id());

    foo();
}

fn foo() {
    #[cfg(unix)]
    unsafe {
        use std::ffi;

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

    let _ = std::hint::black_box(unsafe { *ptr::null_mut::<i32>().offset(1) });
    process::exit(0);
}
