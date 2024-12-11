use std::env;

mod macos;

fn main() {
    let pid: i32 = env::args().skip(1).next().unwrap().parse().unwrap();
    unsafe { macos::foo(pid) };
}