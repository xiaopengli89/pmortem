# pmortem
A process dumper built in Rust.

# Usage
```sh
λ pmortem -h
A process dumper

Usage: pmortem [OPTIONS] --output <OUTPUT> <PID>

Arguments:
  <PID>

Options:
  -o, --output <OUTPUT>  Output dump file
  -e, --exception        Write a dump when the process encounters an unhandled exception
      --exit             Write a dump when the process exit
  -h, --help             Print help
  -V, --version          Print version
```

- Dump the process with PID '1324':
```sh
pmortem 1324
```

- Dump the process with PID '1324' encounters an unhandled exception or exit:
```sh
pmortem -e --exit 1324
```
