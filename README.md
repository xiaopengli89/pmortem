# pmortem
A process dumper built in Rust.

# Usage
- Dump the process with PID '1324':
```sh
pmortem -o foo.dmp 1324
```

- Dump the process with PID '1324' encounters an unhandled exception or exit:
```sh
pmortem -e --exit -o foo.dmp 1324
```
