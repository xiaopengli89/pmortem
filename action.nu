export-env {
    if (sys host).name == "Darwin" {
        $env.MACOSX_DEPLOYMENT_TARGET = "10.13"
    }

    if (sys host).name == "Windows" {
        $env.RUSTFLAGS = "-C target-feature=+crt-static"
    }
}

export def build [
    ...target: string 
] {
    let name = (open Cargo.toml).package.name
    let version = (open Cargo.toml).package.version

    for t in $target {
        rustup target add $t
        cargo build --release --target $t
        match $t {
            "aarch64-apple-darwin" | "x86_64-apple-darwin" | "x86_64-unknown-linux-gnu" => {
                (tar 
                    -C $"target/($t)/release" 
                    -czvf $"target/($name)-($t)-($version).tar.gz" 
                    $name)
            }
            "i686-pc-windows-msvc" | "x86_64-pc-windows-msvc" => {
                mv $"target/($t)/release/($name).exe" $"target/($name)-($t)-($version).exe"
            }
        }
    }
}
