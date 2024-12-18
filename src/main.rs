use clap::{Parser, Subcommand};
use serde::Serialize;
use std::{fs::File, path::PathBuf};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

fn main() {
    let cli = Cli::parse();
    let Commands::Inspect { pid, output, exit } = cli.command;
    let mut output_file = File::create(&output).unwrap();
    #[cfg(target_os = "macos")]
    unsafe {
        macos::inspect(pid, exit, &mut output_file)
    };
    #[cfg(windows)]
    unsafe {
        windows::inspect(pid, exit, &mut output_file)
    };
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Inspect {
        pid: i32,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        exit: bool,
    },
}

#[allow(dead_code)]
#[derive(Serialize)]
struct Snapshot {
    threads: Vec<Thread>,
    modules: Vec<Module>,
}

#[derive(Serialize)]
struct Exception {
    reason: i32,
    code: [i32; 2],
}

#[derive(Serialize)]
struct Thread {
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    exception: Option<Exception>,
    backtrace: Vec<Backtrace>,
}

#[derive(Serialize)]
struct Backtrace {
    depth: u32,
    #[serde(with = "hex")]
    address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<Module>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
}

impl Backtrace {
    #[allow(dead_code)]
    fn new(depth: u32, address: u64, modules: &[Module]) -> Self {
        Self {
            depth,
            module: modules
                .into_iter()
                .find(|m| {
                    m.text_segment
                        .as_ref()
                        .map(|s| s.contains(address))
                        .unwrap_or_default()
                })
                .map(ToOwned::to_owned),
            address,
            symbol: None,
        }
    }
}

#[derive(Serialize, Clone)]
struct Module {
    path: String,
    #[serde(with = "hex")]
    load_address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_segment: Option<Range>,
    #[allow(dead_code)]
    #[serde(skip)]
    exit_address: Option<u64>,
}

#[derive(Serialize, Clone, Copy)]
struct Range {
    #[serde(with = "hex")]
    start: u64,
    #[serde(with = "hex")]
    end: u64,
}

impl Range {
    fn contains(&self, item: u64) -> bool {
        self.start <= item && item <= self.end
    }
}

mod hex {
    use serde::Serializer;
    use std::fmt::LowerHex;

    pub fn serialize<V, S>(number: &V, serializer: S) -> Result<S::Ok, S::Error>
    where
        V: LowerHex,
        S: Serializer,
    {
        let s = format!("{number:#018x}");
        serializer.serialize_str(&s)
    }
}
