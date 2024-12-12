use serde::Serialize;
use std::env;

mod macos;

fn main() {
    let pid: i32 = env::args().skip(1).next().unwrap().parse().unwrap();
    let snapshot = unsafe { macos::inspect(pid) };
    let t = serde_json::to_string_pretty(&snapshot).unwrap();
    println!("{t}");
}

#[derive(Serialize)]
struct Snapshot {
    threads: Vec<Thread>,
    modules: Vec<Module>,
}

#[derive(Serialize)]
struct Thread {
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
