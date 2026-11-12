//! Standalone mock intermediary: `cargo run -p testsupport --example mock-server -- <pki-dir> <dump-dir>`
//! Serves until killed; prints the endpoint URL on start.
use std::path::Path;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let pki = Path::new(&args[1]);
    let dump = Path::new(&args[2]);
    let mock = testsupport::MockIntermediary::start_simple(pki, dump)?;
    println!("MOCK_URL={}", mock.url());
    println!("mock serving on {} — kill to stop", mock.url());
    std::thread::sleep(std::time::Duration::from_secs(3600));
    Ok(())
}
