# nessus-rs [![Build Status](https://travis-ci.org/kpcyrd/nessus-rs.svg?branch=master)](https://travis-ci.org/kpcyrd/nessus-rs) [![Crates.io](https://img.shields.io/crates/v/nessus.svg)](https://crates.io/crates/nessus)

Nessus Vulnerability Scanner API client.

```toml
[dependencies]
nessus = "0.1"
```

## Usage

```rust,no_run
extern crate nessus;

use std::time::Duration;

fn main() {
    let scan_id = 31337;
    let client = nessus::Client::new("https://nessus.example.com", "yourtoken", "secrettoken").unwrap();

    let scan = client.launch_scan(scan_id).unwrap();
    scan.wait(&client, Duration::from_secs(60), Some(30)).unwrap();

    let export = client.export_scan(scan_id).unwrap();
    export.wait(&client, Duration::from_secs(3), Some(40)).unwrap();

    let report = export.download(&client).unwrap();
    println!("download: {:?}", report);
}
```

See `examples/`.

## License

LGPL3
