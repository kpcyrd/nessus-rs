# nessus-rs [![Build Status][travis-img]][travis] [![crates.io][crates-img]][crates] [![docs.rs][docs-img]][docs]

[travis-img]:   https://travis-ci.org/kpcyrd/nessus-rs.svg?branch=master
[travis]:       https://travis-ci.org/kpcyrd/nessus-rs
[crates-img]:   https://img.shields.io/crates/v/nessus.svg
[crates]:       https://crates.io/crates/nessus
[docs-img]:     https://docs.rs/nessus/badge.svg
[docs]:         https://docs.rs/nessus

Nessus Vulnerability Scanner API client.

```toml
[dependencies]
nessus = "0.4"
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

## Why are there so many releases?

nessus-rs is still being tested for production use and while there is some documentation from tenable.com, the response
objects aren't sufficiently documented to deserialize them properly. While this library should work for you most of the
time, there are edgecases which cause the deserialization to fail and require updates to the struct definition. One
might argue those are 0.0.X updates, but since they are technically breaking changes to the library, they are
released as 0.X.0 updates. If you experience `JsonError`s there's a good chance updating your nessus-rs dependency
resolves those. Updating the dependency should be fairly safe and usually doesn't require updates on your code.

If you work for tenable.com, please consider documenting which fields might be null or missing and file an issue.

## License

LGPL3
