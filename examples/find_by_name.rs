extern crate nessus;
extern crate env_logger;

use std::env;
use nessus::VulnScanner;

fn main() {
    env_logger::init().unwrap();

    let host = env::var("NESSUS_HOST").expect("NESSUS_HOST not set");
    let token = env::var("NESSUS_TOKEN").expect("NESSUS_TOKEN not set");
    let secret = env::var("NESSUS_SECRET").expect("NESSUS_SECRET not set");

    let args: Vec<String> = env::args().collect();
    let mut args_iter = args.iter().skip(1);

    let folder_id = args_iter.next().expect("missing <folder_id>").parse().expect("invalid folder_id");
    let scan_name = args_iter.next().expect("missing <name>");

    let client = nessus::Client::new(&host, token, secret).unwrap();

    let resp = client.list_scan_folder(folder_id).expect("failed to list folder");

    for scan in resp.scans {
        if scan.name == *scan_name {
            println!("{:?}", scan);
        }
    }
}
