extern crate nessus;
extern crate env_logger;

use std::env;
use std::time::Duration;

fn main() {
    env_logger::init().unwrap();

    let host = env::var("NESSUS_HOST").unwrap();
    let token = env::var("NESSUS_TOKEN").unwrap();
    let secret = env::var("NESSUS_SECRET").unwrap();

    let scan_id: u64 = env::var("NESSUS_SCAN").unwrap().parse().unwrap();

    let client = nessus::Client::new(&host, token, secret).unwrap();

    println!("[*] starting scan: {:?}...", scan_id);
    let scan = client.launch_scan(scan_id).unwrap();
    scan.wait(&client, Duration::from_secs(60), Some(30)).unwrap();

    println!("[*] scan finished, exporting...");
    let export = client.export_scan(scan_id).unwrap();
    export.wait(&client, Duration::from_secs(3), Some(40)).unwrap();

    println!("[+] export finished");
    let export = export.download(&client).unwrap();

    println!("{:?}:", export.report.name);
    for host in export.report.report_hosts {
        match host.patch_needed() {
            Some(advice) => {
                println!("\t{:?}:", host.name);
                for item in advice {
                    println!("\t\t{:?}", item);
                }
            },
            None => (),
        };
    }
}
