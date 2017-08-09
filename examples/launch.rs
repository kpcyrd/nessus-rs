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

    let scan = client.launch_scan(scan_id).unwrap();
    println!("launch_scan: {:?}", scan);

    scan.wait(&client, Duration::from_secs(60), Some(30)).unwrap();

    let export = client.export_scan(scan_id).unwrap();
    export.wait(&client, Duration::from_secs(3), Some(40)).unwrap();

    let export = export.download(&client).unwrap();

    println!("{:?}:", export.report.name);
    for host in export.report.report_hosts {
        println!("\t{:?}:", host.name);
        for prop in host.host_properties.tags {
            println!("\t\t{:?}: {:?}", prop.name, prop.value);
        }

        for item in host.report_items {
            println!("\t\t{:?}", item);
        }
    }
}
