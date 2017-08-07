extern crate nessus;
extern crate env_logger;

use std::env;
use std::time::Duration;
use std::thread::sleep;

fn main() {
    env_logger::init().unwrap();

    let host = env::var("NESSUS_HOST").unwrap();
    let token = env::var("NESSUS_TOKEN").unwrap();
    let secret = env::var("NESSUS_SECRET").unwrap();

    let scan: u64 = env::var("NESSUS_SCAN").unwrap().parse().unwrap();

    let client = nessus::Client::new(host, token, secret);

    let x = client.launch_scan(scan);
    println!("launch_scan: {:?}", x);

    // TODO: make this nicer
    for n in 0..100 {
        let details = client.scan_details(scan).unwrap();
        println!("details: {:?}", details);

        if ! details.is_running() {
            break;
        }

        sleep(Duration::from_secs(60));

        if n == 99 {
            panic!("timeout");
        }
    }

    let x = client.export_scan(scan).unwrap();

    if ! x.wait(&client, Duration::from_secs(3), Some(40)).unwrap() {
        panic!("export timeout")
    }

    let y = x.download(&client);
    println!("download: {:?}", y);
}
