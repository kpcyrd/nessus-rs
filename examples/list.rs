extern crate nessus;
extern crate env_logger;

use std::env;

fn main() {
    env_logger::init().unwrap();

    let host = env::var("NESSUS_HOST").unwrap();
    let token = env::var("NESSUS_TOKEN").unwrap();
    let secret = env::var("NESSUS_SECRET").unwrap();


    let client = nessus::Client::new(host, token, secret);

    let x = client.list_policies();
    println!("list_policies: {:?}", x);

    let x = client.list_scans();
    println!("list_scans: {:?}", x);
}
