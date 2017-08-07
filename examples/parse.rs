extern crate nessus;

use std::io;
use std::io::prelude::*;

fn main() {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).unwrap();

    let report = nessus::parser::parse(buffer).unwrap();
    println!("parsed: {:?}", report);
}
