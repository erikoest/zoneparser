extern crate zoneparser;

use std::fs::File;
use std::env;

use std::collections::HashMap;

use zoneparser::ZoneParser;
use zoneparser::RRType;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: zonecount <zonefile>");
        return;
    }

    let file = File::open(&args[1]).unwrap();

    let mut rr_count: HashMap::<RRType, u32> = HashMap::new();
    let mut rrset_count: HashMap::<RRType, u32> = HashMap::new();
    let mut count = 0;
    let mut last_name = "".to_string();
    let mut last_rrtype = RRType::None;

    let p = ZoneParser::new(&file);

    for rr in p {
	// Count rrs
	if last_name != rr.name || last_rrtype != rr.rrtype {
            if let Some(rrset_c) = rrset_count.get(&rr.rrtype) {
		rrset_count.insert(rr.rrtype, rrset_c + 1);
            }
            else {
		rrset_count.insert(rr.rrtype, 1);
            }

	    last_name = rr.name;
	    last_rrtype = rr.rrtype;
	}
		
        // Count rrs
        if let Some(rr_c) = rr_count.get(&rr.rrtype) {
	    rr_count.insert(rr.rrtype, rr_c + 1);
        }
        else {
	    rr_count.insert(rr.rrtype, 1);
        }
	
	count += 1;
    }

    println!("");
    println!("RR count:");
    for k in rr_count.keys() {
        println!("{:?}: {}", k, rr_count.get(k).unwrap());
    }
        
    println!("");
    println!("RRSet count:");
    for k in rrset_count.keys() {
        println!("{:?}: {}", k, rrset_count.get(k).unwrap());
    }

    println!("");
    println!("{} records", count);
}
