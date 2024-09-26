extern crate zoneparser;

use std::fs::File;
use std::env;

use std::collections::HashMap;

use zoneparser::ZoneParser;
use zoneparser::RRType;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut origin = "";
    let mut arg_count = 1;

    loop {
        match args[arg_count].as_str() {
            "-o" | "--origin" => {
                origin = &args[arg_count + 1];
                arg_count += 2;
            },
            _ => break,
        }
    }

    if args.len() < 1 + arg_count {
        println!("Usage: zonecount [-o origin] <zonefile>");
        return;
    }

    if origin == "" {
        origin = &args[arg_count];
    }

    let file = File::open(&args[arg_count]).unwrap();

    let mut rr_count: HashMap::<RRType, u32> = HashMap::new();
    let mut rrset_count: HashMap::<RRType, u32> = HashMap::new();
    let mut rrset_tmp: HashMap::<RRType, u32> = HashMap::new();
    let mut rr_total = 0;
    let mut rrset_total = 0;
    let mut last_name = "".to_string();

    let p = ZoneParser::new(&file, origin);

    for rr in p {
	// Count rrs
	if last_name != rr.name {
	    // Transfer all temporary rrset counts
	    for rrtype in rrset_tmp.keys() {
		if let Some(rrset_c) = rrset_count.get(&rrtype) {
		    rrset_count.insert(*rrtype, rrset_c + 1);
		}
		else {
		    rrset_count.insert(*rrtype, 1);
		}
		rrset_total += 1;
	    }

	    last_name = rr.name;

	    // Clear temporary rrset count
	    rrset_tmp.clear();
	}

        // Count rrs
        if let Some(rr_c) = rr_count.get(&rr.rrtype) {
	    rr_count.insert(rr.rrtype, rr_c + 1);
        }
        else {
	    rr_count.insert(rr.rrtype, 1);
        }

	// Count rrsets
	rrset_tmp.insert(rr.rrtype, 1);
	
	rr_total += 1;
    }

    // Count the last rrsets
    for rrtype in rrset_tmp.keys() {
	if let Some(rrset_c) = rrset_count.get(&rrtype) {
	    rrset_count.insert(*rrtype, rrset_c + 1);
	}
	else {
	    rrset_count.insert(*rrtype, 1);
	}
	rrset_total += 1;
    }

    println!("");
    println!("RR:");
    for k in rr_count.keys() {
        println!("  {:?}: {}", k, rr_count.get(k).unwrap());
    }
    println!("  total: {}", rr_total);

    println!("");
    println!("RRSet:");
    for k in rrset_count.keys() {
        println!("  {:?}: {}", k, rrset_count.get(k).unwrap());
    }
    println!("  total: {}", rrset_total);
}
