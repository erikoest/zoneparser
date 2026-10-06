extern crate zoneparser;

use std::fs::File;
use std::env;
use std::process::ExitCode;
use std::collections::HashMap;

use zoneparser::ZoneParser;
use zoneparser::RRType;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let mut origin = "".to_string();
    let mut domain = vec!();
    let mut arg_count = 1;
    let mut rr_str = vec!();
    let mut short = false;
    let mut complete = false;

    loop {
        if args.len() <= arg_count {
            break;
        }

        match args[arg_count].as_str() {
            "-o" | "--origin" => {
                origin = args[arg_count + 1].to_string();
                arg_count += 2;
            },
            "-d" | "--domain" => {
                domain.push(args[arg_count + 1].to_string());
                arg_count += 2;
            },
            "-r" | "--rrtype" => {
                rr_str.push(args[arg_count + 1].to_string());
                arg_count += 2;
            },
            "-s" | "--short" => {
                short = true;
                arg_count += 1;
            },
            "--complete" => {
                complete = true;
                arg_count += 1;
            },
            a => {
                if a.starts_with('-') {
                    println!("Invalid option {}", a);
                    return 10.into();
                }
                else {
                    break;
                }
            },
        }
    }

    if args.len() <= arg_count {
        println!("Usage: zonegrep [-o origin] [-d domain] [-r rrtype]");
        println!("  [-s] [--complete] <zonefile>");
        println!("    -o, --origin: zone origin");
        println!("    -d, --domain domain: match domain name");
        println!("    -r, --rrtype rrtype: match record type");
        println!("    -s, --short: print data fields only");
        println!("    --complete: parse the complete zone even after the");
        println!("                domains have been matched.");
        println!("    <zonefile>: file to be parsed");
        println!(" -d and -r may be repeated");

        return 10.into();
    }

    if origin == "" {
        if args[arg_count].ends_with('.') {
            origin = args[arg_count].to_string();
        }
        else {
            origin = format!("{}.", &args[arg_count]);
        }
    }

    let mut domain_todo = HashMap::new();

    for d in domain {
        if d == "" {
            domain_todo.insert(origin.to_string(), true);
        }
        else if !d.ends_with('.') {
            domain_todo.insert(format!("{}.", &d), true);
        }
        else {
            domain_todo.insert(d.to_string(), true);
        }
    }

    if domain_todo.is_empty() {
        domain_todo.insert(origin.to_string(), true);
    }

    let file = File::open(&args[arg_count]).unwrap();

    let p = ZoneParser::new(&file, &origin);

    let rrtype = rr_str.into_iter()
        .map(|rrs|
             p.rrtype_from_str(&rrs).expect(
                 &format!("Invalid rrtype {}", &rrs))
        )
        .collect::<Vec<RRType>>();

    let mut last_domain = "".to_string();

    for result in p {
        match result {
            Err(e) => {
                println!("Parse error: {}", e);
                return 255.into();
            },
            Ok(rr) => {
                if rr.name != last_domain {
                    if !complete {
                        domain_todo.remove(&last_domain);

                        if domain_todo.is_empty() {
                            // Skip the rest if we have done all the domains
                            break;
                        }
                    }

                }

                last_domain = rr.name.clone();

                if !domain_todo.contains_key(&last_domain) {
                    continue;
                }

                let mut found_rr = false;

                if rrtype.is_empty() {
                    found_rr = true;
                }
                else {
                    for rrt in &rrtype {
                        if rr.rrtype == *rrt {
                            found_rr = true;
                        }
                    }
                }

                if !found_rr {
                    continue;
                }

                if short {
                    let data = rr.data.into_iter()
                        .map(|rd| rd.data)
                        .collect::<Vec<String>>()
                        .join(" ");
                    println!("{}", data);
                }
                else {
                    println!("{}", rr);
                }

                domain_todo.insert(last_domain.clone(), false);
            },
        }
    }

    for (d, todo) in domain_todo {
        if todo {
            println!("(no results for domain {})", d);
        }
    }

    return 0.into();
}
