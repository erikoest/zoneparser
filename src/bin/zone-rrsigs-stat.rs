extern crate zoneparser;

use std::fs::File;
use std::env;
use std::process::ExitCode;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::prelude::*;
use chrono::prelude::*;
use std::cmp::{max, min};

use zoneparser::{ZoneParser, Record};
use zoneparser::RRType;

struct SigData {
    key_expiry_sum: i64,
    key_expiry_min: i32,
    key_expiry_max: i32,
    key_sig_count: u32,
    zone_expiry_sum: i64,
    zone_expiry_min: i32,
    zone_expiry_max: i32,
    zone_sig_count: u32,
}

impl SigData {
    fn new() -> Self {
        SigData {
            key_expiry_sum: 0,
            key_expiry_min: i32::MAX,
            key_expiry_max: i32::MIN,
            key_sig_count: 0,
            zone_expiry_sum: 0,
            zone_expiry_min: i32::MAX,
            zone_expiry_max: i32::MIN,
            zone_sig_count: 0,
        }
    }
}

fn calc_keytag(rr: &Record) -> Result<i32, String> {
    let mut tag: i32 = 0;

    let mut bytes = vec!();
    // Flags, u16
    let flags: u16 = rr.data[0].data.parse().unwrap();
    bytes.push((flags >> 8) as u8);
    bytes.push((flags & 255) as u8);
    // Protocol, u8
    bytes.push(rr.data[1].data.parse().unwrap());
    // Algorithm, u8
    bytes.push(rr.data[2].data.parse().unwrap());
    // Pubkey, &[u8]
    for d in &rr.data[3..] {
        let pk = &mut BASE64_STANDARD.decode(&d.data).map_err(|_| "Invalid base64 encoding")?;
        bytes.append(pk);
    }

    for i in 0..bytes.len() {
        if (i & 1) > 0 {
            tag += bytes[i] as i32;
        }
        else {
            tag += (bytes[i] as i32) << 8;
        }
    }

    tag += (tag >> 16) & 0xFFFF;

    return Ok(tag & 0xFFFF);
}

fn timestamp_to_epoch(ts: &str) -> i32 {
    let n: u64 = ts.parse().unwrap_or(0);
    // Convert YYYYMMDDhhmmss field into epoch
    let date = (n/(1000000 as u64)) as u32;
    let time = (n%(1000000 as u64)) as u32;
    return Utc.with_ymd_and_hms(
        (date/10000) as i32,
        (date/100)%100,
        date%100,
        (time/10000)%100,
        (time/100)%100,
        time%100
    ).unwrap().timestamp() as i32;
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    let mut origin = "";
    let mut arg_count = 1;

    loop {
        if args.len() <= arg_count {
            break;
        }

        match args[arg_count].as_str() {
            "-o" | "--origin" => {
                origin = &args[arg_count + 1];
                arg_count += 2;
            },
            _ => break,
        }
    }

    if args.len() < 1 + arg_count {
        println!("Usage: zone-rrsigs-stat [-o origin] <zonefile>");
        return 10.into();
    }

    if origin == "" {
        origin = &args[arg_count];
    }

    let file = File::open(&args[arg_count]).unwrap();

    let mut sig_stats: HashMap::<i32, SigData> = HashMap::new();
    let mut known_keys: Vec::<(i32, bool)> = vec!();
    let mut errors: Vec<String> = vec!();

    let now_systime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let now: i32 = now_systime.as_secs() as i32;

    let p = ZoneParser::new(&file, origin);

    for result in p {
        match result {
            Err(e) => {
                println!("Parse error: {}", e);
                return 255.into();
            },
            Ok(rr) => {
                match rr.rrtype {
                    RRType::DNSKEY => {
                        if rr.data.len() < 4 {
                            errors.push(format!("Error in dnskey. Expected at least 4 data fields, found {}", rr.data.len()));
                            continue;
                        }
                        let tag = calc_keytag(&rr).unwrap_or_else(|e| {
                            errors.push(
                                format!("Error in dnskey: {}", e));
                            -1
                        });

                        let flags: i32 = rr.data[0].data.parse().unwrap_or_else(|_| {
                            errors.push(
                                format!("Error in dnskey: Invalid flags field {}", rr.data[0]));
                            -1
                        });

                        if flags < 0 || tag < 0 {
                            continue;
                        }

                        match flags {
                            256 => known_keys.push((tag, false)),
                            257 => known_keys.push((tag, true)),
                            e   => errors.push(format!("Error in dnskey: Invalid flags field {}", e)),
                        }
                    },
                    RRType::RRSIG => {
                        if rr.data.len() < 9 {
                            errors.push(format!("Error in dnskey. Expected at least 9 fields, found {}", rr.data.len()));
                            continue;
                        }

                        let rrtype = &rr.data[0].data;

                        let mut expiry = timestamp_to_epoch(
                            &rr.data[4].data);
                        if expiry < 0 {
                            errors.push(
                                format!("Error in rrsig: Invalid expiry timestamp field {}", rr.data[4]));
                        }

                        let tag: i32 = rr.data[6].data.parse().unwrap_or_else(
                            |_| {
                                errors.push(
                                    format!("Error in rrsig: Invalid key tag firkd {}", rr.data[6]));
                                -1
                            }
                        );

                        if expiry < 0 || tag < 0 || tag > 65535 {
                            continue;
                        }

                        expiry -= now;

                        let ss = sig_stats.entry(tag).or_insert(SigData::new());

                        if rrtype == "DNSKEY" {
                            ss.key_expiry_sum += expiry as i64;
                            ss.key_expiry_min = min(ss.key_expiry_min, expiry);
                            ss.key_expiry_max = max(ss.key_expiry_max, expiry);
                            ss.key_sig_count += 1;
                        }
                        else {
                            ss.zone_expiry_sum += expiry as i64;
                            ss.zone_expiry_min = min(ss.zone_expiry_min, expiry);
                            ss.zone_expiry_max = max(ss.zone_expiry_max, expiry);
                            ss.zone_sig_count += 1;
                        }
                    },
                    _ => {},
                }
            },
        }
    }

    for (tag, ss) in sig_stats {
        println!("Key {}:", tag);
        if ss.zone_sig_count > 0 {
            println!("  Number of signatures: {}", ss.zone_sig_count);
            println!("  Mean expiry time left: {}",
                     (ss.zone_expiry_sum as f32)/(ss.zone_sig_count as f32));
            println!("  Min expiry time left: {}", ss.zone_expiry_min);
            println!("  Max expiry time left: {}", ss.zone_expiry_max);
        }
        if ss.key_sig_count > 0 {
            println!("  Number of signatures: {}", ss.key_sig_count);
            println!("  Mean expiry time left: {}",
                     (ss.key_expiry_sum as f32)/(ss.key_sig_count as f32));
            println!("  Min expiry time left: {}", ss.key_expiry_min);
            println!("  Max expiry time left: {}", ss.key_expiry_max);
        }
    }

    return 0.into();
}
