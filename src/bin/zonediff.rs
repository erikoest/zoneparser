extern crate zoneparser;

use std::env;
use std::fs::File;
use diffs::{Diff, myers::diff};
use std::collections::HashMap;
use core::ops::Index;

use zoneparser::{ZoneParser, Record, RecordData, RRType};

struct RecordDiffer<'a> {
    old: &'a Vec<Record>,
    new: &'a Vec<Record>,
    verbose: bool,
    has_changes: bool,
}

impl<'a> RecordDiffer<'a> {
    fn new(old: &'a Vec<Record>, new: &'a Vec<Record>, verbose: bool) -> Self {
        Self {
            old: old,
            new: new,
            verbose: verbose,
            has_changes: false,
        }
    }
}

impl<'a> Diff for RecordDiffer<'a> {
    type Error = ();

    fn equal(&mut self, _: usize, _: usize, _: usize)
             -> Result<(), Self::Error> {
        Ok(())
    }

    fn delete(&mut self, old: usize, len: usize, _: usize)
              -> Result<(), Self::Error> {
        self.has_changes = true;

        if self.verbose {
            for i in old..old + len {
                println!("~- {}", self.old[i]);
            }
        }

        Ok(())
    }

    fn insert(&mut self, _: usize, new: usize, new_len: usize)
              -> Result<(), Self::Error> {
        self.has_changes = true;

        if self.verbose {
            for i in new..new + new_len {
                println!("~+ {}", self.new[i]);
            }
        }

        Ok(())
    }

    fn replace(&mut self, old: usize, old_len: usize,
               new: usize, new_len: usize) -> Result<(), Self::Error> {
        self.has_changes = true;

        if self.verbose {
            for i in old..old + old_len {
                println!("~- {}", self.old[i]);
            }

            for i in new..new + new_len {
                println!("~+ {}", self.new[i]);
            }
        }

        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

}

struct RecordSet {
    set: Vec<Record>,
}

impl RecordSet {
    fn new() -> Self {
        Self {
            set: vec!(),
        }
    }

    fn push(&mut self, r: Record) {
        self.set.push(r);
    }

    fn name(&self) -> String {
        self.set[0].name.clone()
    }

    fn rrtype(&self) -> RRType {
        self.set[0].rrtype
    }

    fn print_pf(&self, pf: &str) {
        for i in 0..self.set.len() {
            println!("{} {}", pf, self.set[i]);
        }
    }
}

impl PartialEq for RecordSet {
    fn eq(&self, other: &RecordSet) -> bool {
        return (self.name() == other.name()) &&
            (self.rrtype() == other.rrtype());
    }
}

enum DiffSection {
    Equal(usize, usize, usize),
    Delete(usize, usize, usize),
    Insert(usize, usize, usize),
    Replace(usize, usize, usize, usize),
}

struct SetDiffer {
    differences: Vec<DiffSection>,
    old_tail: usize,
    new_tail: usize,
}

impl SetDiffer {
    fn new() -> Self {
        Self {
            differences: vec!(),
            old_tail: 0,
            new_tail: 0,
        }
    }

    fn trunc_differences(&mut self) {
        // Remove the last differences until we find an equal section
        loop {
            match self.differences.last() {
                Some(DiffSection::Equal(old, new, len)) => {
                    // Update tails.
                    self.old_tail = old + len;
                    self.new_tail = new + len;
                    break;
                },
                None => {
                    // Buffers must contain at least one equal section.
                    // If not, the buffer size is not big enough.
                    panic!("Too many differences. Buffer overflow.");
                },
                _ => {
                    self.differences.pop().unwrap();
                },
            }
        }
    }
}

impl Diff for SetDiffer {
    type Error = ();

    fn equal(&mut self, old: usize, new: usize, len: usize)
             -> Result<(), Self::Error> {
        self.differences.push(DiffSection::Equal(old, new, len));

        Ok(())
    }

    fn delete(&mut self, old: usize, len: usize, new: usize)
              -> Result<(), Self::Error> {
        self.differences.push(DiffSection::Delete(old, len, new));

        Ok(())
    }

    fn insert(&mut self, old: usize, new: usize, new_len: usize)
              -> Result<(), Self::Error> {
        self.differences.push(DiffSection::Insert(old, new, new_len));

        Ok(())
    }

    fn replace(&mut self, old: usize, old_len: usize,
               new: usize, new_len: usize) -> Result<(), Self::Error> {
        self.differences.push(DiffSection::Replace(old, old_len, new, new_len));

        Ok(())
    }

    fn finish(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct Ring<'a> {
    parser: ZoneParser<'a>,
    data: Vec<RecordSet>,
    tail: usize,
    head: usize,
    buf_size: usize,
    ignore_serial: bool,
    skip_dnssec: bool,
    at_end: bool,
    last: Option<RecordSet>,
}

impl<'a> Ring<'a> {
    fn new(file: &'a File, origin: &str, buf_size: usize,
           ignore_serial: bool, skip_dnssec: bool) -> Self {
        Self {
            parser: ZoneParser::new(&file, origin),
            data: vec!(),
            tail: 0,
            head: 0,
            buf_size: buf_size,
            ignore_serial: ignore_serial,
            skip_dnssec: skip_dnssec,
            at_end: false,
            last: None,
        }
    }

    fn read_zone_records(&mut self) {
        let mut name = "".to_string();
        let mut rrtype = RRType::None;

        if self.last.is_some() {
            let last = self.last.as_ref().unwrap();
            name = last.name();
            rrtype = last.rrtype();
        }

        while let Some(mut r) = self.parser.next() {
            if self.skip_dnssec && (r.rrtype == RRType::NSEC ||
                                    r.rrtype == RRType::NSEC3 ||
                                    r.rrtype == RRType::RRSIG) {
                continue;
            }

            if self.ignore_serial && r.rrtype == RRType::SOA {
                r.data[2] = RecordData::new("");
            }

            if self.last.is_some() {
                if r.name == name && r.rrtype == rrtype {
                    self.last.as_mut().unwrap().push(r);
                }
                else {
                    name = r.name.clone();
                    rrtype = r.rrtype;
                    let mut newset = RecordSet::new();
                    newset.push(r);

                    let taken = self.last.replace(newset);
                    self.push(taken.unwrap());

                    // Break here if ring buffer is full
                    if self.head - self.tail == self.buf_size {
                        break;
                    }
                }
            }
            else {
                let mut set = RecordSet::new();
                set.push(r);
                let _ = self.last.insert(set);
            }
        }

        if self.last.is_some() {
            if self.head - self.tail < self.buf_size {
                let last = self.last.take().unwrap();
                self.push(last);
                self.at_end = true;
            }
        }
        else {
            self.at_end = true;
        }
    }

    fn push(&mut self, e: RecordSet) {
        if self.head < self.buf_size {
            self.data.push(e);
            self.head += 1;
        }
        else {
            self.data[self.head % self.buf_size] = e;
            self.head += 1;
            assert!(self.head - self.tail <= self.buf_size,
                    "Ring buffer overflow");
        }
    }

    fn set_tail(&mut self, t: usize) {
        self.tail = t;
    }
}

impl<'a> Index<usize> for Ring<'a> {
    type Output = RecordSet;

    fn index(&self, i: usize) -> &Self::Output {
        return &self.data[i % self.buf_size];
    }
}

struct Differ<'a> {
    old: Ring<'a>,
    new: Ring<'a>,
    count: HashMap<RRType, HashMap<String, usize>>,
    verbose: bool,
}

impl<'a> Differ<'a> {
    fn new(oldfile: &'a File, newfile: &'a File, origin: &str, buf_size: usize,
               ignore_serial: bool, skip_dnssec: bool, verbose: bool) -> Self {
        Self {
            old: Ring::new(&oldfile, origin, buf_size, ignore_serial,
                           skip_dnssec),
            new: Ring::new(&newfile, origin, buf_size, ignore_serial,
                           skip_dnssec),
            count: HashMap::new(),
            verbose: verbose,
        }
    }

    fn increment(&mut self, k1: RRType, k2: &str) {
        if let Some(v1) = self.count.get_mut(&k1) {
            if let Some(c) = v1.get(k2) {
                v1.insert(k2.to_string(), c + 1);
            }
            else {
                v1.insert(k2.to_string(), 1);
            }
        }
        else {
            let mut m = HashMap::new();
            m.insert(k2.to_string(), 1);
            self.count.insert(k1, m);
        }
    }

    fn check_difference(&mut self, d: &DiffSection) {
        match *d {
            DiffSection::Equal(old, new, len) => {
                // The same sets are found in old and new zonefile.
                // Compare sets by record.
                for i in 0..len {
                    let mut rd = RecordDiffer::new(&self.old[old + i].set,
                                                   &self.new[new + i].set,
                                                   self.verbose);

                    diff(&mut rd,
                         &self.old[old + i].set, 0, self.old[old + i].set.len(),
                         &self.new[new + i].set, 0, self.new[new + i].set.len()
                    ).unwrap();

                    if rd.has_changes {
                        self.increment(RRType::None, "changed");
                        self.increment(self.old[old + i].rrtype(), "changed");
                    }
                }
            },
            DiffSection::Delete(old, len, _) => {
                for i in old..old + len {
                    if self.verbose {
                        self.old[i].print_pf("--");
                    }

                    self.increment(RRType::None, "deleted");
                    self.increment(self.old[i].rrtype(), "deleted");
                }
            },
            DiffSection::Insert(_, new, new_len) => {
                for i in new..new + new_len {
                    if self.verbose {
                        self.new[i].print_pf("++");
                    }

                    self.increment(RRType::None, "added");
                    self.increment(self.new[i].rrtype(), "added");
                }
            },
            DiffSection::Replace(old, old_len, new, new_len) => {
                for i in old..old + old_len {
                    if self.verbose {
                        self.old[i].print_pf("--");
                    }

                    self.increment(RRType::None, "deleted");
                    self.increment(self.old[i].rrtype(), "deleted");
                }

                for i in new..new + new_len {
                    if self.verbose {
                        self.new[i].print_pf("++");
                    }

                    self.increment(RRType::None, "added");
                    self.increment(self.new[i].rrtype(), "added");
                }
            }
        }
    }

    fn print_results(&mut self) {
        let mut some_names = None;

        let mut types: Vec<_> = self.count.drain().collect();
        types.sort_by(|(a, _), (b, _)| a.cmp(b));

        for (t, mut h) in types {
            if t == RRType::None {
                some_names.replace(h);
                continue;
            }

            println!("{}:", t);

            let mut count: Vec<_> = h.drain().collect();
            count.sort_by(|(a, _), (b, _)| a.cmp(b));

            for (op, c) in count {
                println!("  {}: {}", op, c);
            }
        }

        if let Some(mut names) = some_names {
            println!("total:");

            let mut count: Vec<_> = names.drain().collect();
            count.sort_by(|(a, _), (b, _)| a.cmp(b));

            for (op, c) in count {
                println!("  {}: {}", op, c);
            }
        }
    }

    fn compare(&mut self) {
        while !self.old.at_end && !self.new.at_end {
            self.old.read_zone_records();
            self.new.read_zone_records();

            let mut sd = SetDiffer::new();

            diff(&mut sd,
                 &self.old, self.old.tail, self.old.head,
                 &self.new, self.new.tail, self.new.head
            ).unwrap();

            if !self.old.at_end || !self.new.at_end {
                // If we haven't parsed all sections, the last differences
                // may be false. Remove them until we get an equal section.
                sd.trunc_differences();
            }

            for d in sd.differences {
                self.check_difference(&d);
            }

            self.old.set_tail(sd.old_tail);
            self.new.set_tail(sd.new_tail);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut origin = "";
    let mut buf_size: usize = 1 << 16;
    let mut verbose = false;
    let mut ignore_serial = false;
    let mut skip_dnssec = false;

    let mut arg_count = 1;

    loop {
        match args[arg_count].as_str() {
            "-o" | "--origin" => {
                origin = &args[arg_count + 1];
                arg_count += 2;
            },
            "-b" | "--buffer-size" => {
                buf_size = args[arg_count + 1].parse().unwrap();
                arg_count += 2;
            }
            "-s" | "--ignore-serial" => {
                arg_count += 1;
                ignore_serial = true;
            },
            "-d" | "--skip-dnssec" => {
                arg_count += 1;
                skip_dnssec = true;
            }
            "-v" | "--verbose" => {
                arg_count += 1;
                verbose = true;
            },
            _ => break,
        }
    }

    if origin == "" {
        origin = &args[arg_count];
    }

    let oldfile = File::open(&args[arg_count]).unwrap();
    let newfile = File::open(&args[arg_count + 1]).unwrap();

    let mut differ = Differ::new(&oldfile, &newfile, origin, buf_size,
                                 ignore_serial, skip_dnssec, verbose);
    differ.compare();
    differ.print_results();
}
