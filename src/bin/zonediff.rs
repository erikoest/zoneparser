extern crate zoneparser;

use std::fs::File;
use std::env;
use std::cmp::Ordering;
    
use zoneparser::{ZoneParser, Record, RecordData, RRType};

/* Compare the records of two zones. The zone records are expected to
be sorted on domain names. The exception is the apex records which is
expected to be found at the start. 
*/

/* Iterator which gets rrset on each iteration. In a strict sense,
this struct is not an iterator (it does not implement the iterator
trait). Also, it does not return the next item. Rather, it keeps it
until the next iteration step is performed.
*/
struct SetIterator<'a> { parser: ZoneParser<'a>, next: Option<Record>,
    set: Vec<Record>, }

impl<'a> SetIterator<'a> {
    fn new(file: &'a File, origin: &str) -> Self {
	let mut parser = ZoneParser::new(&file, origin);
	let next = parser.next();
	let set: Vec<Record> = vec!();

	Self {
	    parser: parser,
	    next: next,
	    set: set,
	}
    }

    fn print_set(&self, pfx: &str) {
	for rr in &self.set {
	    println!("{} {}", pfx, rr);
	}
    }

    fn set_name(&self) -> &str {
	return &self.set[0].name;
    }

    fn is_empty(&self) -> bool {
	return self.set.is_empty();
    }

    fn sets_differ(&self, other: &'a SetIterator<'a>,
		   ignore_serial: bool) -> bool {
	if self.set.len() != other.set.len() {
	    return true;
	}

	for i in 0..self.set.len() {
	    if self.set[i].rrtype == RRType::SOA && ignore_serial {
		let mut this = self.set[i].clone();
		let mut that = self.set[i].clone();
		this.data[2] = RecordData::new("");
		that.data[2] = RecordData::new("");
		if this != that {
		    return true;
		}
	    }
	    else {
		if self.set[i] != other.set[i] {
		    return true;
		}
	    }
	}

	return false;
    }
    
    fn fetch_next(&mut self) {
	self.set.clear();
	if self.next.is_some() {
	    let name = self.next.as_ref().unwrap().name.clone();
	    while self.next.is_some() {
		if &self.next.as_ref().unwrap().name == &name {
		    let nx = self.parser.next();
		    if nx.is_some() {
			self.set.push(self.next.replace(nx.unwrap()).unwrap());
		    }
		    else {
			self.set.push(self.next.take().unwrap());
		    }
		}
		else {
		    break;
		}
	    }
	}
    }
}

struct Differ<'a> {
    old: SetIterator<'a>,
    new: SetIterator<'a>,
    ignore_serial: bool,
    verbose: bool,
    added: usize,
    removed: usize,
    changed: usize,
}

impl<'a> Differ<'a> {
    fn new(oldfile: &'a File, newfile: &'a File, origin: &str,
           ignore_serial: bool, verbose: bool) -> Self {
	let old = SetIterator::new(&oldfile, origin);
	let new = SetIterator::new(&newfile, origin);

	Self {
	    old: old,
	    new: new,
	    ignore_serial: ignore_serial,
	    verbose: verbose,
	    added: 0,
	    removed: 0,
	    changed: 0,
	}
    }

    fn diff_sets(&mut self) {
	if self.old.is_empty() && ! self.new.is_empty() {
	    // Only right set. Set is added
	    if self.verbose {
		self.new.print_set("++");
	    }
	    self.added += 1;
	    self.new.fetch_next();
	    return;
	}

	if ! self.old.is_empty() && self.new.set.is_empty() {
	    // Only left set. Set is removed
	    if self.verbose {
		self.old.print_set("--");
	    }
	    self.removed += 1;
	    self.old.fetch_next();
	    return;
	}

	match self.old.set_name().cmp(self.new.set_name()) {
	    Ordering::Less => {
		// Right set sorts higher. Set is removed
		if self.verbose {
		    self.old.print_set("--");
		}
		self.removed += 1;
		self.old.fetch_next();
		return;
	    },
	    Ordering::Greater => {
		// Left set sorts higher. Set is added
		if self.verbose {
		    self.new.print_set("++");
		}
		self.added += 1;
		self.new.fetch_next();
		return;
	    },
	    Ordering::Equal => {
		// Sets have the same name. Compare all records
		// Diff each set of equal RRTtypes. Option to diff by single
		// records.
		if self.old.sets_differ(&self.new, self.ignore_serial) {
		    if self.verbose {
			self.old.print_set("~-");
			self.new.print_set("~+");
		    }
		    self.changed += 1;
		}
		self.old.fetch_next();
		self.new.fetch_next();
		return;
	    },
	}
    }

    fn diff (&mut self) {
	// Get apex rrset from old and new zone
	self.old.fetch_next();
	self.new.fetch_next();

	// Compare them
	self.diff_sets();

	while ! self.old.is_empty() && ! self.new.is_empty() {
	    self.diff_sets();
	}
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut origin = "";
    let mut verbose = false;
    let mut ignore_serial = false;

    let mut arg_count = 1;

    loop {
	match args[arg_count].as_str() {
            "-o" | "--origin" => {
                origin = &args[arg_count + 1];
                arg_count += 2;
            },
	    "-s" | "--ignore-serial" => {
		arg_count += 1;
		ignore_serial = true;
	    },
	    "-v" | "--verbose" => {
		arg_count += 1;
		verbose = true;
	    },
	    _ => break,
	}
    }
    
    if args.len() < 2 + arg_count {
        println!("Usage: zonediff [-o origin] [-s] [-v] <old zonefile> <new zonefile>");
        return;
    }

    if origin == "" {
        origin = &args[arg_count];
    }

    let oldfile = File::open(&args[arg_count]).unwrap();
    let newfile = File::open(&args[arg_count + 1]).unwrap();

    let mut differ = Differ::new(&oldfile, &newfile, origin, ignore_serial, verbose);
    differ.diff();

    println!("added: {}", differ.added);
    println!("removed: {}", differ.removed);
    println!("changed: {}", differ.changed);
}
