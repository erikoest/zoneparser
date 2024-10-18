extern crate zoneparser;

use std::fs::File;
use std::env;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
    
use zoneparser::{ZoneParser, Record, RecordData, RRType};

/* Compare the records of two zones. The zone records are expected to
be sorted on domain names. The exception is the apex records which is
expected to be found at the start. 
*/

// Compare records in some way. Canonical order is not important here.
fn rr_sort(a: &Record, b: &Record) -> Ordering {
    // We expect name to be equal. Don't compare it here.
    if a.rrtype != b.rrtype {
        return a.rrtype.cmp(&b.rrtype);
    }

    if a.ttl != b.ttl {
        return a.ttl.cmp(&b.ttl);
    }

    if a.class != b.class {
        return a.class.cmp(&b.class);
    }

    for i in 0..a.data.len() {
        if b.data.len() < i {
            return Ordering::Greater;
        }

        if a.data[i] != b.data[i] {
            return a.data[i].data.cmp(&b.data[i].data);
        }
    }

    if b.data.len() > a.data.len() {
        return Ordering::Less;
    }

    Ordering::Equal
}

/* Iterator which gets rrset on each iteration. In a strict sense,
this struct is not an iterator (it does not implement the iterator
trait). Also, it does not return the next item. Rather, it keeps it
until the next iteration step is performed.
*/
struct SetIterator<'a> {
    parser: ZoneParser<'a>,
    next: Option<Record>,
    set: Vec<Record>,
    pub name: String,
}

impl<'a> SetIterator<'a> {
    fn new(file: &'a File, origin: &str) -> Self {
	let mut parser = ZoneParser::new(&file, origin);
	let next = parser.next();
	let set: Vec<Record> = vec!();

	Self {
	    parser: parser,
	    next: next,
	    set: set,
            name: "".to_string(),
	}
    }

    fn print_set(&self, pfx: &str) {
        for rr in &self.set {
            println!("{} {}", pfx, rr);
        }
    }

    fn count_and_print_differences(&self, other: &'a SetIterator<'a>,
                                   changed: &'a mut HashMap<RRType, usize>,
                                   verbose: bool) {
        // Sort sets in-place
        let mut this = self.set.clone();
        this.sort_by(|a, b| rr_sort(&a, &b));
        let mut that = other.set.clone();
        that.sort_by(|a, b| rr_sort(&a, &b));

        let mut changed_types: HashSet<RRType> = HashSet::new();

        while ! this.is_empty() && ! that.is_empty() {
            if this.is_empty() && ! that.is_empty() {
	        // Only right set. Record is added
                let r = that.pop().unwrap();
                changed_types.insert(r.rrtype);
                if verbose {
                    println!("~+ {}", r);
                }
	    }

	    if ! this.is_empty() && that.is_empty() {
	        // Only left set. Record is deleted
                let r = this.pop().unwrap();
                changed_types.insert(r.rrtype);
                if verbose {
                    println!("~- {}", r);
                }
	    }

            let rthis = this.pop().unwrap();
            let rthat = that.pop().unwrap();

	    match rr_sort(&rthis, &rthat) {
	        Ordering::Greater => {
		    // Right set sorts higher. Record is deleted
                    changed_types.insert(rthis.rrtype);
                    if verbose {
                        println!("~- {}", rthis);
                    }
                    that.push(rthat);
	        },
	        Ordering::Less => {
		    // Left set sorts higher. Record is added
                    changed_types.insert(rthat.rrtype);
                    if verbose {
                        println!("~+ {}", rthat);
                    }
                    this.push(rthis);
	        },
	        Ordering::Equal => {
		    // No changes.
	        },
	    }
        }

        for t in changed_types {
            if let Some(&i) = changed.get(&t) {
                changed.insert(t, i + 1);
            }
            else {
                changed.insert(t, 1);
            }
        }

        changed.insert(RRType::None,
                       *changed.get(&RRType::None).unwrap() + 1);
    }

    fn is_empty(&self) -> bool {
	return self.set.is_empty();
    }

    fn check_differences(&self, other: &'a SetIterator<'a>,
                         changed: &'a mut HashMap<RRType, usize>,
                         verbose: bool) {
        let mut is_changed = false;

        for i in 0..self.set.len() {
            if self.set[i] != other.set[i] {
                is_changed = true;
            }
        }

        if is_changed {
            // Count changes per rr type
            self.count_and_print_differences(&other, changed, verbose);
        }
    }

    fn count_records(&self, count: &mut HashMap<RRType, usize>) {
        let mut rrt: HashSet<RRType> = HashSet::new();

        for rr in &self.set {
            rrt.insert(rr.rrtype);
        }

        for t in rrt {
            if let Some(i) = count.get(&t) {
                count.insert(t, i + 1);
            }
            else {
                count.insert(t, 1);
            }
        }

        count.insert(RRType::None,
                     count.get(&RRType::None).unwrap() + 1);
    }
    
    fn fetch_next(&mut self, ignore_serial: bool) {
	self.set.clear();

	if self.next.is_some() {
	    self.name = self.next.as_ref().unwrap().name.clone();
	    while self.next.is_some() {
		if &self.next.as_ref().unwrap().name == &self.name {
		    let nx = self.parser.next();
                    let mut rr;
		    if nx.is_some() {
                        rr = self.next.replace(nx.unwrap()).unwrap();
                    }
                    else {
                        rr = self.next.take().unwrap();
		    }

                    if rr.rrtype == RRType::SOA && ignore_serial {
                        // Wipe serial number.
                        rr.data[2] = RecordData::new("");
                    }

                    self.set.push(rr);
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
    added: HashMap<RRType, usize>,
    deleted: HashMap<RRType, usize>,
    changed: HashMap<RRType, usize>,
}

impl<'a> Differ<'a> {
    fn new(oldfile: &'a File, newfile: &'a File, origin: &str,
           ignore_serial: bool, verbose: bool) -> Self {
	let old = SetIterator::new(&oldfile, origin);
	let new = SetIterator::new(&newfile, origin);
        let mut added = HashMap::new();
        let mut deleted = HashMap::new();
        let mut changed = HashMap::new();
        added.insert(RRType::None, 0);
        deleted.insert(RRType::None, 0);
        changed.insert(RRType::None, 0);

	Self {
	    old: old,
	    new: new,
	    ignore_serial: ignore_serial,
	    verbose: verbose,
	    added: added,
	    deleted: deleted,
	    changed: changed,
	}
    }

    fn count_added_sets(&mut self) {
        self.new.count_records(&mut self.added);
	if self.verbose {
	    self.new.print_set("++");
	}
    }

    fn count_deleted_sets(&mut self) {
        self.old.count_records(&mut self.deleted);
	if self.verbose {
	    self.old.print_set("--");
	}
    }

    fn count_changed_sets(&mut self) {
        self.old.check_differences(&self.new, &mut self.changed, self.verbose);
    }

    fn diff_sets(&mut self) {
	if self.old.is_empty() && ! self.new.is_empty() {
	    // Only right set. Set is added
            self.count_added_sets();
	    self.new.fetch_next(self.ignore_serial);
	    return;
	}

	if ! self.old.is_empty() && self.new.set.is_empty() {
	    // Only left set. Set is deleted
            self.count_deleted_sets();
	    self.old.fetch_next(self.ignore_serial);
	    return;
	}

	match self.old.name.cmp(&self.new.name) {
	    Ordering::Less => {
		// Right set sorts higher. Set is deleted
                self.count_deleted_sets();
		self.old.fetch_next(self.ignore_serial);
		return;
	    },
	    Ordering::Greater => {
		// Left set sorts higher. Set is added
                self.count_added_sets();
		self.new.fetch_next(self.ignore_serial);
		return;
	    },
	    Ordering::Equal => {
		// Sets have the same name. Compare all records
		// Diff each set of equal RRTtypes.
                self.count_changed_sets();
		self.old.fetch_next(self.ignore_serial);
		self.new.fetch_next(self.ignore_serial);
		return;
	    },
	}
    }

    fn diff (&mut self) {
	// Get apex rrset from old and new zone
	self.old.fetch_next(self.ignore_serial);
	self.new.fetch_next(self.ignore_serial);

	// Compare them
	self.diff_sets();

	while ! self.old.is_empty() && ! self.new.is_empty() {
	    self.diff_sets();
	}
    }

    fn print_summary(&self) {
        let mut types: HashSet<RRType> = HashSet::new();

        for &t in self.added.keys() {
            types.insert(t);
        }

        for &t in self.deleted.keys() {
            types.insert(t);
        }

        for &t in self.changed.keys() {
            types.insert(t);
        }

        for t in types {
            if t == RRType::None {
                continue;
            }

            println!("{}:", t);

            if self.added.contains_key(&t) {
                println!("  added: {}", self.added.get(&t).unwrap());
            }

            if self.deleted.contains_key(&t) {
                println!("  deleted: {}", self.deleted.get(&t).unwrap());
            }

            if self.changed.contains_key(&t) {
                println!("  changed: {}", self.changed.get(&t).unwrap());
            }
        }

        println!("names:");
        println!("  added: {}", self.added.get(&RRType::None).unwrap());
        println!("  deleted: {}", self.deleted.get(&RRType::None).unwrap());
        println!("  changed: {}", self.changed.get(&RRType::None).unwrap());
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
    differ.print_summary();
}
