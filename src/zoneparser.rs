use std::fs::File;
use std::io::{BufReader, BufRead};
use std::fmt::{Display, Debug, Formatter};
use std::collections::HashMap;
use bstr::ByteSlice;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

// Numeric representation for rrclass
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, EnumIter)]
pub enum RRClass {
    #[default]
    IN = 1,
    CH = 3,
    HS = 4,
}

impl Display for RRClass {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
	write!(f, "{:?}", self)
    }
}

// Numeric representation for rrtype
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash, EnumIter, Ord, PartialOrd)]
pub enum RRType {
    #[default]
    None       = 0,
    A          = 1,
    NS         = 2,
    CNAME      = 5,
    SOA        = 6,
    PTR        = 12,
    HINFO      = 13,
    MX         = 15,
    TXT        = 16,
    RP         = 17,
    AFSDB      = 18,
    SIG        = 24,
    KEY        = 25,
    AAAA       = 28,
    LOC        = 29,
    SRV        = 33,
    NAPTR      = 35,
    KX         = 36,
    CERT       = 37,
    DNAME      = 39,
    APL        = 42,
    DS         = 43,
    SSHFP      = 44,
    IPSECKEY   = 45,
    RRSIG      = 46,
    NSEC       = 47,
    DNSKEY     = 48,
    DHCID      = 49,
    NSEC3      = 50,
    NSEC3PARAM = 51,
    TLSA       = 52,
    SMIMEA     = 53,
    HIP        = 55,
    CDS        = 59,
    CDNSKEY    = 60,
    OPENPGPKEY = 61,
    CSYNC      = 62,
    ZONEMD     = 63,
    SVCB       = 64,
    HTTPS      = 65,
    EUI48      = 108,
    EUI164     = 109,
    TKEY       = 249,
    TSIG       = 250,
    URI        = 256,
    CAA        = 257,
    WALLET     = 262,
    TA         = 32768,
    DLV        = 32769,
}

impl Display for RRType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
	write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub struct RecordData {
    pub data: String,
}

impl RecordData {
    pub fn new(data: &str) -> Self {
	Self {
	    data: data.to_string(),
	}
    }

    pub fn from_bytes(data: &[u8]) -> Self {
	Self {
	    data: data.escape_bytes().to_string(),
	}
    }
}

impl PartialEq for RecordData {
    fn eq(&self, other: &RecordData) -> bool {
	return self.data == other.data;
    }
}

impl Display for RecordData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
	write!(f, "{}", self.data)
    }
}

#[derive(Debug, Clone)]
pub struct Record {
    pub name: String,
    pub ttl: u32,
    pub class: RRClass,
    pub rrtype: RRType,
    pub data: Vec<RecordData>,
}

impl PartialEq for Record {
    fn eq(&self, other: &Record) -> bool {
	if self.name != other.name ||
	    self.ttl != other.ttl ||
	    self.class != other.class ||
	    self.rrtype != other.rrtype ||
	    self.data.len() != other.data.len() {
		return false;
	    }

	let n = self.data.len();
	for i in 0..n {
	    if self.data[i] != other.data[i] {
		return false;
	    }
	}
	
	return true;
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
	write!(f, "{} {} {} {}", self.name, self.ttl, self.class, self.rrtype)?;

	for d in &self.data {
	    write!(f, " {}", d)?
	}

	Ok(())
    }
}

impl Record {
    pub fn new(name: &str, ttl: u32, class: RRClass , rrtype: RRType) -> Self {
	Self {
	    name: name.to_string(),
	    ttl: ttl,
	    class: class,
	    rrtype: rrtype,
	    data: Default::default(),
	}
    }

    pub fn push_data(&mut self, data: RecordData) {
	self.data.push(data)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ParserState {
    #[default]
    Init,
    Common,
    Directive,
    Data,
    QString,
}

pub struct ZoneParser<'a> {
    bufreader: BufReader<&'a File>,
    line_no: usize,

    // Buffer for quoted strings
    quoted_buf: String,
    // Buffer for variable name
    directive_buf: String,
    // Name of current record
    name: String,
    // Name of zone apex
    origin: String,
    // Default ttl
    default_ttl: u32,
    // Current ttl
    ttl: u32,
    // Current class
    class: RRClass,
    // Current type
    rrtype: RRType,
    // Bracket count
    b_count: u16,
    // End of stream flag
    end_of_stream: bool,
    // Parser state
    state: ParserState,

    rrtype_hash: HashMap<String, RRType>,
    rrclass_hash: HashMap<String, RRClass>,
    rrtype_bm_hash: HashMap<String, (u8, u128, u128)>,
}

impl<'a> Iterator for ZoneParser<'a> {
    type Item = Record;

    fn next(&mut self) -> Option<Self::Item> {
	self.state = ParserState::Init;
	if self.default_ttl != 0 {
	    self.ttl = self.default_ttl;
	}

	let mut rec: Option<Record> = None;

	while !self.end_of_stream {
	    self.parse_line(&mut rec);

	    if rec.is_some() && self.b_count == 0 {
		return rec;
	    }
	}

	return None;
    }
}

impl<'a> ZoneParser<'a> {
    pub fn new(file: &'a File, origin: &str) -> Self {
	let buf = BufReader::new(file);

        // Build some lookup tables for classes, types and type bitmaps
	let mut classes = HashMap::new();
	
	for c in RRClass::iter() {
	    classes.insert(format!("{:?}", c).to_lowercase(), c);
	}

	let mut types = HashMap::new();

	for t in RRType::iter() {
            let t_str = format!("{:?}", t).to_lowercase();
	    types.insert(t_str, t);
        }

        let mut bm_hash = HashMap::new();

        for t in RRType::iter() {
            if t == RRType::None {
                continue;
            }

            let t_str = format!("{:?}", t).to_lowercase();
            let window_block = (t as u16 >> 8) as u8;
            let bitpos = (t as u16) & 0xff;
            let bm1: u128;
            let bm2: u128;
            if bitpos < 128 {
                bm1 = 1 << (127 - bitpos);
                bm2 = 0;
            }
            else {
                bm1 = 0;
                bm2 = 1 << (255 - bitpos);
            }
            bm_hash.insert(t_str, (window_block, bm1, bm2));
        }

        // Tolerate origin with or without ending dot
        let mut origin_muted = origin.to_string();
        if !origin_muted.ends_with('.') {
            origin_muted.push('.');
        }

	Self {
	    // Input text with position counters
	    bufreader: buf,
	    line_no: 0,
	    // Parser intermediary values
	    quoted_buf: "".to_string(),
	    directive_buf: "".to_string(),
	    name: "".to_string(),
	    origin: origin_muted,
	    default_ttl: 0,
	    ttl: 0,
	    class: Default::default(),
	    rrtype: Default::default(),
	    b_count: 0,
	    end_of_stream: false,
	    state: Default::default(),

	    rrclass_hash: classes,
	    rrtype_hash: types,
            rrtype_bm_hash: bm_hash,
	}
    }

    pub fn rrclass_from_str(&self, rrclass_str: &str) -> RRClass {
        return *self.rrclass_hash.get(&rrclass_str.to_lowercase()).unwrap();
    }

    pub fn rrtype_from_str(&self, rrtype_str: &str) -> RRType {
        return *self.rrtype_hash.get(&rrtype_str.to_lowercase()).unwrap();
    }

    // RRType bitmap for NSEC and NSEC3 records
    pub fn rrtype_bm_from_str(&self, rrtype_str: &str) -> (u8, u128, u128) {
        return *self.rrtype_bm_hash.get(&rrtype_str.to_lowercase()).unwrap();
    }

    fn parse_line(&mut self, rec: &mut Option<Record>) {
	let mut line: String = "".to_string();
	let len = self.bufreader.read_line(&mut line).
	    expect("Error reading zonefile");
	if len == 0 {
	    self.end_of_stream = true;
	    return;
	}
	let bytes = line.as_bytes();
	let mut pos = 0;
	self.line_no += 1;

	for part in bytes.split_inclusive(
	    |&b| b == b' ' || b == b'\t' || b == b'\n' ||
		 b == b'(' || b == b')') {
	    let plen = part.len();
	    let mut wlen = plen;

	    if part[0] == b';' && self.state != ParserState::QString {
		// Comment. Skip the rest of the line
		return;
	    }
	    
	    // Check end character
	    match part[plen - 1] {
		b' ' | b'\t' | b'\n' => {
		    wlen -= 1;
		},
		b'(' => {
		    self.b_count += 1;
		    wlen -= 1;
		},
		b')' => {
		    self.b_count -= 1;
		    wlen -= 1;
		},
		_ => { },
	    }

	    if wlen == 0 && (part[0] == b'\n' || self.state != ParserState::Init) {
		// Single whitespace, bracket or single newline. Skip it
		continue;
	    }

	    match self.state {
		ParserState::Init => {
		    let word = part[0..wlen].escape_bytes().to_string()
			.to_lowercase();
		    // Parse the common part of the record
		    if pos == 0 && self.b_count == 0 {
			// Start of record. Expect word to be the domain name
			if word.starts_with('$') {
			    // Lines starting with $ is a directive
			    self.directive_buf = word;
			    self.state = ParserState::Directive;
			}
			else {
			    // If the name is empty, use the name from
			    // the last record
			    if wlen > 0 {
				self.name = word;
			    }

			    self.state = ParserState::Common;
			}
		    }
		},
		ParserState::Common => {
		    let word = part[0..wlen].escape_bytes().to_string()
			.to_lowercase();
		    if let Some(class) = self.rrclass_hash.get(&word) {
			// Found class.
			self.class = *class;
		    }
		    else if let Some(rrtype) = self.rrtype_hash.get(&word) {
			// Found type. Create a record
			self.rrtype = *rrtype;
			self.state = ParserState::Data;
			let _ = rec.insert(
			    Record::new(&self.name, self.ttl,
					self.class, self.rrtype));
		    }
		    else {
			// Expect TTL
			self.ttl = word.parse().expect(&format!(
                            "Parse error on line {} pos {}",
                            self.line_no, pos));
		    }
		},
		ParserState::Directive => {
		    // Parsing a directive line.
		    let value = part[0..wlen].escape_bytes().to_string().
			to_lowercase();
		    if self.directive_buf == "$ttl" {
			self.default_ttl = value.parse().expect(&format!(
                            "Parse error on line {} pos {}",
                            self.line_no, pos));
		    }
		    else if self.directive_buf == "$origin" {
			self.origin = value;
		    }
		    else {
			panic!("Unknown directive {}", self.directive_buf);
		    }
		    self.state = ParserState::Init;
		},
		ParserState::Data => {
		    if part[0] == b'"' {
			// Start of quoted string.
			// FIXME: Check the string for escaped chars,
			//        erroneous quotes and other errors
			if part[wlen - 1] == b'"' {
			    // Got end quote
			    rec.as_mut().unwrap().push_data(
				RecordData::from_bytes(&part[1..wlen - 1]));
			}
			else {
			    self.state = ParserState::QString;
			    self.quoted_buf = format!(
				"{}{}", &part[1..wlen].escape_bytes(),
                                part[wlen] as char);
			}
		    }
		    else {
			// Unquoted data
			rec.as_mut().unwrap().push_data(
			    RecordData::from_bytes(&part[0..wlen]));
		    }
		},
		ParserState::QString => {
		    // Continuation of quoted string. Look for end quote.
		    if part[wlen - 1] == b'"' {
			// Got end quote
			let s = format!(
                            "{}", &part[0..wlen - 1].escape_bytes());
			self.quoted_buf.push_str(&s);
			rec.as_mut().unwrap().push_data(
			    RecordData::new(&self.quoted_buf));
			self.state = ParserState::Data;
		    }
		    else {
			// No end quote. Just concatenate the whole part. We
			// expect the next word to continue the string.
			let s = format!(
                            "{}{}", &part[0..wlen].escape_bytes(),
                            part[wlen] as char);
			self.quoted_buf.push_str(&s);
		    }
		},
	    }

	    pos += plen;
	}
    }

    pub fn absolute_name(&self, name: &str) -> String {
	assert!(name != "");

	if name == "@" {
	    return self.origin.clone();
	}

	if name.ends_with('.') {
	    return name.to_string();
	}
	else {
	    return format!("{}.{}", name, self.origin);
	}
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use crate::zoneparser::{ZoneParser, Record, RecordData, RRClass, RRType};

    impl Record {
	pub fn new_with_data(name: &str, ttl: u32, class: RRClass ,
			     rrtype: RRType, data: Vec<&str>) -> Self {
	    let recorddata =
		data.iter().map(|s| RecordData::new(s)).collect::<Vec<_>>();

	    Self {
		name: name.to_string(),
		ttl: ttl,
		class: class,
		rrtype: rrtype,
		data: recorddata,
	    }
	}
    }

    macro_rules! assert_next_rec {
	($parser:expr, $name:expr, $ttl:expr, $class:expr, $rrtype:expr, $( $data:expr ),*) => {
	    assert_eq!(
		$parser.next(),
		Some(Record::new_with_data($name, $ttl, $class, $rrtype, vec![$($data),*])),
	    );
	}
    }
    
    #[test]
    fn simple_zone() {
	let file = File::open("./test_data/simple.zn").unwrap();
	let mut p = ZoneParser::new(&file);

	assert_next_rec!(
	    p, "simple.zn.", 3600, RRClass::IN, RRType::SOA,
	    "ns1.simple.zn.", "hostmaster.simple.zn.",
	    "2024090906", "7200", "1800", "86400", "7200");

	assert_next_rec!(
	    p, "simple.zn.", 3600, RRClass::IN, RRType::NS, "ns1.simple.zn.");

    	assert_next_rec!(
	    p, "simple.zn.", 3600, RRClass::IN, RRType::NS, "ns2.simple.zn.");

    	assert_next_rec!(
	    p, "info.simple.zn.", 3600, RRClass::IN, RRType::MX, "mail.simple.zn.");

    	assert_next_rec!(
	    p, "mail.simple.zn.", 3600, RRClass::IN, RRType::A, "1.2.3.4");

    	assert_next_rec!(
	    p, "mail.simple.zn.", 3600, RRClass::IN, RRType::AAAA, "1:2:3:4");

    	assert!(p.next().is_none());
    }

    #[test]
    fn directives() {
	let file = File::open("./test_data/directives.zn").unwrap();
	let mut p = ZoneParser::new(&file);

	assert!(p.next().is_some());

	assert_eq!(p.origin, "simple.zn.");

	assert_eq!(p.default_ttl, 3600);
    }

    #[test]
    fn case_insensitivity() {
	let file = File::open("./test_data/lc_and_uc.zn").unwrap();
	let mut p = ZoneParser::new(&file);

	assert_next_rec!(
	    p, "simple.zn.", 3600, RRClass::IN, RRType::SOA,
	    "NS1.simple.zn.", "Hostmaster.Simple.Zn.",
	    "2024090906", "7200", "1800", "86400", "7200");

    	assert!(p.next().is_none());
    }

    #[test]
    fn relative_names() {
	let file = File::open("./test_data/relative.zn").unwrap();
	let mut p = ZoneParser::new(&file);
        let mut rr;

	rr = p.next();
	assert!(rr.is_some());
	assert_eq!(p.absolute_name(&rr.unwrap().name), "simple.zn.");

	rr = p.next();
	assert!(rr.is_some());
	assert_eq!(p.absolute_name(&rr.unwrap().name), "simple.zn.");

	rr = p.next();
	assert!(rr.is_some());
	assert_eq!(p.absolute_name(&rr.unwrap().name), "info.simple.zn.");

	rr = p.next();
	assert!(rr.is_some());
	assert_eq!(p.absolute_name(&rr.unwrap().name), "mail.simple.zn.");

    	assert!(p.next().is_none());
    }

    #[test]
    fn default_values() {
	let file = File::open("./test_data/directives.zn").unwrap();
	let mut p = ZoneParser::new(&file);

	assert!(p.next().is_some());

	assert_next_rec!(
	    p, "@", 300, RRClass::IN, RRType::NS, "ns1.simple.zn.");

    	assert_next_rec!(
	    p, "@", 3600, RRClass::IN, RRType::NS, "ns2.simple.zn.");

    	assert!(p.next().is_none());
    }

    #[test]
    fn brackets_and_comments() {
	let file = File::open("./test_data/brackets_and_comments.zn").unwrap();
	let mut p = ZoneParser::new(&file);

	assert_next_rec!(
	    p, "simple.zn.", 3600, RRClass::IN, RRType::SOA,
	    "ns1.simple.zn.", "hostmaster.simple.zn.",
	    "2024090906", "7200", "1800", "86400", "7200");

    	assert!(p.next().is_none());
    }

    #[test]
    fn quotes() {
	let file = File::open("./test_data/quotes.zn").unwrap();
	let mut p = ZoneParser::new(&file);

        assert_next_rec!(
	    p, "simple.zn.", 3600, RRClass::IN, RRType::TXT,
	    "first quote", "Second QUOTE", "3. qt");

    	assert!(p.next().is_none());
    }
}
