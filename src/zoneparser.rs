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
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
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

pub struct RecordData {
    data: String,
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

    pub fn set(&mut self, name: &str, ttl: u32, class: RRClass , rrtype: RRType) {
	self.name = name.to_string();
	self.ttl = ttl;
	self.class = class;
	self.rrtype = rrtype;
    }
    
    pub fn push_data(&mut self, data: RecordData) {
	self.data.push(data)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
enum ParserState {
    #[default]
    Init,
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
    pub fn new(file: &'a File) -> Self {
	let buf = BufReader::new(file);

	let mut classes = HashMap::new();
	
	for c in RRClass::iter() {
	    classes.insert(format!("{:?}", c).to_lowercase(), c);
	}

	let mut types = HashMap::new();

	for t in RRType::iter() {
	    types.insert(format!("{:?}", t).to_lowercase(), t);
	}
	
	Self {
	    // Input text with position counters
	    bufreader: buf,
	    line_no: 0,

	    // Parser intermediary values
	    quoted_buf: "".to_string(),
	    directive_buf: "".to_string(),
	    name: "".to_string(),
	    origin: "".to_string(),
	    default_ttl: 0,
	    ttl: 0,
	    class: Default::default(),
	    rrtype: Default::default(),
	    b_count: 0,
	    end_of_stream: false,
	    state: Default::default(),

	    rrclass_hash: classes,
	    rrtype_hash: types,
	}
    }

    fn parse_line(&mut self, rec: &mut Option<Record>) {
	let mut line: String = "".to_string();
	let len = self.bufreader.read_line(&mut line).expect("Error reading zonefile");
	if len == 0 {
	    self.end_of_stream = true;
	    return;
	}
	let bytes = line.as_bytes();
	let mut pos = 0;
	self.line_no += 1;

	for part in bytes.split_inclusive(|&b| b == b' ' || b == b'\t' || b == b'\n' ||
					  b == b'(' || b == b')') {
	    // FIXME: Decode \DDD -> octal byte, and \X -> byte? What happens if we don't?

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

	    if wlen == 0 {
		// Single whitespace or bracket. Skip it
		continue;
	    }

	    match self.state {
		ParserState::Init => {
		    // FIXME: Is it possible to do this conversion in one step?
		    let word = part[0..wlen].escape_bytes().to_string().to_lowercase();
		    // Parse the common part of the record
		    if pos == 0 && self.b_count == 0 {
			// Start of record. Expect word to be the domain name
			if wlen != 0 {
			    if word.starts_with('$') {
				// Lines starting with $ is a directive
				self.directive_buf = word;
				self.state = ParserState::Directive;
			    }
			    else {
				self.name = word;
			    }
			}
		    }
		    else if let Some(class) = self.rrclass_hash.get(&word) {
			// Found class.
			self.class = *class;
		    }
		    else if let Some(rrtype) = self.rrtype_hash.get(&word) {
			// Found type. Create a record
			self.rrtype = *rrtype;
			self.state = ParserState::Data;
			let _ = rec.insert(Record::new(&self.name, self.ttl, self.class, self.rrtype));
		    }
		    else {
			// Expect TTL
			self.ttl = word.parse().unwrap();
		    }

		},
		ParserState::Directive => {
		    // Parsing a directive line.
		    let value = part[0..wlen].escape_bytes().to_string().to_lowercase();
		    if self.directive_buf == "$ttl" {
			self.default_ttl = value.parse().unwrap();
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
			// FIXME: Check the string for escaped chars, erroneous quotes and other errors
			if part[wlen - 1] == b'"' {
			    // Got end quote
			    rec.as_mut().unwrap().push_data(RecordData::from_bytes(&part[1..wlen - 1]));
			}
			else {
			    self.state = ParserState::QString;
			    self.quoted_buf = part[1..wlen].escape_bytes().to_string();
			}
		    }
		    else {
			// Unquoted data
			rec.as_mut().unwrap().push_data(RecordData::from_bytes(&part[1..wlen]));
		    }
		},
		ParserState::QString => {
		    // Continuation of quoted string. Look for end quote.
		    if part[wlen - 1] == b'"' {
			// Got end quote
			let s = &part[0..wlen - 1].escape_bytes().to_string();
			self.quoted_buf.push_str(s);
			rec.as_mut().unwrap().push_data(RecordData::new(&self.quoted_buf));
			self.state = ParserState::Data;
		    }
		    else {
			// No end quote. Just concatenate the whole part. We expect the next
			// word to continue the string.
			let s = part.escape_bytes().to_string();
			self.quoted_buf.push_str(&s);
		    }
		},
	    }

	    pos += plen;
	}
    }
}
