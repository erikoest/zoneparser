# ZoneParser: A zonefile parser with good performance

The ZoneParser is a DNS zonefile parser. It has been designed to have a good
performance with regards to cpu and memory consumption. It works well with
large zonefiles. The code is in an early stage of development and still has
a somewhat limited functionality.

## Install

Add the following to `Cargo.toml`:

```[dependencies]
zoneparser = "0.1.0"
```

## Usage

The parser is constructed with a file as input. It then works as an iterator
yielding the resource records of the zone. An example:

```use std::fs::File;
use zoneparser::ZoneParser;

fn main() {
  let file = File::open("my-zone.no").unwrap();
  let p = ZoneParser::new(&file);

  for rr in p {
    println!("{}", rr);
  }
}
```

For further examples, see the included command line tools `zcount` and `zdiff`.

## Bugs

- Escaped characters and octal number representations in the zonefile are
  not well handled.

## Missing features

- Error handling is rather crude. Parse errors cause panic.
- Quoted strings are somewhat poorly handled, esp. with escaped content.
- Only the common record fields are parsed. Content specific to the record types are
  returned as anonymous data fields. A later version might support parsing the data
  content as a secondary function call.
- Relative names are not converted to absolute ones.

## Contributing

The limited functionality very much reflects the needs I had when I wrote the library.
If you find it useful, and miss some functionality, please let me know. It might motivate
me to further development. Bug reports are always welcome.
