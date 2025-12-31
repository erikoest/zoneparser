# ZoneParser: A zonefile parser with good performance

The ZoneParser is a DNS zonefile parser. It has been designed to have a good
performance with regards to cpu and memory consumption. It works well with
large zonefiles. The code is in an early stage of development and still has
a somewhat limited functionality.

## Usage

The parser is constructed with a file as input. It then works as an iterator
yielding the resource records of the zone. An example:

```use std::fs::File;
use zoneparser::ZoneParser;

fn main() {
  let file = File::open("my-zone.no").unwrap();
  let p = ZoneParser::new(&file, "my-zone.no");

  for next in p {
    match next {
      Err(e) => {
        println!("Parse error: {}", e);
        break;
      },
      Ok(rr) => {
        println!("{}", rr);
      },
    }
  }
}
```

For further examples, see the included command line tools `zonecount`
and `zonediff`.

## Optional Features

### Serde Support

The library includes optional serialization and deserialization support via the `serde` feature. This allows you to easily convert parsed DNS records to and from formats like JSON, YAML, or any other serde-supported format.

To enable serde support, add the feature to your `Cargo.toml`:

```toml
[dependencies]
zoneparser = { version = "0.1", features = ["serde"] }
serde_json = "1.0"  # or any other serde format library
```

Example use-case - converting a zonefile to JSON:

```rust
use std::fs::File;
use serde_json;
use zoneparser::ZoneParser;

fn main() {
    let file = File::open("my-zone.no").unwrap();
    let parser = ZoneParser::new(&file, "my-zone.no");
    
    // Collect all records
    let records: Vec<_> = parser.collect::<Result<Vec<_>, _>>().unwrap();
    
    // Serialize to JSON
    let json = serde_json::to_string_pretty(&records).unwrap();
    println!("{}", json);
}
```

All main types (`Record`, `RecordData`, `RRType`, and `RRClass`) implement `Serialize` and `Deserialize` when the `serde` feature is enabled.

## Missing features

- Only the common record fields are parsed. Content specific to the
  record types are returned as anonymous data fields. A later version
  might support parsing the data content as a secondary function call.

## Contributing

The limited functionality very much reflects the needs I had when I
wrote the library.  If you find it useful, and miss some
functionality, please let me know. It might motivate me to further
development. Bug reports are always welcome.
