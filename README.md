# ccsds_primary_header
This crate contains an implementation of the CCSDS standard
called Space Packet Protocol, which defines a packet header
called the CCSDS Primary Header.


CCSDS is a packet definition used in space systems, such as the
International Space Station. It is very simple, and expects
the user to extend it with additional information in most
applications. 


This crate will provide only a simple implementation of the
primary header. It is intended to be used as a building
block for larger definitions or packet processing tools.

The PrimaryHeader struct provided by the crate has the
advantage that its in-memory representation matches the
CCSDS standard. This way, it can be cast to a from a 
byte array, sent over a wire, or used to serialize or
deserialize CCSDS packets.


## Usage
To use this crate, add the following to your Cargo.toml
```toml
[dependancies]
ccsds_primary_header="0.1.0"
```

Next add this to you crate:
```rust
extern crate ccsds_primary_header;
use ccsds_primary_header::*;
```

## Notes
This crate has not been used in production code. There is
a comprehensive set of unit test, but until it is used with
real CCSDS packets, I do not recommend relying on it.

## License
This project is licensed until the BSD2 license.
