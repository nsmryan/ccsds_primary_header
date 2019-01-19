# ccsds\_primary\_header
This crate contains an implementation of the CCSDS standard
called Space Packet Protocol, which defines a packet header
called the CCSDS Primary Header.


CCSDS is a packet definition used in many space systems, such as the
International Space Station and many satellites and cubesats.
It is very simple, and expects the user to extend it with additional
information in most applications. 


This crate provides a simple implementation of the
primary header. It is intended to be used as a building
block for larger definitions or packet processing tools.
There is also a mechanism to parse CCSDS packets from a byte
stream, allowing for a variety of checks that can be configured
for a particular project's expectations.


The CcsdsPrimaryHeader struct provided by the crate has the
advantage that its in-memory representation matches the
CCSDS standard. It can be cast to a from a 
byte array, sent over a wire, or used to serialize or
deserialize CCSDS packets.

This crate also provides a PrimaryHeader struct that
is parameterized by either BigEndian or LittleEndian from
byteorder crate. This allows for headers which do not conform
to the CCSDS standard by laying out words in little endian
format.


## Usage

### Primary Header
To use this crate, add the following to your Cargo.toml
```toml
[dependancies]
ccsds_primary_header="0.8.0"
```

Next add this to you crate:
```rust
extern crate ccsds_primary_header;
use ccsds_primary_header::primary_header::*;
```

### Primary Header Parser
This crate also contains a mechanism for parsing CCSDS packets. This
is exposed in the parser module, which provides the CcsdsParser struct.
This struct can be given bytes of data, such as from a packet stream, and
will find valid CCSDS packets within this stream.


Include the parser with the following 'use' statement:
```rust
extern crate ccsds_primary_header;
use ccsds_primary_header::parser::*;
```

The parser can be configured to only allow certain APIDs, to expect
a secondary header flag, to use a maximum length for packets, and to
use a custom validation function that might be project-specific during
parsing. There are also options for a sync of any number of bytes which must
preceed a packet, and optionally a header and/or footer of any length. The header,
footer, and sync can also be kept in the packet, or removed when packets are retrieved
from the parser.


## Notes
This crate has not been used in production code. There is
a comprehensive set of unit tests, but until it is used with
real CCSDS packets I do not recommend relying on it.

## License
This project is licensed until the BSD-3-Clause license.

