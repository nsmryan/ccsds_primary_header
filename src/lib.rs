/*!
This crate provides an implementation of the CCSDS Primary Header defined in the
CCSDS Space Packet Protocol standards document.

This packet header is used in space applications, including the International Space
Station and many cubesat applications, among many other.

The CcsdsPrimaryHeader struct is defined in such a way that it is laid out in memory
as defined by the standard, including bitfields and big endian byte order.
To support this layout the fields are accessed through getters/setters rather
then through direct access.

The PrimaryHeader type is parameterized by either BigEndian or LittleEndian, This
allows for CCSDS implementations that do not conform to the standard.


Header fields that have enumerations are retrieved as enums.


The main thing this crate provides is the PrimaryHeader struct. These can be
created out of sequences of u8s, and by transmuting from raw memory as these structures
read memory directly in the CCSDS format.
*/
extern crate byteorder;

extern crate bytes;

#[cfg(test)]
extern crate rand;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

pub mod primary_header;
pub mod parser;

