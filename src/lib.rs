pub mod types;
use types::*;

use std::mem;
use std::io::Cursor;

extern crate bytes;
use bytes::{Bytes, BytesMut, BufMut, Buf};

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[cfg(test)]
use quickcheck::{quickcheck, TestResult};


/// This module contains definitions for serializing and deserializing
/// CCSDS primary headers.
/// 
/// The bytes crate is used to read and write the header elements in big-endian
/// byte order.
/// 
/// 
/// These definitions could be used to parse primary headers, and to 
/// lay down an header for transfer over a network or into a file.

/// Translate bytes into a Primary Header according to the CCSDS definition.
impl From<Bytes> for PrimaryHeader {
    fn from(bytes : Bytes) -> PrimaryHeader {
        let mut buf = Cursor::new(bytes);

        let first_word  : u16 = buf.get_u16_be();
        let second_word : u16 = buf.get_u16_be();
        let len         : u16 = buf.get_u16_be();

        PrimaryHeader {
          version : ((first_word & 0xE000) >> 13) as u8,
          packet_type : PacketType::from(((first_word & 0x1000) >> 12) as u8),
          sec_header_flag : SecondaryHeaderFlag::from(((first_word & 0x0800) >> 11) as u8),
          apid : first_word & 0x07FF,
          seq_flag : SeqFlag::from(((second_word & 0xC000) >> 14) as u8),
          seq : second_word & 0x3FFF,
          len : len
        }
    }
}

/// Translate a Primary Header into bytes according to the CCSDS definition.
impl From<PrimaryHeader> for Bytes {
    fn from(pri_header : PrimaryHeader) -> Bytes {
        let mut buf = BytesMut::with_capacity(mem::size_of::<PrimaryHeader>());

        buf.put_u16_be((u16::from(u8::from(pri_header.version))         << 13) | 
                       (u16::from(u8::from(pri_header.packet_type))     << 12) |
                       (u16::from(u8::from(pri_header.sec_header_flag)) << 11) |
                       (pri_header.apid));

        buf.put_u16_be((u16::from(pri_header.seq_flag)        << 14) | 
                       (pri_header.seq));

        buf.put_u16_be(pri_header.len);

        Bytes::from(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    /// Test the round trip property going from a header to bytes and back
    quickcheck! {
        fn prop_roundtrip(pri_header : PrimaryHeader) -> bool {
            //println!("{:?}", pri_header);
            //println!("{:?}", Bytes::from(pri_header));
            //println!("{:?}", PrimaryHeader::from(Bytes::from(pri_header)));
            pri_header == PrimaryHeader::from(Bytes::from(pri_header))
        }
    }

    #[test]
    fn ccsds_header_alternating_ones() {
        let mut bytes : [u8;6] = Default::default();
        bytes[0] = 0x10;
        bytes[1] = 37;
        bytes[2] = 0x00;
        bytes[3] = 0x00;
        bytes[4] = 0;
        bytes[5] = 0;

        unsafe {
            let pri_header = std::mem::transmute::<[u8;6], PrimaryHeaderRaw>(bytes);
            println!("{:?}", pri_header.control.version());
            println!("{:?}", pri_header.control.packet_type());
            println!("{:?}", pri_header.control.secondary_header_flag());
            println!("{:?}", pri_header.control.apid());
        }
    }
}
