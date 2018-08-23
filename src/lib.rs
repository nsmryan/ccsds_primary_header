pub mod types;
use types::*;

use std::mem;
use std::io::Cursor;

extern crate bytes;
use bytes::{Bytes, BytesMut, BufMut, Buf};


impl From<Bytes> for PrimaryHeader {
    fn from(bytes : Bytes) -> PrimaryHeader {
        let mut buf = Cursor::new(bytes);

        let first_word  : u16 = buf.get_u16_be();
        let second_word : u16 = buf.get_u16_be();
        let len         : u16 = buf.get_u16_be();

        PrimaryHeader {
          version : 0,
          packet_type : PacketType::Command,
          sec_header_flag : SecondaryHeaderFlag::Present,
          apid : 0,
          seq_flag : SeqFlag::Unsegmented,
          seq : 0,
          len : 0
        }
    }
}

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


    #[test]
    fn test_encode() {
        let pri = PrimaryHeader {
                    version : 0,
                    packet_type : PacketType::Command,
                    sec_header_flag : SecondaryHeaderFlag::Present,
                    apid : 0,
                    seq_flag : SeqFlag::Unsegmented,
                    seq : 0,
                    len : 0
                   };
        let bytes = [u8]::from(Bytes::from(pri));
        println!("{} {} {} {}", bytes[0], bytes[1], bytes[2], bytes[3]);

    }
}

