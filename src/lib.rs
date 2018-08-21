#[macro_use]
pub mod types;
use types::*;
use nom::*;

extern crate nom;

named!(ccsds_first_word<(u8, u8, u8, u16)>,
       bits!(tuple!(take_bits!(u8,   3),     // version
                    take_bits!(u8,   1),     // packet type
                    take_bits!(u8,   1),     // secondary header
                    take_bits!(u16, 11)))); // apid 

named!(ccsds_seq_word<(u8, u16)>,
       bits!(tuple!(take_bits!(u8, 2), take_bits!(u16, 14))));

named!(ccsds_length_field<u16>, call!(be_u16));

named!(primary_header<PrimaryHeader>,
       do_parse!(
         first_word : ccsds_first_word >>
         seq_word : ccsds_seq_word     >>
         len : ccsds_length_field      >>

         (PrimaryHeader
           { version : first_word.0
           , packet_type : PacketType::from(first_word.1)
           , sec_header_flag : SecondaryHeaderFlag::from(first_word.2)
           , apid : first_word.3
           , seq_flag : SeqFlag::from(seq_word.0)
           , seq : seq_word.1
           , len : len 
           })));

