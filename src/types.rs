extern crate packed_struct;
#[macro_use]
extern crate packed_struct_codegen;

use packed_struct::prelude::*;

#[cfg(test)]
extern crate quickcheck;

#[cfg(test)]
use quickcheck::*;

#[cfg(test)]
extern crate rand;

#[cfg(test)]
use self::rand::{Rand};

#[cfg(test)]
use self::rand::seq::{sample_iter};

#[allow(dead_code)]
const CCSDS_VERSION : u8 = 0;

// TODO Should use mem::size_of when it is in stable
#[allow(dead_code)]
const CCSDS_MIN_LENGTH : usize = 7; // mem::size_of::<PrimaryHeader>() + 1;

#[allow(dead_code)]
const CCSDS_PRI_HEADER_SIZE_BYTES : usize = 6;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PacketType {
  Data,
  Command,
  Unknown
} 

#[cfg(test)]
impl Rand for PacketType {
    fn rand<R: Rng>(rng : &mut R) -> Self {
        use PacketType::*;
        *sample_iter(rng, [Data, Command].iter(), 1).unwrap()[0]
    }
}

impl Default for PacketType {
    fn default() -> PacketType {
        PacketType::Data
    }
}

impl From<u8> for PacketType {
    fn from(byte : u8) -> PacketType {
        match byte {
            0 => PacketType::Data,
            1 => PacketType::Command,
            _ => PacketType::Unknown
        }
    }
}

impl From<PacketType> for u8 {
    fn from(packet_type : PacketType) -> u8 {
        match packet_type { 
            PacketType::Data    => 0,
            PacketType::Command => 1,
            PacketType::Unknown => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SecondaryHeaderFlag {
  NotPresent,
  Present,
  Unknown
} 

#[cfg(test)]
impl Rand for SecondaryHeaderFlag {
    fn rand<R: Rng>(rng : &mut R) -> Self {
        use SecondaryHeaderFlag::*;
        *sample_iter(rng, [NotPresent, Present].iter(), 1).unwrap()[0]
    }
}

impl Default for SecondaryHeaderFlag {
    fn default() -> SecondaryHeaderFlag {
        SecondaryHeaderFlag::NotPresent
    }
}

impl From<u8> for SecondaryHeaderFlag {
    fn from(byte : u8) -> SecondaryHeaderFlag {
        match byte {
            0 => SecondaryHeaderFlag::NotPresent,
            1 => SecondaryHeaderFlag::Present,
            _ => SecondaryHeaderFlag::Unknown
        }
    }
}

impl From<SecondaryHeaderFlag> for u8 {
    fn from(flag : SecondaryHeaderFlag) -> u8 {
        match flag {
            SecondaryHeaderFlag::NotPresent => 0,
            SecondaryHeaderFlag::Present    => 1,
            SecondaryHeaderFlag::Unknown    => 0
        }
    }
}


#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SeqFlag {
  Continuation,
  FirstSegment,
  LastSegment,
  Unsegmented,
  Unknown
}

#[cfg(test)]
impl Rand for SeqFlag {
    fn rand<R: Rng>(rng : &mut R) -> Self {
        use SeqFlag::*;
        *sample_iter(rng, [Continuation, FirstSegment, LastSegment, Unsegmented].iter(), 1).unwrap()[0]
    }
}

impl Default for SeqFlag {
    fn default() -> SeqFlag {
        SeqFlag::Unsegmented
    }
}

impl From<u8> for SeqFlag {
    fn from(byte : u8) -> SeqFlag {
        match byte {
            0 => SeqFlag::Continuation,
            1 => SeqFlag::FirstSegment,
            2 => SeqFlag::LastSegment,
            3 => SeqFlag::Unsegmented,
            _ => SeqFlag::Unknown
        }
    }
}

impl From<SeqFlag> for u16 {
    fn from(byte : SeqFlag) -> u16 {
        match byte {
            SeqFlag::Continuation => 0,
            SeqFlag::FirstSegment => 1,
            SeqFlag::LastSegment  => 2,
            SeqFlag::Unsegmented  => 3,
            SeqFlag::Unknown      => 0
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
pub struct PrimaryHeader {
  pub version : u8,
  pub packet_type : PacketType,
  pub sec_header_flag : SecondaryHeaderFlag,
  pub apid : u16,
  pub seq_flag : SeqFlag,
  pub seq : u16,
  pub len : u16
}

#[cfg(test)]
impl Arbitrary for PrimaryHeader {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        PrimaryHeader {
            version : g.gen_range(0, 0x8),
            packet_type : g.gen(),
            sec_header_flag : g.gen(),
            apid : g.gen_range(0, 0x800),
            seq_flag : g.gen(),
            seq : g.gen_range(0, 0x4000),
            len : g.gen()
        }
    }
}

/* Primary Header with BitFields */
//bitfield!{
//    #[derive(Clone)]
//    pub struct PacketWord(u16);
//    pub u16, version, set_version: 0, 2;
//    pub u16, into PacketType, packet_type, set_packet_type: 3;
//    pub u16, into SecondaryHeaderFlag, secondary_header_flag, set_secondary_header_flag: 4;
//    pub u16, apid, set_apid: 5, 15;
//}
//
//#[cfg(test)]
//impl Arbitrary for PacketWord {
//    fn arbitrary<G : Gen>(g : &mut G) -> Self {
//        let control_word = g.gen();
//        PacketWord( control_word )
//    }
//}
//
//bitfield!{
//    #[derive(Clone)]
//    pub struct SequenceWord(u16);
//    pub u8, into SeqFlag, sequence_type, get_sequence_type: 0, 1;
//    pub u16, sequence_count, get_sequence_count: 2, 15;
//}
//#[cfg(test)]
//impl Arbitrary for SequenceWord {
//    fn arbitrary<G : Gen>(g : &mut G) -> Self {
//        let sequence_word = g.gen();
//        SequenceWord(sequence_word)
//    }
//}
//
//#[repr(C)]
//#[derive(Clone)]
//pub struct PrimaryHeaderRaw {
//    pub control : PacketWord,
//    pub sequence : SequenceWord,
//    pub length : u16
//}
//
//#[cfg(test)]
//impl Arbitrary for PrimaryHeaderRaw {
//    fn arbitrary<G : Gen>(g : &mut G) -> Self {
//        PrimaryHeaderRaw {
//            control  : PacketWord(g.gen::<u16>()),
//            sequence : SequenceWord(g.gen::<u16>()),
//            length   : g.gen()
//        }
//    }
//}
