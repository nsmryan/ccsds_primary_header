use std::mem;


#[allow(dead_code)]
const CCSDS_VERSION : u8 = 0;

#[allow(dead_code)]
const CCSDS_MIN_LENGTH : usize = mem::size_of::<PrimaryHeader>() + 1;

#[derive(Debug, PartialEq)]
pub enum PacketType {
  Data,
  Command,
  Unknown
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

#[derive(Debug, PartialEq)]
pub enum SecondaryHeaderFlag {
  NotPresent,
  Present,
  Unknown
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


#[derive(Debug, PartialEq)]
pub enum SeqFlag {
  Continuation,
  FirstSegment,
  LastSegment,
  Unsegmented,
  Unknown
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

#[derive(Debug, PartialEq)]
pub struct PrimaryHeader {
  pub version : u8,
  pub packet_type : PacketType,
  pub sec_header_flag : SecondaryHeaderFlag,
  pub apid : u16,
  pub seq_flag : SeqFlag,
  pub seq : u16,
  pub len : u16
}

