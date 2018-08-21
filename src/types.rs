use std::mem;


#[allow(dead_code)]
const CCSDS_VERSION : u8 = 0;

#[allow(dead_code)]
const CCSDS_MIN_LENGTH : usize = mem::size_of::<PrimaryHeader>() + 1;

#[derive(Debug, PartialEq)]
pub enum PacketType {
  Data,
  Command
} 

#[derive(Debug, PartialEq)]
pub enum SecondaryHeaderFlag {
  NotPresent,
  Present
} 


#[derive(Debug, PartialEq)]
pub enum SeqFlag {
  Continuation,
  FirstSegment,
  LastSegment,
  Unsegmented
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

