/*!
This crate provides an implementation of the CCSDS Primary Header defined in the
CCSDS Space Packet Protocol standards document.

This packet header is used in space applications, including the International Space
Station and many cubsat applications, among many other.

The PrimaryHeader struct is defined in such a way that it is laid out in memory
as defined by the standard, including bitfields and big endian byte order.
To support this layout the fields are accessed through getters/setters rather
then through direct access.

Header fields that have enumerations are retrieved as enums.
*/
extern crate byteorder;

use self::byteorder::{ByteOrder, BigEndian};

extern crate quickcheck;

use quickcheck::*;

extern crate rand;

use self::rand::{Rand};

use self::rand::seq::{sample_iter};

/// The CCSDS Version (always 0 currently).
#[allow(dead_code)]
pub const CCSDS_VERSION : u8 = 0;

/// The CCSDS primary header size in bytes.
#[allow(dead_code)]
pub const CCSDS_PRI_HEADER_SIZE_BYTES : u16 = 6;

/// The minimum size of a CCSDS packet's data section.
#[allow(dead_code)]
pub const CCSDS_MIN_DATA_LENGTH_BYTES : u16 = 1;

/// The minimum packet length of a CCSDS packet.
/// This is the primary header size plus 1 byte.
#[allow(dead_code)]
pub const CCSDS_MIN_LENGTH : u16 = CCSDS_PRI_HEADER_SIZE_BYTES + CCSDS_MIN_DATA_LENGTH_BYTES; // mem::size_of::<PrimaryHeader>() + 1;


/// The PacketType indicates whether the packet is a command (Command) or a 
/// telemetry (Data) packet.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PacketType {
  /// The packet contains telemetry data.
  Data,
  /// The packet contains a command.
  Command,
  /// The packet type is unknown. This should not occur, but it is included
  /// for encoding an integer into a packet type.
  Unknown
} 

impl Rand for PacketType {
    fn rand<R: Rng>(rng : &mut R) -> Self {
        use self::PacketType::*;
        *sample_iter(rng, [Data, Command].iter(), 1).unwrap()[0]
    }
}

impl Arbitrary for PacketType {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        let packet_type : u8 = g.gen();
        PacketType::from(packet_type & 0x01)
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

/// The secondary header flag indicates whether there is another header
/// following the primary header (Present) or not (NotPresent).
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SecondaryHeaderFlag {
  /// The secondary header is not present. The bytes following the primary header
  /// is the packet's data section.
  NotPresent,
  /// A secondary header is present in the packet. The secondary header follows the
  /// primary header.
  Present,
  /// The secondary header flag in not valid. This should not occur, but it is included
  /// for turning an integer into a SecondaryHeaderFlag.
  Unknown
} 

impl Rand for SecondaryHeaderFlag {
    fn rand<R: Rng>(rng : &mut R) -> Self {
        use SecondaryHeaderFlag::*;
        *sample_iter(rng, [NotPresent, Present].iter(), 1).unwrap()[0]
    }
}

impl Arbitrary for SecondaryHeaderFlag {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        let seq_header_flag : u8 = g.gen();
        SecondaryHeaderFlag::from(seq_header_flag & 0x01)
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


/// The sequence flag indicates the interpretation of the sequence count.
/// Continuation- the sequence count indicates the block in a series of packets
///               containing segmented data
/// FirstSegement- the packet is the first in a series of segemented packets.
/// LastSegement- the packet is the last in a series of segemented packets.
/// Unsegmented- the sequence count is an incrementing counter used to distinguish
///              packets.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum SeqFlag {
  /// The packets is a continuation in a series of packets.
  Continuation,
  /// The packets is the first is a series of packets.
  FirstSegment,
  /// The packets is the last is a series of packets.
  LastSegment,
  /// The packets is a standalone packet. Most packets are unsegmented.
  Unsegmented,
  /// The sequence flag is unknown. This should not occur, but it is included
  /// for encoding integers into this type.
  Unknown
}

impl Rand for SeqFlag {
    fn rand<R: Rng>(rng : &mut R) -> Self {
        use SeqFlag::*;
        *sample_iter(rng, [Continuation, FirstSegment, LastSegment, Unsegmented].iter(), 1).unwrap()[0]
    }
}

impl Arbitrary for SeqFlag {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        let seq_flag : u8 = g.gen();
        SeqFlag::from(seq_flag % 0x03)
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

/// The control word is the first word of the primary header.
/// This word contains:
///
///
/// * The packet's CCSDS version
/// * A flag indicating whether or not there is a
///   secondary header.
/// * A flag indicating whether the packet is a command
///   or telemetry packet
/// * The packet's APID, indicating the packet's source,
///   destination, and contents.
#[derive(Debug, Copy, Clone, Default)]
pub struct ControlWord([u8;2]);

impl ControlWord {
    pub fn version(&self) -> u16 {
        (BigEndian::read_u16(&self.0) & 0xE000) >> 13
    }

    pub fn set_version(&mut self, version : u16) {
        let word = (BigEndian::read_u16(&self.0) & 0x1FFF) | (version << 13);

        BigEndian::write_u16(&mut self.0, word);
    }

    pub fn packet_type(&self) -> PacketType {
        PacketType::from(((BigEndian::read_u16(&self.0) & 0x1000) >> 12) as u8)
    }
    
    pub fn set_packet_type(&mut self, packet_type : PacketType) {
        let word = (BigEndian::read_u16(&self.0) & 0xEFFF) | ((packet_type as u16) << 12);

        BigEndian::write_u16(&mut self.0, word);
    }

    pub fn secondary_header_flag(&self) -> SecondaryHeaderFlag {
        SecondaryHeaderFlag::from(((BigEndian::read_u16(&self.0) & 0x0800) >> 11) as u8)
    }
    
    pub fn set_secondary_header_flag(&mut self, sec_header_flag : SecondaryHeaderFlag) {
        let word = (BigEndian::read_u16(&self.0) & 0xF7FF) | ((sec_header_flag as u16) << 11);

        BigEndian::write_u16(&mut self.0, word);
    }

    pub fn apid(&self) -> u16 {
        (BigEndian::read_u16(&self.0) & 0x07FF)
    }
    
    pub fn set_apid(&mut self, apid : u16) {
        let word = (BigEndian::read_u16(&self.0) & 0xF800) | (apid & 0x07FF);

        BigEndian::write_u16(&mut self.0, word);
    }
}

impl Arbitrary for ControlWord {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        let control_word = g.gen();
        ControlWord( control_word )
    }
}

/// The sequence word is the second word of the primary header.
/// It contains a sequence count and an enum that determines how
/// to interpret the sequence count.
#[derive(Debug, Copy, Clone, Default)]
pub struct SequenceWord([u8;2]);

impl SequenceWord {
    pub fn sequence_type(&self) -> SeqFlag {
        SeqFlag::from((BigEndian::read_u16(&self.0) >> 14) as u8)
    }
    
    pub fn set_sequence_type(&mut self, seq_flag : SeqFlag) {
        let word = (BigEndian::read_u16(&self.0) & 0x3FFF) | (u16::from(seq_flag) << 14);

        BigEndian::write_u16(&mut self.0, word);
    }

    pub fn sequence_count(&self) -> u16 {
        BigEndian::read_u16(&self.0) & 0x3FFF
    }

    pub fn set_sequence_count(&mut self, seq_count : u16) {
        let word = (BigEndian::read_u16(&self.0) & 0xC000) | (seq_count & 0x3FFF);

        BigEndian::write_u16(&mut self.0, word);
    }
}

impl Arbitrary for SequenceWord {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        let sequence_word = g.gen();
        SequenceWord(sequence_word)
    }
}

/// The length word of the CCSDS header. This is just a u16, but
/// it is wrapped in a struct for consistency with the other fields.
#[derive(Debug, Copy, Clone, Default)]
pub struct LengthWord([u8;2]);

/// The sequence word is the third word of the primary header.
impl LengthWord {
    pub fn length_field(&self) -> u16 {
        BigEndian::read_u16(&self.0)
    }

    pub fn set_length_field(&mut self, length : u16) {
        BigEndian::write_u16(&mut self.0, length);
    }
}

impl Rand for LengthWord {
    fn rand<R: Rng>(rng : &mut R) -> Self {
        LengthWord(rng.gen())
    }
}

impl Arbitrary for LengthWord {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        let len = g.gen();
        LengthWord(len)
    }
}

/// The PrimaryHeader struct represents a CCSDS Primary header.
/// Its representation in memory matches the CCSDS standard.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PrimaryHeader {
    pub control  : ControlWord,
    pub sequence : SequenceWord,
    pub length   : LengthWord
}

impl PrimaryHeader {
    /// Get the length of the packet in bytes, including the primary header.
    pub fn packet_length(&self) -> u16 {
        self.length.length_field() + CCSDS_PRI_HEADER_SIZE_BYTES + CCSDS_MIN_DATA_LENGTH_BYTES
    }

    /// Set the length of the packet in bytes, including the primary header.
    pub fn set_packet_length(&mut self, packet_length : u16) {
        BigEndian::write_u16(&mut self.length.0, packet_length);
    }
}

impl Arbitrary for PrimaryHeader {
    fn arbitrary<G : Gen>(g : &mut G) -> Self {
        PrimaryHeader {
            control  : ControlWord(g.gen::<[u8;2]>()),
            sequence : SequenceWord(g.gen::<[u8;2]>()),
            length   : g.gen()
        }
    }
}
