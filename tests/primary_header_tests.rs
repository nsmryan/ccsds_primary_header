extern crate ccsds_primary_header;
extern crate rand;
extern crate quickcheck;
extern crate byteorder;

use std::marker::PhantomData;

use quickcheck::*;

use rand::{Rand};

use rand::seq::{sample_iter};

use byteorder::{ByteOrder, LittleEndian, BigEndian};

use ccsds_primary_header::*;
use ccsds_primary_header::primary_header::*;

use quickcheck::*;


/*
impl Rand for PacketType {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        use self::PacketType::*;
        return *sample_iter(rng, [Data, Command].iter(), 1).unwrap()[0];
    }
}

impl Arbitrary for PacketType {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let packet_type: u8 = g.gen();
        return PacketType::from(packet_type & 0x01);
    }
}

impl Rand for SecondaryHeaderFlag {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        *sample_iter(rng, [SecondaryHeaderFlag::NotPresent, SecondaryHeaderFlag::Present].iter(), 1).unwrap()[0]
    }
}

impl Arbitrary for SecondaryHeaderFlag {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let seq_header_flag: u8 = g.gen();
        return SecondaryHeaderFlag::from(seq_header_flag & 0x01);
    }
}

impl Rand for SeqFlag {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        return *sample_iter(rng, [SeqFlag::Continuation, SeqFlag::FirstSegment, SeqFlag::LastSegment, SeqFlag::Unsegmented].iter(), 1).unwrap()[0];
    }
}

impl Arbitrary for SeqFlag {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let seq_flag: u8 = g.gen();
        return SeqFlag::from(seq_flag % 0x03);
    }
}

impl<E: Send + Clone + 'static> Arbitrary for ControlWord<E> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let control_word = g.gen();
        return ControlWord(control_word, PhantomData);
    }
}

impl<E: Send + Clone + 'static> Arbitrary for SequenceWord<E> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let sequence_word = g.gen();
        return SequenceWord(sequence_word, PhantomData);
    }
}

impl<E> Rand for LengthWord<E> {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        return LengthWord(rng.gen(), PhantomData);
    }
}

impl<E: Clone + Send + 'static> Arbitrary for LengthWord<E> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let len = g.gen();
        return LengthWord(len, PhantomData);
    }
}

impl<E: ByteOrder + Send + 'static> Arbitrary for PrimaryHeader<E> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        return PrimaryHeader {
            control:     ControlWord(g.gen::<[u8;2]>(), PhantomData),
            sequence:    SequenceWord(g.gen::<[u8;2]>(), PhantomData),
            length:      g.gen(),
            endianness:  PhantomData,
        };
    }
}
*/


mod tests {
    use super::*;

    #[test]
    fn test_ccsds_header_alternating_ones() {
        let mut bytes: [u8;6] = Default::default();
        bytes[0] = 0x17;
        bytes[1] = 0xFF;
        bytes[2] = 0x3F;
        bytes[3] = 0xFF;
        bytes[4] = 0x00;
        bytes[5] = 0x00;

        unsafe {
            let pri_header = std::mem::transmute::<[u8;6], CcsdsPrimaryHeader>(bytes);
            assert!(pri_header.control.version() == 0);
            assert!(pri_header.control.packet_type() == PacketType::Command);
            assert!(pri_header.control.secondary_header_flag() == SecondaryHeaderFlag::NotPresent);
            assert!(pri_header.control.apid() == 0x07FF);

            assert!(pri_header.sequence.sequence_type() == SeqFlag::Continuation);
            assert!(pri_header.sequence.sequence_count() == 0x3FFF);

            assert!(pri_header.length.length_field() == 0x0000);
        }
    }

    #[test]
    fn test_ccsds_header_alternating_ones_alt() {
        let mut bytes: [u8;6] = Default::default();
        bytes[0] = 0xE8;
        bytes[1] = 0x00;
        bytes[2] = 0xC0;
        bytes[3] = 0x00;
        bytes[4] = 0xFF;
        bytes[5] = 0xFF;

        unsafe {
            let pri_header = std::mem::transmute::<[u8;6], CcsdsPrimaryHeader>(bytes);
            assert!(pri_header.control.version() == 0x7);
            assert!(pri_header.control.packet_type() == PacketType::Data);
            assert!(pri_header.control.secondary_header_flag() == SecondaryHeaderFlag::Present);
            assert!(pri_header.control.apid() == 0x0000);

            assert!(pri_header.sequence.sequence_type() == SeqFlag::Unsegmented);
            assert!(pri_header.sequence.sequence_count() == 0x0000);

            assert!(pri_header.length.length_field() == 0xFFFF);
        }
    }

    #[test]
    fn test_ccsds_header_size() {
        assert!(std::mem::size_of::<CcsdsPrimaryHeader>() == CCSDS_PRI_HEADER_SIZE_BYTES as usize);
    }

    #[test]
    fn test_ccsds_header_from_slice() {
        assert!(CcsdsPrimaryHeader::from_slice(&[0]) == None);
        assert!(CcsdsPrimaryHeader::from_slice(&[0, 0, 0, 0, 0, 0]) == Some(Default::default()));
        assert!(CcsdsPrimaryHeader::from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) == Some(Default::default()));
    }

    quickcheck! {
        fn test_ccsds_version_get_set(version: u16) -> bool {
            let version = version % 0x7;

            let mut pri_header: CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_version(version);

            return pri_header.control.version() == version;
        }

        fn test_ccsds_packet_type_get_set(command_type: bool) -> bool {
            let packet_type =
                if command_type {
                    PacketType::Command
                } else {
                    PacketType::Data
                };

            let mut pri_header: CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_packet_type(packet_type);

            return pri_header.control.packet_type() == packet_type;
        }

        fn test_ccsds_sec_header_flag_get_set(sec_header_present: bool) -> bool {
            let sec_header_flag = 
                if sec_header_present {
                    SecondaryHeaderFlag::Present
                } else {
                    SecondaryHeaderFlag::NotPresent
                };

            let mut pri_header: CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_secondary_header_flag(sec_header_flag);

            return pri_header.control.secondary_header_flag() == sec_header_flag;
        }

        fn test_ccsds_seq_flag_get_set(seq_flag_u8: u8) -> bool {
            let seq_flag = match seq_flag_u8 % 4 {
                0 => SeqFlag::Continuation,
                1 => SeqFlag::FirstSegment,
                2 => SeqFlag::LastSegment,
                3 => SeqFlag::Unsegmented,
                _ => return true, // default to just pass if given a bad input
            };

            let mut pri_header: CcsdsPrimaryHeader = Default::default();

            pri_header.sequence.set_sequence_type(seq_flag);

            return pri_header.sequence.sequence_type() == seq_flag;
        }

        fn test_ccsds_apid_get_set(apid: u16) -> bool {
            let apid = apid % 0x7FF;

            let mut pri_header: CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_apid(apid);

            return pri_header.control.apid() == apid;
        }


        fn test_ccsds_seq_count_get_set(seq_count: u16) -> bool {
            let seq_count = seq_count % 0x3FFF;

            let mut pri_header: CcsdsPrimaryHeader = Default::default();

            pri_header.sequence.set_sequence_count(seq_count);

            return pri_header.sequence.sequence_count() == seq_count;
        }

        fn test_ccsds_length_get_set(length: u16) -> bool {
            let mut pri_header: CcsdsPrimaryHeader = Default::default();

            pri_header.length.set_length_field(length);

            return pri_header.length.length_field() == length;
        }
    }
}
