extern crate ccsds_primary_header;

use ccsds_primary_header::*;
use ccsds_primary_header::primary_header::*;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ccsds_header_alternating_ones() {
        let mut bytes : [u8;6] = Default::default();
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
        let mut bytes : [u8;6] = Default::default();
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
        fn test_ccsds_version_get_set(version : u16) -> bool {
            let version = version % 0x7;

            let mut pri_header : CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_version(version);

            pri_header.control.version() == version
        }

        fn test_ccsds_packet_type_get_set(packet_type : PacketType) -> bool {
            let mut pri_header : CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_packet_type(packet_type);

            pri_header.control.packet_type() == packet_type
        }

        fn test_ccsds_sec_header_flag_get_set(sec_header_flag : SecondaryHeaderFlag) -> bool {
            let mut pri_header : CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_secondary_header_flag(sec_header_flag);

            pri_header.control.secondary_header_flag() == sec_header_flag
        }

        fn test_ccsds_apid_get_set(apid : u16) -> bool {
            let apid = apid % 0x7FF;

            let mut pri_header : CcsdsPrimaryHeader = Default::default();

            pri_header.control.set_apid(apid);

            pri_header.control.apid() == apid
        }

        fn test_ccsds_seq_flag_get_set(seq_flag : SeqFlag) -> bool {
            let mut pri_header : CcsdsPrimaryHeader = Default::default();

            pri_header.sequence.set_sequence_type(seq_flag);

            pri_header.sequence.sequence_type() == seq_flag
        }

        fn test_ccsds_seq_count_get_set(seq_count : u16) -> bool {
            let seq_count = seq_count % 0x3FFF;

            let mut pri_header : CcsdsPrimaryHeader = Default::default();

            pri_header.sequence.set_sequence_count(seq_count);

            pri_header.sequence.sequence_count() == seq_count
        }

        fn test_ccsds_length_get_set(length : u16) -> bool {
            let mut pri_header : CcsdsPrimaryHeader = Default::default();

            pri_header.length.set_length_field(length);

            pri_header.length.length_field() == length
        }
    }
}
