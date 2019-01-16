extern crate ccsds_primary_header;

use ccsds_primary_header::*;


fn main() {
    // If we have the bytes for a primary header from a file, socket, or some other source,
    // we can cast it read and write its fields using the PrimaryHeader struct

    // This is a typical CCSDS Primary Header for a command with a secondary header,
    // 4 bytes of data section, unsegmented, with a sequence count of 1.
    let bytes : [u8;6] = [ 0x18, 0x10, 0xC0, 0x01, 0x00, 0x03 ];
    println!("starting bytes {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
             bytes[0], bytes[1], bytes[2],
             bytes[3], bytes[4], bytes[5]);
    
    unsafe {
        let pri_header = std::mem::transmute::<[u8;6], CcsdsPrimaryHeader>(bytes);

        let pri_header_new = CcsdsPrimaryHeader::new(bytes);

        assert!(pri_header == pri_header_new);

        // CCSDS version is currently always 0
        assert!(pri_header.control.version() == 0);

        // Packet type is command
        assert!(pri_header.control.packet_type() == PacketType::Command);

        // Secondary header is present in this packet
        assert!(pri_header.control.secondary_header_flag() == SecondaryHeaderFlag::Present);

        // APID is 16 (0x10)
        assert!(pri_header.control.apid() == 16);

        // Unsegmented packet
        assert!(pri_header.sequence.sequence_type() == SeqFlag::Unsegmented);

        // Sequence count of 1
        assert!(pri_header.sequence.sequence_count() == 1);

        // Packet length field of 3
        assert!(pri_header.length.length_field() == 3);

        // Total packet length is 10 (length field + size of header + 1) as per the CCSDS
        // standard.
        assert!(pri_header.packet_length() == 10);
    }

    // We can also lay down a packet header with field setters.
    // We will build up the same packet that we have above, but using PrimaryHeader
    // rather then laying out the bytes in a [u8;6];
    let mut pri_header : CcsdsPrimaryHeader = Default::default();

    pri_header.control.set_version(0);
    pri_header.control.set_packet_type(PacketType::Command);
    pri_header.control.set_secondary_header_flag(SecondaryHeaderFlag::Present);
    pri_header.control.set_apid(16);

    pri_header.sequence.set_sequence_type(SeqFlag::Unsegmented);
    pri_header.sequence.set_sequence_count(1);

    // you can also set the packet length with pri_header.set_packet_length(4), which
    // accounts for the primary header size and the 1 byte minimum size defined in the standard.
    pri_header.length.set_length_field(3);
    
    unsafe {
        let bytes : [u8;6] = std::mem::transmute::<CcsdsPrimaryHeader, [u8;6]>(pri_header);
        println!("ending bytes   {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
                 bytes[0], bytes[1], bytes[2],
                 bytes[3], bytes[4], bytes[5]);
    }
}
