extern crate bytes;
extern crate ccsds_primary_header;

use bytes::BytesMut;

use ccsds_primary_header::primary_header::*;
use ccsds_primary_header::parser::*;


#[test]
fn test_ccsds_parser_too_few_bytes() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0,0,0]);

    assert!(parser.pull_packet() == None);
    assert!(parser.current_status() == CcsdsParserStatus::NotEnoughBytesForHeader);
}

#[test]
fn test_ccsds_parser_fs_invalid() {
    let mut parser = CcsdsParser::new();
    let slice: [u8; 80000] = [0xFF; 80000];
    parser.recv_slice(&slice);

    assert!(parser.current_status() == CcsdsParserStatus::InvalidCcsdsVersion);
    assert!(parser.pull_packet() == None);
}

#[test]
fn test_ccsds_parser_version_valid() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0x1F,0xFF,0xFF,0xFF,0x00,0x00,0xFF, 0xFF]);

    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
    assert!(parser.pull_packet() != None);
}

#[test]
fn test_ccsds_parser_max_length() {
    let mut parser = CcsdsParser::new();
    parser.max_packet_length = Some(8);
    parser.recv_slice(&[0x1F,0xFF,0xFF,0xFF,0x00,3,0xFF, 0xFF, 0xFF, 0xFF]);

    println!("max len status = {:?}", parser.current_status());
    assert!(parser.current_status() == CcsdsParserStatus::ExceedsMaxPacketLength);
    assert!(parser.pull_packet() == None);
}

#[test]
fn test_ccsds_parser_packet_length_too_large() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0x1F,0xFF,0xFF,0xFF,0x03,0x00,0xFF,0xFF]);

    assert!(parser.current_status() == CcsdsParserStatus::NotEnoughBytesPacketLength);
    assert!(parser.pull_packet() == None);
}

#[test]
fn test_ccsds_parser_push_bytes() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0x1F,0xFF,0xFF,0xFF,0x00,0x03,0xFF,0xFF]);

    assert!(parser.current_status() == CcsdsParserStatus::NotEnoughBytesPacketLength);
    assert!(parser.pull_packet() == None);

    parser.recv_slice(&[0, 0]);
    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
    assert!(parser.pull_packet() != None);
}

#[test]
fn test_ccsds_parser_sec_header_required_and_present() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0x08,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF]);

    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
    parser.secondary_header_required = true;
    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
}

#[test]
fn test_ccsds_parser_sec_header_invalid() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF]);

    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
    parser.secondary_header_required = true;
    assert!(parser.current_status() == CcsdsParserStatus::SecondaryHeaderInvalid);
}

#[test]
fn test_ccsds_parser_validation_fail() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF]);

    parser.validation_callback = Some(Box::new(|_| false));
    assert!(parser.current_status() == CcsdsParserStatus::ValidationFailed);
}

#[test]
fn test_ccsds_parser_validation_pass() {
    let mut parser = CcsdsParser::new();
    parser.recv_slice(&[0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF]);

    parser.validation_callback = Some(Box::new(|_| true));
    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
}

#[test]
fn test_ccsds_parser_sync() {
    let mut parser = CcsdsParser::new();
    parser.sync_bytes.push(0xEB);
    parser.sync_bytes.push(0x90);
    parser.recv_slice(&[0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF, 0x00, 0x00]);
    assert!(parser.current_status() == CcsdsParserStatus::SyncNotFound);

    parser.bytes.clear();
    parser.recv_slice(&[0xEB, 0x90, 0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF]);
    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
}

#[test]
fn test_ccsds_parser_find_sync() {
    let mut parser = CcsdsParser::new();
    parser.sync_bytes.push(0xEB);
    parser.sync_bytes.push(0x90);
    parser.recv_slice(&[0x00, 0x01, 0xEB, 0x90, 0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF, 0x00, 0x00]);
    assert!(parser.current_status() == CcsdsParserStatus::SyncNotFound);
    let packet = parser.pull_packet();
    assert!(packet != None);
    assert!(packet.unwrap().len() == 8);
}

#[test]
fn test_ccsds_parser_keep_header() {
    let mut parser = CcsdsParser::new();
    parser.sync_bytes.push(0xEB);
    parser.sync_bytes.push(0x90);
    parser.num_header_bytes = 2;
    parser.keep_header = true;
    parser.recv_slice(&[0xEB, 0x90, 0x00, 0x01, 0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF, 0x00, 0x00]);
    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
    let packet = parser.pull_packet();
    assert!(packet != None);
    println!("len = {}", packet.clone().unwrap().len());
    assert!(packet.unwrap().len() == 10)
}

#[test]
fn test_ccsds_parser_keep_header_and_sync() {
    let mut parser = CcsdsParser::new();
    parser.sync_bytes.push(0xEB);
    parser.sync_bytes.push(0x90);
    parser.keep_sync = true;

    parser.num_header_bytes = 2;
    parser.keep_header = true;

    parser.recv_slice(&[0xEB, 0x90, 0x00, 0x01, 0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF, 0x00, 0x00]);
    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
    let packet = parser.pull_packet();
    assert!(packet != None);
    println!("len = {}", packet.clone().unwrap().len());
    assert!(packet.unwrap().len() == 12)
}

#[test]
fn test_ccsds_parser_keep_footer() {
    let slice = [0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF, 0x12, 0x34];
    let mut parser = CcsdsParser::new();
    parser.keep_footer = true;
    parser.num_footer_bytes = 2;

    parser.recv_slice(&slice);
    assert!(parser.current_status() == CcsdsParserStatus::ValidPacket);
    let packet = parser.pull_packet();
    assert!(packet != None);
    let num_bytes = packet.clone().unwrap().len();
    assert!(num_bytes == 10);

    let mut bytes = BytesMut::new();
    bytes.extend_from_slice(&slice);
    assert!(packet.unwrap() == bytes);
}

#[test]
fn test_ccsds_parser_iterator() {
    let slice = [0x00,0x3,0xFF,0xFF,0x00,0x01,0xFF,0xFF];
    let mut parser = CcsdsParser::new();

    let n = 100;

    for _ in 0..n {
        parser.recv_slice(&slice);
    }

    for _ in 0..n {
        let packet = parser.next();
        assert!(packet != None);
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&slice);
        assert!(packet.unwrap() == bytes);
    }
}
