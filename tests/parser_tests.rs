extern crate ccsds_primary_header;

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
