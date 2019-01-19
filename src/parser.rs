use bytes::{Bytes, BytesMut};

use primary_header::*;


pub struct CcsdsParser {
    pub bytes: BytesMut,
    pub allowed_apids: Option<Vec<u16>>,
    pub max_packet_length: Option<u32>,
    pub secondary_header_required: bool,
    pub validation_callback: Option<Box<Fn (&BytesMut) -> bool>>,

    pub sync_bytes: Vec<u8>,
    pub keep_sync: bool,

    pub num_header_bytes: u32,
    pub keep_header: bool,

    pub num_footer_bytes: u32,
    pub keep_footer: bool,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum CcsdsParserStatus {
    NotEnoughBytesForHeader,
    ExceedsMaxPacketLength,
    NotEnoughBytesPacketLength,
    InvalidCcsdsVersion,
    SecondaryHeaderInvalid,
    ValidationFailed,
    ApidNotAllowed,
    ValidPacket,
    SyncNotFound,
}

impl CcsdsParser {
    pub fn new() -> Self {
        CcsdsParser {
            bytes: BytesMut::new(),
            allowed_apids: None,
            max_packet_length: None,
            secondary_header_required: false,
            validation_callback: None,
            sync_bytes: Vec::new(),
            keep_sync: false,
            num_header_bytes: 0,
            keep_header: false,
            num_footer_bytes: 0,
            keep_footer: false,
        }
    }

    pub fn allow_apid(&mut self, apid: u16) {
        match self.allowed_apids {
            None => {
                let mut apids = Vec::new();
                apids.push(apid);
                self.allowed_apids = Some(apids);
            },

            Some(ref mut apids) => {
                apids.push(apid);
            },
        }
    }

    pub fn recv_bytes(&mut self, new_bytes: Bytes) {
        self.bytes.extend(new_bytes);
    }

    pub fn recv_slice(&mut self, new_bytes: &[u8]) {
        self.bytes.extend_from_slice(new_bytes);
    }

    pub fn current_header(&self) -> Option<CcsdsPrimaryHeader> {
        let min_length = CCSDS_MIN_LENGTH      +
                         self.num_header_bytes +
                         self.num_footer_bytes +
                         self.sync_bytes.len() as u32;

        if self.bytes.len() < min_length as usize {
            None
        } else {
            let start_of_header = self.num_header_bytes as usize + self.sync_bytes.len();
            let end_of_header = start_of_header + CCSDS_PRI_HEADER_SIZE_BYTES as usize;
            let mut header_bytes:[u8; 6] = [0; 6];
            header_bytes.clone_from_slice(&self.bytes[start_of_header..end_of_header]);
            Some(CcsdsPrimaryHeader::from_slice(&header_bytes).unwrap())
        }
    }

    pub fn current_status(&self) -> CcsdsParserStatus {
        let pri_header;

        match self.current_header() {
            Some(header) => pri_header = header,
            None => return CcsdsParserStatus::NotEnoughBytesForHeader,
        }

        if !self.sync_bytes.iter().zip(self.bytes.iter()).map(|(b0, b1)| *b0 == *b1).all(|b| b == true) {
            return CcsdsParserStatus::SyncNotFound;
        }

        // a packet length that exceeds the maximum is not a valid packet
        match self.max_packet_length {
            Some(max_length) => {
                if pri_header.packet_length() > max_length {
                    return CcsdsParserStatus::ExceedsMaxPacketLength;
                }
            },

            _ => { },
        }

        if self.bytes.len() < pri_header.packet_length() as usize {
            return CcsdsParserStatus::NotEnoughBytesPacketLength;
        }

        // if the version is not 0, assume that the packet is malformed.
        if pri_header.control.version() as u8 != CCSDS_VERSION {
            return CcsdsParserStatus::InvalidCcsdsVersion;
        }

        // if the secondary header flag is required, but not present, assume that the
        // packet is malformed.
        if self.secondary_header_required &&
            pri_header.control.secondary_header_flag() == SecondaryHeaderFlag::NotPresent {
            return CcsdsParserStatus::SecondaryHeaderInvalid;
        }

        match self.validation_callback {
            Some(ref valid) => {
                if !valid(&self.bytes) {
                    return CcsdsParserStatus::ValidationFailed;
                }
            },

            _ => {},
        }

        // check if the APID is allowed
        match self.allowed_apids {
            Some(ref apid_list) => {
                if !apid_list.contains(&pri_header.control.apid()) {
                    // enough bytes, APID not allowed
                    //self.bytes.advance(pri_header.packet_length() as usize);
                    return CcsdsParserStatus::ApidNotAllowed;
                }
            },

            _ => {},
        }

        CcsdsParserStatus::ValidPacket
    }

    pub fn pull_packet(&mut self) -> Option<BytesMut> {
        let mut parser_status = self.current_status();

        while parser_status != CcsdsParserStatus::ValidPacket {

            // if there is not enough data to determine whether we have a valid packet,
            // then return None and wait for more bytes.
            if (parser_status == CcsdsParserStatus::NotEnoughBytesForHeader) ||
               (parser_status == CcsdsParserStatus::NotEnoughBytesPacketLength) {
                   return None;
            }

            self.bytes.advance(1);

            parser_status = self.current_status();
        }

        let mut packet_length = self.current_header().unwrap().packet_length();
        if self.keep_sync {
            packet_length += self.sync_bytes.len() as u32;
        }

        if self.keep_header {
            packet_length += self.num_header_bytes;
        }

        if self.keep_footer {
            packet_length += self.num_footer_bytes;
        }

        return Some(self.bytes.split_to(packet_length as usize));
    }
}

