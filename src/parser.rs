use std::iter::Iterator;

use bytes::{Bytes, BytesMut};

use primary_header::*;


/// A CcsdsParserStatus is the current state of a CcsdsParser. The parser can determine
/// whether a packet is valid, have enough bytes, or is otherwise invalid. The 
/// only enum value that indicates a valid packet is ValidPacket.
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

impl CcsdsParserConfig {
    pub fn new() -> CcsdsParserConfig {
        CcsdsParserConfig {
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
}

/// A CcsdsParser is a configuration and a byte buffer which can be queried
/// for CCSDS packets. The parser is created and configured, and then can be
/// fed bytes. At any time it can be queried for packets, which will be
/// provided as a BytesMut without copying.
///
/// The parser will return a CcsdsParserStatus describing the current packet-
/// indicating whether there are enough bytes, and if so whether the packet
/// passes the configured conditions for validaity.
///
/// Some conditions cannot be hardcoded in a library and are project specific,
/// so a validation functon (validation_callback) can be provided to perform
/// project-specific checks such as a checksum or CRC of the packet.
pub struct CcsdsParser {
    /// A byte buffer to pull packets from. This can be fed more bytes with
    /// recv_bytes or recv_slice.
    pub bytes: BytesMut,

    /// The config field provides configuration for how to read out Ccsds packets,
    /// such as which APIDs are allowed or whether there is a header or footer on 
    /// each packet. See CcsdsParserConfig for details.
    pub config: CcsdsParserConfig,

    /// This private field is used when running the parser as an iterator. This allows
    /// the parser to know if it is being called after apparently running out of bytes.
    reached_end: bool,
}


/// The CcsdsParserConfig struct provides all configuration used by a CcsdsParser.
/// This is broken out into a seprate structure to be read in, serialized, and otherwise
/// manipulated independantly of a particular CcsdsParser.
pub struct CcsdsParserConfig {
    /// The allowed APIDs list is either None, meaning any APID is valid,
    /// or a Vec of allowed APIDs.
    /// Note that if an APId is not in the allowed APID list, the packet
    /// is considered improperly formatted, rather then being a valid
    /// packet with an unexpected APID.
    pub allowed_apids: Option<Vec<u16>>,

    /// The max packet length is either None, meaning any packet length is valid,
    /// or a given number of bytes. This applies to the CCSDS packet length.
    /// If a packet's length exceeds this amount, then it is considered improperly
    /// formatted.
    pub max_packet_length: Option<u32>,

    /// The secondary header bit may or may not be set in a particular CCSDS 
    /// packet. For some projects, all packets have a secondary header. In this
    /// case, this flag can be set to indicate that a properly formatted packet
    /// must have this flag set.
    pub secondary_header_required: bool,

    /// The validation callback is a user-provided function that can
    /// validate a packet in a project-specific way. This could include
    /// a checksum or CRC, or any other check required.
    /// Note that the function is provided the packet from the start,
    /// including a sync and header if they are configured.
    pub validation_callback: Option<Box<Fn (&BytesMut) -> bool>>,

    /// The sync bytes are a Vec of bytes that must proceed a packet for
    /// it to be valid. This is useful when there is a sync marker before each 
    /// packet.
    pub sync_bytes: Vec<u8>,

    /// The keep sync flag is used to determine if sync bytes are passed along to the
    /// called when pull_packet is called, or left behind.
    pub keep_sync: bool,

    /// A packet can have a header with a fixed number of bytes. This is usually 0, but
    /// in some cases there is a prefix on each packet from another protocol.
    pub num_header_bytes: u32,

    /// The keep header flag is used to determine if sync bytes are passed along to the
    /// called when pull_packet is called, or left behind.
    pub keep_header: bool,

    /// A packet can have a footer with a fixed number of bytes, such as a CRC that is
    /// outside of the CCSDS packet and used by another protocol. This is usually 0, but
    /// in some cases there is a prefix on each packet from another protocol.
    pub num_footer_bytes: u32,

    /// The keep footer flag is used to determine if sync bytes are passed along to the
    /// called when pull_packet is called, or left behind.
    pub keep_footer: bool,
}

/// The iterator for CcsdsParser produces CCSDS packets in turn. When it returned
/// None, then the buffer has no vaild packets.
///
/// After the first None, next can be called again. In this case, if buffer
/// may have a valid packet, but is prefixed with garbage,
/// then the buffer will be advanced by a byte. This allows
/// the packet processing to continue, assuming that we may then be able to look past the garbage
/// and find another packet.
impl Iterator for CcsdsParser {
    type Item = BytesMut;

    fn next(&mut self) -> Option<Self::Item> {
        match self.pull_packet() {
            Some(bytes) => {
                Some(bytes)
            },

            None => {
                if !self.reached_end {
                    if self.current_status() != CcsdsParserStatus::NotEnoughBytesForHeader {
                        self.bytes.advance(1);
                        self.pull_packet()
                    } else {
                        self.reached_end = true;
                        None
                    }
                } else {
                    None
                }
            },
        }
    }
}

impl CcsdsParser {
    /// Create a new parser with default configuration options.
    pub fn new() -> Self {
        CcsdsParser {
            bytes: BytesMut::new(),
            config: CcsdsParserConfig::new(),
            reached_end: false,
        }
    }

    /// Create a new parser with the given configuration options.
    pub fn with_config(config: CcsdsParserConfig) -> Self {
        CcsdsParser {
            bytes: BytesMut::new(),
            config: config,
            reached_end: false,
        }
    }

    /// Allow a particular APID. If the allowed_apids field is None, it is
    /// turned into a Vec with a single element.
    pub fn allow_apid(&mut self, apid: u16) {
        match self.config.allowed_apids {
            None => {
                let mut apids = Vec::new();
                apids.push(apid);
                self.config.allowed_apids = Some(apids);
            },

            Some(ref mut apids) => {
                apids.push(apid);
            },
        }
    }

    /// The recv_bytes function allows the user to feed additional bytes to a
    /// parser. These may come from a byte stream such as TCP, where we may or may
    /// not get a full packet, or we may get multiple packets.
    pub fn recv_bytes(&mut self, new_bytes: Bytes) {
        self.bytes.extend(new_bytes);
    }


    /// The recv_slice function allows the user to feed additional bytes to a
    /// parser. These may come from a byte stream such as TCP, where we may or may
    /// not get a full packet, or we may get multiple packets.
    pub fn recv_slice(&mut self, new_bytes: &[u8]) {
        self.bytes.extend_from_slice(new_bytes);
    }

    /// The current header function extracts the primary header from a parser
    /// if one is available.
    pub fn current_header(&self) -> Option<CcsdsPrimaryHeader> {
        let min_length = CCSDS_MIN_LENGTH      +
                         self.config.num_header_bytes +
                         self.config.num_footer_bytes +
                         self.config.sync_bytes.len() as u32;

        if self.bytes.len() < min_length as usize {
            None
        } else {
            let start_of_header = self.config.num_header_bytes as usize + self.config.sync_bytes.len();
            let end_of_header = start_of_header + CCSDS_PRI_HEADER_SIZE_BYTES as usize;
            let mut header_bytes:[u8; 6] = [0; 6];
            header_bytes.clone_from_slice(&self.bytes[start_of_header..end_of_header]);
            Some(CcsdsPrimaryHeader::from_slice(&header_bytes).unwrap())
        }
    }

    /// The current status is the validity of the parser's current packet.
    pub fn current_status(&self) -> CcsdsParserStatus {
        let pri_header;

        match self.current_header() {
            Some(header) => pri_header = header,
            None => return CcsdsParserStatus::NotEnoughBytesForHeader,
        }

        if !self.config.sync_bytes.iter().zip(self.bytes.iter()).map(|(b0, b1)| *b0 == *b1).all(|b| b == true) {
            return CcsdsParserStatus::SyncNotFound;
        }

        // a packet length that exceeds the maximum is not a valid packet
        match self.config.max_packet_length {
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
        if self.config.secondary_header_required &&
            pri_header.control.secondary_header_flag() == SecondaryHeaderFlag::NotPresent {
            return CcsdsParserStatus::SecondaryHeaderInvalid;
        }

        match self.config.validation_callback {
            Some(ref valid) => {
                if !valid(&self.bytes) {
                    return CcsdsParserStatus::ValidationFailed;
                }
            },

            _ => {},
        }

        // check if the APID is allowed
        match self.config.allowed_apids {
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

    /// The pull_packet function retrieves the next packet from the parser,
    /// or returns None if there are no valid packets. This advances the byte buffer
    /// to the next packet. If the current buffer may or may not be a valid packet, but
    /// more bytes are needed to decide, the current position is kept.
    ///
    /// Note that this can potentially lead to a situation where the packet stream has
    /// garbage in front, but contains a valid packet. The parser may not be able to find the
    /// valid packet because the garbage data may indicate that a valid but long CCSDS
    /// packet is present and there are not enough bytes to read it.
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
        if self.config.keep_sync {
            packet_length += self.config.sync_bytes.len() as u32;
        }

        if self.config.keep_header {
            packet_length += self.config.num_header_bytes;
        }

        if self.config.keep_footer {
            packet_length += self.config.num_footer_bytes;
        }

        return Some(self.bytes.split_to(packet_length as usize));
    }
}

