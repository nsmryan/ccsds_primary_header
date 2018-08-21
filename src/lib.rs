pub mod types;
use types::*;

extern create nom;

/*
named!(primary_header,
  do_parse!(
    version : ccsds_version,
    packet_type : ccsds_packet_type,
    sec_header_flag : ccsds_sec_header_flag,
    apid : ccsds_apid,
    seq_flag : ccsds_seq_flag,
    seq : ccsds_seq,
    len : ccsds_len,

    (PrimaryHeader::new(
      {  version = version
      , packet_type = packet_type
      , sec_header_flag = sec_header_flag 
      , apid = apid
      , seq_flag = seq_flag
      , seq = seq
      , len = len
      }))
  )
);


