// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{NetlinkMessage, NLM_F_DUMP, NLM_F_REQUEST};

use crate::{
    conntrack::{
        nlas::{
            nla::ConntrackNla, IPTuple, ProtoInfo, ProtoInfoTCP, ProtoTuple,
            TCPFlags, Tuple,
        },
        ConntrackMessage,
    },
    constants::{AF_INET, AF_UNSPEC},
    NetfilterHeader, NetfilterMessage,
};

// wireshark capture of nlmon against command:
// conntrack -L
#[test]
fn test_dump_conntrack() {
    let raw: Vec<u8> = vec![
        0x14, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x03, 0xb9, 0x80, 0xc2, 0x68,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut expected: NetlinkMessage<NetfilterMessage> = NetfilterMessage::new(
        NetfilterHeader::new(AF_UNSPEC, 0, 0),
        ConntrackMessage::Get(vec![]),
    )
    .into();
    expected.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    expected.header.sequence_number = 1757577401;
    expected.finalize();

    let mut buffer = vec![0; expected.buffer_len()];
    expected.serialize(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    // Check if the deserialization was correct
    assert_eq!(
        expected,
        NetlinkMessage::<NetfilterMessage>::deserialize(&raw).unwrap()
    );
}

// wireshark capture of nlmon against command:
// conntrack -G -p tcp -s 10.57.97.124 -d 148.113.20.105 --sport 39600 --dport 443
#[test]
fn test_get_conntrack() {
    let raw: Vec<u8> = vec![
        0x60, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x92, 0xe5, 0xcf, 0x68,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x34, 0x00, 0x01, 0x80,
        0x14, 0x00, 0x01, 0x80, 0x08, 0x00, 0x01, 0x00, 0x0a, 0x39, 0x61, 0x7c,
        0x08, 0x00, 0x02, 0x00, 0x94, 0x71, 0x14, 0x69, 0x1c, 0x00, 0x02, 0x80,
        0x05, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00,
        0x9a, 0xb0, 0x00, 0x00, 0x06, 0x00, 0x03, 0x00, 0x01, 0xbb, 0x00, 0x00,
        0x18, 0x00, 0x04, 0x80, 0x14, 0x00, 0x01, 0x80, 0x06, 0x00, 0x04, 0x00,
        0x0a, 0x0a, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x0a, 0x0a, 0x00, 0x00,
    ];

    let src_addr =
        IPTuple::SourceAddress(IpAddr::V4("10.57.97.124".parse().unwrap()));
    let dst_addr = IPTuple::DestinationAddress(IpAddr::V4(
        "148.113.20.105".parse().unwrap(),
    ));

    let proto_num = ProtoTuple::Protocol(6);
    let src_port = ProtoTuple::SourcePort(39600);
    let dst_port = ProtoTuple::DestinationPort(443);

    let ip_tuple = Tuple::Ip(vec![src_addr, dst_addr]);
    let proto_tuple = Tuple::Proto(vec![proto_num, src_port, dst_port]);

    let proto_info = ProtoInfo::TCP(vec![
        ProtoInfoTCP::OriginalFlags(TCPFlags {
            flags: 10,
            mask: 10,
        }),
        ProtoInfoTCP::ReplyFlags(TCPFlags {
            flags: 10,
            mask: 10,
        }),
    ]);

    let nlas = vec![
        ConntrackNla::CtaTupleOrig(vec![ip_tuple, proto_tuple]),
        ConntrackNla::CtaProtoInfo(vec![proto_info]),
    ];

    let mut expected: NetlinkMessage<NetfilterMessage> = NetfilterMessage::new(
        NetfilterHeader::new(AF_INET, 0, 0),
        ConntrackMessage::Get(nlas),
    )
    .into();
    expected.header.flags = NLM_F_REQUEST;
    expected.header.sequence_number = 1758455186;
    expected.finalize();

    let mut buffer = vec![0; expected.buffer_len()];
    expected.serialize(&mut buffer);

    // Check if the serialization was correct
    assert_eq!(buffer, raw);

    // Check if the deserialization was correct
    assert_eq!(
        expected,
        NetlinkMessage::<NetfilterMessage>::deserialize(&raw).unwrap()
    );
}
