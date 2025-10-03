// SPDX-License-Identifier: MIT

use derive_more::{From, IsVariant};
use netlink_packet_core::{
    emit_u16_be, parse_u16_be, parse_u8, DecodeError, DefaultNla, ErrorContext,
    Nla, NlaBuffer, Parseable,
};

use crate::constants::{CTA_PROTO_DST_PORT, CTA_PROTO_NUM, CTA_PROTO_SRC_PORT};

#[derive(Clone, Debug, PartialEq, Eq, From, IsVariant)]
pub enum ProtoTuple {
    Protocol(u8),
    SourcePort(u16),
    #[from(ignore)]
    DestinationPort(u16),
    Other(DefaultNla),
}

impl Nla for ProtoTuple {
    fn value_len(&self) -> usize {
        match self {
            ProtoTuple::Protocol(attr) => size_of_val(attr),
            ProtoTuple::SourcePort(attr) => size_of_val(attr),
            ProtoTuple::DestinationPort(attr) => size_of_val(attr),
            ProtoTuple::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ProtoTuple::Protocol(_) => CTA_PROTO_NUM,
            ProtoTuple::SourcePort(_) => CTA_PROTO_SRC_PORT,
            ProtoTuple::DestinationPort(_) => CTA_PROTO_DST_PORT,
            ProtoTuple::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ProtoTuple::Protocol(attr) => buffer[0] = *attr,
            ProtoTuple::SourcePort(attr) => emit_u16_be(buffer, *attr).unwrap(),
            ProtoTuple::DestinationPort(attr) => {
                emit_u16_be(buffer, *attr).unwrap()
            }
            ProtoTuple::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ProtoTuple
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_PROTO_NUM => ProtoTuple::Protocol(
                parse_u8(payload).context("invalid CTA_PROTO_NUM value")?,
            ),
            CTA_PROTO_SRC_PORT => ProtoTuple::SourcePort(
                parse_u16_be(payload)
                    .context("invalid CTA_PROTO_SRC_PORT value")?,
            ),
            CTA_PROTO_DST_PORT => ProtoTuple::DestinationPort(
                parse_u16_be(payload)
                    .context("invalid CTA_PROTO_DST_PORT value")?,
            ),
            _ => ProtoTuple::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
