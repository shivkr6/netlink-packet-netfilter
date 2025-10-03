// SPDX-License-Identifier: MIT

use derive_more::{From, IsVariant};
use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable,
};

use crate::{
    conntrack::nlas::{protoinfo::ProtoInfo, tuple::Tuple},
    constants::{CTA_PROTOINFO, CTA_TUPLE_ORIG},
};

#[derive(Clone, Debug, PartialEq, Eq, From, IsVariant)]
pub enum ConntrackNla {
    CtaTupleOrig(Vec<Tuple>),
    CtaProtoInfo(Vec<ProtoInfo>),
    Other(DefaultNla),
}

impl Nla for ConntrackNla {
    fn value_len(&self) -> usize {
        match self {
            ConntrackNla::CtaTupleOrig(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackNla::CtaProtoInfo(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackNla::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConntrackNla::CtaTupleOrig(_) => CTA_TUPLE_ORIG,
            ConntrackNla::CtaProtoInfo(_) => CTA_PROTOINFO,
            ConntrackNla::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            ConntrackNla::CtaTupleOrig(attr) => {
                let mut len = 0;
                for op in attr {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            ConntrackNla::CtaProtoInfo(attr) => {
                let mut len = 0;
                for op in attr {
                    op.emit(&mut buffer[len..]);
                    len += op.buffer_len();
                }
            }
            ConntrackNla::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn is_nested(&self) -> bool {
        matches!(
            self,
            ConntrackNla::CtaTupleOrig(_) | ConntrackNla::CtaProtoInfo(_)
        )
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for ConntrackNla
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            CTA_TUPLE_ORIG => {
                let mut tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context("invalid CTA_TUPLE_ORIG value")?;
                    tuples.push(Tuple::parse(nlas)?);
                }
                ConntrackNla::CtaTupleOrig(tuples)
            }
            CTA_PROTOINFO => {
                let mut proto_infos = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context("invalid CTA_PROTOINFO value")?;
                    proto_infos.push(ProtoInfo::parse(nlas)?);
                }
                ConntrackNla::CtaProtoInfo(proto_infos)
            }
            _ => ConntrackNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
