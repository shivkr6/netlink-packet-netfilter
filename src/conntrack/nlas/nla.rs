// SPDX-License-Identifier: MIT

use crate::conntrack::nlas::{protoinfo::ProtoInfo, tuple::Tuple};
use derive_more::{From, IsVariant};
use netlink_packet_core::{
    emit_u32_be, parse_u32_be, DecodeError, DefaultNla, Emitable, ErrorContext,
    Nla, NlaBuffer, NlasIterator, Parseable,
};

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_PROTOINFO: u16 = 4;
const CTA_STATUS: u16 = 3;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;

#[derive(Clone, Debug, PartialEq, Eq, From, IsVariant)]
pub enum ConntrackNla {
    CtaTupleOrig(Vec<Tuple>),
    #[from(ignore)]
    CtaTupleReply(Vec<Tuple>),
    CtaProtoInfo(Vec<ProtoInfo>),
    CtaStatus(u32),
    #[from(ignore)]
    CtaTimeout(u32),
    #[from(ignore)]
    CtaMark(u32),
    Other(DefaultNla),
}

impl Nla for ConntrackNla {
    fn value_len(&self) -> usize {
        match self {
            ConntrackNla::CtaTupleOrig(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackNla::CtaTupleReply(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackNla::CtaProtoInfo(attr) => {
                attr.iter().map(|op| op.buffer_len()).sum()
            }
            ConntrackNla::CtaStatus(attr) => size_of_val(attr),
            ConntrackNla::CtaTimeout(attr) => size_of_val(attr),
            ConntrackNla::CtaMark(attr) => size_of_val(attr),
            ConntrackNla::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            ConntrackNla::CtaTupleOrig(_) => CTA_TUPLE_ORIG,
            ConntrackNla::CtaTupleReply(_) => CTA_TUPLE_REPLY,
            ConntrackNla::CtaProtoInfo(_) => CTA_PROTOINFO,
            ConntrackNla::CtaStatus(_) => CTA_STATUS,
            ConntrackNla::CtaTimeout(_) => CTA_TIMEOUT,
            ConntrackNla::CtaMark(_) => CTA_MARK,
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
            ConntrackNla::CtaTupleReply(attr) => {
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
            ConntrackNla::CtaStatus(attr) => {
                emit_u32_be(buffer, *attr).unwrap()
            }
            ConntrackNla::CtaTimeout(attr) => {
                emit_u32_be(buffer, *attr).unwrap()
            }
            ConntrackNla::CtaMark(attr) => emit_u32_be(buffer, *attr).unwrap(),
            ConntrackNla::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn is_nested(&self) -> bool {
        matches!(
            self,
            ConntrackNla::CtaTupleOrig(_)
                | ConntrackNla::CtaTupleReply(_)
                | ConntrackNla::CtaProtoInfo(_)
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
            CTA_TUPLE_REPLY => {
                let mut tuples = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas =
                        &nlas.context("invalid CTA_TUPLE_REPLY value")?;
                    tuples.push(Tuple::parse(nlas)?);
                }
                ConntrackNla::CtaTupleReply(tuples)
            }
            CTA_PROTOINFO => {
                let mut proto_infos = Vec::new();
                for nlas in NlasIterator::new(payload) {
                    let nlas = &nlas.context("invalid CTA_PROTOINFO value")?;
                    proto_infos.push(ProtoInfo::parse(nlas)?);
                }
                ConntrackNla::CtaProtoInfo(proto_infos)
            }
            CTA_STATUS => ConntrackNla::CtaStatus(
                parse_u32_be(payload).context("invalid CTA_STATUS value")?,
            ),
            CTA_TIMEOUT => ConntrackNla::CtaTimeout(
                parse_u32_be(payload).context("invalid CTA_TIMEOUT value")?,
            ),
            CTA_MARK => ConntrackNla::CtaMark(
                parse_u32_be(payload).context("invalid CTA_MARK value")?,
            ),
            _ => ConntrackNla::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
