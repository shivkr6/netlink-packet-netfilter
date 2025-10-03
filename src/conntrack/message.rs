// SPDX-License-Identifier: MIT

use crate::{
    buffer::NetfilterBuffer,
    conntrack::nlas::nla::ConntrackNla,
    constants::{IPCTNL_MSG_CT_GET, NFNL_SUBSYS_CTNETLINK},
};
use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, Parseable, ParseableParametrized,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConntrackMessage {
    Get(Vec<ConntrackNla>),
    Other {
        message_type: u8,
        nlas: Vec<DefaultNla>,
    },
}

impl ConntrackMessage {
    pub const SUBSYS: u8 = NFNL_SUBSYS_CTNETLINK;

    pub fn message_type(&self) -> u8 {
        match self {
            ConntrackMessage::Get(_) => IPCTNL_MSG_CT_GET,
            ConntrackMessage::Other { message_type, .. } => *message_type,
        }
    }
}

impl Emitable for ConntrackMessage {
    fn buffer_len(&self) -> usize {
        match self {
            ConntrackMessage::Get(nlas) => nlas.as_slice().buffer_len(),
            ConntrackMessage::Other { nlas, .. } => {
                nlas.as_slice().buffer_len()
            }
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        match self {
            ConntrackMessage::Get(nlas) => nlas.as_slice().emit(buffer),
            ConntrackMessage::Other { nlas, .. } => {
                nlas.as_slice().emit(buffer)
            }
        };
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NetfilterBuffer<&'a T>, u8> for ConntrackMessage
{
    fn parse_with_param(
        buf: &NetfilterBuffer<&'a T>,
        message_type: u8,
    ) -> Result<Self, DecodeError> {
        Ok(match message_type {
            IPCTNL_MSG_CT_GET => {
                let nlas = buf
                    .parse_all_nlas(|nla_buf| ConntrackNla::parse(&nla_buf))?;
                ConntrackMessage::Get(nlas)
            }
            _ => ConntrackMessage::Other {
                message_type,
                nlas: buf.default_nlas()?,
            },
        })
    }
}
