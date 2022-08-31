use alloc::boxed::Box;
use std::net::Ipv4Addr;

use ::log::info;
use esp_idf_hal::mutex::Mutex;
use esp_idf_sys::*;
use log::error;

#[derive(Debug)]
pub enum State {
    Started,
    Stopped,
}

pub enum MeshAddr {
    Mac([u8; 6]),
    MIP { ip: Ipv4Addr, port: u16 },
}

/// Protocol of transmitted application data.
pub enum MeshProto {
    Binary = 0,
    Http = 1,
    Json = 2,
    Mqtt = 3,
    /// IP network mesh communication of node’s AP interface
    Ap = 4,
    /// IP network mesh communication of node’s STA interface
    Sta = 5,
}

/// For reliable transmission, mesh stack provides three type of services.
pub enum MeshTos {
    /// provide P2P (point-to-point) retransmission on mesh stack by default
    P2P = 0,
    /// provide E2E (end-to-end) retransmission on mesh stack (Unimplemented)
    E2E = 1,
    /// no retransmission on mesh stack
    DEF = 2,
}

pub struct MeshData {
    pub data: Vec<u8>,
    pub proto: MeshProto,
    pub tos: MeshTos,
}

pub enum MeshOpt {
    /// data transmission by group
    SendGroup { addrs: Vec<MeshAddr> },
    /// return a remote IP address
    RecvDsAddr { ip: Ipv4Addr },
}
