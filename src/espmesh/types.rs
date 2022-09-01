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

pub struct RcvMessage {
    pub from: MeshAddr,
    pub data: MeshData,
    pub flag: u16,
}

/// Mesh router configuration
pub struct MeshRouterConfig {
    /// SSID
    pub ssid: String,
    /// password
    pub password: String,
    /// BSSID, if this value is specified, users should also specify \"allow_router_switch\".
    pub bssid: [u8; 6],
    /// if the BSSID is specified and this value is also set, when the router of this specified BSSID
    /// fails to be found after \"fail\" (mesh_attempts_t) times, the whole network is allowed to switch
    /// to another router with the same SSID. The new router might also be on a different channel.
    /// The default value is false.
    /// There is a risk that if the password is different between the new switched router and the previous
    /// one, the mesh network could be established but the root will never connect to the new switched router.
    pub allow_router_switch: bool,
}

pub struct MeshApConfig {
    // mesh softAP password
    pub password: String,
    // max mesh connections
    pub max_connection: u8,
    // max non-mesh connections
    pub nonmesh_max_connection: u8,
}

/// Mesh initialization configuration
pub struct MeshConfig {
    pub channel: u8,
    /// if this value is set, when \"fail\" (mesh_attempts_t) times is reached, device will change to
    /// a full channel scan for a network that could join. The default value is false.
    pub allow_channel_switch: bool,
    /// mesh network identification
    pub mesh_id: MeshAddr,
    /// router configuration
    pub router: MeshRouterConfig,
    /// mesh softAP configuration
    pub ap: MeshApConfig,
    // /// crypto functions
    // pub crypto_funcs: *const mesh_crypto_funcs_t,
}
