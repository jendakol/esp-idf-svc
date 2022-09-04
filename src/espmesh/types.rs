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

#[derive(Copy, Clone)]
pub enum MeshAddr {
    Mac([u8; 6]),
    MIP { ip: Ipv4Addr, port: u16 },
}

impl From<MeshAddr> for mesh_addr_t {
    fn from(addr: MeshAddr) -> Self {
        match addr {
            MeshAddr::Mac(raw) => mesh_addr_t { addr: raw },
            MeshAddr::MIP { ip, port } => mesh_addr_t {
                mip: mip_t {
                    ip4: ip4_addr_t { addr: ip.into() },
                    port,
                },
            },
        }
    }
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
    pub ssid: &'static str,
    /// password
    pub password: &'static str,
    /// BSSID, if this value is specified, users should also specify \"allow_router_switch\".
    pub bssid: Option<[u8; 6]>,
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
    pub password: &'static str,
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

#[derive(Debug)]
pub enum MeshEvent {
    /// mesh is started
    MeshEventStarted = 0,
    /// mesh is stopped
    MeshEventStopped = 1,
    /// channel switch
    MeshEventChannelSwitch = 2,
    /// a child is connected on softAP interface
    MeshEventChildConnected = 3,
    /// a child is disconnected on softAP interface
    MeshEventChildDisconnected = 4,
    /// routing table is changed by adding newly joined children
    MeshEventRoutingTableAdd = 5,
    /// routing table is changed by removing leave children
    MeshEventRoutingTableRemove = 6,
    /// parent is connected on station interface
    MeshEventParentConnected = 7,
    /// parent is disconnected on station interface
    MeshEventParentDisconnected = 8,
    /// no parent found
    MeshEventNoParentFound = 9,
    /// layer changes over the mesh network
    MeshEventLayerChange = 10,
    /// state represents whether the root is able to access external IP network
    MeshEventTodsState = 11,
    /// the process of voting a new root is started either by children or by the root
    MeshEventVoteStarted = 12,
    /// the process of voting a new root is stopped
    MeshEventVoteStopped = 13,
    /// the root address is obtained. It is posted by mesh stack automatically.
    MeshEventRootAddress = 14,
    /// root switch request sent from a new voted root candidate
    MeshEventRootSwitchReq = 15,
    /// root switch acknowledgment responds the above request sent from current root
    MeshEventRootSwitchAck = 16,
    /// the root is asked yield by a more powerful existing root. If self organized is disabled
    /// and this device is specified to be a root by users, users should set a new parent
    /// for this device. if self organized is enabled, this device will find a new parent
    /// by itself, users could ignore this event.
    MeshEventRootAskedYield = 17,
    /// when devices join a network, if the setting of Fixed Root for one device is different
    /// from that of its parent, the device will update the setting the same as its parent's.
    /// Fixed Root Setting of each device is variable as that setting changes of the root.
    MeshEventRootFixed = 18,
    /// if self-organized networking is disabled, user can call esp_wifi_scan_start() to trigger
    /// this event, and add the corresponding scan done handler in this event.
    MeshEventScanDone = 19,
    /// network state, such as whether current mesh network has a root.
    MeshEventNetworkState = 20,
    /// the root stops reconnecting to the router and non-root devices stop reconnecting to their parents.
    MeshEventStopReconnection = 21,
    /// when the channel field in mesh configuration is set to zero, mesh stack will perform a
    /// full channel scan to find a mesh network that can join, and return the channel value
    /// after finding it.
    MeshEventFindNetwork = 22,
    /// if users specify BSSID of the router in mesh configuration, when the root connects to another
    /// router with the same SSID, this event will be posted and the new router information is attached.
    MeshEventRouterSwitch = 23,
    /// parent duty
    MeshEventPsParentDuty = 24,
    /// child duty
    MeshEventPsChildDuty = 25,
    /// device duty
    MeshEventPsDeviceDuty = 26,
    MeshEventMax = 27,
}

/// The number of packets pending in the queue waiting to be sent by the mesh stack
#[derive(Debug, Copy, Clone)]
pub struct TxPacketsPending {
    /// to parent queue
    pub to_parent: u32,
    /// to parent (P2P) queue
    pub to_parent_p2p: u32,
    /// to child queue
    pub to_child: u32,
    /// to child (P2P) queue
    pub to_child_p2p: u32,
    /// management queue
    pub mgmt: u32,
    /// broadcast and multicast queue
    pub broadcast: u32,
}
/// The number of packets available in the queue waiting to be received by applications
#[derive(Debug, Copy, Clone)]
pub struct RxPacketsPending {
    /// to external DS
    pub to_ds: u32,
    /// to self
    pub to_self: u32,
}
