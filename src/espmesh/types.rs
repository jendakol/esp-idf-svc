use core::fmt::Debug;
use std::mem::transmute;
use std::net::Ipv4Addr;

use esp_idf_sys::*;

macro_rules! simple_enum_mapping {
    ($rust:ident <=> $c_enum:ident) => {
        impl From<$rust> for $c_enum {
            fn from(t: $rust) -> Self {
                t as u32
            }
        }

        impl From<$c_enum> for $rust {
            fn from(t: $c_enum) -> Self {
                unsafe { transmute(t as u8) }
            }
        }
    };
}

#[derive(Copy, Clone, Debug)]
pub enum State {
    Started,
    Stopped,
}

#[derive(Debug, Copy, Clone)]
pub enum MeshAddr {
    Mac([u8; 6]),
    MIP { ip: Ipv4Addr, port: u16 }, // it's really u16 in the ESP-IDF
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
#[derive(Debug, Copy, Clone)]
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

simple_enum_mapping!(MeshProto <=> mesh_proto_t);

/// For reliable transmission, mesh stack provides three type of services.
#[derive(Debug, Copy, Clone)]
pub enum MeshTos {
    /// provide P2P (point-to-point) retransmission on mesh stack by default
    P2P = 0,
    /// provide E2E (end-to-end) retransmission on mesh stack (Unimplemented)
    E2E = 1,
    /// no retransmission on mesh stack
    DEF = 2,
}

simple_enum_mapping!(MeshTos <=> mesh_tos_t);

#[derive(Debug, Clone)]
pub enum MeshOpt {
    /// data transmission by group
    SendGroup { addrs: Vec<MeshAddr> },
    /// return a remote IP address
    RecvDsAddr { ip: Ipv4Addr },
}

#[derive(Debug, Clone)]
pub struct RcvMessage {
    pub from: MeshAddr,
    pub to: MeshAddr,
    pub data: Vec<u8>,
    pub proto: MeshProto,
    pub tos: MeshTos,
    pub flag: u16,
}

/// Mesh router configuration
pub type MeshRouterConfig = mesh_router_t;

pub type MeshApConfig = mesh_ap_cfg_t;

/// Mesh initialization configuration
pub type MeshConfig = mesh_cfg_t;

/// Attempts configuration for mesh self-organized networking
pub type MeshAttemptsConfig = mesh_attempts_t;

#[derive(Debug, Copy, Clone)]
pub enum MeshEvent {
    /// mesh is started
    Started = 0,
    /// mesh is stopped
    Stopped = 1,
    /// channel switch
    ChannelSwitch = 2,
    /// a child is connected on softAP interface
    ChildConnected = 3,
    /// a child is disconnected on softAP interface
    ChildDisconnected = 4,
    /// routing table is changed by adding newly joined children
    RoutingTableAdd = 5,
    /// routing table is changed by removing leave children
    RoutingTableRemove = 6,
    /// parent is connected on station interface
    ParentConnected = 7,
    /// parent is disconnected on station interface
    ParentDisconnected = 8,
    /// no parent found
    NoParentFound = 9,
    /// layer changes over the mesh network
    LayerChange = 10,
    /// state represents whether the root is able to access external IP network
    TodsState = 11,
    /// the process of voting a new root is started either by children or by the root
    VoteStarted = 12,
    /// the process of voting a new root is stopped
    VoteStopped = 13,
    /// the root address is obtained. It is posted by mesh stack automatically.
    RootAddress = 14,
    /// root switch request sent from a new voted root candidate
    RootSwitchReq = 15,
    /// root switch acknowledgment responds the above request sent from current root
    RootSwitchAck = 16,
    /// the root is asked yield by a more powerful existing root. If self organized is disabled
    /// and this device is specified to be a root by users, users should set a new parent
    /// for this device. if self organized is enabled, this device will find a new parent
    /// by itself, users could ignore this event.
    RootAskedYield = 17,
    /// when devices join a network, if the setting of Fixed Root for one device is different
    /// from that of its parent, the device will update the setting the same as its parent's.
    /// Fixed Root Setting of each device is variable as that setting changes of the root.
    RootFixed = 18,
    /// if self-organized networking is disabled, user can call esp_wifi_scan_start() to trigger
    /// this event, and add the corresponding scan done handler in this event.
    ScanDone = 19,
    /// network state, such as whether current mesh network has a root.
    NetworkState = 20,
    /// the root stops reconnecting to the router and non-root devices stop reconnecting to their parents.
    StopReconnection = 21,
    /// when the channel field in mesh configuration is set to zero, mesh stack will perform a
    /// full channel scan to find a mesh network that can join, and return the channel value
    /// after finding it.
    FindNetwork = 22,
    /// if users specify BSSID of the router in mesh configuration, when the root connects to another
    /// router with the same SSID, this event will be posted and the new router information is attached.
    RouterSwitch = 23,
    /// parent duty
    PsParentDuty = 24,
    /// child duty
    PsChildDuty = 25,
    /// device duty
    PsDeviceDuty = 26,
    Max = 27,
}

impl From<i32> for MeshEvent {
    fn from(id: i32) -> Self {
        unsafe { transmute(id as u8) }
    }
}

/// The number of packets pending in the queue waiting to be sent by the mesh stack
pub type TxPacketsPending = mesh_tx_pending_t;

/// The number of packets available in the queue waiting to be received by applications
pub type RxPacketsPending = mesh_rx_pending_t;

#[derive(Debug, Copy, Clone)]
pub enum MeshTopology {
    Tree = 0,
    Chain = 1,
}

simple_enum_mapping!(MeshTopology <=> esp_mesh_topology_t);

/// Device (mesh node) type
#[derive(Debug, Copy, Clone)]
pub enum MeshNodeType {
    /// hasn't joined the mesh network yet
    Idle = 0,
    /// the only sink of the mesh network. Has the ability to access external IP network
    Root = 1,
    /// intermediate device. Has the ability to forward packets over the mesh network
    Node = 2,
    /// has no forwarding ability
    Leaf = 3,
    /// connect to router with a standalone Wi-Fi station mode, no network expansion capability
    Sta = 4,
}

simple_enum_mapping!(MeshNodeType <=> mesh_type_t);
