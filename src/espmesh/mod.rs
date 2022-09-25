use alloc::boxed::Box;
use core::fmt::{Debug, Formatter};
use std::io::Write;
use std::mem;
use std::mem::transmute;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use std::sync::Arc;
use std::time::Duration;

pub use embedded_svc::wifi::AuthMethod;
use esp_idf_hal::modem::WifiModemPeripheral;
use esp_idf_sys::*;
use log::{debug, error, info};
use once_cell::sync::Lazy;
use pub_sub::{PubSub, Subscription};

pub use types::*;

use crate::private::mutex::{Mutex, RawMutex};
use crate::wifi::EspWifi;

static TAKEN: Mutex<bool> = Mutex::wrap(RawMutex::new(), false);
static EVENTS_CHANNEL: Lazy<PubSub<MeshEvent>> = Lazy::new(PubSub::new);

mod types;

pub struct EspMeshClient<'a, M: WifiModemPeripheral> {
    state: State,
    // yes, this is actually never read.. but we have to hold it's not neither used somewhere else nor dropped (=> deinitialized)
    _wifi: Arc<Mutex<EspWifi<'a, M>>>,
}

pub struct EspMeshClientInner {}

impl<'a, M: WifiModemPeripheral> Debug for EspMeshClient<'a, M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EspMeshClient")
            .field("state", &self.state)
            .finish()
    }
}

impl<'a, M: WifiModemPeripheral> EspMeshClient<'a, M> {
    pub fn get_instance(mut wifi: EspWifi<'a, M>) -> Result<EspMeshClient<'a, M>, EspError> {
        let mut taken = TAKEN.lock();

        if *taken {
            error!("There must exist only a single ESP-WIFI-MESH client at the moment!");
            esp!(ESP_ERR_INVALID_STATE as i32)?;
        }

        *taken = true;

        // mesh won't start without this 🤷‍️
        let aps = wifi.scan()?;
        debug!("Visible networks: {:?}", aps);

        let wifi = Arc::new(Mutex::new(wifi));

        info!("Initializing ESP-WIFI-MESH");
        esp!(unsafe { esp_mesh_init() })?;

        esp!(unsafe {
            esp_event_handler_register(
                MESH_EVENT,
                ESP_EVENT_ANY_ID,
                Some(mesh_event_handler),
                null_mut(),
            )
        })?;

        Ok(EspMeshClient {
            state: State::Stopped,
            _wifi: wifi,
        })
    }
}

extern "C" fn mesh_event_handler(
    _event_handler_arg: *mut c_types::c_void,
    _event_base: esp_event_base_t,
    event_id: i32,
    _event_data: *mut c_types::c_void,
) {
    let event = MeshEvent::from(event_id);
    info!("mesh_event_handler: {:?}", event);
    EVENTS_CHANNEL
        .send(event)
        .expect("Event channel was closed");
}

impl<'a, M: WifiModemPeripheral> EspMeshClient<'a, M> {
    /// Gets a subscription for all mesh events.
    pub fn mesh_event_subscription(&self) -> Subscription<MeshEvent> {
        EVENTS_CHANNEL.subscribe()
    }

    /// Start mesh.
    ///
    /// - Initialize mesh IE.
    /// - Start mesh network management service.
    /// - Create TX and RX queues according to the configuration.
    /// - Register mesh packets receive callback.
    ///
    /// Does nothing if the mesh is already started.
    pub fn start(&mut self) -> Result<(), EspError> {
        if let State::Stopped = mem::replace(&mut self.state, State::Started) {
            info!("Starting ESP-WIFI-MESH");
            esp!(unsafe { esp_mesh_start() })?;
        };
        // else nothing - so it's idempotent

        Ok(())
    }

    /// Stop mesh.
    ///
    /// - Deinitialize mesh IE.
    /// - Disconnect with current parent.
    /// - Disassociate all currently associated children.
    /// - Stop mesh network management service.
    /// - Unregister mesh packets receive callback.
    /// - Delete TX and RX queues.
    /// - Release resources.
    /// - Restore Wi-Fi softAP to default settings if Wi-Fi dual mode is enabled.
    /// - Set Wi-Fi Power Save type to WIFI_PS_NONE.
    ///
    /// Does nothing if the mesh is already stopped.
    pub fn stop(&mut self) -> Result<(), EspError> {
        if let State::Started = mem::replace(&mut self.state, State::Stopped) {
            info!("Stopping ESP-WIFI-MESH");
            esp!(unsafe { esp_mesh_stop() })?;
        };
        // else nothing - so it's idempotent

        Ok(())
    }

    pub fn is_started(&self) -> bool {
        matches!(self.state, State::Started)
    }

    /// Send a packet over the mesh network:
    ///
    /// - to any device in the mesh network
    /// - to external IP network
    pub fn send(
        &self,
        to: MeshAddr,
        data: MeshData,
        flag: u32,
        opt: Option<MeshOpt>,
    ) -> Result<(), EspError> {
        let addr = Box::into_raw(Box::new(to.into()));

        // to change to mut
        let mut data = data;

        let data = Box::into_raw(Box::new(mesh_data_t {
            data: data.data.as_mut_ptr(),
            size: data.data.len() as u16,
            proto: data.proto.into(),
            tos: data.tos.into(),
        }));

        let opt = opt.map(|o| match o {
            MeshOpt::SendGroup { addrs: _ } => {
                // TODO fix
                let mut data: Vec<u8> = vec![];
                Box::into_raw(Box::new(mesh_opt_t {
                    type_: MESH_OPT_SEND_GROUP as u8,
                    val: data.as_mut_ptr(),
                    len: data.len() as u16,
                }))
            }
            MeshOpt::RecvDsAddr { ip } => Box::into_raw(Box::new(mesh_opt_t {
                type_: MESH_OPT_RECV_DS_ADDR as u8,
                val: ip.octets().as_mut_ptr(),
                len: 4u16,
            })),
        });

        let (opt, opt_c) = if let Some(o) = opt {
            (o, 1)
        } else {
            (null_mut(), 0)
        };

        unsafe {
            let r = esp!(esp_mesh_send(addr, data, flag as i32, opt, opt_c));

            drop(Box::from_raw(addr));
            drop(Box::from_raw(data));
            drop(Box::from_raw(opt));

            r
        }
    }

    /// Set blocking time of `send()`
    pub fn send_block_time(&self, d: Duration) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_send_block_time(d.as_millis() as u32) })
    }

    /// Receive a packet targeted to self over the mesh network
    pub fn recv(&self, timeout: Duration) -> Result<Option<RcvMessage>, EspError> {
        if !self.has_rx_data_pending()? {
            debug!("No data are pending to be received, early return");
            return Ok(None);
        }

        let rcv_addr = Box::into_raw(Box::new(mesh_addr_t::default()));
        let rcv_opt = Box::into_raw(Box::new(mesh_opt_t::default()));

        println!("Free mem:      {} B", unsafe { esp_get_free_heap_size() });
        println!("Max mem block: {} B", unsafe {
            heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT)
        });

        let mut data_raw = Vec::<u8>::with_capacity(MESH_MPS as usize);

        let rcv_data = mesh_data_t {
            data: data_raw.as_mut_ptr(),
            size: MESH_MPS as u16,
            ..Default::default()
        };

        let rcv_data = Box::into_raw(Box::new(rcv_data));

        let mut flag = 0;

        // this is to fail if it should fail but still to release the memory potentially
        // allocated by the structs
        let r = esp!(unsafe {
            esp_mesh_recv(
                rcv_addr,
                rcv_data,
                timeout.as_millis() as i32,
                &mut flag,
                rcv_opt,
                0,
            )
        });

        debug!("Raw recv: {:?}", r);

        let rcv_addr = unsafe { Box::<mesh_addr_t>::from_raw(rcv_addr) };
        let rcv_data = unsafe { Box::<mesh_data_t>::from_raw(rcv_data) };
        // TODO use
        let _rcv_opt = unsafe { Box::from_raw(rcv_opt) };

        if r.is_err_and(|e| e.code() == ESP_ERR_MESH_TIMEOUT) {
            return Ok(None);
        } else {
            r?;
        }

        // To prevent double-free.
        // If we do this earlier, we wouldn't release the memory in case of the early-return above.
        mem::forget(data_raw);

        let data_size = rcv_data.size as usize;
        let mut data = unsafe { Vec::from_raw_parts(rcv_data.data, data_size, MESH_MPS as usize) };
        data.truncate(data_size);

        let addr_from: MeshAddr = MeshAddr::Mac(unsafe { rcv_addr.addr });
        let addr_to: MeshAddr = MeshAddr::Mac([0, 0, 0, 0, 0, 0]); // TODO get self
        let proto: MeshProto = unsafe { transmute(rcv_data.proto as u8) };
        let tos: MeshTos = unsafe { transmute(rcv_data.tos as u8) };

        Ok(Some(RcvMessage {
            from: addr_from,
            to: addr_to,
            data: MeshData { data, proto, tos },
            flag: flag as u16,
        }))
    }

    /// Receive a packet targeted to DS over the mesh network
    pub fn recv_to_ds(&self, timeout: Duration) -> Result<Option<RcvMessage>, EspError> {
        if !self.has_to_ds_data_pending()? {
            debug!("No data are pending to be forwarded, early return");
            return Ok(None);
        }

        let rcv_addr_from = Box::into_raw(Box::new(mesh_addr_t::default()));
        let rcv_addr_to = Box::into_raw(Box::new(mesh_addr_t::default()));
        let rcv_opt = Box::into_raw(Box::new(mesh_opt_t::default()));

        let mut data_raw = Vec::<u8>::with_capacity(MESH_MPS as usize);

        let rcv_data = mesh_data_t {
            data: data_raw.as_mut_ptr(),
            size: MESH_MPS as u16,
            ..Default::default()
        };

        let rcv_data = Box::into_raw(Box::new(rcv_data));

        let mut flag = 0;

        // this is to fail if it should fail but still to release the memory potentially
        // allocated by the structs
        let r = esp!(unsafe {
            esp_mesh_recv_toDS(
                rcv_addr_from,
                rcv_addr_to,
                rcv_data,
                timeout.as_millis() as i32,
                &mut flag,
                rcv_opt,
                0,
            )
        });

        debug!("Raw recv_toDS: {:?}", r);

        assert!(MESH_DATA_TODS == flag as u32);

        let rcv_addr_from = unsafe { Box::<mesh_addr_t>::from_raw(rcv_addr_from) };
        let rcv_addr_to = unsafe { Box::<mesh_addr_t>::from_raw(rcv_addr_to) };
        let rcv_data = unsafe { Box::<mesh_data_t>::from_raw(rcv_data) };
        // TODO use
        let _rcv_opt = unsafe { Box::from_raw(rcv_opt) };

        if r.is_err_and(|e| e.code() == ESP_ERR_MESH_TIMEOUT) {
            return Ok(None);
        } else {
            r?;
        }

        // To prevent double-free.
        // If we do this earlier, we wouldn't release the memory in case of the early-return above.
        mem::forget(data_raw);

        let data_size = rcv_data.size as usize;
        let mut data = unsafe { Vec::from_raw_parts(rcv_data.data, data_size, MESH_MPS as usize) };
        data.truncate(data_size);

        let addr_from: MeshAddr = MeshAddr::Mac(unsafe { rcv_addr_from.addr });
        let addr_to: mip_t = unsafe { rcv_addr_to.mip };
        let addr_to: MeshAddr = MeshAddr::MIP {
            ip: Ipv4Addr::from(addr_to.ip4.addr),
            port: addr_to.port,
        };

        let proto: MeshProto = unsafe { transmute(rcv_data.proto as u8) };
        let tos: MeshTos = unsafe { transmute(rcv_data.tos as u8) };

        Ok(Some(RcvMessage {
            from: addr_from,
            to: addr_to,
            data: MeshData { data, proto, tos },
            flag: flag as u16,
        }))
    }

    fn has_rx_data_pending(&self) -> Result<bool, EspError> {
        Ok(self.get_rx_pending()?.to_self != 0)
    }

    fn has_to_ds_data_pending(&self) -> Result<bool, EspError> {
        Ok(self.get_rx_pending()?.to_ds != 0)
    }

    pub fn set_config(&self, config: MeshConfig) -> Result<(), EspError> {
        let mesh_id = mesh_addr_t {
            addr: config.mesh_id,
        };

        let mut tmp = [0u8; 64];

        tmp.as_mut_slice()
            .write_all(config.ap.password.as_bytes())
            .expect("Can't copy bytes in memory");

        // TODO check max connections

        let mesh_ap = mesh_ap_cfg_t {
            password: tmp,
            max_connection: config.ap.max_connection,
            nonmesh_max_connection: config.ap.nonmesh_max_connection,
        };

        let password = config.router.password.as_bytes();

        let mut tmp = [0u8; 64];
        (&mut tmp as &mut [u8])
            .write_all(password)
            .expect("Can't copy bytes in memory");

        let ssid = config.router.ssid.as_bytes();

        let mut tmp2 = [0u8; 32];
        (&mut tmp2 as &mut [u8])
            .write_all(ssid)
            .expect("Can't copy bytes in memory");

        let router = mesh_router_t {
            ssid: tmp2,
            ssid_len: ssid.len() as u8,
            password: tmp,
            bssid: config.router.bssid.unwrap_or([0, 0, 0, 0, 0, 0]),
            allow_router_switch: config.router.allow_router_switch,
        };

        let crypto_funcs = Box::into_raw(Box::new(unsafe { g_wifi_default_mesh_crypto_funcs }));

        let cfg = Box::into_raw(Box::new(mesh_cfg_t {
            mesh_id,
            mesh_ap,
            router,
            channel: config.channel,
            allow_channel_switch: config.allow_channel_switch,
            crypto_funcs,
        }));

        unsafe {
            let r = esp!(esp_mesh_set_config(cfg));
            drop(Box::from_raw(cfg));
            r
        }
    }

    pub fn get_config(&self) -> Result<MeshConfig, EspError> {
        todo!()
    }

    /// Set router config.  
    /// This API is used to dynamically modify the router configuration after mesh is configured.
    pub fn set_router(&self, _cfg: MeshRouterConfig) -> Result<MeshConfig, EspError> {
        todo!()
    }

    pub fn get_router(&self) -> Result<MeshRouterConfig, EspError> {
        let cfg: *mut mesh_router_t = Box::into_raw(Box::new(mesh_router_t::default()));
        esp!(unsafe { esp_mesh_get_router(cfg) })?;
        let cfg = MeshRouterConfig::from(*unsafe { Box::from_raw(cfg) });
        Ok(cfg)
    }

    /// Set mesh network ID.  
    /// This API is used to dynamically modify the router configuration after mesh is configured.
    pub fn set_id(&self, _id: [u8; 6]) -> Result<(), EspError> {
        todo!()
    }

    /// Get mesh network ID.
    pub fn get_id(&self) -> Result<[u8; 6], EspError> {
        todo!()
    }

    /// Designate device type over the mesh network.
    ///
    /// - `Idle`: designates a device as a self-organized node for a mesh network
    /// - `Root`: designates the root node for a mesh network
    /// - `Node`: designates a device as an intermediate device
    /// - `Leaf`: designates a device as a standalone Wi-Fi station that connects to a parent
    /// - `Sta`: designates a device as a standalone Wi-Fi station that connects to a router
    pub fn set_type(&self, t: MeshNodeType) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_set_type(t.into()) })
    }

    /// Get device type over mesh network.  
    /// This API shall be called after having received the event `ParentConnected`.
    pub fn get_type(&self) -> MeshNodeType {
        unsafe { esp_mesh_get_type() }.into()
    }

    /// Set attempts for mesh self-organized networking
    pub fn set_attempts(&mut self, config: MeshAttemptsConfig) -> Result<(), EspError> {
        let raw = Box::into_raw(Box::new(mesh_attempts_t {
            scan: config.scan as i32,
            vote: config.vote as i32,
            fail: config.fail as i32,
            monitor_ie: config.monitor_ie as i32,
        }));
        esp!(unsafe { esp_mesh_set_attempts(raw) })?;
        drop(unsafe { Box::from_raw(raw) });
        Ok(())
    }

    /// Get attempts for mesh self-organized networking
    pub fn get_attempts(&self) -> Result<MeshAttemptsConfig, EspError> {
        let raw = Box::into_raw(Box::new(mesh_attempts_t::default()));
        esp!(unsafe { esp_mesh_get_attempts(raw) })?;
        let raw = unsafe { Box::from_raw(raw) };

        Ok(MeshAttemptsConfig {
            scan: raw.scan as u8,
            vote: raw.vote as u8,
            fail: raw.fail as u8,
            monitor_ie: raw.monitor_ie as u8,
        })
    }

    pub fn set_max_layer(&self, max_layer: u16) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_set_max_layer(max_layer as i32) })
    }

    pub fn get_max_layer(&self) -> u16 {
        (unsafe { esp_mesh_get_max_layer() }) as u16
    }

    /// Set mesh softAP password.  
    /// This API shall be called before mesh is started.
    pub fn set_ap_password(&self, pass: &str) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_set_ap_password(pass.as_ptr(), pass.len() as i32) })
    }

    /// Set mesh softAP authentication mode.
    /// This API shall be called before mesh is started.
    pub fn set_ap_authmode(&self, mode: AuthMethod) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_set_ap_authmode(mode as u32) })
    }

    pub fn get_ap_authmode(&self) -> AuthMethod {
        unsafe { transmute(esp_mesh_get_ap_authmode() as u8) }
    }

    /// Set mesh max connection value.  
    /// Set mesh softAP max connection = mesh max connection + non-mesh max connection  
    /// This API shall be called before mesh is started.
    pub fn set_ap_connections(&self, max_connections: u8) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_set_ap_connections(max_connections as i32) })
    }

    pub fn get_ap_connections(&self) -> u8 {
        (unsafe { esp_mesh_get_ap_connections() }) as u8
    }

    pub fn get_non_mesh_connections(&self) -> u8 {
        (unsafe { esp_mesh_get_non_mesh_connections() }) as u8
    }

    /// Get current layer value over the mesh network.  
    /// This API shall be called after having received the event `ParentConnected`.
    pub fn get_layer(&self) -> u16 {
        (unsafe { esp_mesh_get_layer() }) as u16
    }

    /// Get the parent BSSID.  
    /// This API shall be called after having received the event `ParentConnected`.
    pub fn get_parent_bssid(&self) -> Result<[u8; 6], EspError> {
        let raw = Box::into_raw(Box::new(mesh_addr_t::default()));
        esp!(unsafe { esp_mesh_get_parent_bssid(raw) })?;
        let raw = unsafe { Box::from_raw(raw).addr };
        Ok(raw)
    }

    pub fn is_root(&self) -> bool {
        unsafe { esp_mesh_is_root() }
    }

    pub fn get_routing_table_size(&self) -> u8 {
        (unsafe { esp_mesh_get_routing_table_size() }) as u8
    }

    pub fn get_routing_table(&self) -> Result<Vec<MeshAddr>, EspError> {
        let size = self.get_routing_table_size();
        let mut data: Vec<mesh_addr_t> = Vec::with_capacity(size as usize);

        let data_p = data.as_mut_ptr();

        let mut out_len = 0;

        esp!(unsafe { esp_mesh_get_routing_table(data_p, (size * 6) as i32, &mut out_len) })?;
        mem::forget(data);

        debug!("Read routing table; size {}", out_len);

        let data = unsafe { Vec::from_raw_parts(data_p, out_len as usize, size as usize) };

        let data = data
            .into_iter()
            .map(|a| MeshAddr::Mac(unsafe { a.addr }))
            .collect();

        Ok(data)
    }

    pub fn get_tx_pending(&self) -> Result<TxPacketsPending, EspError> {
        let r = Box::into_raw(Box::new(mesh_tx_pending_t::default()));
        esp!(unsafe { esp_mesh_get_tx_pending(r) })?;
        let r = unsafe { Box::from_raw(r) };

        Ok(TxPacketsPending {
            to_parent: r.to_parent as u32,
            to_parent_p2p: r.to_parent_p2p as u32,
            to_child: r.to_child as u32,
            to_child_p2p: r.to_child_p2p as u32,
            mgmt: r.mgmt as u32,
            broadcast: r.broadcast as u32,
        })
    }

    pub fn get_rx_pending(&self) -> Result<RxPacketsPending, EspError> {
        let r = Box::into_raw(Box::new(mesh_rx_pending_t::default()));
        esp!(unsafe { esp_mesh_get_rx_pending(r) })?;
        let r = unsafe { Box::from_raw(r) };

        Ok(RxPacketsPending {
            to_ds: r.toDS as u32,
            to_self: r.toSelf as u32,
        })
    }

    pub fn enable_ps(&self) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_enable_ps() })
    }

    pub fn disable_ps(&self) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_disable_ps() })
    }

    pub fn is_ps_enabled(&self) -> bool {
        unsafe { esp_mesh_is_ps_enabled() }
    }

    /// Check whether the device is in active state.
    ///
    /// If the device is not in active state, it will neither transmit nor receive frames.
    pub fn is_device_active(&self) -> bool {
        unsafe { esp_mesh_is_device_active() }
    }

    /// Set mesh topology. The default value is Tree.
    /// Chain topology supports up to 1000 layers.
    pub fn set_topology(&self, topo: MeshTopology) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_set_topology(topo.into()) })
    }

    /// Get mesh topology.
    pub fn get_topology(&self) -> MeshTopology {
        unsafe { esp_mesh_get_topology() }.into()
    }
}

impl<'a, M: WifiModemPeripheral> Drop for EspMeshClient<'a, M> {
    fn drop(&mut self) {
        let mut taken = TAKEN.lock();
        *taken = false;

        info!("Deinitializing ESP-WIFI-MESH client");

        esp!(unsafe { esp_mesh_deinit() }).expect("Could not deinit ESP-WIFI-MESH!");
    }
}
