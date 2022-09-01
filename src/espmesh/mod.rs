use alloc::boxed::Box;
use std::io::Write;
use std::net::Ipv4Addr;
use std::ptr::{null, null_mut};
use std::time::Duration;

use ::log::info;
use esp_idf_hal::mutex::Mutex;
use esp_idf_sys::*;
use log::error;

use types::State;

use crate::espmesh::types::{
    MeshAddr, MeshConfig, MeshData, MeshOpt, MeshProto, MeshTos, RcvMessage,
};

static TAKEN: Mutex<bool> = Mutex::new(false);

mod types;

#[derive(Debug)]
pub struct EspMeshClient {
    state: State,
}

impl EspMeshClient {
    pub fn new() -> Result<Self, EspError> {
        let mut taken = TAKEN.lock();

        if *taken {
            error!("There must exist only a single ESP-WIFI-MESH client at one moment!");
            esp!(ESP_ERR_INVALID_STATE as i32)?;
        }

        info!("Initializing ESP-WIFI-MESH");
        esp!(unsafe { esp_mesh_init() })?;

        *taken = true;
        Ok(Self {
            state: State::Stopped,
        })
    }
}

impl EspMeshClient {
    pub fn start(&mut self) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_start() })?;
        self.state = State::Started;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_stop() })?;
        self.state = State::Stopped;
        Ok(())
    }

    /// Send a packet over the mesh network:
    ///
    /// - to any device in the mesh network
    /// - to external IP network
    pub fn send(
        &mut self,
        to: MeshAddr,
        data: MeshData,
        flag: u16,
        opt: Option<MeshOpt>,
    ) -> Result<(), EspError> {
        let addr = Box::into_raw(Box::new(match to {
            MeshAddr::Mac(raw) => mesh_addr_t { addr: raw },
            MeshAddr::MIP { ip, port } => mesh_addr_t {
                mip: mip_t {
                    ip4: ip4_addr_t { addr: ip.into() },
                    port,
                },
            },
        }));

        // to change to mut
        let mut data = data;

        let data = Box::into_raw(Box::new(mesh_data_t {
            data: data.data.as_mut_ptr(),
            size: data.data.len() as u16,
            proto: data.proto as u32,
            tos: data.tos as u32,
        }));

        let opt = match opt {
            Some(MeshOpt::SendGroup { addrs: _ }) => {
                // TODO fix
                let mut data: Vec<u8> = vec![];
                Box::into_raw(Box::new(mesh_opt_t {
                    type_: MESH_OPT_SEND_GROUP as u8,
                    val: data.as_mut_ptr(),
                    len: data.len() as u16,
                }))
            }
            Some(MeshOpt::RecvDsAddr { ip }) => Box::into_raw(Box::new(mesh_opt_t {
                type_: MESH_OPT_RECV_DS_ADDR as u8,
                val: ip.octets().as_mut_ptr(),
                len: 4u16,
            })),
            None => null_mut(),
        };

        unsafe {
            let r = esp!(esp_mesh_send(addr, data, flag.into(), opt, 1));

            drop(Box::from_raw(addr));
            drop(Box::from_raw(data));
            drop(Box::from_raw(opt));

            r
        }
    }

    pub fn send_block_time(d: Duration) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_send_block_time(d.as_millis() as u32) })
    }

    /// Receive a packet targeted to self over the mesh network
    pub fn recv(&mut self, timeout: Duration) -> Result<RcvMessage, EspError> {
        let rcv_addr = null_mut() as *mut mesh_addr_t;
        let rcv_data = Box::into_raw(Box::new(mesh_data_t::default()));
        let rcv_opt = Box::into_raw(Box::new(mesh_opt_t::default()));

        let mut flag = 0;

        let rcv_data = unsafe {
            let r = esp!(esp_mesh_recv(
                rcv_addr,
                rcv_data,
                timeout.as_millis() as i32,
                &mut flag,
                rcv_opt,
                1
            ));

            // this is to fail if it should fail but still to release the memory potentially
            // allocated by the structs

            // TODO use
            let _rcv_addr = Box::from_raw(rcv_addr);
            let rcv_data = Box::from_raw(rcv_data);
            let _rcv_opt = Box::from_raw(rcv_opt);

            r?;

            //     match *rcv_addr {
            //     mesh_addr_t { mip: mip_t } => MeshAddr::MIP {
            //         ip: mip.ip4.addr.into(),
            //         port: mip.port,
            //     },
            //     mesh_addr_t { addr } => MeshAddr::Mac(addr.into()),
            // };

            Ok(rcv_data)
        }?;

        let from: MeshAddr = MeshAddr::Mac([0, 0, 0, 0, 0, 0]);

        let data = unsafe {
            Vec::from_raw_parts(
                rcv_data.data,
                rcv_data.size as usize,
                rcv_data.size as usize,
            )
        };

        let proto: MeshProto = unsafe { std::mem::transmute(rcv_data.proto as u8) };
        let tos: MeshTos = unsafe { std::mem::transmute(rcv_data.tos as u8) };

        Ok(RcvMessage {
            from,
            data: MeshData { data, proto, tos },
            flag: flag as u16,
        })
    }

    pub fn set_config(&mut self, config: MeshConfig) -> Result<(), EspError> {
        let mesh_id = match config.mesh_id {
            MeshAddr::Mac(raw) => mesh_addr_t { addr: raw },
            MeshAddr::MIP { ip, port } => mesh_addr_t {
                mip: mip_t {
                    ip4: ip4_addr_t { addr: ip.into() },
                    port,
                },
            },
        };

        let mut tmp = [0u8; 64];
        (&mut tmp as &mut [u8])
            .write(config.ap.password.as_bytes())
            .expect("Can't copy bytes in memory");

        let mesh_ap = mesh_ap_cfg_t {
            password: tmp,
            max_connection: config.ap.max_connection,
            nonmesh_max_connection: config.ap.nonmesh_max_connection,
        };

        let mut tmp = [0u8; 64];
        (&mut tmp as &mut [u8])
            .write(config.router.password.as_bytes())
            .expect("Can't copy bytes in memory");

        let mut tmp2 = [0u8; 32];
        (&mut tmp2 as &mut [u8])
            .write(config.router.ssid.as_bytes())
            .expect("Can't copy bytes in memory");

        let router = mesh_router_t {
            ssid: tmp2,
            ssid_len: config.router.ssid.len() as u8,
            password: tmp,
            bssid: config.router.bssid,
            allow_router_switch: config.router.allow_router_switch,
        };

        let cfg = Box::into_raw(Box::new(mesh_cfg_t {
            mesh_id,
            mesh_ap,
            router,
            channel: config.channel,
            allow_channel_switch: config.allow_channel_switch,
            crypto_funcs: null(),
        }));

        unsafe {
            let r = esp!(esp_mesh_set_config(cfg));
            drop(Box::from_raw(cfg));
            r
        }
    }

    pub fn set_max_layer(&mut self, max_layer: u16) -> Result<(), EspError> {
        esp!(unsafe { esp_mesh_set_max_layer(max_layer as i32) })
    }
}

impl Drop for EspMeshClient {
    fn drop(&mut self) {
        let mut taken = TAKEN.lock();
        *taken = false;

        esp!(unsafe { esp_mesh_deinit() }).expect("Could not deinit ESP-WIFI-MESH!");
    }
}
