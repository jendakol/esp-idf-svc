use alloc::boxed::Box;
use std::net::Ipv4Addr;
use std::ptr::null;

use ::log::info;
use esp_idf_hal::mutex::Mutex;
use esp_idf_sys::*;
use log::error;

use types::State;

use crate::espmesh::types::{MeshAddr, MeshData, MeshOpt, MeshTos};

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

        let opt: *const mesh_opt_t = match opt {
            Some(MeshOpt::SendGroup { addrs }) => {
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
            None => null(),
        };

        unsafe {
            let r = esp!(esp_mesh_send(addr, data, flag.into(), opt, 1));

            std::mem::drop(Box::from_raw(addr));
            std::mem::drop(Box::from_raw(data));
            std::mem::drop(Box::from_raw(opt as *mut mesh_opt_t));

            r
        }
    }
}

impl Drop for EspMeshClient {
    fn drop(&mut self) {
        let mut taken = TAKEN.lock();
        *taken = false;

        esp!(unsafe { esp_mesh_deinit() }).expect("Could not deinit ESP-WIFI-MESH!");
    }
}
