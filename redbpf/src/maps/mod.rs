pub mod hash_map;
pub mod array_map;
pub mod percpu_array_map;

pub use crate::error::{Error, Result};
use bpf_sys::{bcc_create_map, bpf_map_def};
use std::ffi::CString;
use std::os::unix::io::RawFd;

#[derive(Debug, Clone)]
pub struct Map {
    pub name: String,
    pub kind: u32,
    pub fd: RawFd,
    pub config: bpf_map_def,
}

impl Map {
    pub fn load(name: &str, code: &[u8]) -> Result<Self> {
        let config: bpf_map_def = *zero::read(code);
        let cname = CString::new(name.to_owned())?;
        let fd = unsafe {
            bcc_create_map(
                config.type_,
                cname.as_ptr(),
                config.key_size as i32,
                config.value_size as i32,
                config.max_entries as i32,
                config.map_flags as i32,
            )
        };
        if fd < 0 {
            Err(Error::Map)
        } else {
            Ok(Map {
                name: name.to_string(),
                kind: config.type_,
                fd,
                config,
            })
        }
    }
}
