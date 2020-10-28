// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::error::{Error, Result};
use crate::maps::Map;
use bpf_sys::{
    bpf_delete_elem, bpf_lookup_elem, bpf_update_elem,
};
use std::marker::PhantomData;
use std::mem;
use std::mem::MaybeUninit;

pub struct LPMTrieMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct LPMTrieKey {
    pub prefixlen: u32,
    pub data: Vec<u8>
}

impl<'base, K: Clone, V: Clone> LPMTrieMap<'base, K, V> {
    pub fn new<'a>(base: &'a Map) -> Result<LPMTrieMap<'a, K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
        {
            return Err(Error::Map);
        }
        Ok(LPMTrieMap {
            base,
            _k: PhantomData,
            _v: PhantomData
        })
    }

    pub fn set(&self, mut prefix_key: &mut LPMTrieKey, mut value: V) {
        unsafe {
            bpf_update_elem(
                self.base.fd,
                &mut prefix_key as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
                0
            );
        }
    }

    pub fn get(&self, mut prefix_key: &mut LPMTrieKey) -> Option<V> {
        let mut value = MaybeUninit::zeroed();
        if unsafe {
            bpf_lookup_elem(
                self.base.fd,
                &mut prefix_key as *mut _ as *mut _,
                &mut value as *mut _ as *mut _
            )
        } < 0
        {
            return None;
        } else {
            Some(unsafe { value.assume_init() })
        }
    }

    pub fn delete(&self, mut prefix_key: &mut LPMTrieKey) {
        unsafe {
            bpf_delete_elem(self.base.fd, &mut prefix_key as *mut _ as *mut _);
        }
    }
}
