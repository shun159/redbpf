// Copyright 2019 Authors of Red Sift
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::error::{Error, Result};
use crate::maps::Map;
use crate::cpus::get_online;
use bpf_sys::{
    bpf_get_first_key, bpf_get_next_key, bpf_lookup_elem, bpf_update_elem,
};
use std::marker::PhantomData;
use std::mem;
use std::mem::MaybeUninit;

pub struct PerCPUArrayMap<'a, K: Clone, V: Clone> {
    base: &'a Map,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

pub struct Iterable<'a, 'b, K: Clone, V: Clone> {
    map: &'a PerCPUArrayMap<'b, K, V>,
    key: Option<K>,
}

impl<'base, K: Clone, V: Clone> PerCPUArrayMap<'base, K, V> {
    pub fn new<'a>(base: &'a Map) -> Result<PerCPUArrayMap<'a, K, V>> {
        if mem::size_of::<K>() != base.config.key_size as usize
            || mem::size_of::<V>() != base.config.value_size as usize
        {
            return Err(Error::Map);
        }

        Ok(PerCPUArrayMap {
            base,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    pub fn set(&self, mut key: K, mut value: V) {
        unsafe {
            bpf_update_elem(
                self.base.fd,
                &mut key as *mut _ as *mut _,
                &mut value as *mut _ as *mut _,
                0,
            );
        }
    }

    pub fn get(&self, mut key: K) -> Option<Vec<V>> {
        let cores = num_cpu_cores();
        let mut vec: Vec<V> = Vec::with_capacity(cores);
        unsafe { vec.set_len(cores); }
        let value = Box::into_raw(vec.into_boxed_slice()) as *mut std::ffi::c_void;
        if unsafe {
            bpf_lookup_elem(
                self.base.fd,
                &mut key as *mut _ as *mut _,
                value
            )
        } < 0
        {
            return None;
        } else {
            unsafe {
                let s: Vec<V> = Vec::from_raw_parts(value as *mut V, cores, cores);
                Some(s)
            }
        }
    }

    pub fn iter<'a>(&'a self) -> Iterable<'a, '_, K, V> {
        Iterable {
            map: self,
            key: None,
        }
    }
}

impl<K: Clone, V: Clone> Iterable<'_, '_, K, V> {
    pub fn get_first_key(&mut self, mut key: MaybeUninit<K>) -> Option<K> {
        if unsafe {
            bpf_get_first_key(
                self.map.base.fd,
                &mut key as *mut _ as *mut _,
                self.map.base.config.key_size.into(),
            )
        } < 0
        {
            None
        } else {
            Some(unsafe { key.assume_init() })
        }
    }

    pub fn get_next_key(&mut self, mut next_key: MaybeUninit<K>, mut key: K) -> Option<K> {
        if unsafe {
            bpf_get_next_key(
                self.map.base.fd,
                &mut key as *mut _ as *mut _,
                &mut next_key as *mut _ as *mut _,
            )
        } < 0
        {
            None
        } else {
            Some(unsafe { next_key.assume_init() })
        }
    }
}

impl<K: Clone, V: Clone> Iterator for Iterable<'_, '_, K, V> {
    type Item = (K, Vec<V>);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.key.take();
        self.key = match key {
            Some(key) => {
                let next_key = MaybeUninit::<K>::zeroed();
                self.get_next_key(next_key, key)
            }
            None => {
                let key = MaybeUninit::<K>::zeroed();
                self.get_first_key(key)
            }
        };

        if self.key.is_none() {
            return None;
        }

        let key = self.key.clone().unwrap();
        Some((key.clone(), self.map.get(key).unwrap()))
    }
}

fn num_cpu_cores() -> usize {
    get_online()
        .unwrap()
        .len()
}
