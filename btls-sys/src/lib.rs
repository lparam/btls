#![allow(
    clippy::missing_safety_doc,
    clippy::redundant_static_lifetimes,
    clippy::too_many_arguments,
    clippy::unreadable_literal,
    clippy::upper_case_acronyms,
    improper_ctypes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_imports
)]

use std::convert::TryInto;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_uint, c_ulong};

#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::manual_div_ceil,
    clippy::ptr_offset_with_cast,
    clippy::useless_transmute,
    dead_code,
    unknown_lints,
    unnecessary_transmutes,
    suspicious_runtime_symbol_definitions
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

// explicitly require presence of some symbols to check if the bindings worked
pub use generated::{ssl_compliance_policy_t, ERR_add_error_data, SSL_set1_groups}; // if these are missing, your include path is incorrect or has a wrong version of boringssl
pub use generated::{BIO_new, OPENSSL_free, SSL_ERROR_NONE}; // if these are missing, your include path is incorrect
#[cfg(feature = "fips")]
pub use generated::{FIPS_mode, SSL_CTX_set_compliance_policy}; // your include path is incorrect or has a version of boringssl without FIPS support
#[cfg(feature = "mlkem")]
pub use generated::{MLKEM768_encap, MLKEM768_private_key_from_seed}; // your include path is incorrect or has a version of boringssl without mlkem support
#[cfg(feature = "rpk")]
pub use generated::{SSL_CREDENTIAL_new_raw_public_key_empty, SSL_CREDENTIAL_set1_spki}; // your include path is incorrect or has a version of boringssl without rpk support
#[cfg(not(feature = "fips"))]
pub use generated::{SSL_seal_app_data, SSL_seal_app_data_limits}; // your include path is incorrect or has a version of boringssl without patch 0012 (seal-app-data)

pub use generated::*;
#[cfg(target_pointer_width = "64")]
pub type BN_ULONG = u64;
#[cfg(target_pointer_width = "32")]
pub type BN_ULONG = u32;

extern "C" {
    pub fn SSL_set_fixed_ecdh_private_key(
        ssl: *mut SSL,
        key: *const u8,
        key_len: usize,
    );

    pub fn SSL_set_client_hello_filter(
        ssl: *mut SSL,
        filter: Option<unsafe extern "C" fn(ssl: *mut SSL, msg: *mut u8, msg_len: usize, arg: *mut c_void) -> c_int>,
        arg: *mut c_void,
    );

    pub fn SSL_get_unconsumed_read_buffer(
        ssl: *const SSL,
        out_ptr: *mut *const u8,
    ) -> usize;

    pub fn EVP_PKEY_new_raw_private_key(
        type_: c_int,
        engine: *mut ENGINE,
        key: *const u8,
        len: usize,
    ) -> *mut EVP_PKEY;

    pub fn EVP_PKEY_get_raw_public_key(
        pkey: *const EVP_PKEY,
        out: *mut u8,
        len: *mut usize,
    ) -> c_int;

    pub fn X25519(
        out_shared_key: *mut u8,
        private_key: *const u8,
        peer_public_value: *const u8,
    ) -> c_int;

    pub fn X25519_public_from_private(out_public_value: *mut u8, private_key: *const u8);

    pub fn X25519_keypair(out_public_value: *mut u8, out_private_key: *mut u8);
}

#[must_use]
pub const fn ERR_PACK(l: c_int, f: c_int, r: c_int) -> c_ulong {
    ((l as c_ulong & 0x0FF) << 24) | ((f as c_ulong & 0xFFF) << 12) | (r as c_ulong & 0xFFF)
}

#[must_use]
pub const fn ERR_GET_LIB(l: c_uint) -> c_int {
    ((l >> 24) & 0x0FF) as c_int
}

#[must_use]
pub const fn ERR_GET_FUNC(l: c_uint) -> c_int {
    ((l >> 12) & 0xFFF) as c_int
}

#[must_use]
pub const fn ERR_GET_REASON(l: c_uint) -> c_int {
    (l & 0xFFF) as c_int
}

pub fn init() {
    unsafe {
        CRYPTO_library_init();
    }
}

// CBS_init is inline in BoringSSL, so bindgen can't generate bindings for it.
#[inline]
pub fn cbs_init(data: &[u8]) -> CBS {
    CBS {
        data: data.as_ptr(),
        len: data.len(),
    }
}

pub mod internal {
    // BoringSSL now exposes this in the public `openssl/tls_prf.h`, so bindgen
    // generates it; kept as a re-export so the old path still works.
    pub use super::CRYPTO_tls1_prf;
}
