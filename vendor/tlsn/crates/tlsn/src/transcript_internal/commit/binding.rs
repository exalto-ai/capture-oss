//! Privacy-preserving binding between the root TLS VM and an ephemeral chunk VM.
//!
//! The decoded value is a salted hash of high-entropy TLS traffic keys. It is
//! computationally hiding and does not contain transcript plaintext. A child
//! VM must reproduce it before using its independently authenticated key.

use mpz_common::Context;
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{
    Array, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::Vm;

use crate::{Error, Result, proxy::PlainSessionKeys};

const DOMAIN: &[u8] = b"llm-notary/ephemeral-key-binding/v1";

fn internal<E>(error: E) -> Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    Error::internal().with_source(error)
}

fn binding_hash<T: Vm<Binary>>(
    vm: &mut T,
    client_write_key: Array<U8, 16>,
    client_write_iv: Array<U8, 4>,
    server_write_key: Array<U8, 16>,
    server_write_iv: Array<U8, 4>,
    salt: Array<U8, 16>,
) -> Result<Array<U8, 32>> {
    let domain = vm.alloc_vec::<U8>(DOMAIN.len()).map_err(internal)?;
    vm.mark_public(domain).map_err(internal)?;
    vm.assign(domain, DOMAIN.to_vec()).map_err(internal)?;
    vm.commit(domain).map_err(internal)?;

    let mut hasher = Sha256::new_with_init(vm).map_err(|e| Error::internal().with_source(e))?;
    hasher.update(&domain);
    hasher.update(&Vector::from(client_write_key));
    hasher.update(&Vector::from(client_write_iv));
    hasher.update(&Vector::from(server_write_key));
    hasher.update(&Vector::from(server_write_iv));
    hasher.update(&Vector::from(salt));
    hasher
        .finalize(vm)
        .map_err(|e| Error::internal().with_source(e))
}

async fn decode_binding<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    hash: Array<U8, 32>,
) -> Result<[u8; 32]> {
    let mut decoded = vm.decode(Vector::from(hash)).map_err(internal)?;
    vm.execute_all(ctx).await.map_err(internal)?;
    let bytes = decoded
        .try_recv()
        .map_err(|e| Error::internal().with_source(e))?
        .ok_or_else(|| Error::internal().with_msg("key-binding hash was not decoded"))?;
    bytes
        .try_into()
        .map_err(|_| Error::internal().with_msg("key-binding hash has invalid length"))
}

/// Computes and decodes the root VM's salted traffic-key binding on the prover.
pub(crate) async fn prove_root_binding<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &mpc_tls::SessionKeys,
    salt: [u8; 16],
) -> Result<[u8; 32]> {
    let salt_ref = vm.alloc::<Array<U8, 16>>().map_err(internal)?;
    vm.mark_private(salt_ref).map_err(internal)?;
    vm.assign(salt_ref, salt).map_err(internal)?;
    vm.commit(salt_ref).map_err(internal)?;
    let hash = binding_hash(
        vm,
        keys.client_write_key,
        keys.client_write_iv,
        keys.server_write_key,
        keys.server_write_iv,
        salt_ref,
    )?;
    decode_binding(ctx, vm, hash).await
}

/// Computes and decodes the root VM's salted traffic-key binding on the verifier.
pub(crate) async fn verify_root_binding<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &mpc_tls::SessionKeys,
) -> Result<[u8; 32]> {
    let salt_ref = vm.alloc::<Array<U8, 16>>().map_err(internal)?;
    vm.mark_blind(salt_ref).map_err(internal)?;
    vm.commit(salt_ref).map_err(internal)?;
    let hash = binding_hash(
        vm,
        keys.client_write_key,
        keys.client_write_iv,
        keys.server_write_key,
        keys.server_write_iv,
        salt_ref,
    )?;
    decode_binding(ctx, vm, hash).await
}

/// Allocates private traffic keys in an ephemeral prover VM and returns its
/// decoded binding. The caller compares it with the root binding.
pub(crate) async fn prove_child_binding<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
    keys: &PlainSessionKeys,
    salt: [u8; 16],
) -> Result<([Array<U8, 16>; 2], [Array<U8, 4>; 2], [u8; 32])> {
    fn private<T: Vm<Binary>, const N: usize>(vm: &mut T, value: [u8; N]) -> Result<Array<U8, N>> {
        let reference = vm.alloc::<Array<U8, N>>().map_err(internal)?;
        vm.mark_private(reference).map_err(internal)?;
        vm.assign(reference, value).map_err(internal)?;
        vm.commit(reference).map_err(internal)?;
        Ok(reference)
    }

    let client_key = private(vm, keys.client_write_key)?;
    let client_iv = private(vm, keys.client_write_iv)?;
    let server_key = private(vm, keys.server_write_key)?;
    let server_iv = private(vm, keys.server_write_iv)?;
    let salt = private(vm, salt)?;
    let hash = binding_hash(vm, client_key, client_iv, server_key, server_iv, salt)?;
    let binding = decode_binding(ctx, vm, hash).await?;
    Ok(([client_key, server_key], [client_iv, server_iv], binding))
}

/// Allocates blind traffic keys in an ephemeral verifier VM and returns its
/// decoded binding. The caller compares it with the root binding.
pub(crate) async fn verify_child_binding<T: Vm<Binary> + Send + Sync>(
    ctx: &mut Context,
    vm: &mut T,
) -> Result<([Array<U8, 16>; 2], [Array<U8, 4>; 2], [u8; 32])> {
    fn blind<T: Vm<Binary>, const N: usize>(vm: &mut T) -> Result<Array<U8, N>> {
        let reference = vm.alloc::<Array<U8, N>>().map_err(internal)?;
        vm.mark_blind(reference).map_err(internal)?;
        vm.commit(reference).map_err(internal)?;
        Ok(reference)
    }

    let client_key = blind(vm)?;
    let client_iv = blind(vm)?;
    let server_key = blind(vm)?;
    let server_iv = blind(vm)?;
    let salt = blind(vm)?;
    let hash = binding_hash(vm, client_key, client_iv, server_key, server_iv, salt)?;
    let binding = decode_binding(ctx, vm, hash).await?;
    Ok(([client_key, server_key], [client_iv, server_iv], binding))
}
