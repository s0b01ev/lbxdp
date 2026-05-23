#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_csum_diff,
    macros::{map, xdp},
    maps::{Array, LruHashMap, PerCpuArray, PerCpuHashMap},
    programs::XdpContext,
};
use aya_ebpf_bindings::bindings::__be32;
use aya_log_ebpf::info;
use core::{mem, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[repr(C)]
#[derive(Copy, Clone)]
struct ClientToBackendMapKey {
    client_ip: [u8; 4],
    client_port: u16,
    client_mac: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ClientToBackendMapVal {
    backend_ip: [u8; 4],
    backend_mac: [u8; 6],
    handshake_phase: TcpHandshakePhase,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BackendToClientMapKey {
    backend_ip: [u8; 4],
    client_port: u16,
    backend_mac: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BackendToClientMapVal {
    client_ip: [u8; 4],
    client_mac: [u8; 6],
    handshake_phase: TcpHandshakePhase,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct AddrPair {
    saddr: u32,
    daddr: u32,
}

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
enum TcpHandshakePhase {
    Syn,
    SynAck,
    Ack,
}

// TODO: to config
const MAX_BACKENDS: u32 = 4;
static OWN_IP: u32 = 0xc0a856fa; // 192.168.86.250
static OWN_MAC: [u8; 6] = [0x48, 0xf1, 0x7f, 0x60, 0x29, 0xc6];
static LISTENING_PORT: u16 = 8740;

#[map(name = "CLIENT_TO_BACKEND")]
static CLIENT_TO_BACKEND: PerCpuHashMap<ClientToBackendMapKey, ClientToBackendMapVal> =
    PerCpuHashMap::with_max_entries(1024, 0);

#[map(name = "BACKEND_TO_CLIENT")]
static BACKEND_TO_CLIENT: PerCpuHashMap<BackendToClientMapKey, BackendToClientMapVal> =
    PerCpuHashMap::with_max_entries(1024, 0);

#[map(name = "BACKENDS")]
static BACKENDS: Array<[u8; 4]> = Array::with_max_entries(MAX_BACKENDS, 0);

#[map(name = "BACKEND_MACS")]
static BACKEND_MACS: Array<[u8; 6]> = Array::with_max_entries(MAX_BACKENDS, 0);

#[map(name = "BACKEND_CONNECTIONS")]
static BACKEND_CONNECTIONS: PerCpuArray<i32> = PerCpuArray::with_max_entries(MAX_BACKENDS, 0);

#[inline(always)]
fn csum_diff(old_ips: AddrPair, new_ips: AddrPair) -> i64 {
    let diff = unsafe {
        bpf_csum_diff(
            &old_ips as *const _ as *mut __be32,
            core::mem::size_of::<AddrPair>() as u32,
            &new_ips as *const _ as *mut __be32,
            core::mem::size_of::<AddrPair>() as u32,
            0,
        )
    };
    return diff as i64;
}

#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _ in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}

#[inline(always)]
fn csum_unfold(csum: u16) -> u64 {
    (!(csum) as u64) & 0xffff
}

#[inline(always)]
fn apply_diff(check: [u8; 2], diff: i64) -> [u8; 2] {
    let check = u16::from_be_bytes(check);
    let sum = csum_unfold(check).wrapping_add(diff as u64);
    u16::to_be_bytes(csum_fold_helper(sum))
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

fn add_to_client_to_backend_map(
    client_ip: [u8; 4],
    client_port: u16,
    backend_ip: [u8; 4],
    backend_mac: [u8; 6],
    handshake_phase: TcpHandshakePhase,
    ethhdr: *const EthHdr,
) -> Result<(), ()> {
    let map_key = ClientToBackendMapKey {
        client_ip: client_ip,
        client_port: client_port,
        client_mac: unsafe { (*ethhdr).src_addr },
    };
    let map_val = ClientToBackendMapVal {
        backend_ip: backend_ip,
        backend_mac: backend_mac,
        handshake_phase: handshake_phase,
    };
    unsafe {
        CLIENT_TO_BACKEND
            .insert(map_key, map_val, 0)
            .map_err(|_| ())?;
    }
    Ok(())
}

fn delete_from_client_to_backend_map(
    client_ip: [u8; 4],
    client_port: u16,
    client_mac: [u8; 6],
) -> Result<(), ()> {
    let map_key = ClientToBackendMapKey {
        client_ip: client_ip,
        client_port: client_port,
        client_mac: client_mac,
    };
    unsafe { CLIENT_TO_BACKEND.remove(map_key).map_err(|_| ())? };
    Ok(())
}

fn add_to_backend_to_client_map(
    client_ip: [u8; 4],
    client_port: u16,
    backend_ip: [u8; 4],
    backend_mac: [u8; 6],
    handshake_phase: TcpHandshakePhase,
    ethhdr: *const EthHdr,
) -> Result<(), ()> {
    let map_key = BackendToClientMapKey {
        backend_ip: backend_ip,
        client_port: client_port,
        backend_mac: backend_mac,
    };
    let map_val = BackendToClientMapVal {
        client_ip: client_ip,
        client_mac: unsafe { (*ethhdr).src_addr },
        handshake_phase: handshake_phase,
    };
    unsafe {
        BACKEND_TO_CLIENT
            .insert(map_key, map_val, 0)
            .map_err(|_| ())?;
    }
    Ok(())
}

fn delete_from_backend_to_client_map(
    backend_ip: [u8; 4],
    client_port: u16,
    backend_mac: [u8; 6],
) -> Result<(), ()> {
    let map_key = BackendToClientMapKey {
        backend_ip: backend_ip,
        client_port: client_port,
        backend_mac: backend_mac,
    };
    unsafe { BACKEND_TO_CLIENT.remove(map_key).map_err(|_| ())? };
    Ok(())
}

#[inline(always)]
fn get_least_conn_backend() -> Result<([u8; 4], [u8; 6]), ()> {
    let first = match BACKEND_CONNECTIONS.get(0) {
        Some(&v) => v,
        None => return Err(()),
    };

    let mut least = first;
    let mut least_idx = 0;
    let mut i = 1;

    while i < MAX_BACKENDS {
        if let Some(&value) = BACKEND_CONNECTIONS.get(i) {
            if value < least && value != -1 {
                least = value;
                least_idx = i;
            }
        }
        i += 1;
    }

    let ip = match BACKENDS.get(least_idx) {
        Some(&v) => v,
        None => return Err(()),
    };
    let mac = match BACKEND_MACS.get(least_idx) {
        Some(&v) => v,
        None => return Err(()),
    };
    return Ok((ip, mac));
}

#[inline(always)]
fn is_backend_ip(ip: [u8; 4]) -> bool {
    let mut i = 0;
    while i < MAX_BACKENDS {
        if let Some(backend_ip) = BACKENDS.get(i) {
            if *backend_ip == ip {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[inline(always)]
fn get_from_client_to_backend_map(
    client_ip: [u8; 4],
    client_port: u16,
    client_mac: [u8; 6],
) -> Result<ClientToBackendMapVal, ()> {
    let key = ClientToBackendMapKey {
        client_ip,
        client_port,
        client_mac,
    };
    let backend = match unsafe { CLIENT_TO_BACKEND.get(key) } {
        Some(&v) => v,
        None => return Err(()),
    };
    return Ok(backend);
}

#[inline(always)]
fn get_from_backend_to_client_map(
    backend_ip: [u8; 4],
    client_port: u16,
    backend_mac: [u8; 6],
) -> Result<BackendToClientMapVal, ()> {
    let reverse_key = BackendToClientMapKey {
        backend_ip,
        client_port,
        backend_mac,
    };
    let client = match unsafe { BACKEND_TO_CLIENT.get(reverse_key) } {
        Some(&v) => v,
        None => return Err(()),
    };
    return Ok(client);
}

#[inline(always)]
fn update_backend_to_client_map(
    backend_ip: [u8; 4],
    client_port: u16,
    backend_mac: [u8; 6],
    tcp_hs_phase: TcpHandshakePhase,
) -> Result<(), ()> {
    let map_key = BackendToClientMapKey {
        backend_ip: backend_ip,
        client_port: client_port,
        backend_mac: backend_mac,
    };
    let map_val = match unsafe { BACKEND_TO_CLIENT.get(map_key) } {
        Some(&v) => v,
        None => return Err(()),
    };
    let new_map_val = BackendToClientMapVal {
        client_ip: map_val.client_ip,
        client_mac: map_val.client_mac,
        handshake_phase: tcp_hs_phase,
    };
    unsafe {
        BACKEND_TO_CLIENT
            .insert(map_key, new_map_val, 0)
            .map_err(|_| ())?;
    }
    Ok(())
}

#[inline(always)]
fn update_client_to_backend_map(
    client_ip: [u8; 4],
    client_port: u16,
    client_mac: [u8; 6],
    tcp_hs_phase: TcpHandshakePhase,
) -> Result<(), ()> {
    let map_key = ClientToBackendMapKey {
        client_ip: client_ip,
        client_port: client_port,
        client_mac: client_mac,
    };
    let map_val = match unsafe { CLIENT_TO_BACKEND.get(map_key) } {
        Some(&v) => v,
        None => return Err(()),
    };
    let new_map_val = ClientToBackendMapVal {
        backend_ip: map_val.backend_ip,
        backend_mac: map_val.backend_mac,
        handshake_phase: tcp_hs_phase,
    };
    unsafe {
        CLIENT_TO_BACKEND
            .insert(map_key, new_map_val, 0)
            .map_err(|_| ())?;
    }
    Ok(())
}

#[inline(always)]
fn is_pure_ack(tcphdr: *const TcpHdr) -> bool {
    unsafe {
        (*tcphdr).ack() == 1
            && (*tcphdr).syn() == 0
            && (*tcphdr).fin() == 0
            && (*tcphdr).rst() == 0
            && (*tcphdr).psh() == 0
            && (*tcphdr).urg() == 0
            && (*tcphdr).ece() == 0
            && (*tcphdr).cwr() == 0
    }
}

#[inline(always)]
fn is_syn_ack(tcphdr: *const TcpHdr) -> bool {
    unsafe {
        (*tcphdr).ack() == 1
            && (*tcphdr).syn() == 1
            && (*tcphdr).fin() == 0
            && (*tcphdr).rst() == 0
            && (*tcphdr).psh() == 0
            && (*tcphdr).urg() == 0
            && (*tcphdr).ece() == 0
            && (*tcphdr).cwr() == 0
    }
}

#[inline(always)]
fn is_fin(tcphdr: *const TcpHdr) -> bool {
    unsafe { (*tcphdr).fin() == 1 }
}

#[inline(always)]
fn is_pure_fin(tcphdr: *const TcpHdr) -> bool {
    unsafe {
        (*tcphdr).fin() == 1
            && (*tcphdr).syn() == 0
            && (*tcphdr).ack() == 0
            && (*tcphdr).rst() == 0
            && (*tcphdr).psh() == 0
            && (*tcphdr).urg() == 0
            && (*tcphdr).ece() == 0
            && (*tcphdr).cwr() == 0
    }
}

#[inline(always)]
fn is_rst(tcphdr: *const TcpHdr) -> bool {
    unsafe { (*tcphdr).rst() == 1 }
}

#[inline(always)]
fn is_pure_rst(tcphdr: *const TcpHdr) -> bool {
    unsafe {
        (*tcphdr).rst() == 1
            && (*tcphdr).syn() == 0
            && (*tcphdr).ack() == 0
            && (*tcphdr).fin() == 0
            && (*tcphdr).psh() == 0
            && (*tcphdr).urg() == 0
            && (*tcphdr).ece() == 0
            && (*tcphdr).cwr() == 0
    }
}

// TODO: join with is_backend_ip()
#[inline(always)]
fn get_backend_idx(backend_ip: [u8; 4]) -> Result<u32, ()> {
    let mut i = 0;
    while i < MAX_BACKENDS {
        if let Some(ip) = BACKENDS.get(i) {
            if *ip == backend_ip {
                return Ok(i);
            }
        }
        i += 1;
    }
    return Err(());
}

#[inline(always)]
fn increment_backend_connections(key: u32, inc: bool) -> Result<i32, ()> {
    match unsafe { BACKEND_CONNECTIONS.get_ptr_mut(key) } {
        Some(ptr) => {
            unsafe { if inc { *ptr += 1 } else { *ptr -= 1 } };
            return Ok(unsafe { *ptr });
        }
        None => {
            return Err(());
        }
    }
}

#[xdp]
pub fn lbxdp(ctx: XdpContext) -> u32 {
    match try_lbxdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lbxdp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = mut_ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let source_mac = unsafe { (*ethhdr).src_addr };

    let ipv4hdr: *mut Ipv4Hdr = mut_ptr_at(&ctx, EthHdr::LEN)?;
    let source_ip = unsafe { (*ipv4hdr).src_addr };
    let source_ip_display = u32::from_be_bytes(source_ip);

    let dest_ip = unsafe { (*ipv4hdr).dst_addr };
    let dest_ip_display = u32::from_be_bytes(dest_ip);

    let old_ips = AddrPair {
        saddr: source_ip_display,
        daddr: dest_ip_display,
    };

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            let source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
            let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });

            if dest_port != LISTENING_PORT && source_port != LISTENING_PORT {
                return Ok(xdp_action::XDP_PASS);
            }

            let syn = unsafe { (*tcphdr).syn() };

            //// client -> LB packets
            if !is_backend_ip(source_ip) {
                let least_loaded_backend = get_least_conn_backend()?;
                if syn == 1 {
                    add_to_client_to_backend_map(
                        source_ip,
                        source_port,
                        least_loaded_backend.0,
                        least_loaded_backend.1,
                        TcpHandshakePhase::Syn,
                        ethhdr,
                    )?;
                    info!(&ctx, "added to direct");
                    add_to_backend_to_client_map(
                        source_ip,
                        source_port,
                        least_loaded_backend.0,
                        least_loaded_backend.1,
                        TcpHandshakePhase::Syn,
                        ethhdr,
                    )?;
                    info!(
                        &ctx,
                        "added to reverse --- ip: {}.{}.{}.{} mac: {:x}:{:x}:{:x}:{:x}:{:x}:{:x} port: {}",
                        least_loaded_backend.0[0],
                        least_loaded_backend.0[1],
                        least_loaded_backend.0[2],
                        least_loaded_backend.0[3],
                        least_loaded_backend.1[0],
                        least_loaded_backend.1[1],
                        least_loaded_backend.1[2],
                        least_loaded_backend.1[3],
                        least_loaded_backend.1[4],
                        least_loaded_backend.1[5],
                        source_port
                    );
                }
                if is_fin(tcphdr) || is_rst(tcphdr) {
                    let backend =
                        get_from_client_to_backend_map(source_ip, source_port, source_mac)?;
                    delete_from_client_to_backend_map(source_ip, source_port, source_mac)?;
                    info!(
                        &ctx,
                        "removed from direct --- ip: {}.{}.{}.{} mac: {:x}:{:x}:{:x}:{:x}:{:x}:{:x} port: {}",
                        source_ip[0],
                        source_ip[1],
                        source_ip[2],
                        source_ip[3],
                        source_mac[0],
                        source_mac[1],
                        source_mac[2],
                        source_mac[3],
                        source_mac[4],
                        source_mac[5],
                        source_port
                    );
                    delete_from_backend_to_client_map(
                        backend.backend_ip,
                        source_port,
                        backend.backend_mac,
                    )?;
                    info!(
                        &ctx,
                        "removed from reverse --- ip: {}.{}.{}.{} mac: {:x}:{:x}:{:x}:{:x}:{:x}:{:x} port: {}",
                        backend.backend_ip[0],
                        backend.backend_ip[1],
                        backend.backend_ip[2],
                        backend.backend_ip[3],
                        backend.backend_mac[0],
                        backend.backend_mac[1],
                        backend.backend_mac[2],
                        backend.backend_mac[3],
                        backend.backend_mac[4],
                        backend.backend_mac[5],
                        source_port
                    );
                    // should not get here, if the conn was removed from both maps and previoous calls failed
                    let backend_idx = get_backend_idx(backend.backend_ip)?;
                    let conn = increment_backend_connections(backend_idx, false)?;
                    info!(
                        &ctx,
                        "decremented conn for backend {} -> {}", backend_idx, conn
                    );
                }

                let new_ips = AddrPair {
                    saddr: OWN_IP,
                    daddr: u32::from_be_bytes(least_loaded_backend.0),
                };
                let diff = csum_diff(old_ips, new_ips);
                if diff < 0 {
                    return Err(());
                }
                unsafe {
                    (*ipv4hdr).dst_addr = least_loaded_backend.0;
                    (*ipv4hdr).src_addr = u32::to_be_bytes(OWN_IP);
                    (*ethhdr).src_addr = OWN_MAC;
                    (*ethhdr).dst_addr = least_loaded_backend.1;
                    (*ipv4hdr).check = apply_diff((*ipv4hdr).check, diff);
                    (*tcphdr).check = apply_diff((*tcphdr).check, diff);
                };
                Ok(xdp_action::XDP_TX)

            //// backend -> LB packets
            } else if is_backend_ip(source_ip) {
                let client = get_from_backend_to_client_map(source_ip, dest_port, source_mac)?;
                let backend_idx = get_backend_idx(source_ip)?;
                if is_fin(tcphdr) || is_rst(tcphdr) {
                    let conn = increment_backend_connections(backend_idx, false)?;
                    info!(
                        &ctx,
                        "decremented conn for backend {} -> {}", backend_idx, conn
                    );
                    delete_from_backend_to_client_map(source_ip, dest_port, source_mac)?;
                    info!(&ctx, "response: removed from reverse");
                    delete_from_client_to_backend_map(
                        client.client_ip,
                        dest_port,
                        client.client_mac,
                    )?;
                    info!(&ctx, "response: removed from direct");
                }
                if is_syn_ack(tcphdr) {
                    info!(&ctx, "GOT SYN ACK");
                    update_backend_to_client_map(
                        source_ip,
                        dest_port,
                        source_mac,
                        TcpHandshakePhase::SynAck,
                    )?;
                    info!(
                        &ctx,
                        "updated  reverse --- ip: {}.{}.{}.{} mac: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}, port: {}",
                        source_ip[0],
                        source_ip[1],
                        source_ip[2],
                        source_ip[3],
                        source_mac[0],
                        source_mac[1],
                        source_mac[2],
                        source_mac[3],
                        source_mac[4],
                        source_mac[5],
                        dest_port
                    );
                    update_client_to_backend_map(
                        client.client_ip,
                        dest_port,
                        client.client_mac,
                        TcpHandshakePhase::SynAck,
                    )?;
                }
                if is_pure_ack(tcphdr) {
                    if client.handshake_phase == TcpHandshakePhase::SynAck {
                        info!(&ctx, "GOT ACK");
                        info!(&ctx, "backend id = {}", backend_idx);
                        let conn = increment_backend_connections(backend_idx, true)?;
                        info!(
                            &ctx,
                            "incremented conn for backend {} -> {}", backend_idx, conn
                        );
                        update_backend_to_client_map(
                            source_ip,
                            dest_port,
                            source_mac,
                            TcpHandshakePhase::Ack,
                        )?;
                        update_client_to_backend_map(
                            client.client_ip,
                            dest_port,
                            client.client_mac,
                            TcpHandshakePhase::Ack,
                        )?;
                    }
                }

                let new_ips = AddrPair {
                    saddr: OWN_IP,
                    daddr: u32::from_be_bytes(client.client_ip),
                };
                let diff = csum_diff(old_ips, new_ips);
                if diff < 0 {
                    return Err(());
                }

                unsafe {
                    (*ipv4hdr).dst_addr = client.client_ip;
                    (*ipv4hdr).src_addr = u32::to_be_bytes(OWN_IP);
                    (*ethhdr).dst_addr = client.client_mac;
                    (*ethhdr).src_addr = OWN_MAC;
                    (*ipv4hdr).check = apply_diff((*ipv4hdr).check, diff);
                    (*tcphdr).check = apply_diff((*tcphdr).check, diff);
                };
                Ok(xdp_action::XDP_TX)
            } else {
                Ok(xdp_action::XDP_PASS)
            }
        }
        IpProto::Udp => Ok(xdp_action::XDP_PASS),
        _ => Err(()),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
