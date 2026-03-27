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

struct ClientToBackendMapKey {
    client_ip: [u8; 4],
    client_port: u16,
    client_mac: [u8; 6],
}
struct ClientToBackendMapVal {
    backend_ip: [u8; 4],
    backend_mac: [u8; 6],
}

struct BackendToClientMapKey {
    backend_ip: [u8; 4],
    backend_mac: [u8; 6],
}
struct BackendToClientMapVal {
    client_ip: [u8; 4],
    client_port: u16,
    client_mac: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct AddrPair {
    saddr: u32,
    daddr: u32,
}

const MAX_BACKENDS: u32 = 4;

static OWN_IP: u32 = 0xc0a856fa; // 192.168.86.250
static OWN_MAC: [u8; 6] = [0x48, 0xf1, 0x7f, 0x60, 0x29, 0xc6];
static BACKEND_IP: u32 = 0xc0a856f7; // 192.168.86.247
static BACKEND_MAC: [u8; 6] = [0xa0, 0x78, 0x17, 0x6c, 0xa4, 0x4f];
static CLIENT_IP: u32 = 0xc0a8561d; // 192.168.86.29
static CLIENT_MAC: [u8; 6] = [0xd8, 0x3a, 0xdd, 0x4c, 0xdf, 0xe7];

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
    ethhdr: *const EthHdr,
) -> Result<(), ()> {
    let map_key = ClientToBackendMapKey {
        client_ip: client_ip,
        client_port: client_port,
        client_mac: unsafe { (*ethhdr).src_addr },
    };
    unsafe { CLIENT_TO_BACKEND.remove(map_key).map_err(|_| ())? };
    Ok(())
}

fn add_to_backend_to_client_map(
    client_ip: [u8; 4],
    client_port: u16,
    backend_ip: [u8; 4],
    backend_mac: [u8; 6],
    ethhdr: *const EthHdr,
) -> Result<(), ()> {
    let map_key = BackendToClientMapKey {
        backend_ip: backend_ip,
        backend_mac: backend_mac,
    };
    let map_val = BackendToClientMapVal {
        client_ip: client_ip,
        client_port: client_port,
        client_mac: unsafe { (*ethhdr).src_addr },
    };
    unsafe {
        BACKEND_TO_CLIENT
            .insert(map_key, map_val, 0)
            .map_err(|_| ())?;
    }
    Ok(())
}

fn delete_from_backend_to_client_map(backend_ip: [u8; 4], backend_mac: [u8; 6]) -> Result<(), ()> {
    let map_key = BackendToClientMapKey {
        backend_ip: backend_ip,
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
        let _ = match BACKENDS.get(i) {
            Some(v) => {
                if are_ips_same(*v, ip) {
                    return true;
                }
            }
            None => (),
        };
        i += 1;
    }
    false
}

#[inline(always)]
fn are_ips_same(ip1: [u8; 4], ip2: [u8; 4]) -> bool {
    if ip1[0] != ip2[0] {
        return false;
    }
    if ip1[1] != ip2[1] {
        return false;
    }
    if ip1[2] != ip2[2] {
        return false;
    }
    if ip1[3] != ip2[3] {
        return false;
    }
    true
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

    let ipv4hdr: *mut Ipv4Hdr = mut_ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = unsafe { (*ipv4hdr).src_addr };
    let source_addr_display = u32::from_be_bytes(source_addr);

    let dest_addr = unsafe { (*ipv4hdr).dst_addr };
    let dest_addr_display = u32::from_be_bytes(dest_addr);

    let old_ips = AddrPair {
        saddr: source_addr_display,
        daddr: dest_addr_display,
    };

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            let source_port = u16::from_be_bytes(unsafe { (*tcphdr).source });
            let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });

            // TODO: unhardcode port
            if dest_port != 8740 && source_port != 8740 {
                return Ok(xdp_action::XDP_PASS);
            }

            //// client -> LB packets
            let least_loaded_backend = get_least_conn_backend()?;

            if !is_backend_ip(source_addr) {
                let syn = unsafe { (*tcphdr).syn() };
                if syn == 1 {
                    add_to_client_to_backend_map(
                        source_addr,
                        source_port,
                        least_loaded_backend.0,
                        least_loaded_backend.1,
                        ethhdr,
                    )?;
                    info!(&ctx, "added to direct");
                    add_to_backend_to_client_map(
                        source_addr,
                        source_port,
                        least_loaded_backend.0,
                        least_loaded_backend.1,
                        ethhdr,
                    )?;
                    info!(&ctx, "added to reverse");
                }
                let fin = unsafe { (*tcphdr).fin() };
                if fin == 1 {
                    delete_from_client_to_backend_map(source_addr, source_port, ethhdr)?;
                    info!(&ctx, "removed from direct");
                    delete_from_backend_to_client_map(
                        least_loaded_backend.0,
                        least_loaded_backend.1,
                    )?;
                    info!(&ctx, "removed from reverse");
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
            } else if is_backend_ip(source_addr) {
                let new_ips = AddrPair {
                    saddr: OWN_IP,
                    daddr: CLIENT_IP,
                };
                let diff = csum_diff(old_ips, new_ips);
                if diff < 0 {
                    return Err(());
                }

                unsafe {
                    (*ipv4hdr).dst_addr = u32::to_be_bytes(CLIENT_IP);
                    (*ipv4hdr).src_addr = u32::to_be_bytes(OWN_IP);
                    (*ethhdr).dst_addr = CLIENT_MAC;
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
