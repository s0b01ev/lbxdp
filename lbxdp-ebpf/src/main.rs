#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_csum_diff,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{LruHashMap, PerCpuArray, PerCpuHashMap},
    programs::XdpContext,
};
use aya_ebpf_bindings::bindings::{__be32, __wsum};
use aya_log_ebpf::info;
use core::{mem, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{self, IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

struct ConnMapKey {
    src_addr: u32,
    src_port: u16,
}
struct ConnMapValue {
    backend_id: u32,
    state: u16,
    last_seen: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct AddrPair {
    saddr: u32,
    daddr: u32,
}

static MAX_BACKENDS: u32 = 4;

static OWN_IP: u32 = 0xc0a856fa; // 192.168.86.250
static OWN_MAC: [u8; 6] = [0x48, 0xf1, 0x7f, 0x60, 0x29, 0xc6];
static BACKEND_IP: u32 = 0xc0a856f7; // 192.168.86.247
static BACKEND_MAC: [u8; 6] = [0xa0, 0x78, 0x17, 0x6c, 0xa4, 0x4f];
static CLIENT_IP: u32 = 0xc0a8561d; // 192.168.86.29
static CLIENT_MAC: [u8; 6] = [0xd8, 0x3a, 0xdd, 0x4c, 0xdf, 0xe7];

#[map(name = "CONNECTIONS")]
static CONNECTIONS: LruHashMap<ConnMapKey, ConnMapValue> = LruHashMap::with_max_entries(1024, 0);

#[map(name = "BACKEND_CONNS")]
static BACKEND_CONNS: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

// TODO: can be just Array<u32>
#[map(name = "BACKENDS")]
static BACKENDS: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

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

            // client -> LB packets
            let new_ips = AddrPair {
                saddr: OWN_IP,
                daddr: BACKEND_IP,
            };
            let diff = csum_diff(old_ips, new_ips);
            if diff < 0 {
                return Err(());
            }

            if source_addr != u32::to_be_bytes(BACKEND_IP) {
                unsafe {
                    (*ipv4hdr).dst_addr = u32::to_be_bytes(BACKEND_IP);
                    (*ipv4hdr).src_addr = u32::to_be_bytes(OWN_IP);
                    (*ethhdr).src_addr = OWN_MAC;
                    (*ethhdr).dst_addr = BACKEND_MAC;
                    (*ipv4hdr).check = apply_diff((*ipv4hdr).check, diff);
                    (*tcphdr).check = apply_diff((*tcphdr).check, diff);
                };
                return Ok(xdp_action::XDP_TX);
            // backend -> LB packets
            } else if source_addr == u32::to_be_bytes(BACKEND_IP) {
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
                return Ok(xdp_action::XDP_TX);
            } else {
                return Ok(xdp_action::XDP_PASS);
            }
        }
        IpProto::Udp => {
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Err(()),
    };

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
