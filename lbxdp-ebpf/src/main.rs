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
use aya_log_ebpf::info;
use core::{mem, ptr};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{self, IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

#[repr(C)]
struct Ipv4PseudoHeader {
    saddr: u32,
    daddr: u32,
    zero: u8,
    proto: u8,
    len: u16,
}

struct ConnMapKey {
    src_addr: u32,
    src_port: u16,
}
struct ConnMapValue {
    backend_id: u32,
    state: u16,
    last_seen: u64,
}

static MAX_BACKENDS: u32 = 4;

#[map(name = "CONNECTIONS")]
static CONNECTIONS: LruHashMap<ConnMapKey, ConnMapValue> = LruHashMap::with_max_entries(1024, 0);

#[map(name = "BACKEND_CONNS")]
static BACKEND_CONNS: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

// TODO: can be just Array<u32>
#[map(name = "BACKENDS")]
static BACKENDS: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

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

#[inline(always)]
fn csum_add(mut sum: u32, add: u32) -> u32 {
    sum = sum.wrapping_add(add);
    (sum & 0xffff) + (sum >> 16)
}

#[inline(always)]
fn csum_finish(mut sum: u32) -> u16 {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[inline(always)]
fn csum_apply_diff(old_check_be: [u8; 2], diff: u32) -> [u8; 2] {
    // checksum field is stored in network byte order
    let old_check = u16::from_be_bytes(old_check_be);

    let mut sum = (!old_check as u32) & 0xffff;

    sum = sum.wrapping_add(diff);

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    let new_check = !(sum as u16);
    new_check.to_be_bytes()
}

#[inline(always)]
unsafe fn tcp_csum_replace_daddr(tcph: *mut TcpHdr, mut old_dst_addr: u32, mut new_dst_addr: u32) {
    let diff = bpf_csum_diff(
        &mut old_dst_addr as *mut _ as *mut u32,
        mem::size_of::<u32>() as u32,
        &mut new_dst_addr as *mut _ as *mut u32,
        mem::size_of::<u32>() as u32,
        0,
    ) as u32;

    (*tcph).check = csum_apply_diff((*tcph).check, diff);
}

#[xdp]
pub fn lbxdp(ctx: XdpContext) -> u32 {
    match try_lbxdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_lbxdp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = mut_ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = unsafe { (*ipv4hdr).src_addr };
    let source_addr_display = u32::from_be_bytes(source_addr);

    let dest_addr = unsafe { (*ipv4hdr).dst_addr };
    let dest_addr_display = u32::from_be_bytes(dest_addr);

    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Err(()),
    };

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = mut_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });

            // TODO: unhardcode port
            if dest_port != 8740 {
                return Ok(xdp_action::XDP_PASS);
            }

            let syn = unsafe { (*tcphdr).syn() };
            let fin = unsafe { (*tcphdr).fin() };
            let rst = unsafe { (*tcphdr).rst() };
            info!(
                &ctx,
                "{:i}:{} --> {:i}:{} syn: {} fin: {}",
                source_addr_display,
                source_port,
                dest_addr_display,
                dest_port,
                syn,
                fin
            );
            let conn_map_key = ConnMapKey {
                src_addr: source_addr_display,
                src_port: source_port,
            };
            if syn == 1 {
                let csum_hdr = unsafe { (*ipv4hdr).checksum() };
                info!(&ctx, "checksum from header: {:x}", csum_hdr);
                // new connection
                //
                // 1. find BACKEND_CONNS idx with min value
                // 2. find backend ip: BACKENDS[idx]
                // 3. replace dst ip in the packet header
                //  3a. replace the ip
                //  3b. compute and replace ip checksum
                //  3c. compute and replace tcp checksum
                // 4. update CONNECTIONS
                //      key: {src_ip, src_port} value: {idx. state(?), last_seen}
                // 5. update BACKEND_CONNS
                //      BACKEND_CONNS[idx]++
                // 1.
                let mut least_conn = 0;
                let mut least_conn_id = 0;
                for i in 0..MAX_BACKENDS {
                    match BACKENDS.get(i) {
                        Some(v) => {
                            let conn = v.clone();
                            if conn < least_conn {
                                least_conn = conn;
                                least_conn_id = i;
                            }
                        }
                        None => {}
                    }
                }
                // 2.
                let mut backend_ip: u32 = 0;
                match BACKENDS.get(least_conn_id) {
                    Some(v) => {
                        backend_ip = v.clone();
                        info!(&ctx, "BACKENDS {:x}", backend_ip);
                    }
                    None => {}
                }
                // 3a.
                //let old = unsafe { (*ipv4hdr).checksum() };
                unsafe { (*ipv4hdr).set_checksum(0) };
                unsafe {
                    (*ipv4hdr).dst_addr = u32::to_be_bytes(backend_ip);
                };
                let full_cksum = unsafe {
                    bpf_csum_diff(
                        ptr::null_mut(),
                        0,
                        ipv4hdr as *mut u32,
                        Ipv4Hdr::LEN as u32,
                        0,
                    )
                } as u64;
                let csum = csum_fold_helper(full_cksum);
                info!(&ctx, "csum: {:x}", csum);
                //unsafe { (*ipv4hdr).set_checksum(old) };
                unsafe { (*ipv4hdr).set_checksum(csum.to_be()) };
                // 4
                let conn_map_value = ConnMapValue {
                    backend_id: least_conn_id,
                    // TODO: set the real connection state
                    state: 1,
                    last_seen: unsafe { bpf_ktime_get_ns() },
                };
                let tcp_csum = unsafe { (*tcphdr).check };
                info!(&ctx, "TCP CSUM {:x} {:x}", tcp_csum[0], tcp_csum[1]);
                // 3c
                unsafe {
                    tcp_csum_replace_daddr(tcphdr, dest_addr_display, backend_ip);
                }
                let tcp_csum = unsafe { (*tcphdr).check };
                info!(&ctx, "NEW TCP CSUM {:x} {:x}", tcp_csum[0], tcp_csum[1]);

                match CONNECTIONS.insert(&conn_map_key, &conn_map_value, 0) {
                    Ok(_) => {
                        info!(
                            &ctx,
                            " -- inserted {:i}:{} --> {:i}:{}  {}",
                            source_addr_display,
                            source_port,
                            dest_addr_display,
                            dest_port,
                            conn_map_value.last_seen
                        );
                    }
                    Err(_) => {}
                }
            } else if fin == 1 || rst == 1 {
                match CONNECTIONS.remove(&conn_map_key) {
                    Ok(_) => {
                        info!(
                            &ctx,
                            " -- deleted {:i}:{} --> {:i}:{}",
                            source_addr_display,
                            source_port,
                            dest_addr_display,
                            dest_port
                        );
                    }
                    Err(_) => {}
                }
            } else {
                // !SYN && !FIN && !RST
                unsafe {
                    // if conn is in the map, we just update last_seen
                    // if not, we ignore it assuming these are very last ACKs for closed conn
                    // TODO: if FIN or RST were missing for some reason, the conn will stay in the map
                    // forever. Need some expiration logic for such connections
                    if let Some(val) = CONNECTIONS.get_ptr_mut(&conn_map_key) {
                        (*val).last_seen = bpf_ktime_get_ns();
                        info!(
                            &ctx,
                            " -- updated {:i}:{} --> {:i}:{}  {}",
                            source_addr_display,
                            source_port,
                            dest_addr_display,
                            dest_port,
                            (*val).last_seen
                        );
                    }
                }
            }
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
