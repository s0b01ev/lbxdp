#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{LruHashMap, PerCpuArray, PerCpuHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

struct ConnMapKey {
    src_addr: u32,
    src_port: u16,
}
struct ConnMapValue {
    backend_id: u16,
    state: u16,
    last_seen: u64,
}

#[map(name = "CONNECTIONS")]
static CONNECTIONS: LruHashMap<ConnMapKey, ConnMapValue> = LruHashMap::with_max_entries(1024, 0);

#[map(name = "BACKEND_CONNS")]
static BACKEND_CONNS: PerCpuArray<u32> = PerCpuArray::with_max_entries(32, 0);

// TODO: can be just Array<u16>
#[map(name = "BACKENDS")]
static BACKENDS: PerCpuArray<u16> = PerCpuArray::with_max_entries(32, 0);

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

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
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
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

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
            let conn_map_value = ConnMapValue {
                backend_id: 1,
                state: 1,
                last_seen: unsafe { bpf_ktime_get_ns() },
            };
            if syn == 1 {
                // new connection
                //
                // 1 find a backend with least conn
                //  find BACKEND_CONNS idx with min value
                //  find port number: BACKENDS[idx]
                // 2 update CONNECTIONS
                //  key: {src_ip, src_port} value: {idx. state(?), last_seen}
                // 3 update BACKEN_CONNS
                //  BACKEND_CONNS[idx]++
                match BACKENDS.get(0) {
                    Some(v) => {
                        let vv = v.clone();
                        info!(&ctx, "BACKENDS {}", vv);
                    }
                    None => {}
                }
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
