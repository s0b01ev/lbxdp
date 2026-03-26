use anyhow::Context as _;
use aya::{
    maps::{Array, PerCpuArray, PerCpuHashMap, PerCpuValues},
    programs::{Xdp, XdpFlags},
    util::nr_cpus,
};
use clap::Parser;
use std::net::Ipv4Addr;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp2s0")]
    iface: String,
}

const MAX_BACKENDS: u32 = 4;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/lbxdp"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf
        .program_mut("lbxdp")
        .context("eBPF program 'lbxdp' was not found in the loaded object")?
        .try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;

    let b_ips: Vec<[u8; 4]> = vec![
        Ipv4Addr::new(192, 168, 86, 247).octets(),
        Ipv4Addr::new(192, 168, 86, 248).octets(),
    ];

    let b_macs: Vec<[u8; 6]> = vec![
        [0xa0, 0x78, 0x17, 0x6c, 0xa4, 0x4f],
        [0xa0, 0x78, 0x17, 0x6c, 0xa4, 0x4f],
    ];

    let mut backend_ips: Array<_, [u8; 4]> = Array::try_from(ebpf.map_mut("BACKENDS").unwrap())?;
    for (idx, ip) in b_ips.iter().enumerate() {
        backend_ips.set(idx as u32, ip, 0)?
    }

    let mut backend_macs: Array<_, [u8; 6]> =
        Array::try_from(ebpf.map_mut("BACKEND_MACS").unwrap())?;
    for (idx, mac) in b_macs.iter().enumerate() {
        backend_macs.set(idx as u32, mac, 0)?
    }

    let mut connections: PerCpuArray<_, i32> =
        PerCpuArray::try_from(ebpf.map_mut("BACKEND_CONNECTIONS").unwrap())?;
    let len = b_ips.len();
    // for i in 0..len {
    //     connections.set(i as u32, PerCpuValues::try_from(vec![0i32; nr_cpus])?, 0)?
    // }
    connections.set(0 as u32, PerCpuValues::try_from(vec![2i32; nr_cpus])?, 0)?;
    connections.set(1 as u32, PerCpuValues::try_from(vec![3i32; nr_cpus])?, 0)?;
    for i in len..MAX_BACKENDS as usize {
        connections.set(i as u32, PerCpuValues::try_from(vec![-1i32; nr_cpus])?, 0)?
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
