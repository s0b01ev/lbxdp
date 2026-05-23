use anyhow::{Context, bail};
use aya::{
    maps::{Array, PerCpuArray, PerCpuValues},
    programs::{Xdp, XdpFlags},
    util::nr_cpus,
};
use config::{Config, File};
use std::net::Ipv4Addr;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use lbxdp_common::MAX_BACKENDS;

mod cfg;

async fn load_config() -> Result<cfg::Settings, config::ConfigError> {
    let settings = Config::builder()
        .add_source(File::with_name("config"))
        .build()?;

    settings.try_deserialize()
}

fn ip_from_string(ip_str: String) -> anyhow::Result<Ipv4Addr> {
    let octets: Vec<u8> = ip_str
        .split('.')
        .map(|o| {
            o.parse::<u8>()
                .with_context(|| format!("invalid IPv4 octet: {o}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    if octets.len() != 4 {
        bail!(
            "invalid IPv4 address {ip_str}: expected 4 octets, got {}",
            octets.len()
        );
    }

    Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

fn mac_from_string(mac_str: String) -> anyhow::Result<[u8; 6]> {
    let octets: Vec<u8> = mac_str
        .split(':')
        .map(|o| u8::from_str_radix(o, 16).with_context(|| format!("invalid mac octet: {o}")))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let len = octets.len();

    octets
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid mac address {mac_str}: expected 6 octets, got {len}"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let cfg = load_config().await?;
    let iface = cfg.load_balancer.iface;

    let program: &mut Xdp = ebpf
        .program_mut("lbxdp")
        .context("eBPF program 'lbxdp' was not found in the loaded object")?
        .try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;

    let b_ips_cfg = cfg.backends.ips;
    let b_macs_cfg = cfg.backends.macs;
    let b_ips_len = b_ips_cfg.len();
    let b_macs_len = b_macs_cfg.len();
    if b_ips_len < 2 {
        bail!("backed ips list should be >= 2, got {}", b_ips_len);
    }
    if b_macs_len < 2 {
        bail!("backed macs list should be >= 2, got {}", b_macs_len);
    }
    if b_macs_len != b_ips_len {
        bail!("backend ip list and mac list are of different lenght");
    }

    let b_ips: Vec<Ipv4Addr> = b_ips_cfg
        .into_iter()
        .map(ip_from_string)
        .collect::<anyhow::Result<Vec<_>>>()?;

    let b_macs: Vec<[u8; 6]> = b_macs_cfg
        .into_iter()
        .map(mac_from_string)
        .collect::<anyhow::Result<Vec<_>>>()?
        .try_into()?;

    let mut backend_ips: Array<_, [u8; 4]> = Array::try_from(ebpf.map_mut("BACKENDS").unwrap())?;
    for (idx, ip) in b_ips.iter().enumerate() {
        backend_ips.set(idx as u32, ip.octets(), 0)?
    }

    let mut backend_macs: Array<_, [u8; 6]> =
        Array::try_from(ebpf.map_mut("BACKEND_MACS").unwrap())?;
    for (idx, mac) in b_macs.iter().enumerate() {
        backend_macs.set(idx as u32, mac, 0)?
    }

    let mut connections: PerCpuArray<_, i32> =
        PerCpuArray::try_from(ebpf.map_mut("BACKEND_CONNECTIONS").unwrap())?;
    let len = b_ips.len();
    for i in 0..len {
        connections.set(i as u32, PerCpuValues::try_from(vec![0i32; nr_cpus])?, 0)?
    }
    for i in len..MAX_BACKENDS as usize {
        connections.set(i as u32, PerCpuValues::try_from(vec![-1i32; nr_cpus])?, 0)?
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
