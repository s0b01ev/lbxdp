use anyhow::Context as _;
use aya::{
    maps::{PerCpuArray, PerCpuValues},
    programs::{Xdp, XdpFlags},
    util::nr_cpus,
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp2s0")]
    iface: String,
}

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

    let mut backends: PerCpuArray<_, u16> =
        PerCpuArray::try_from(ebpf.map_mut("BACKENDS").unwrap())?;

    let nr_cpus = nr_cpus().map_err(|(_, error)| error)?;
    // TODO: make it configurable
    let backend_ports: Vec<u16> = vec![3000, 3001, 3002];
    for (idx, &port) in backend_ports.iter().enumerate() {
        let values = PerCpuValues::try_from(vec![port; nr_cpus])?;
        backends.set(idx as u32, values, 0)?;
    }
    /*
    backend_ports
        .iter()
        .enumerate()
        .try_for_each(|(idx, &port)| {
            let values = PerCpuValues::try_from(vec![port; nr_cpus])?;
            backends.set(idx as u32, values, 0)
        })?;
    */

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
