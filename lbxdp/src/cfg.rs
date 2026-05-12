use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub load_balancer: LoadBalancerConfig,
    pub backends: BackendsConfig,
}

#[derive(Debug, Deserialize)]
pub struct LoadBalancerConfig {
    pub iface: String,
    pub ip: String,
    pub mac: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct BackendsConfig {
    pub ips: Vec<String>,
    pub macs: Vec<String>,
}
