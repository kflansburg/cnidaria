use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{self, Read};

const CNI_VERSION: &str = "1.0.0";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// This is a JSON document describing a network to which a container can be
/// joined.
pub struct NetworkConfiguration {
    /// Semantic Version 2.0 of CNI specification to which this configuration
    /// conforms.
    pub cni_version: String,
    /// Network name. This should be unique across all containers on the host
    /// (or other administrative domain). Must start with a alphanumeric
    /// character, optionally followed by any combination of one or more
    /// alphanumeric characters, underscore (_), dot (.) or hyphen (-).
    pub name: String,
    /// Refers to the filename of the CNI plugin executable.
    #[serde(rename = "type")]
    pub ty: String,
    /// Additional arguments provided by the container runtime.
    pub args: Option<Map<String, Value>>,
    /// If supported by the plugin, sets up an IP masquerade on the host for
    /// this network. This is necessary if the host will act as a gateway to
    /// subnets that are not able to route to the IP assigned to the container.
    pub ip_masq: Option<bool>,
    /// Dictionary with IPAM specific values.
    pub ipam: Option<IpamConfiguration>,
    #[serde(flatten)]
    pub params: Map<String, Value>,
    /// Dictionary with DNS specific values.
    pub dns: Option<DnsConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// Dictionary with IPAM specific values.
pub struct IpamConfiguration {
    /// Refers to the filename of the IPAM plugin executable.
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
/// Dictionary with DNS specific values.
pub struct DnsConfig {
    /// List of a priority-ordered list of DNS nameservers that this network is
    /// aware of. Each entry in the list is a string containing either an IPv4
    /// or an IPv6 address.
    pub nameservers: Option<Vec<String>>,
    /// The local domain used for short hostname lookups.
    pub domain: Option<String>,
    /// List of priority ordered search domains for short hostname lookups.
    /// Will be preferred over domain by most resolvers.
    pub search: Option<Vec<String>>,
    /// List of options that can be passed to the resolver.
    pub options: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
/// Route configuration information.
pub struct RouteConfig {
    /// Destination subnet specified in CIDR notation.
    pub dst: String,
    /// IP of the gateway. If omitted, a default gateway is assumed (as
    /// determined by the CNI plugin).
    pub gw: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
/// IP configuration for a network interface.
pub struct IPConfig {
    /// An IP address in CIDR notation (eg "192.168.1.3/24").
    pub address: String,
    /// The default gateway for this subnet, if one exists.
    pub gateway: Option<String>,
    /// The index into the interfaces list for a CNI Plugin Result indicating
    /// which interface this IP configuration should be applied to.
    pub interface: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceConfig {
    pub name: String,
    /// The hardware address of the interface. If L2 addresses are not
    /// meaningful for the plugin then this field is optional.
    pub mac: Option<String>,
    /// Container/namespace-based environments should return the full
    /// filesystem path to the network namespace of that sandbox.
    /// Hypervisor/VM-based plugins should return an ID unique to the
    /// virtualized sandbox the interface was created in. This item must be
    /// provided for interfaces created or moved into a sandbox like a network
    /// namespace or a hypervisor/VM.
    pub sandbox: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
/// Return information from a successful ADD plugin call.
pub struct AddResult {
    /// Semantic Version 2.0 of CNI specification used by the plugin.
    pub cni_version: String,
    /// Describes specific network interfaces the plugin created. If the
    /// `CNI_IFNAME` variable exists the plugin must use that name for the
    /// sandbox/hypervisor interface or return an error if it cannot.
    pub interfaces: Vec<InterfaceConfig>,
    /// List of IP configuration information.
    pub ips: Vec<IPConfig>,
    /// List of route configuration information.
    pub routes: Option<Vec<RouteConfig>>,
    /// Common DNS information.
    pub dns: Option<DnsConfig>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
/// Return information from a successful `ADD` plugin call.
pub struct VersionResult {
    /// Semantic Version 2.0 of CNI specification used by the plugin.
    pub cni_version: &'static str,
    /// List of CNI spec versions that this plugin supports.
    pub supported_versions: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
/// Report an error from the plugin call.
pub struct PluginError {
    /// Semantic Version 2.0 of CNI specification used by the plugin.
    pub cni_version: &'static str,
    /// Error codes 0-99 are reserved for well-known errors (see Well-known
    /// Error Codes section). Values of 100+ can be freely used for plugin
    /// specific errors.
    pub code: u32,
    /// Short error message.
    pub msg: String,
    /// Long error message.
    pub details: Option<String>,
}

/// Main trait to implement for creating CNI plugin.
pub trait Plugin {
    /// Add container to network.
    fn add(
        &self,
        container_id: &str,
        network_namespace_path: &str,
        network_configuration: NetworkConfiguration,
        args: HashMap<String, String>,
        interface_name: &str,
    ) -> Result<AddResult, PluginError>;

    /// Delete container from network. Plugins should generally complete a
    /// `DEL` action without error even if some resources are missing.
    fn delete(
        &self,
        container_id: &str,
        network_namespace_path: &str,
        network_configuration: NetworkConfiguration,
        args: HashMap<String, String>,
        interface_name: &str,
    ) -> Result<(), PluginError>;

    /// Check container's networking is as expected.
    fn check(
        &self,
        _container_id: &str,
        _network_namespace_path: &str,
        _network_configuration: NetworkConfiguration,
        _args: HashMap<String, String>,
        _interface_name: &str,
    ) -> Result<(), PluginError> {
        Ok(())
    }

    /// Report version.
    fn version(&self) -> VersionResult {
        VersionResult {
            cni_version: CNI_VERSION,
            supported_versions: vec![CNI_VERSION.to_string()],
        }
    }
}

fn load_var(name: &str) -> Result<String, PluginError> {
    match std::env::var(name) {
        Ok(s) => Ok(s),
        Err(std::env::VarError::NotPresent) => {
            let error = PluginError {
                cni_version: CNI_VERSION,
                code: 4,
                msg: format!("Missing `{}`.", name),
                details: None,
            };
            Err(error)
        }
        Err(std::env::VarError::NotUnicode(s)) => {
            let error = PluginError {
                cni_version: CNI_VERSION,
                code: 4,
                msg: format!("Unable to decode `{}` as unicode: '{:?}'", name, s),
                details: None,
            };
            Err(error)
        }
    }
}

fn load_args() -> Result<HashMap<String, String>, PluginError> {
    load_var("CNI_ARGS")
        .unwrap_or_else(|_| "".to_string())
        .split(';')
        .map(|s| {
            let v: Vec<&str> = s.split('=').collect();
            if v.len() == 2 {
                Ok((v[0].to_string(), v[1].to_string()))
            } else {
                let error = PluginError {
                    cni_version: CNI_VERSION,
                    code: 6,
                    msg: format!("Could not parse argument: '{}'", s),
                    details: None,
                };
                Err(error)
            }
        })
        .collect::<Result<HashMap<String, String>, PluginError>>()
}

fn load_network_config() -> Result<NetworkConfiguration, PluginError> {
    let mut buffer = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    match handle.read_to_string(&mut buffer) {
        Ok(_) => (),
        Err(e) => {
            let error = PluginError {
                cni_version: CNI_VERSION,
                code: 5,
                msg: format!("Unable to read network configuration from stdin: '{:?}'", e),
                details: None,
            };
            return Err(error);
        }
    }
    serde_json::from_str::<NetworkConfiguration>(&buffer).map_err(|e| PluginError {
        cni_version: CNI_VERSION,
        code: 6,
        msg: format!(
            "Unable to parse network configuration from stdin: '{:?}'",
            e
        ),
        details: None,
    })
}

enum CNICommand {
    Add,
    Delete,
    Check,
    Version,
}

impl std::convert::TryFrom<String> for CNICommand {
    type Error = PluginError;

    fn try_from(s: String) -> Result<CNICommand, Self::Error> {
        match s {
            s if s == "ADD" => Ok(CNICommand::Add),
            s if s == "DEL" => Ok(CNICommand::Delete),
            s if s == "CHECK" => Ok(CNICommand::Check),
            s if s == "VERSION" => Ok(CNICommand::Version),
            s => {
                let error = PluginError {
                    cni_version: CNI_VERSION,
                    code: 4,
                    msg: format!("Unrecognized `CNI_COMMAND`: '{}'", s),
                    details: None,
                };
                Err(error)
            }
        }
    }
}

fn run_invoke<P: Plugin>(plugin: P) -> Result<(), PluginError> {
    let cni_command: CNICommand = CNICommand::try_from(load_var("CNI_COMMAND")?)?;

    match cni_command {
        CNICommand::Add | CNICommand::Delete | CNICommand::Check => {
            let container_id = load_var("CNI_CONTAINERID")?;
            let network_namespace_path = load_var("CNI_NETNS")?;
            let interface_name = load_var("CNI_IFNAME")?;
            let args = load_args()?;
            let network_config = load_network_config()?;
            match cni_command {
                CNICommand::Add => plugin
                    .add(
                        &container_id,
                        &network_namespace_path,
                        network_config,
                        args,
                        &interface_name,
                    )
                    .map(|result| {
                        println!("{}", serde_json::to_string(&result).unwrap());
                    }),
                CNICommand::Delete => plugin.delete(
                    &container_id,
                    &network_namespace_path,
                    network_config,
                    args,
                    &interface_name,
                ),
                CNICommand::Check => plugin.check(
                    &container_id,
                    &network_namespace_path,
                    network_config,
                    args,
                    &interface_name,
                ),
                CNICommand::Version => unreachable!(),
            }
        }
        CNICommand::Version => {
            let result = plugin.version();
            println!("{}", serde_json::to_string(&result).unwrap());
            Ok(())
        }
    }
}

/// Invoke plugin using environment variables and stdin.
pub fn invoke<P: Plugin>(plugin: P) -> Result<(), PluginError> {
    match run_invoke(plugin) {
        Ok(()) => Ok(()),
        Err(error) => {
            println!("{}", serde_json::to_string(&error).unwrap());
            Err(error)
        }
    }
}
