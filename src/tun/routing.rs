//! Namespace-bound ownership of a TUN's routing resources.

use super::error::{context, invalid};
use super::{Routing, TunConfig};
use crate::netlink::{MAIN_TABLE, Netlink, Rule};
use crate::path::lock;
use std::io;
use std::sync::Mutex;

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(invalid(format!(
            "interface name {name:?} must have 1 to 15 bytes"
        )));
    }
    if !name
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        return Err(invalid(format!(
            "interface name {name:?} has characters other than letters, digits, _ and -"
        )));
    }
    Ok(())
}

fn validate_table(table: u32) -> io::Result<()> {
    // Unspecified, default, main and local.
    if table == 0 || (253..=255).contains(&table) {
        return Err(invalid(format!("routing table {table} is reserved")));
    }
    Ok(())
}

pub(super) fn validate(config: &TunConfig) -> io::Result<()> {
    validate_name(&config.name)?;
    match &config.routing {
        Routing::UePolicy {
            table, priority, ..
        } => {
            validate_table(*table)?;
            if !(1..32766).contains(priority) {
                return Err(invalid(format!(
                    "rule priority {priority} is outside 1..=32765"
                )));
            }
        }
        Routing::UeVrf {
            table, vrf_name, ..
        } => {
            validate_table(*table)?;
            validate_name(vrf_name)?;
        }
        Routing::Upf { .. } => {}
    }
    Ok(())
}

pub(super) struct RoutingLease {
    name: String,
    cleanup: Mutex<Cleanup>,
}

/// What `close` removes. The TUN's address and routes go with it.
struct Cleanup {
    // A netlink socket remains in its creation namespace even when the
    // port moves to a task running in another namespace.
    netlink: Netlink,
    index: Option<u32>,
    rule: Option<Rule>,
    vrf: Option<(u32, String)>,
}

fn remove_link(netlink: &mut Netlink, index: u32, name: &str) -> io::Result<()> {
    // An externally removed interface can leave its index to another one.
    if netlink.name_of(index)?.as_deref() != Some(name) {
        return Ok(());
    }
    match netlink.delete_link(index) {
        Err(error) if error.raw_os_error() == Some(libc::ENODEV) => Ok(()),
        result => result,
    }
}

impl RoutingLease {
    pub(super) fn create(
        name: String,
        netlink: Netlink,
        index: u32,
        routing: Routing,
    ) -> io::Result<Self> {
        let lease = Self {
            name,
            cleanup: Mutex::new(Cleanup {
                netlink,
                index: Some(index),
                rule: None,
                vrf: None,
            }),
        };
        lease.configure(routing)?;
        Ok(lease)
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    fn configure(&self, routing: Routing) -> io::Result<()> {
        let mut cleanup = lock(&self.cleanup);
        let Cleanup {
            netlink,
            index,
            rule: saved_rule,
            vrf: saved_vrf,
        } = &mut *cleanup;
        let index = index.expect("new TUN has an interface index");
        let name = &self.name;
        // The routing is IPv4 only. Without IPv6 addresses, Linux sends no
        // router solicitations through the TUN. A kernel without IPv6 has
        // none to disable.
        match netlink.disable_ipv6_addresses(index) {
            Err(error)
                if !matches!(
                    error.raw_os_error(),
                    Some(libc::EAFNOSUPPORT | libc::EOPNOTSUPP)
                ) =>
            {
                return Err(context(
                    error,
                    format_args!("disable IPv6 addresses on {name}"),
                ));
            }
            _ => {}
        }
        match routing {
            Routing::UePolicy {
                address,
                table,
                priority,
            } => {
                netlink
                    .add_address(index, address)
                    .map_err(|e| context(e, format_args!("add {address}/32 to {name}")))?;
                netlink
                    .set_up(index)
                    .map_err(|e| context(e, format_args!("set {name} up")))?;
                netlink.add_route(None, index, table).map_err(|e| {
                    context(
                        e,
                        format_args!("add default route via {name} to table {table}"),
                    )
                })?;
                let rule = Rule {
                    source: address,
                    table,
                    priority,
                };
                netlink.add_rule(rule).map_err(|e| {
                    context(
                        e,
                        format_args!("add rule {priority}: from {address} lookup {table}"),
                    )
                })?;
                *saved_rule = Some(rule);
            }
            Routing::UeVrf {
                address,
                table,
                vrf_name,
            } => {
                let vrf = netlink.add_vrf(&vrf_name, table).map_err(|e| {
                    context(e, format_args!("add VRF {vrf_name} for table {table}"))
                })?;
                *saved_vrf = Some((vrf, vrf_name.clone()));
                netlink
                    .set_controller(index, vrf)
                    .map_err(|e| context(e, format_args!("put {name} in VRF {vrf_name}")))?;
                netlink
                    .add_address(index, address)
                    .map_err(|e| context(e, format_args!("add {address}/32 to {name}")))?;
                netlink
                    .set_up(index)
                    .map_err(|e| context(e, format_args!("set {name} up")))?;
                netlink
                    .set_up(vrf)
                    .map_err(|e| context(e, format_args!("set {vrf_name} up")))?;
                netlink.add_route(None, index, table).map_err(|e| {
                    context(
                        e,
                        format_args!("add default route via {name} to table {table}"),
                    )
                })?;
            }
            Routing::Upf { ue_address } => {
                netlink
                    .set_up(index)
                    .map_err(|e| context(e, format_args!("set {name} up")))?;
                netlink
                    .add_route(Some(ue_address), index, MAIN_TABLE)
                    .map_err(|e| {
                        context(e, format_args!("add route {ue_address}/32 via {name}"))
                    })?;
            }
        }
        Ok(())
    }

    pub(super) fn try_close(&self) -> io::Result<()> {
        let mut cleanup = lock(&self.cleanup);
        let Cleanup {
            netlink,
            index,
            rule,
            vrf,
        } = &mut *cleanup;
        let mut failure = None;
        if let Some(value) = *rule {
            match netlink.delete_rule(value) {
                Ok(()) => *rule = None,
                Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                    *rule = None
                }
                Err(error) => {
                    failure = Some(context(
                        error,
                        format_args!("remove rule of TUN {}", self.name),
                    ))
                }
            }
        }
        if let Some(value) = *index {
            match remove_link(netlink, value, &self.name) {
                Ok(()) => *index = None,
                Err(error) => {
                    failure.get_or_insert_with(|| {
                        context(error, format_args!("remove TUN {}", self.name))
                    });
                }
            }
        }
        if let Some((value, name)) = vrf {
            match remove_link(netlink, *value, name) {
                Ok(()) => *vrf = None,
                Err(error) => {
                    failure.get_or_insert_with(|| {
                        context(error, format_args!("remove VRF of TUN {}", self.name))
                    });
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Perform best-effort cleanup, logging any failure. Later calls
    /// retry remaining resources; use [`try_close`](Self::try_close) to
    /// inspect failures.
    pub(super) fn close(&self) {
        if let Err(error) = self.try_close() {
            tracing::warn!("{error}");
        }
    }
}

impl Drop for RoutingLease {
    fn drop(&mut self) {
        self.close();
    }
}
