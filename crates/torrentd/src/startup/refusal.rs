//! Boot failures that are the configuration's, which `main` exits
//! `EX_CONFIG` for, and the locks whose refusal is one.

use anyhow::Context;

/// Marks a boot failure as the configuration's: `main` exits `EX_CONFIG` (78)
/// for it, which the unit's `RestartPreventExitStatus=78` does not restart,
/// rather than 70, which it does. Only for what no restart can change — a
/// tunnel that failed to come up is not one.
#[derive(Debug)]
pub struct ConfigRefused;

impl std::fmt::Display for ConfigRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the configuration is refused")
    }
}

/// Wrap `e` as a [`ConfigRefused`].
pub(super) fn refused(e: anyhow::Error) -> anyhow::Error {
    e.context(ConfigRefused)
}

/// The kill switch's refusal of `uid`, as a [`ConfigRefused`]: the
/// pre-flight `main` runs before `boot` makes it, so a daemon running as root
/// exits 78 before any tunnel is raised rather than 70 after every one is.
pub fn kill_switch_uid_refusal(uid: u32) -> Option<anyhow::Error> {
    crate::vpn::killswitch::refusal_for_uid(uid).map(|e| refused(e.into()))
}

/// The error a failed [`crate::vpn::killswitch::enable`] fails the boot with:
/// its uid refusal is the configuration's, and anything else (an `nft`
/// failure, a tunnel address that could not be read) is not.
pub(super) fn kill_switch_enable_failure(e: std::io::Error) -> anyhow::Error {
    let refusal = crate::vpn::killswitch::is_uid_refusal(&e);
    let e = anyhow::Error::new(e);
    let e = if refusal { refused(e) } else { e };
    e.context("install nftables kill switch (network_kill_switch=true)")
}

/// Whether a boot failure is a [`ConfigRefused`].
pub fn is_config_refusal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ConfigRefused>().is_some()
}

/// Take this uid's [`crate::vpn::killswitch::TableLock`]. Its refusal is a
/// [`ConfigRefused`]: two daemons under one uid is a deployment no restart
/// fixes, and exiting 78 keeps the unit from restarting into it every five
/// seconds. Any other failure, an unreadable uid included, is not.
pub(super) fn acquire_table_lock() -> anyhow::Result<crate::vpn::killswitch::TableLock> {
    let uid = crate::vpn::killswitch::current_uid()
        .context("read this process's uid for the kill-switch table lock")?;
    crate::vpn::killswitch::TableLock::acquire(uid).map_err(table_lock_failure)
}

/// The error a failed [`crate::vpn::killswitch::TableLock::acquire`] fails
/// the boot with: see [`acquire_table_lock`].
fn table_lock_failure(e: std::io::Error) -> anyhow::Error {
    let held = e.kind() == std::io::ErrorKind::AddrInUse;
    let e = anyhow::Error::new(e);
    let e = if held { refused(e) } else { e };
    e.context("take the kill-switch table lock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::test_support::failed;

    #[test]
    fn a_config_refusal_is_told_apart_from_other_boot_failures() {
        let e = refused(anyhow::anyhow!("host profile beside network_kill_switch"));
        assert!(is_config_refusal(&e));
        assert!(
            is_config_refusal(&e.context("boot")),
            "survives more context"
        );
        assert!(format!("{:#}", refused(anyhow::anyhow!("why"))).ends_with(": why"));
        assert!(!is_config_refusal(&anyhow::anyhow!("no profile came up")));
    }

    #[test]
    fn the_kill_switch_s_root_refusal_is_the_configuration_s_and_an_nft_failure_is_not() {
        // As root the kill switch is refused whatever the host does, so a
        // restart only raises every tunnel again to be refused again: it
        // exits 78, which the unit does not restart. An `nft` failure might
        // pass on the next try, so it keeps exiting 70.
        assert!(kill_switch_uid_refusal(1000).is_none());
        let pre_flight = kill_switch_uid_refusal(0).expect("uid 0 is refused");
        assert!(is_config_refusal(&pre_flight));
        assert!(format!("{pre_flight:#}").contains("non-root user"));

        let enable = crate::vpn::killswitch::refusal_for_uid(0).unwrap();
        let e = kill_switch_enable_failure(enable);
        assert!(is_config_refusal(&e), "got: {e:#}");
        assert!(format!("{e:#}").contains("install nftables kill switch"));

        let e = kill_switch_enable_failure(failed().unwrap_err());
        assert!(!is_config_refusal(&e), "got: {e:#}");
    }

    /// A table lock another daemon of this uid holds exits 78, which the
    /// unit does not restart, naming the holder; a socket that could not be
    /// bound for any other reason keeps exiting 70.
    #[test]
    fn a_held_table_lock_is_the_configuration_s_refusal_and_another_failure_is_not() {
        let name = format!("torrentd_ks_test_{}_boot", std::process::id());
        let _held = crate::vpn::killswitch::TableLock::acquire_named(&name).unwrap();
        let refusal = crate::vpn::killswitch::TableLock::acquire_named(&name).unwrap_err();
        let e = table_lock_failure(refusal);
        assert!(is_config_refusal(&e), "got: {e:#}");
        let msg = format!("{e:#}");
        assert!(
            msg.contains("take the kill-switch table lock"),
            "got: {msg}"
        );
        assert!(
            msg.contains(&format!("(pid {})", std::process::id())),
            "got: {msg}"
        );

        let other = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no");
        assert!(!is_config_refusal(&table_lock_failure(other)));
    }
}
