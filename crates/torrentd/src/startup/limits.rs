//! The open-file budget: every descriptor the daemon may hold at once,
//! against `RLIMIT_NOFILE`.

use tracing::warn;

use super::http_stage::HTTP_MAX_CONNECTIONS;
use crate::config::Config;

/// Every descriptor the daemon may hold at once, against `RLIMIT_NOFILE`.
///
/// Each session may open `connections_limit` peer sockets and keep
/// `file_pool_size` payload files open, and the API accepts up to
/// [`HTTP_MAX_CONNECTIONS`]; each session and the process itself hold more
/// beside those ([`descriptors_needed`]). A soft limit below the sum is a
/// daemon that seeds until the pool grows and then fails `accept` and `open`
/// with `EMFILE` — in
/// libtorrent's logs, as disk and peer errors, far from the cause. The values
/// are the effective ones: `Settings::server_seed_overrides` sets both, and
/// the config's keys override that.
///
/// Boot warns and carries on, since the limit is the unit file's and the
/// daemon cannot raise it. A reload holds `connections_limit` to the same
/// sum and refuses a raise past the limit (`reload::refuse_short_descriptors`).
pub(super) fn warn_if_descriptors_are_short(cfg: &Config) {
    let need = descriptors_needed(cfg);
    match nofile_soft_limit() {
        Some(limit) if limit < need => warn!(
            rlimit_nofile = limit,
            needed = need,
            "the open-file limit is below what the daemon may hold at once \
             (connections_limit + file_pool_size per profile, plus the HTTP \
             connection cap and an allowance for the sessions and the process \
             themselves); raise LimitNOFILE or lower those keys, or peers, \
             payload files and API clients will fail with EMFILE under load",
        ),
        Some(_) => {}
        None => warn!("could not read RLIMIT_NOFILE; the open-file limit is unchecked"),
    }
}

/// `connections_limit + file_pool_size` and [`DESCRIPTORS_PER_SESSION`] per
/// configured profile, plus the HTTP connection cap and
/// [`DESCRIPTORS_FOR_THE_PROCESS`].
pub(crate) fn descriptors_needed(cfg: &Config) -> u64 {
    let s = cfg.libtorrent_settings();
    let per_session = u64::from(s.connections_limit.unwrap_or_default())
        + u64::from(s.file_pool_size.unwrap_or_default())
        + DESCRIPTORS_PER_SESSION;
    per_session * cfg.profile.len() as u64 + http_connection_cap() + DESCRIPTORS_FOR_THE_PROCESS
}

/// What a session holds beside its peers and payload files: its listen
/// sockets (TCP and uTP, per address), DHT, the trackers and port mappings
/// it is talking to, the `.torrent` and resume files being written, its
/// reactor's own descriptors, and a tunnel's helper (an OpenVPN process's
/// pipes and management socket).
const DESCRIPTORS_PER_SESSION: u64 = 32;

/// What the process holds whatever its configuration: stdio, the log and
/// journal, `pool.db` with its WAL and shared-memory files and a reader, the
/// API listener, the runtime's reactor, signal and timer descriptors, the
/// instance lock, and the pipes of the `nft` and `ip` commands it runs.
const DESCRIPTORS_FOR_THE_PROCESS: u64 = 64;

/// [`HTTP_MAX_CONNECTIONS`] as a descriptor count.
fn http_connection_cap() -> u64 {
    u64::try_from(HTTP_MAX_CONNECTIONS.get()).unwrap_or(u64::MAX)
}

/// The soft `RLIMIT_NOFILE`, or `None` if it cannot be read.
pub(crate) fn nofile_soft_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable `rlimit` for the whole call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    (rc == 0).then_some(lim.rlim_cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile_registry::ProfileStatus;

    #[test]
    fn the_descriptor_budget_counts_every_session_and_the_api() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::minimal_for_tests(dir.path(), false);
        cfg.connections_limit = Some(1_000);
        cfg.file_pool_size = Some(100);
        cfg.profile = vec![
            crate::profile_registry::test_entry("a", ProfileStatus::Active).config,
            crate::profile_registry::test_entry("b", ProfileStatus::Active).config,
        ];
        assert_eq!(
            descriptors_needed(&cfg),
            2 * (1_100 + DESCRIPTORS_PER_SESSION) + 256 + DESCRIPTORS_FOR_THE_PROCESS,
            "the database, subprocess pipes, logs and listeners count too",
        );
        // And the shipped unit's LimitNOFILE covers a one-profile default.
        cfg.connections_limit = None;
        cfg.file_pool_size = None;
        cfg.profile.truncate(1);
        assert!(descriptors_needed(&cfg) <= 65_536);
        assert!(nofile_soft_limit().is_some_and(|n| n > 0));
    }
}
