//! Where the daemon is, and what to authenticate with.
//!
//! Resolved in order: flags, then `TORRENTCTL_URL` / `TORRENTCTL_TOKEN`, then
//! `$XDG_CONFIG_HOME/torrentctl/config.toml`. With no URL from any of them, the
//! daemon's unix socket at [`DEFAULT_SOCKET`] is preferred when it exists, and
//! [`DEFAULT_URL`] is the fallback. A URL may name a socket as `unix:/path`.
//! A token is read from a file only
//! when that file is private to its owner: a readable token file is a leaked
//! token, and refusing to use one is how the operator finds out. Private
//! means no group or other permission bit is set (`mode & 0o077 == 0`, so
//! `0600` and `0400` both pass); who owns the file is not checked. A relative
//! `token_file`, from the flag or the config file, is resolved against the
//! current directory, not the config file's. A token from any source must be
//! visible ASCII, and one that is not is refused at startup.

use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

/// The daemon's default `http_listen`.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8080";

/// The socket path `docs/running.md` §6 and `deploy/torrentd.sample.toml`
/// name for `http_listen = "unix:…"`, as a URL. Preferred over [`DEFAULT_URL`] when it
/// exists: a socket's permissions say who may connect, and nobody else can
/// take its path over while the daemon is down, as any local user can take
/// over a TCP port.
pub const DEFAULT_SOCKET: &str = "unix:/run/torrentd/api.sock";

/// The config file.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// The daemon's base URL, or `unix:/path` for its socket.
    pub url: Option<String>,
    /// A file holding a bearer token (`tdp_…`), with no group or other
    /// permission bits (`0600` or `0400`). A relative path is resolved
    /// against the current directory, not this file's.
    pub token_file: Option<PathBuf>,
}

/// What the flags and environment supplied.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub url: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub config: Option<PathBuf>,
}

/// The resolved configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub url: String,
    /// A static token, when one was given. Without one, the TUI signs in
    /// with the operator password and holds the session token in memory.
    pub token: Option<String>,
}

/// Why the configuration could not be resolved.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error(
        "{path} is readable by others (mode {mode:o}); a token file must be private: chmod 600 {path}"
    )]
    TokenFileNotPrivate { path: PathBuf, mode: u32 },
    #[error("{path} holds no token")]
    EmptyTokenFile { path: PathBuf },
    /// A token no `Authorization` header could carry as given. The token
    /// itself is never printed, only where it came from and where in it the
    /// first offending character is.
    #[error(
        "the token from {origin} is not valid: character {position} is not visible ASCII \
         (a token has no spaces, control or non-ASCII characters)"
    )]
    MalformedToken { origin: String, position: usize },
}

/// `token`, when every character is visible ASCII (`!` to `~`): the only
/// characters a bearer token is made of. Anything else would fail every
/// request before it is sent, which the UI could only show as a failed
/// request, over and over; refusing it here names the cause once.
fn checked_token(token: String, origin: impl FnOnce() -> String) -> Result<String, ConfigError> {
    match token.chars().position(|c| !c.is_ascii_graphic()) {
        Some(index) => Err(ConfigError::MalformedToken {
            origin: origin(),
            position: index + 1,
        }),
        None => Ok(token),
    }
}

/// The default config file path.
pub fn default_path() -> Option<PathBuf> {
    use etcetera::BaseStrategy as _;
    etcetera::choose_base_strategy()
        .ok()
        .map(|s| s.config_dir().join("torrentctl").join("config.toml"))
}

/// Resolve `overrides` against the environment and the config file.
pub fn resolve(overrides: Overrides) -> Result<Config, ConfigError> {
    let env_url = std::env::var("TORRENTCTL_URL")
        .ok()
        .filter(|v| !v.is_empty());
    let env_token = std::env::var("TORRENTCTL_TOKEN").ok();
    let file = read_file(overrides.config.as_deref(), default_path().as_deref())?;
    let default_socket = DEFAULT_SOCKET
        .strip_prefix(crate::api::UNIX_PREFIX)
        .is_some_and(|p| Path::new(p).exists());
    resolve_from(overrides, env_url, env_token, file, default_socket)
}

/// The config file: `explicit` must exist, since a path the operator named
/// and mistyped would otherwise fall back to the defaults unnoticed; only the
/// `default` path may be absent.
fn read_file(explicit: Option<&Path>, default: Option<&Path>) -> Result<File, ConfigError> {
    match (explicit, default) {
        (Some(path), _) => load(path),
        (None, Some(path)) if path.exists() => load(path),
        (None, _) => Ok(File::default()),
    }
}

fn load(path: &Path) -> Result<File, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ConfigError::Parse {
        path: path.to_owned(),
        source,
    })
}

fn resolve_from(
    overrides: Overrides,
    env_url: Option<String>,
    env_token: Option<String>,
    file: File,
    default_socket_exists: bool,
) -> Result<Config, ConfigError> {
    let url = overrides.url.or(env_url).or(file.url).unwrap_or_else(|| {
        if default_socket_exists {
            DEFAULT_SOCKET
        } else {
            DEFAULT_URL
        }
        .to_owned()
    });
    // Trimmed like a token file, so `TORRENTCTL_TOKEN=$(cat token)` and a
    // value pasted with a newline both work; blank is unset.
    let env_token = env_token
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty());
    let token = match (
        overrides.token,
        overrides.token_file,
        env_token,
        file.token_file,
    ) {
        (Some(t), _, _, _) => Some(checked_token(t, || "--token".to_owned())?),
        (None, Some(path), _, _) => Some(read_token_file(&path)?),
        (None, None, Some(t), _) => Some(checked_token(t, || "TORRENTCTL_TOKEN".to_owned())?),
        (None, None, None, Some(path)) => Some(read_token_file(&path)?),
        (None, None, None, None) => None,
    };
    Ok(Config {
        url: url.trim_end_matches('/').to_owned(),
        token,
    })
}

/// A token from `path`, which must be private to its owner: `mode & 0o077`
/// is zero. Its owner is not checked. The file is opened once and its mode
/// read from that handle, so what is checked is what is read. The trimmed
/// contents must be a visible-ASCII token.
pub fn read_token_file(path: &Path) -> Result<String, ConfigError> {
    use std::io::Read as _;
    let read_error = |source| ConfigError::Read {
        path: path.to_owned(),
        source,
    };
    let mut file = std::fs::File::open(path).map_err(read_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = file.metadata().map_err(read_error)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ConfigError::TokenFileNotPrivate {
                path: path.to_owned(),
                mode: mode & 0o777,
            });
        }
    }
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(read_error)?;
    let token = text.trim();
    if token.is_empty() {
        return Err(ConfigError::EmptyTokenFile {
            path: path.to_owned(),
        });
    }
    checked_token(token.to_owned(), || path.display().to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn token_file(dir: &Path, mode: u32, body: &str) -> PathBuf {
        let path = dir.join("token");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn flags_beat_the_environment_which_beats_the_file() {
        let file = File {
            url: Some("http://file:1".into()),
            token_file: None,
        };
        let cfg = resolve_from(
            Overrides {
                url: Some("http://flag:1/".into()),
                token: Some("tdp_flag".into()),
                ..Default::default()
            },
            Some("http://env:1".into()),
            Some("tdp_env".into()),
            file,
            true,
        )
        .unwrap();
        assert_eq!(cfg.url, "http://flag:1", "a trailing slash is trimmed");
        assert_eq!(cfg.token.as_deref(), Some("tdp_flag"));

        let cfg = resolve_from(
            Overrides::default(),
            Some("http://env:1".into()),
            Some("tdp_env".into()),
            File {
                url: Some("http://file:1".into()),
                token_file: None,
            },
            true,
        )
        .unwrap();
        assert_eq!(cfg.url, "http://env:1");
        assert_eq!(cfg.token.as_deref(), Some("tdp_env"));

        let cfg = resolve_from(Overrides::default(), None, None, File::default(), false).unwrap();
        assert_eq!(cfg.url, DEFAULT_URL);
        assert_eq!(cfg.token, None, "no token means a password sign-in");
    }

    #[test]
    fn the_daemon_socket_is_preferred_over_the_tcp_default_but_not_over_a_stated_url() {
        let cfg = resolve_from(Overrides::default(), None, None, File::default(), true).unwrap();
        assert_eq!(cfg.url, DEFAULT_SOCKET);

        let file = File {
            url: Some("http://file:1".into()),
            token_file: None,
        };
        let cfg = resolve_from(Overrides::default(), None, None, file, true).unwrap();
        assert_eq!(
            cfg.url, "http://file:1",
            "a configured URL wins over the socket"
        );

        let file = File {
            url: Some("unix:/srv/torrentd/api.sock".into()),
            token_file: None,
        };
        let cfg = resolve_from(Overrides::default(), None, None, file, false).unwrap();
        assert_eq!(cfg.url, "unix:/srv/torrentd/api.sock");
    }

    #[test]
    fn a_token_file_is_used_only_when_private() {
        let dir = tempfile::tempdir().unwrap();
        let private = token_file(dir.path(), 0o600, "tdp_secret\n");
        assert_eq!(read_token_file(&private).unwrap(), "tdp_secret");

        for mode in [0o644, 0o640, 0o604] {
            let shared = token_file(dir.path(), mode, "tdp_secret");
            let err = read_token_file(&shared).unwrap_err();
            assert!(
                matches!(err, ConfigError::TokenFileNotPrivate { .. }),
                "{mode:o}: {err}"
            );
            assert!(err.to_string().contains("chmod 600"));
        }

        let empty = token_file(dir.path(), 0o600, "  \n");
        assert!(matches!(
            read_token_file(&empty).unwrap_err(),
            ConfigError::EmptyTokenFile { .. }
        ));
    }

    #[test]
    fn a_token_that_is_not_visible_ascii_is_refused_naming_where_it_came_from() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["tdp_a b", "tdp_a\u{1}b", "tdp_\u{e9}t\u{e9}", "tdp_a\u{7f}"] {
            let path = token_file(dir.path(), 0o600, &format!("{bad}\n"));
            let err = read_token_file(&path).unwrap_err();
            assert!(
                matches!(&err, ConfigError::MalformedToken { origin, .. }
                    if *origin == path.display().to_string()),
                "{bad:?}: {err}"
            );
            assert!(!err.to_string().contains(bad), "the token never prints");

            let err = resolve_from(
                Overrides::default(),
                None,
                Some(bad.into()),
                File::default(),
                false,
            )
            .unwrap_err();
            assert!(
                matches!(&err, ConfigError::MalformedToken { origin, .. }
                    if origin == "TORRENTCTL_TOKEN"),
                "{bad:?}: {err}"
            );

            let err = resolve_from(
                Overrides {
                    token: Some(bad.into()),
                    ..Default::default()
                },
                None,
                None,
                File::default(),
                false,
            )
            .unwrap_err();
            assert!(
                matches!(&err, ConfigError::MalformedToken { origin, .. } if origin == "--token"),
                "{bad:?}: {err}"
            );
        }
        let err = resolve_from(
            Overrides::default(),
            None,
            Some("tdp_a\u{1}b".into()),
            File::default(),
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("character 6"),
            "the offending position is named: {err}"
        );
    }

    #[test]
    fn the_environment_token_is_trimmed_and_blank_is_unset() {
        let cfg = resolve_from(
            Overrides::default(),
            None,
            Some(" tdp_env\n".into()),
            File::default(),
            false,
        )
        .unwrap();
        assert_eq!(cfg.token.as_deref(), Some("tdp_env"));

        let cfg = resolve_from(
            Overrides::default(),
            None,
            Some(" \n".into()),
            File::default(),
            false,
        )
        .unwrap();
        assert_eq!(cfg.token, None, "a blank variable is no token");
    }

    #[test]
    fn an_explicit_config_path_that_does_not_exist_is_an_error_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("typo.toml");
        let err = resolve(Overrides {
            config: Some(missing.clone()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            matches!(&err, ConfigError::Read { path, source }
                if path == &missing && source.kind() == std::io::ErrorKind::NotFound),
            "{err}"
        );
        assert!(err.to_string().contains(&*missing.to_string_lossy()));

        let present = dir.path().join("config.toml");
        std::fs::write(&present, "not toml").unwrap();
        let err = resolve(Overrides {
            config: Some(present.clone()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            matches!(&err, ConfigError::Parse { path, .. } if path == &present),
            "an existing explicit file is still read: {err}"
        );
    }

    #[test]
    fn only_the_default_config_path_may_be_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("config.toml");
        assert_eq!(read_file(None, Some(&missing)).unwrap(), File::default());
        assert_eq!(read_file(None, None).unwrap(), File::default());
        assert!(matches!(
            read_file(Some(&missing), None).unwrap_err(),
            ConfigError::Read { .. }
        ));

        let present = dir.path().join("present.toml");
        std::fs::write(&present, "url = 'http://file:1'").unwrap();
        let file = read_file(None, Some(&present)).unwrap();
        assert_eq!(file.url.as_deref(), Some("http://file:1"));
        let file = read_file(Some(&present), Some(&missing)).unwrap();
        assert_eq!(
            file.url.as_deref(),
            Some("http://file:1"),
            "an explicit path replaces the default"
        );
    }

    #[test]
    fn the_config_file_refuses_unknown_keys() {
        let err = toml::from_str::<File>("url = 'http://x'\ntoken = 'no'").unwrap_err();
        assert!(
            err.to_string().contains("unknown field `token`"),
            "refused for the unknown key, not anything else: {err}"
        );
        let file: File = toml::from_str("url = 'http://x'\ntoken_file = '/t'").unwrap();
        assert_eq!(file.token_file.as_deref(), Some(Path::new("/t")));
    }
}
