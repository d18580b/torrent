//! Where the daemon is, and what to authenticate with.
//!
//! Resolved in order: flags, then `TORRENTCTL_URL` / `TORRENTCTL_TOKEN`, then
//! `$XDG_CONFIG_HOME/torrentctl/config.toml`. A token is read from a file only
//! when that file is private to its owner: a readable token file is a leaked
//! token, and refusing to use one is how the operator finds out.

use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;

/// The daemon's default `http_listen`.
pub const DEFAULT_URL: &str = "http://127.0.0.1:8080";

/// The config file.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// The daemon's base URL.
    pub url: Option<String>,
    /// A file holding a bearer token (`tdp_…`), mode `0600`.
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
    let env_token = std::env::var("TORRENTCTL_TOKEN")
        .ok()
        .filter(|v| !v.is_empty());
    let path = overrides.config.clone().or_else(default_path);
    let file = match &path {
        Some(p) if p.exists() => load(p)?,
        _ => File::default(),
    };
    resolve_from(overrides, env_url, env_token, file)
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
) -> Result<Config, ConfigError> {
    let url = overrides
        .url
        .or(env_url)
        .or(file.url)
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let token = match (
        overrides.token,
        overrides.token_file,
        env_token,
        file.token_file,
    ) {
        (Some(t), _, _, _) => Some(t),
        (None, Some(path), _, _) => Some(read_token_file(&path)?),
        (None, None, Some(t), _) => Some(t),
        (None, None, None, Some(path)) => Some(read_token_file(&path)?),
        (None, None, None, None) => None,
    };
    Ok(Config {
        url: url.trim_end_matches('/').to_owned(),
        token,
    })
}

/// A token from `path`, which must be private to its owner. The file is
/// opened once and its mode read from that handle, so what is checked is
/// what is read.
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
    Ok(token.to_owned())
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
        )
        .unwrap();
        assert_eq!(cfg.url, "http://env:1");
        assert_eq!(cfg.token.as_deref(), Some("tdp_env"));

        let cfg = resolve_from(Overrides::default(), None, None, File::default()).unwrap();
        assert_eq!(cfg.url, DEFAULT_URL);
        assert_eq!(cfg.token, None, "no token means a password sign-in");
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
    fn the_config_file_refuses_unknown_keys() {
        assert!(toml::from_str::<File>("url = 'http://x'\ntoken = 'no'").is_err());
        let file: File = toml::from_str("url = 'http://x'\ntoken_file = '/t'").unwrap();
        assert_eq!(file.token_file.as_deref(), Some(Path::new("/t")));
    }
}
