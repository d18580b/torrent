//! torrentctl on a host with no CA certificates.
//!
//! Its own test binary: `SSL_CERT_FILE` and `SSL_CERT_DIR` replace the system
//! store for every client built after they are set, and are process-wide, so
//! no other test may share the process.

use torrentctl::api::Api;

#[test]
fn only_https_needs_ca_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    // An empty bundle and no directory: the store a host without
    // ca-certificates has. `cargo test` itself exports SSL_CERT_DIR (cargo
    // probes for OpenSSL's certificates), so it has to go too. Nothing else
    // runs in this process, and no thread reads the environment meanwhile.
    std::env::set_var("SSL_CERT_FILE", &empty);
    std::env::remove_var("SSL_CERT_DIR");

    // Plain HTTP and the unix socket never reach TLS, so they build with no
    // trust anchors at all.
    for url in [
        "http://127.0.0.1:8080",
        "HTTP://127.0.0.1:8080",
        "unix:/run/torrentd/api.sock",
    ] {
        assert!(
            Api::new(url, None).is_ok(),
            "{url} needs no CA certificates"
        );
    }

    // A URL that is neither is refused as such, not as missing certificates.
    let err = Api::new("localhost:8080", None).unwrap_err();
    assert!(err.starts_with("invalid daemon URL"), "got {err}");

    // https does, and says what to do about it.
    let err = Api::new("https://torrentd.example", None).unwrap_err();
    assert!(err.contains("No CA certificates"), "got {err}");
    assert!(err.contains("SSL_CERT_FILE"), "got {err}");
    assert!(err.contains("ca-certificates"), "got {err}");
}
