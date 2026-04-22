//! Tests that the TLS configuration plumbing on `S3ClientConfig` reaches the underlying CRT
//! bootstrap cleanly. These tests do not perform network I/O; they only exercise client
//! construction.

use std::path::PathBuf;

use mountpoint_s3_client::S3CrtClient;
use mountpoint_s3_client::config::{S3ClientConfig, TlsConfig};

#[test]
fn empty_tls_config_constructs() {
    let config = S3ClientConfig::new().tls_config(TlsConfig::default());
    S3CrtClient::new(config).expect("empty TlsConfig should be equivalent to the default");
}

#[test]
fn missing_ca_bundle_fails_cleanly() {
    let config = S3ClientConfig::new().tls_config(TlsConfig {
        ca_bundle: Some(PathBuf::from("/nonexistent/mountpoint-s3-test/ca.pem")),
        ..Default::default()
    });
    let err = S3CrtClient::new(config).expect_err("missing CA bundle should fail at client construction");
    // The exact CRT error code is backend-specific; we only require that a failure is reported.
    let msg = err.to_string();
    assert!(!msg.is_empty(), "expected a non-empty error message, got {msg:?}");
}

#[test]
fn mismatched_client_cert_without_key_fails() {
    let config = S3ClientConfig::new().tls_config(TlsConfig {
        client_cert: Some(PathBuf::from("/tmp/does-not-matter.pem")),
        client_key: None,
        ..Default::default()
    });
    let err = S3CrtClient::new(config).expect_err("client_cert without client_key should fail");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("client_cert") || msg.contains("client_key") || msg.contains("invalid configuration"),
        "expected configuration error, got: {msg}"
    );
}
