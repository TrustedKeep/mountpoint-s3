//! TLS context configuration, including custom trust stores and mutual TLS (mTLS) client certs.
//!
//! The CRT's S3 client takes per-connection TLS settings via [`TlsConnectionOptions`], which is
//! derived from a [`TlsContext`]. The typical flow:
//!
//! 1. Build a [`TlsContextOptions`] and configure it — optionally pointing at a custom CA bundle
//!    and/or a client cert/key pair.
//! 2. Hand it to [`TlsContext::new_client`] to obtain a reference-counted [`TlsContext`].
//! 3. Derive a [`TlsConnectionOptions`] from the context via
//!    [`TlsConnectionOptions::new_from_ctx`], and pass that to the consumer (e.g.
//!    [`mountpoint_s3_crt::s3::client::ClientConfig::tls_connection_options`](super::super::s3::client::ClientConfig::tls_connection_options)).
//!
//! PEM-based client mTLS (`aws_tls_ctx_options_init_client_mtls_from_path`) is implemented by the
//! s2n-tls backend and is Linux-only. Overriding the default trust store works on every platform.

use crate::CrtError as _;
use crate::common::allocator::Allocator;
use crate::common::error::Error;
use mountpoint_s3_crt_sys::*;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::NonNull;

/// Builder for a [`TlsContext`]. Drop this after calling [`TlsContext::new_client`].
///
/// The underlying `aws_tls_ctx_options` stores the allocator pointer it was initialized with, so
/// clean-up does not require re-supplying an allocator. For methods that do (currently only
/// [`TlsContextOptions::set_client_mtls_from_path`]), pass the same allocator the options were
/// initialized with.
#[derive(Debug)]
pub struct TlsContextOptions {
    inner: aws_tls_ctx_options,
}

fn path_to_cstring(path: &Path) -> Result<CString, Error> {
    // A nul byte in a Unix path would be extremely unusual; render as "unknown error" if hit.
    CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::from(-1))
}

impl TlsContextOptions {
    /// Create a new options struct initialized for a default client TLS context.
    pub fn new_default_client(allocator: &Allocator) -> Self {
        let mut inner: aws_tls_ctx_options = Default::default();
        // SAFETY: init_default_client initializes the options struct in place with the given
        // allocator. It is infallible (void return). The options struct stores the allocator
        // pointer internally; the caller must ensure the allocator (typically the CRT default,
        // which is a static global) outlives this options struct.
        unsafe {
            aws_tls_ctx_options_init_default_client(&mut inner, allocator.inner.as_ptr());
        }
        Self { inner }
    }

    /// Override the default trust store with a custom CA bundle on disk.
    ///
    /// At least one of `ca_dir` (a directory of hashed CA certificates) or `ca_file`
    /// (a PEM bundle) must be provided. For the typical CLI case, pass `(None, Some(bundle))`.
    pub fn override_default_trust_store_from_path(
        &mut self,
        ca_dir: Option<&Path>,
        ca_file: Option<&Path>,
    ) -> Result<(), Error> {
        let ca_dir_cstr = ca_dir.map(path_to_cstring).transpose()?;
        let ca_file_cstr = ca_file.map(path_to_cstring).transpose()?;
        let ca_dir_ptr = ca_dir_cstr.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        let ca_file_ptr = ca_file_cstr.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
        // SAFETY: the options struct is valid, and the C function reads and copies the certificate
        // file contents before returning, so the CStrings only need to live for the call.
        unsafe {
            aws_tls_ctx_options_override_default_trust_store_from_path(&mut self.inner, ca_dir_ptr, ca_file_ptr)
                .ok_or_last_error()
        }
    }

    /// Configure the client certificate and private key used for mutual TLS authentication.
    ///
    /// Both files must be PEM-encoded. This is implemented by the s2n-tls backend and is
    /// Linux-only. On other platforms this method is unavailable.
    ///
    /// **Ordering note:** the underlying `aws_tls_ctx_options_init_client_mtls_from_path`
    /// re-initializes the options struct from scratch, discarding any state already set on it
    /// (notably any CA override from [`Self::override_default_trust_store_from_path`]). Callers
    /// mixing both should invoke this method first and apply the CA override afterwards.
    #[cfg(target_os = "linux")]
    pub fn set_client_mtls_from_path(
        &mut self,
        allocator: &Allocator,
        cert_path: &Path,
        pkey_path: &Path,
    ) -> Result<(), Error> {
        let cert_cstr = path_to_cstring(cert_path)?;
        let pkey_cstr = path_to_cstring(pkey_path)?;
        // SAFETY: the options struct is valid, and the C function reads and copies the PEM file
        // contents before returning, so the CStrings only need to live for the call.
        unsafe {
            aws_tls_ctx_options_init_client_mtls_from_path(
                &mut self.inner,
                allocator.inner.as_ptr(),
                cert_cstr.as_ptr(),
                pkey_cstr.as_ptr(),
            )
            .ok_or_last_error()
        }
    }
}

impl Drop for TlsContextOptions {
    fn drop(&mut self) {
        // SAFETY: self.inner was initialized via `aws_tls_ctx_options_init_default_client`, which
        // populates the allocator pointer used by clean_up.
        unsafe {
            aws_tls_ctx_options_clean_up(&mut self.inner);
        }
    }
}

/// A reference-counted TLS context. Cheap to [`Clone`].
#[derive(Debug)]
pub struct TlsContext {
    pub(crate) inner: NonNull<aws_tls_ctx>,
}

impl TlsContext {
    /// Construct a client-side TLS context from the given options.
    ///
    /// The CRT copies everything it needs out of `options`; the options struct is dropped at the
    /// end of this call.
    pub fn new_client(allocator: &Allocator, options: TlsContextOptions) -> Result<Self, Error> {
        // SAFETY: `allocator` and `options.inner` are both valid. The CRT may read from the options
        // struct and allocate a new aws_tls_ctx, returning null on failure.
        let inner =
            unsafe { aws_tls_client_ctx_new(allocator.inner.as_ptr(), &options.inner).ok_or_last_error()? };
        Ok(Self { inner })
    }
}

impl Clone for TlsContext {
    fn clone(&self) -> Self {
        // SAFETY: self.inner is a valid aws_tls_ctx. aws_tls_ctx_acquire increments the refcount
        // and returns the same (non-null) pointer.
        let inner = unsafe { NonNull::new_unchecked(aws_tls_ctx_acquire(self.inner.as_ptr())) };
        Self { inner }
    }
}

impl Drop for TlsContext {
    fn drop(&mut self) {
        // SAFETY: self.inner is a valid aws_tls_ctx, and we're dropping one of our references.
        unsafe {
            aws_tls_ctx_release(self.inner.as_ptr());
        }
    }
}

// SAFETY: `aws_tls_ctx` is reference counted and its methods are thread-safe.
unsafe impl Send for TlsContext {}
// SAFETY: `aws_tls_ctx` is reference counted and its methods are thread-safe.
unsafe impl Sync for TlsContext {}

/// Per-connection TLS options derived from a [`TlsContext`]. The CRT's HTTP/S3 clients consume
/// these for each outbound connection they make. The options hold an owning reference to the
/// underlying TLS context, so the context need not be kept alive separately.
///
/// The struct exposes a raw pointer via [`TlsConnectionOptions::as_ptr`] so a consumer
/// (typically [`mountpoint_s3_crt::s3::client::ClientConfig`]) can set it on a CRT config. The
/// consumer is responsible for ensuring the `TlsConnectionOptions` outlives any struct that
/// borrows the pointer.
#[derive(Debug)]
pub struct TlsConnectionOptions {
    inner: aws_tls_connection_options,
}

impl TlsConnectionOptions {
    /// Create a per-connection options struct from a [`TlsContext`].
    pub fn new_from_ctx(ctx: &TlsContext) -> Self {
        let mut inner: aws_tls_connection_options = Default::default();
        // SAFETY: init_from_ctx populates the options struct in place and acquires its own
        // reference on the aws_tls_ctx; it does not retain a pointer to `ctx` itself, so our
        // Rust handle can drop independently.
        unsafe {
            aws_tls_connection_options_init_from_ctx(&mut inner, ctx.inner.as_ptr());
        }
        Self { inner }
    }

    /// Raw pointer to the inner struct for passing to CRT APIs that take a
    /// `const struct aws_tls_connection_options *`.
    pub(crate) fn as_ptr(&self) -> *const aws_tls_connection_options {
        &self.inner
    }
}

impl Drop for TlsConnectionOptions {
    fn drop(&mut self) {
        // SAFETY: self.inner was initialized via `aws_tls_connection_options_init_from_ctx`, so
        // clean_up is valid here. It releases the reference on the underlying aws_tls_ctx.
        unsafe {
            aws_tls_connection_options_clean_up(&mut self.inner);
        }
    }
}

// SAFETY: `aws_tls_connection_options` is an opaque-to-us plain-data container that holds an
// acquired refcount on an `aws_tls_ctx` (which is itself thread-safe). Moving it between
// threads is safe. Sharing requires exclusive access by method (the Rust borrow checker),
// since `init_from_ctx` / `clean_up` / `copy` mutate the struct in place.
unsafe impl Send for TlsConnectionOptions {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_client_context_constructs() {
        let allocator = Allocator::default();
        let opts = TlsContextOptions::new_default_client(&allocator);
        let _ctx = TlsContext::new_client(&allocator, opts).expect("default TLS context");
    }

    #[test]
    fn override_trust_store_missing_path_errors() {
        let allocator = Allocator::default();
        let mut opts = TlsContextOptions::new_default_client(&allocator);
        let missing = Path::new("/nonexistent/mountpoint-s3-test/ca.pem");
        let err = opts.override_default_trust_store_from_path(None, Some(missing));
        assert!(err.is_err(), "expected error for missing CA file, got {err:?}");
    }
}
