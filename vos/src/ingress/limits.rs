//! Resource caps for the built-in HTTP/1.1 parser.

pub(crate) const MAX_HEADERS: usize = 64;
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Default body ceiling. Package-bearing lifecycle routes use their exact
/// protocol envelope ceiling and a separate, process-wide upload admission cap.
pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;

pub(crate) fn request_body_limit(method: &http::Method, uri: &http::Uri) -> usize {
    #[cfg(all(feature = "network", feature = "storage", target_os = "linux"))]
    if method == http::Method::POST && uri.query().is_none() {
        match uri.path() {
            "/__agents/local" => {
                return crate::agent::local_lifecycle::LocalCreateSubmission::MAX_BYTES;
            }
            "/__agents/local/install" => {
                return crate::agent::local_lifecycle::LocalInstallSubmission::MAX_BYTES;
            }
            "/__agents/shared" => {
                return crate::agent::local_lifecycle::SharedCreateSubmission::MAX_BYTES;
            }
            "/__agents/shared/install" => {
                return crate::agent::local_lifecycle::SharedInstallSubmission::MAX_BYTES;
            }
            _ => {}
        }
    }
    let _ = (method, uri);
    MAX_BODY_BYTES
}

#[cfg(all(test, feature = "network", feature = "storage", target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn only_exact_package_routes_receive_the_protocol_body_ceiling() {
        for (path, ceiling) in [
            (
                "/__agents/local",
                crate::agent::local_lifecycle::LocalCreateSubmission::MAX_BYTES,
            ),
            (
                "/__agents/local/install",
                crate::agent::local_lifecycle::LocalInstallSubmission::MAX_BYTES,
            ),
        ] {
            assert_eq!(
                request_body_limit(&http::Method::POST, &path.parse().unwrap()),
                ceiling
            );
            assert_eq!(
                request_body_limit(&http::Method::GET, &path.parse().unwrap()),
                MAX_BODY_BYTES
            );
            for suffix in ["/", "?alias=1"] {
                assert_eq!(
                    request_body_limit(
                        &http::Method::POST,
                        &format!("{path}{suffix}").parse().unwrap()
                    ),
                    MAX_BODY_BYTES
                );
            }
        }
        assert_eq!(
            request_body_limit(&http::Method::POST, &"/__agents/invoke".parse().unwrap()),
            MAX_BODY_BYTES
        );
    }
}
