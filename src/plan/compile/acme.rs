//! Lowering of a site's `tls.acme`.

use super::{Compiler, Where};
use crate::config::SiteTls;
use crate::config::acme::{AcmeSettings, SiteAcme};
use crate::plan::CertSource;

impl Compiler<'_> {
    /// The certificate source of a TLS site whose names get certificates from an ACME CA,
    /// recording what the ACME client must issue in `self.acme`. `None` (with a diagnostic)
    /// when the site cannot be served that way.
    pub(super) fn acme_certificate(
        &mut self,
        site: &str,
        names: Vec<Box<str>>,
        spec: &SiteAcme,
        settings: Option<&AcmeSettings>,
        tls: &SiteTls,
        at: &Where,
    ) -> Option<CertSource> {
        let _ = (site, names, spec, settings, tls);
        self.error(
            at,
            "in-process ACME is not supported by this upstreamer yet",
        );
        None
    }
}
