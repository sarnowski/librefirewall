//! The one page this product ever serves a person.
//!
//! # Deliberately plain
//!
//! No stylesheet, no script, no image, no font — not as an aesthetic and not as
//! a shortcut. Every one of those is a second thing an appliance with no owner
//! would serve to whoever reached it, and the page's whole job is to carry two
//! strings an administrator compares character for character against a console.
//! A layout that made either of them harder to compare would be a defect, so
//! the fingerprint is rendered exactly as the certificate profile fixes it and
//! sits alone on its own line.
//!
//! # There is no upload form, and that is a statement rather than an omission
//!
//! The surface takes a configuration package and the page does not offer a
//! control for one. A browser form can only send a body it has wrapped in an
//! encoding of its own, and unwrapping that would be a second parser on the one
//! path an unauthenticated peer reaches — for a wrapping that carries nothing,
//! the package being the whole body of the request. So the page prints the
//! command instead, which is a string an administrator runs rather than a
//! format this appliance has to read.
//!
//! # The address is a placeholder and the fingerprint is not
//!
//! The command cannot name this appliance, because the only thing on the wire
//! that claims to is the `Host` field a peer typed — and no byte a peer sent
//! reaches this page. So the address is written as a placeholder an
//! administrator substitutes; they know it, having just used it. The
//! fingerprint beside it is this appliance's own and is rendered exactly once,
//! the way the certificate profile fixes it.
//!
//! # Adversary
//!
//! None reaches the composition: every byte written here is a compile-time
//! constant or one of two hexadecimal renderings this appliance produced from
//! its own key. Nothing a peer sent appears on the page, which is what keeps it
//! free of any question about escaping.

use lfw_x509::{DEVICE_ID_LEN, FINGERPRINT_LEN};

/// Bytes the composed page occupies at most, derived from the template and the
/// two fixed-width strings it carries rather than measured.
pub const MAX_PAGE_LEN: usize = template_len() + DEVICE_ID_LEN + FINGERPRINT_LEN;

/// The page, split where the two renderings go.
///
/// A slice of literals rather than one string with placeholders: there is no
/// formatting machinery in the composition at all, so there is no way for a
/// value to be written anywhere but where a gap between two literals puts it.
const BEFORE_DEVICE: &str = concat!(
    "<!DOCTYPE html>\n",
    "<html lang=\"en\">\n",
    "<head><meta charset=\"utf-8\"><title>librefirewall onboarding</title></head>\n",
    "<body>\n",
    "<h1>librefirewall</h1>\n",
    "<p>This appliance has no owner yet. It forwards nothing, and this page is\n",
    "the whole of what it serves.</p>\n",
    "<h2>Is this the right appliance?</h2>\n",
    "<p>Compare the fingerprint below, character for character, against the one\n",
    "this appliance printed on its console. They are the same string, rendered\n",
    "the same way. If they differ, you are not talking to this appliance.</p>\n",
    "<p>Device identifier</p>\n",
    "<p><code>",
);

const BETWEEN: &str = concat!(
    "</code></p>\n",
    "<p>Public key fingerprint (SHA-256 over the SubjectPublicKeyInfo)</p>\n",
    "<p><code>",
);

const AFTER_FINGERPRINT: &str = concat!(
    "</code></p>\n",
    "<h2>Next step</h2>\n",
    "<p>Download the certificate signing request and give it to your management\n",
    "application, which signs it and hands back a configuration package.</p>\n",
    "<p><a href=\"/certificate.csr\">/certificate.csr</a></p>\n",
    "<h2>Uploading the package</h2>\n",
    "<p>Upload the package to this appliance, substituting the address you\n",
    "reached this page on. There is no form: the package travels as the whole\n",
    "body of the request, and a browser can only send one wrapped in an\n",
    "encoding this appliance would then have to unwrap.</p>\n",
    "<pre><code>curl -i --insecure --data-binary @package.tar \\\n",
    "  https://APPLIANCE/configuration.tar</code></pre>\n",
    "<p><code>--insecure</code> means this appliance has no certificate\n",
    "authority above it, not that nothing was checked. The fingerprint above is\n",
    "the check, and you have already made it.</p>\n",
    "<p>A package that is accepted is answered <code>200</code> with no body,\n",
    "and the console then carries the fingerprint of the authority this\n",
    "appliance has accepted and the endpoint it will answer to. Anything else\n",
    "names the refusal on the console. Once a package is accepted this page and\n",
    "everything beside it are gone for good: an appliance with an owner serves\n",
    "no onboarding, and a factory reset is the way back.</p>\n",
    "</body>\n",
    "</html>\n",
);

/// Bytes of literal in the template.
const fn template_len() -> usize {
    BEFORE_DEVICE.len() + BETWEEN.len() + AFTER_FINGERPRINT.len()
}

/// The page could not be composed because the caller's storage was short.
/// One variant, because every other input is a fixed-width array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageDoesNotFit {
    pub capacity: usize,
}

/// Compose the page into `out`, answering its length.
///
/// # Errors
/// [`PageDoesNotFit`] where `out` is shorter than [`MAX_PAGE_LEN`], which is
/// derived from exactly what this writes and so is unreachable for a caller
/// that reserves it.
pub fn write_page(
    device: &[u8; DEVICE_ID_LEN],
    fingerprint: &[u8; FINGERPRINT_LEN],
    out: &mut [u8],
) -> Result<usize, PageDoesNotFit> {
    let capacity = out.len();
    let mut at = 0usize;
    for piece in [
        BEFORE_DEVICE.as_bytes(),
        device.as_slice(),
        BETWEEN.as_bytes(),
        fingerprint.as_slice(),
        AFTER_FINGERPRINT.as_bytes(),
    ] {
        let end = at
            .checked_add(piece.len())
            .ok_or(PageDoesNotFit { capacity })?;
        let room = out.get_mut(at..end).ok_or(PageDoesNotFit { capacity })?;
        room.copy_from_slice(piece);
        at = end;
    }
    Ok(at)
}
