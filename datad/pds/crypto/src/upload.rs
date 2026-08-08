//! Taking delivery of an onboarding package: where an upload's bytes go, what
//! judges them here, and what is asked of the domain that holds the device key.
//!
//! # Adversary
//!
//! The **unauthenticated management-plane attacker**, directly. Every byte that
//! reaches [`PackageUpload::take`] came off the onboarding port as the body of a
//! request nobody authenticated, and so did the pacing and the length claimed
//! about it. Nothing in this file reads one: they go through a cursor into a
//! region and come back into a window, and what reads them is `lfw_package` and
//! the adopted certificate validator.
//!
//! And the **byzantine neighbour protection domain** behind the delegation, on
//! `delegate`'s terms: what comes back from an install is a status word this
//! domain believes about nothing except whether to answer the peer 200.
//!
//! # The bytes are written once, into the place they are judged from
//!
//! The archive goes straight through the cursor into the staging region as it
//! arrives, and the window this domain validates is a **copy read back out of
//! that region**. It would have been shorter to accumulate in the window and
//! write the region once at the end, and it would have been wrong in a way that
//! is hard to see: the two domains that read this package would then be reading
//! two different byte strings, held equal by a copy nothing checks. Reading back
//! makes the archive this domain accepts the archive the other one installs.
//!
//! # The window is the arena's, and the refusal comes before the allocation
//!
//! A hundred and twenty-eight kibibytes is far too much for a stack frame and
//! is exactly what the bounded arena exists for. It is taken in
//! [`PackageUpload::open`], which is the one moment an upload can still be
//! refused for want of room — [`Bump::remaining`] is compared against the whole
//! of what an upload costs *before* a byte is allocated, so exhaustion is a
//! peer being told the surface is unavailable rather than an allocation that
//! cannot return.
//!
//! # Two readings, and this is the first
//!
//! What happens here is the general one: every structural rule of the package
//! contract, and then the adopted X.509 validator over the chain. The domain
//! that holds the key runs the second and narrower one against its own record.
//! Both refusals reach the console under the package contract's own token,
//! because it is one catalogue and an operator reading two domains' records is
//! reading one appliance.

use alloc::{sync::Arc, vec, vec::Vec};

use lfw_log::{Refusal, RefusalDetail};
use lfw_onboarding::{MAX_UPLOAD_LEN, Upload, UploadRefused};
use lfw_package::{Operands, PackageError};
use lfw_tls::{Bump, CryptoProvider, DeliveredAnchor, STEP_RESERVE};
use lfw_x509::SPKI_LEN;
use wire::{InstallStaging, UploadCursor};

use crate::delegate::Delegated;

/// Bytes of arena an upload must find free before it begins.
///
/// The window it is validated in, plus the headroom a session still owes its own
/// steps: the response to an upload is composed and encrypted after the package
/// has been judged, so an arena that had exactly enough room for the window
/// would have none for the answer. Compared against [`Bump::remaining`] once,
/// before anything is taken.
const UPLOAD_RESERVE: usize = MAX_UPLOAD_LEN + STEP_RESERVE;

/// The uploading end of onboarding, held across the deliveries one package
/// arrives in.
pub struct PackageUpload {
    arena: &'static Bump,
    staging: &'static InstallStaging,
    delegated: Arc<Delegated>,
    /// This appliance's own `SubjectPublicKeyInfo`, encoded once at bring-up.
    ///
    /// Here rather than derived per upload because deriving it can fail, and a
    /// failure that could only happen at bring-up should not be a way for a peer
    /// to make this domain refuse: the boot that could not encode its own key
    /// establishes no identity at all and serves nothing.
    appliance_key: [u8; SPKI_LEN],
    /// The assembled provider the adopted validator runs under, or nothing on a
    /// boot that established no cryptography.
    ///
    /// Optional rather than required at construction because this value is built
    /// on every boot, including one whose cryptography refused: such a boot
    /// serves nothing — the surface above refuses every request before a route
    /// is resolved — so what is here is never reached, and an `Option` says that
    /// without inventing a provider to stand in for one that does not exist.
    provider: Option<Arc<CryptoProvider>>,
    /// Seconds since the epoch, as the validity windows in a chain are judged
    /// against. Taken per session rather than per byte, a handshake being far
    /// shorter than the resolution any of those windows has.
    now: u64,
    /// The upload in progress: where the next segment goes, and how long the
    /// whole is claimed to be.
    cursor: Option<UploadCursor<'static>>,
    declared: usize,
    /// The window the package is validated in, out of the arena.
    window: Option<Vec<u8>>,
    /// What to tell the console about the refusal this upload earned.
    ///
    /// Held rather than emitted, because the record has to be written where the
    /// terminator collects them — an upload is judged deep inside a call the
    /// surface drives, and a sink reached from there would emit out of order
    /// with the session's own records.
    refusal: Option<Refusal>,
}

impl PackageUpload {
    pub const fn new(
        arena: &'static Bump,
        staging: &'static InstallStaging,
        delegated: Arc<Delegated>,
        appliance_key: [u8; SPKI_LEN],
        provider: Option<Arc<CryptoProvider>>,
    ) -> Self {
        Self {
            arena,
            staging,
            delegated,
            appliance_key,
            provider,
            now: 0,
            cursor: None,
            declared: 0,
            window: None,
            refusal: None,
        }
    }

    /// Begin a session: forget whatever the last one left, and take the instant
    /// a chain will be judged against.
    ///
    /// The window is dropped **here**, before the arena is wound back, so the
    /// allocation it holds is given up while the bookkeeper still accounts for
    /// it rather than after the cursor has moved under it.
    pub fn opened(&mut self, now: u64) {
        self.cursor = None;
        self.declared = 0;
        self.window = None;
        self.refusal = None;
        self.now = now;
    }

    /// What this upload owes the console, taken as it is read.
    pub fn take_refusal(&mut self) -> Option<Refusal> {
        self.refusal.take()
    }

    /// Read the staged archive back and hold it to the package contract.
    ///
    /// Destructured rather than reached through `self`, because the window is
    /// borrowed mutably for the read-back while the region, the key and the
    /// provider are read beside it — and the refusal afterwards borrows this
    /// value again, so the validation's borrows have to have ended by then.
    fn validate(&mut self) -> Result<(), UploadRefused> {
        let Self {
            staging,
            appliance_key,
            provider,
            now,
            declared,
            window,
            ..
        } = self;
        let ready = window
            .as_mut()
            .and_then(|held| held.get_mut(..*declared))
            .zip(provider.as_ref());
        let outcome = match ready {
            Some((archive, provider)) => {
                // Back out of the region, so what is judged is what the other
                // domain will read rather than an accumulation of this one's.
                staging.written().copy(archive);
                let verifier = DeliveredAnchor::new(Arc::clone(provider), *now);
                lfw_package::read(archive, appliance_key, &verifier)
                    .map(|_| ())
                    .map_err(Some)
            }
            // No window, so no upload was opened, or no provider, so this boot
            // established no cryptography. Both are unreachable — the surface
            // calls `open` first and refuses every request on a boot that
            // established nothing — and both are answered rather than asserted,
            // nothing on a path a peer paces being allowed to fault.
            None => Err(None),
        };
        match outcome {
            Ok(()) => Ok(()),
            Err(Some(error)) => {
                let (cause, detail) = named(error);
                self.refuse(cause, detail);
                Err(UploadRefused)
            }
            Err(None) => {
                self.refuse("upload-unprepared", RefusalDetail::None);
                Err(UploadRefused)
            }
        }
    }

    /// Record what refused this upload, under the shared catalogue's name.
    fn refuse(&mut self, cause: &'static str, detail: RefusalDetail) {
        self.refusal = Some(Refusal {
            cause,
            detail,
            // No device here to be told anything: this domain owns none.
            signalled: false,
        });
    }
}

impl Upload for PackageUpload {
    fn open(&mut self, declared: usize) -> Result<(), UploadRefused> {
        if self.arena.remaining() < UPLOAD_RESERVE {
            self.refuse(
                "upload-window-unavailable",
                RefusalDetail::Two(UPLOAD_RESERVE as u64, self.arena.remaining() as u64),
            );
            return Err(UploadRefused);
        }
        self.declared = declared;
        self.window = Some(vec![0_u8; MAX_UPLOAD_LEN]);
        self.cursor = Some(self.staging.upload().cursor());
        Ok(())
    }

    fn take(&mut self, segment: &[u8]) -> usize {
        // Nothing where no upload is open, which the surface reads as bytes it
        // could not place and answers by name.
        self.cursor
            .as_mut()
            .map_or(0, |cursor| cursor.write(segment))
    }

    fn install(&mut self) -> Result<(), UploadRefused> {
        self.validate()?;
        let Some(cursor) = self.cursor.take() else {
            self.refuse("upload-unprepared", RefusalDetail::None);
            return Err(UploadRefused);
        };
        // The token the cursor minted, which states the length that was really
        // written rather than the one a peer claimed.
        match self.delegated.install(cursor.finish()) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.refuse(error.cause(), RefusalDetail::None);
                Err(UploadRefused)
            }
        }
    }
}

/// The console token and the numbers a package refusal carries, both out of the
/// package contract's own catalogue.
///
/// Neither is spelled here. A second vocabulary for one contract is what the
/// catalogue exists to prevent, and an operator reading this domain's record
/// beside the installing domain's is reading one appliance.
fn named(error: PackageError) -> (&'static str, RefusalDetail) {
    let detail = match error.operands() {
        Operands::None => RefusalDetail::None,
        Operands::One(value) => RefusalDetail::One(value),
        Operands::Two(first, second) => RefusalDetail::Two(first, second),
    };
    (error.cause(), detail)
}
