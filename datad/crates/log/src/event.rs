//! What a call site says happened, and the closed vocabularies it says it in.

use core::fmt;

use net_headers::{Ipv4Address, MacAddress};

use crate::detail::DomainDetail;
use crate::identifier::Identifier;

/// Declares an enum whose variants, their `ALL` array and their console tokens
/// come from one list, so a variant cannot exist without a slot in `ALL` and a
/// name — the exhaustiveness a hand-written pair of the two only asks review to
/// notice.
macro_rules! closed_vocabulary {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident => $token:literal,)+
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)+
        }

        impl $name {
            /// Every variant, in discriminant order.
            pub const ALL: [Self; [$(stringify!($variant),)+].len()] = [$(Self::$variant,)+];

            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $token,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

closed_vocabulary! {
    /// Which protection domain an [`Event::Domain`] record is about. The names
    /// are the domain names in the Microkit system description, so a console
    /// line and the capability topology use one identity.
    Domain {
        Forwarder => "forwarder",
        NicDriver => "nic-driver",
        Config => "config",
        Console => "console",
        Clock => "clock",
        Management => "management",
        Recorder => "recorder",
        HardwareProbe => "hardware-probe",
        Crypto => "crypto",
        Store => "store",
    }
}

closed_vocabulary! {
    /// Which cryptographic primitive a record is about. The names are what an
    /// operator reads on the console and what the crypto-profile page states,
    /// so the page is held to this list rather than to a second copy of it.
    Primitive {
        Sha256 => "sha-256",
        HmacSha256 => "hmac-sha-256",
        HkdfSha256 => "hkdf-sha-256",
        ChaCha20 => "chacha20",
        ChaCha20Poly1305 => "chacha20-poly1305",
        Aes256Gcm => "aes-256-gcm",
        Drbg => "chacha20-drbg",
        EcdsaP256 => "ecdsa-p256",
        X25519 => "x25519",
        MlKem768 => "ml-kem-768",
    }
}

closed_vocabulary! {
    /// How a connection this appliance *originated* finished. A mirror of
    /// `lfw_ip_endpoint::outbound::Ended` and of the two refusal sets beside it,
    /// held to them by the one call site that maps them, and here for the reason
    /// [`Primitive`] is: a console vocabulary lives where the console's own
    /// tokens live, and this crate reaches for no transport.
    ///
    /// **One token per distinct cause, and that is the whole design of this
    /// list.** A deployed node has no shell and no debugger, so a failure to
    /// reach the management server is diagnosable from the console or not at
    /// all — and a token covering three causes is one that names none of them.
    /// The three the peer can produce are three tokens, the three this node's
    /// transport can produce are three more, and the three its own addressing
    /// can produce are three again, because each of the nine sends somebody to a
    /// different place. The order is the wire encoding, so a variant is appended
    /// and never inserted.
    DialOutcome {
        Answered => "answered",

        // The link: nothing this end sent could be addressed at all.
        NextHopUnreachable => "next-hop-unreachable",
        NoRoomToResolve => "no-room-to-resolve",

        // The peer: a connection was dialled and something, or nothing, came
        // back.
        /// The retransmission budget ran out with **nothing arriving at all**.
        Unanswered => "unanswered",
        /// A reset from the peer ended the connection: somebody is there and is
        /// refusing this port.
        ResetByPeer => "reset-by-peer",
        /// The peer acknowledged a number this end never sent, which draws a
        /// reset and leaves the dial standing, so the channel then runs its
        /// attempts out. The two numbers are on the record beside this token.
        UnacceptableAcknowledgement => "unacceptable-acknowledgement",
        /// The connection went away and none of the three above explains it.
        /// The residual, and named as one: what makes it readable is that the
        /// three causes it used to swallow are now their own tokens.
        ConnectionLost => "connection-lost",

        // This node's own transport, which refused the dial before a `SYN`
        // could be composed.
        /// Its table was full and nothing in it could be taken back.
        NoRoomToDial => "no-room-to-dial",
        /// It already holds a connection on this very peer address and port.
        ConnectionAlreadyOpen => "connection-already-open",
        /// The `SYN` did not fit the storage offered for it. **This node's own
        /// defect**, expected never to appear.
        SynDidNotFit => "syn-did-not-fit",

        // This node's own addressing and state, which refused the open before
        // the transport was asked.
        /// A session was already running on this port.
        SessionAlreadyRunning => "session-already-running",
        /// No next hop could be chosen: the destination, the prefix or the
        /// gateway is wrong.
        DestinationUnroutable => "destination-unroutable",
        /// The probe was longer than the room a session holds for one.
        ProbeTooLong => "probe-too-long",
    }
}

closed_vocabulary! {
    /// Which of an addressed port's two answers chose a next hop. A mirror of
    /// `lfw_ip_endpoint::route::Via`, on [`DialOutcome`]'s terms.
    ///
    /// It travels beside the address because the address alone cannot say: a
    /// gateway that happens to be the destination reads exactly like an on-link
    /// destination, and the two send an operator to different halves of the
    /// configuration document.
    NextHopVia {
        /// Inside the port's own prefix, reached as itself.
        Prefix => "prefix",
        /// Outside it, so the frame goes to the port's stated gateway.
        Gateway => "gateway",
        /// **No next hop was chosen at all** — the address beside this token is
        /// where the appliance meant to go and not a station it picked. Its own
        /// token rather than one of the two above because saying a frame went
        /// on-link when no route was found is precisely the kind of false
        /// signal this vocabulary exists to be rid of.
        None => "none",
    }
}

closed_vocabulary! {
    /// Which end finished an onboarding session, as the two domains that carry
    /// one report it.
    ///
    /// The tokens are single words on purpose, unlike [`DialOutcome`]'s: they
    /// name a *party* rather than a fault, and there is no fault vocabulary
    /// here — what went wrong on this path is a `cause=` token on a refusal
    /// record of its own, so a session's end and a session's failure are two
    /// facts a reader never has to disentangle from one field.
    OnboardEnd {
        /// The peer on the network closed its half. The ordinary end of a
        /// session an administrator finished with.
        Peer => "peer",
        /// The domain terminating the session said it was over.
        Consumer => "consumer",
        /// The connection stopped existing while neither end had said
        /// anything: a reset, an eviction under table pressure, a reaping.
        Forgotten => "forgotten",
        /// The session was ended by this appliance because the relay carrying
        /// it answered something that could not be believed or acted on. The
        /// `cause=` token on the record beside this one says which.
        Refused => "refused",
    }
}

closed_vocabulary! {
    /// Which of the onboarding surface's two resources a request was answered
    /// with.
    ///
    /// Two members, and it is closed because the surface is: an unprovisioned
    /// appliance serves a page and a certificate signing request, and anything
    /// else is a refusal with a token of its own. The token names the resource
    /// and never the target a peer typed — a request target is adversary-chosen
    /// bytes, and no such byte reaches a console line.
    ///
    /// The order is the wire encoding, so a variant is appended and never
    /// inserted.
    OnboardRoute {
        /// The onboarding page, which carries the appliance's name and the
        /// fingerprint an administrator compares against the console.
        Page => "page",
        /// The certificate signing request, as the certificate profile fixes
        /// it.
        CertificateRequest => "certificate-request",
    }
}

closed_vocabulary! {
    /// Why a request on the onboarding surface was refused.
    ///
    /// **One token per cause, and no token covering two.** An administrator
    /// whose client cannot get past this surface has the console and nothing
    /// else, so a token standing for "the request was bad" would name none of
    /// the fifteen ways it can be. Five of these are the surface's own
    /// decisions — the limiter, an identity that does not exist yet, a target
    /// nothing serves, a method nothing serves it under, and a head that
    /// outgrew what may be accumulated — and the fifteen after them mirror
    /// `lfw_http::RequestError` member for member.
    ///
    /// That mirror is **closed on both sides**, unlike the two that quote the
    /// adopted TLS library: the parser is first-party, so the one call site
    /// that maps it names every variant with no residual, and a variant added
    /// there fails this build rather than landing on a token that says nothing.
    ///
    /// The order is the wire encoding, so a variant is appended and never
    /// inserted.
    OnboardRefusal {
        /// The limiter had no allowance left. The record beside this one says
        /// how many consecutive refusals there have been and how long the next
        /// allowance is away, and there is always a next one: a lockout that
        /// did not expire would be a remote bricking primitive against an
        /// appliance whose port is the only way in.
        RateLimited => "rate-limited",
        /// The request arrived before this appliance had an identity to answer
        /// with — a boot whose cryptography never established. Nothing about
        /// the request was wrong.
        IdentityAbsent => "identity-absent",
        /// The target names no resource this surface serves.
        UnknownRoute => "unknown-route",
        /// The target names one, under a method it is not served with.
        MethodNotServed => "method-not-served",
        /// The head outgrew what may be accumulated before it ends. This
        /// appliance's bound rather than the parser's: what it refuses is a
        /// peer that never stops writing a head.
        HeadTooLong => "head-too-long",
        BareLineFeed => "bare-line-feed",
        StrayCarriageReturn => "stray-carriage-return",
        MalformedRequestLine => "malformed-request-line",
        MalformedMethod => "malformed-method",
        MalformedTarget => "malformed-target",
        TargetTooLong => "target-too-long",
        UnsupportedVersion => "unsupported-version",
        MalformedVersion => "malformed-version",
        TooManyHeaders => "too-many-headers",
        MalformedHeaderName => "malformed-header-name",
        MalformedHeaderValue => "malformed-header-value",
        ObsoleteLineFolding => "obsolete-line-folding",
        /// A body framed in a way the parser will not read: any
        /// `Transfer-Encoding`, a repeated or non-decimal `Content-Length`, or a
        /// body on a method other than `POST`.
        BodyNotAccepted => "body-not-accepted",
        /// A declared body length past the widest package this appliance will
        /// look at. Refused at the head, so no byte of it is accumulated on the
        /// way to finding out.
        BodyTooLarge => "body-too-large",
        /// Bytes no string can hold, which a head is never made of.
        NotUtf8 => "not-utf8",
        /// This appliance already has an owner, so the surface is shut. Its own
        /// token and not the one for an address that is not served: an
        /// administrator told "no such resource" would go looking for a typing
        /// mistake, and what has happened is that the appliance moved on. The
        /// close is permanent and a **factory reset** is the way back.
        AlreadyOwned => "already-owned",
        /// A package upload declaring no body at all. Nothing was staged and
        /// nothing was asked of the domain that holds the key, so no other
        /// domain's record says anything about this request — which is why it
        /// is named here rather than left to be inferred from silence.
        UploadEmpty => "upload-empty",
        /// The peer sent more body than the length it declared. Its own token
        /// because it is the peer contradicting itself, rather than any rule
        /// about what a package is.
        UploadOverran => "upload-overran",
        /// This appliance could not begin an upload: the room a package is
        /// validated in was not free. Nothing about the request was wrong, and
        /// the domain that refused says on its own console what it was short
        /// of.
        UploadUnavailable => "upload-unavailable",
        /// The upload began and the bytes would not all go where they were
        /// meant to. Unreachable while the declared length is held to the room
        /// that was reserved for it, and named rather than asserted because
        /// nothing on a path a peer paces may fault.
        UploadUnstaged => "upload-unstaged",
        /// The package arrived whole and the domain that holds the device key
        /// did not install it. **Which rule refused it is that domain's
        /// record**, in the package contract's own vocabulary, beside the facts
        /// that place it; this token says the upload got that far and was
        /// judged, which is what tells it apart from every refusal above.
        PackageRefused => "package-refused",
    }
}

closed_vocabulary! {
    /// How one handshake on the onboarding port ended, as the domain that
    /// terminates it reports.
    ///
    /// **One token per cause, and that is the whole design of this list**, on
    /// [`DialOutcome`]'s terms and for the same reason: an administrator whose
    /// client cannot establish the management connection has the console and
    /// nothing else, so a token covering three causes names none of them. The
    /// handshake that succeeded is a member here rather than a separate record,
    /// because one key an operator greps for is what makes a boot's onboarding
    /// story readable in one pass.
    ///
    /// Three of these carry a second token beside them — the library's own
    /// account of what it would not accept — and four carry numbers. The order
    /// is the wire encoding, so a variant is appended and never inserted.
    OnboardOutcome {
        /// The handshake completed. The three code points it settled on are on
        /// the record beside this token.
        Established => "established",
        /// The peer opened the connection and sent no byte at all.
        NoClientHello => "no-client-hello",
        /// The peer and this appliance had no protocol in common, before there
        /// was a suite or a group to compare. [`TlsIncompatible`] says which.
        Incompatible => "incompatible",
        /// The peer offered no cipher suite, or no key-exchange group, that
        /// this appliance has. What it did offer is on the two records beside
        /// this one.
        NothingInCommon => "nothing-in-common",
        /// The peer gave up with a fatal alert, whose registry code point is on
        /// the record beside this token.
        AlertReceived => "alert-received",
        /// This appliance refused the session. [`TlsRefusal`] says what it
        /// decided.
        Refused => "refused",
        /// The peer went away before the handshake completed.
        PeerClosed => "peer-closed",
        /// The bounded allocator had less than one phase's reserve free. What
        /// was asked for and what was left is on the `arena-` record beside
        /// this token.
        ArenaExhausted => "arena-exhausted",
        /// A direction outgrew what one session holds, carrying what it would
        /// have had to hold.
        Backlogged => "backlogged",
        /// Neither the library nor this appliance could make progress.
        Stalled => "stalled",
    }
}

closed_vocabulary! {
    /// Why the adopted TLS library and a peer had no protocol in common: its
    /// own `PeerIncompatible`, as a console token.
    ///
    /// **A mirror of a third party's vocabulary, and deliberately whole.** The
    /// alternative was one token for the lot, and the three cases that provoke
    /// it most — a client with no TLS 1.3, one that sent no supported-versions
    /// extension at all, and one whose suites this appliance does not have —
    /// are three separate things for an administrator to go and change. The
    /// library already tells them apart; folding them here would be this
    /// appliance losing the distinction on the way to the operator.
    ///
    /// It is a *naming* of that vocabulary and never a claim about the
    /// library's behaviour: the one call site that maps it names every variant
    /// explicitly, so a release that renames one fails the build. A release
    /// that *adds* one lands on [`Self::Unrecognized`], which is what that
    /// token is for — the library's type is open, so a mirror that pretended to
    /// be closed would be the lie.
    ///
    /// Several members cannot arise on a server that offers one version, one
    /// suite and one group and asks for no client certificate. They are here
    /// because a partial mirror is one somebody has to keep deciding the
    /// boundary of. The order is the wire encoding, so a variant is appended
    /// and never inserted.
    TlsIncompatible {
        EcPointsExtensionRequired => "ec-points-extension-required",
        ExtendedMasterSecretExtensionRequired => "extended-master-secret-extension-required",
        IncorrectCertificateTypeExtension => "incorrect-certificate-type-extension",
        KeyShareExtensionRequired => "key-share-extension-required",
        NamedGroupsExtensionRequired => "named-groups-extension-required",
        NoCertificateRequestSignatureSchemesInCommon =>
            "no-certificate-request-signature-schemes-in-common",
        NoCipherSuitesInCommon => "no-cipher-suites-in-common",
        NoEcPointFormatsInCommon => "no-ec-point-formats-in-common",
        NoKxGroupsInCommon => "no-kx-groups-in-common",
        NoSignatureSchemesInCommon => "no-signature-schemes-in-common",
        NullCompressionRequired => "null-compression-required",
        ServerDoesNotSupportTls12Or13 => "server-does-not-support-tls12-or13",
        ServerSentHelloRetryRequestWithUnknownExtension =>
            "server-sent-hello-retry-request-with-unknown-extension",
        ServerTlsVersionIsDisabledByOurConfig => "server-tls-version-is-disabled-by-our-config",
        SignatureAlgorithmsExtensionRequired => "signature-algorithms-extension-required",
        SupportedVersionsExtensionRequired => "supported-versions-extension-required",
        Tls12NotOffered => "tls12-not-offered",
        Tls12NotOfferedOrEnabled => "tls12-not-offered-or-enabled",
        Tls13RequiredForQuic => "tls13-required-for-quic",
        UncompressedEcPointsRequired => "uncompressed-ec-points-required",
        UnsolicitedCertificateTypeExtension => "unsolicited-certificate-type-extension",
        ServerRejectedEncryptedClientHello => "server-rejected-encrypted-client-hello",
        /// A member the library grew after this mirror was written. Its own
        /// token rather than a nearby one, so an operator reading it knows the
        /// answer is "this build cannot name it" and not "this is what
        /// happened".
        Unrecognized => "unrecognized",
    }
}

closed_vocabulary! {
    /// What this appliance decided against a peer's bytes: the adopted TLS
    /// library's own `Error`, as a console token.
    ///
    /// [`TlsIncompatible`]'s mirror on the other of the two vocabularies that
    /// reach an operator from the library, under all of its reasoning. It is
    /// **the error variant and not the alert byte that went out beside it**:
    /// the library exposes no outgoing alert on this path, so a table from one
    /// to the other would be a first-party claim about a third party's
    /// behaviour that a version bump falsifies with nothing failing.
    ///
    /// It stops at the top-level variant. Several of them carry a nested
    /// vocabulary of their own — which field of which message was malformed —
    /// and mirroring those would multiply this list many times over to separate
    /// causes an administrator answers identically: the peer is not speaking
    /// this protocol correctly. Where the distinction *is* actionable the
    /// library puts it in a different variant, which is what this list carries.
    ///
    /// The order is the wire encoding, so a variant is appended and never
    /// inserted.
    TlsRefusal {
        InappropriateMessage => "inappropriate-message",
        InappropriateHandshakeMessage => "inappropriate-handshake-message",
        InvalidEncryptedClientHello => "invalid-encrypted-client-hello",
        InvalidMessage => "invalid-message",
        NoCertificatesPresented => "no-certificates-presented",
        UnsupportedNameType => "unsupported-name-type",
        DecryptError => "decrypt-error",
        EncryptError => "encrypt-error",
        PeerIncompatible => "peer-incompatible",
        PeerMisbehaved => "peer-misbehaved",
        AlertReceived => "alert-received",
        InvalidCertificate => "invalid-certificate",
        InvalidCertRevocationList => "invalid-cert-revocation-list",
        General => "general",
        FailedToGetCurrentTime => "failed-to-get-current-time",
        FailedToGetRandomBytes => "failed-to-get-random-bytes",
        HandshakeNotComplete => "handshake-not-complete",
        PeerSentOversizedRecord => "peer-sent-oversized-record",
        NoApplicationProtocol => "no-application-protocol",
        BadMaxFragmentSize => "bad-max-fragment-size",
        InconsistentKeys => "inconsistent-keys",
        /// The library's own residual, which it uses for a failure a provider
        /// reported. Distinct from [`Self::Unrecognized`] below: this one is
        /// the library saying it has no better name, and that one is this build
        /// having none.
        Other => "other",
        /// A member the library grew after this mirror was written, on
        /// [`TlsIncompatible::Unrecognized`]'s terms.
        Unrecognized => "unrecognized",
    }
}

closed_vocabulary! {
    /// Whether this appliance has an owner, as the domain that decides frames
    /// believes it.
    ///
    /// The tokens are the ones the drop reason and the metric label already
    /// spell, deliberately: a node that forwards nothing refuses every frame
    /// under `unowned`, counts it under `unowned`, and says `unowned` on the
    /// console, so an operator meets one word wherever they look rather than
    /// three renderings of one fact to line up by hand.
    Ownership {
        Unowned => "unowned",
        Owned => "owned",
    }
}

closed_vocabulary! {
    /// The lifecycle points a domain reports. `Negotiated` sits between the
    /// other two because a device that answered and a device whose queues are
    /// primed are different failures to be looking at: one is a bring-up
    /// handshake, the other a mapping or a pool.
    DomainState {
        Starting => "starting",
        Negotiated => "negotiated",
        Ready => "ready",
        Refused => "refused",
    }
}

closed_vocabulary! {
    ChangeKind {
        Added => "added",
        Removed => "removed",
        Modified => "modified",
    }
}

closed_vocabulary! {
    ObjectKind {
        Interface => "interface",
        Neighbour => "neighbour",
        Management => "management",
        Rule => "rule",
    }
}

closed_vocabulary! {
    /// Which attribute of an object changed. The tokens are the configuration
    /// document's own attribute names, so a change record points at the text an
    /// operator edits rather than at an internal field name.
    Field {
        Port => "port",
        Enabled => "enabled",
        Mac => "mac",
        Address => "address",
        PrefixLength => "prefix-length",
        /// The station the management port hands its own outbound traffic to
        /// for anything off its prefix. `none` where the operator stated no
        /// gateway, spelled rather than omitted like every other value here.
        Gateway => "gateway",
        Interface => "interface",
        /// A rule's own name. A field rather than the key its records are
        /// filed under, unlike every other object: a rule is identified by
        /// where it sits, so its id is something it *says* rather than what it
        /// is, and renaming one is a change to report like any other.
        Id => "id",
        Ingress => "ingress",
        Egress => "egress",
        Source => "source",
        Destination => "destination",
        Protocol => "protocol",
        SourcePort => "source-port",
        DestinationPort => "destination-port",
        IcmpType => "icmp-type",
        /// Which of the two things that reach the filter a rule is about.
        Tracking => "tracking",
        Action => "action",
    }
}

closed_vocabulary! {
    GenerationOutcome {
        Applied => "applied",
        Refused => "refused",
        Unchanged => "unchanged",
    }
}

closed_vocabulary! {
    /// Why a configuration document was refused, at the granularity an operator
    /// acts on: each token names one thing to go and fix.
    ///
    /// The first group is the document's syntax and the hardening bounds its
    /// *bytes* are held to; the second is semantic validation over the parsed
    /// model, where `capacity-exceeded` belongs — a document naming more
    /// interfaces than the handover image holds passed every byte bound and does
    /// not fit. A reason never carries the offending bytes; the record pairs it
    /// with a byte offset. The order is the wire encoding, so a reason is
    /// appended and never inserted.
    RejectReason {
        Malformed => "malformed",
        Doctype => "doctype",
        EntityDeclaration => "entity-declaration",
        UnknownEntityReference => "unknown-entity-reference",
        InvalidCharacterReference => "invalid-character-reference",
        DocumentTooLarge => "document-too-large",
        DepthExceeded => "depth-exceeded",
        TooManyAttributes => "too-many-attributes",
        NameTooLong => "name-too-long",
        ValueTooLong => "value-too-long",
        UnexpectedCharacterData => "unexpected-character-data",
        DuplicateAttribute => "duplicate-attribute",
        UnknownElement => "unknown-element",
        UnknownAttribute => "unknown-attribute",
        MissingElement => "missing-element",
        MissingAttribute => "missing-attribute",
        MalformedValue => "malformed-value",
        DuplicateIdentifier => "duplicate-identifier",
        DuplicatePort => "duplicate-port",
        PortOutOfRange => "port-out-of-range",
        PrefixLengthOutOfRange => "prefix-length-out-of-range",
        /// The address is the prefix's network or broadcast address, which no
        /// host may hold.
        AddressNotAHostAddress => "address-not-a-host-address",
        AddressNotUnicast => "address-not-unicast",
        MacNotUnicast => "mac-not-unicast",
        OverlappingPrefixes => "overlapping-prefixes",
        UnknownInterfaceReference => "unknown-interface-reference",
        NeighbourOutsidePrefix => "neighbour-outside-prefix",
        NeighbourIsInterfaceAddress => "neighbour-is-interface-address",
        DuplicateNeighbourAddress => "duplicate-neighbour-address",
        /// More interfaces, neighbours or rules than the handover image holds.
        CapacityExceeded => "capacity-exceeded",
        /// A prefix written with host bits set, so the block it names is not the
        /// one the address suggests. Refused rather than masked off: an operator
        /// reading `10.0.0.5/24` back as `10.0.0.0/24` learned it from the
        /// refusal or never at all.
        PrefixNotCanonical => "prefix-not-canonical",
        /// A range whose low port exceeds its high one, which matches nothing.
        PortRangeReversed => "port-range-reversed",
        /// A port criterion on a rule that names ICMP, which carries no ports.
        PortCriterionOnIcmp => "port-criterion-on-icmp",
        /// An ICMP type criterion on a rule that names a protocol other than
        /// ICMP, which carries no type.
        IcmpTypeOnNonIcmp => "icmp-type-on-non-icmp",
        /// Every rule passed, and the configuration's own canonical form is
        /// longer than a document may be — so the appliance could commit it and
        /// then be unable to state it back. Refused instead, because reading the
        /// running configuration is the first step of changing it and a policy an
        /// operator cannot read back is one they cannot edit. Distinct from
        /// `document-too-large`, which is the submitted bytes exceeding the same
        /// bound: this one is about what the appliance would answer, and a
        /// document well inside the bound can provoke it.
        RenderingTooLarge => "rendering-too-large",
        /// The bytes offered in the handover region do not fold to the digest they
        /// carry, so they are not one publication: either the domain that sealed
        /// them sealed them wrongly, or the reader's copy was taken across two
        /// publications. **The operator's document may be perfectly correct.**
        ///
        /// Its own reason rather than `malformed-value`, and the distinction is a
        /// decision about what a console line instructs. Every other
        /// `malformed-value` is a statement about a document somebody wrote, whose
        /// next action is to edit it; this one is a statement about what the node
        /// published, whose next action is to suspect the node. A vocabulary may be
        /// coarser than the fault tree it summarises — it may not point away from
        /// the thing at fault.
        HandoverNotOnePublication => "handover-not-one-publication",
        /// A gateway outside the prefix of the port that would use it, so no
        /// station on that link can answer for it. Its own token rather than
        /// `neighbour-outside-prefix`: that one names an object with an id to
        /// go and edit, and this names an attribute of the management port.
        ///
        /// Appended here rather than filed beside the other semantic reasons,
        /// which is what the order above is for: a token's position is the wire
        /// encoding, so a reason inserted among them would renumber every one
        /// that followed it.
        GatewayNotOnLink => "gateway-not-on-link",
        /// A gateway equal to the address of the port that would use it, which
        /// would hand every off-prefix datagram back to this node. Appended for
        /// the reason above.
        GatewayIsTheLocalAddress => "gateway-is-the-local-address",
    }
}

/// A value an event may carry.
///
/// Closed by construction: every variant is an already-parsed domain type, so a
/// byte string out of a configuration document has no representation here and
/// cannot reach a rendered line as itself. [`Value::Id`] is the one
/// route text takes, and only through [`Identifier`], whose alphabet is what
/// makes it renderable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Value {
    Port(u8),
    Ipv4(Ipv4Address),
    Mac(MacAddress),
    PrefixLength(u8),
    Bool(bool),
    Generation(u32),
    Count(u32),
    Id(Identifier),
    /// One filter rule's match criterion, as the token the document writes it
    /// as: `any`, `tcp`, `accept`, `443`, `1024-65535`. Text rather than a
    /// variant per criterion because a record renders it and decides nothing
    /// about it, and the criterion vocabularies are the configuration crate's;
    /// [`Identifier`]'s alphabet is what makes it renderable, and every token
    /// those vocabularies mint is inside it.
    Selector(Identifier),
    /// The one criterion no token can carry, `.` and `/` being outside that
    /// alphabet. A wildcard address is [`Self::Selector`]'s `any`, so this is
    /// always a stated block.
    Prefix {
        network: Ipv4Address,
        prefix_length: u8,
    },
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(port) => write!(f, "{port}"),
            Self::Ipv4(address) => write!(f, "{address}"),
            Self::Mac(mac) => write!(f, "{mac}"),
            Self::PrefixLength(length) => write!(f, "{length}"),
            Self::Bool(flag) => write!(f, "{flag}"),
            Self::Generation(generation) => write!(f, "{generation}"),
            Self::Count(count) => write!(f, "{count}"),
            Self::Id(id) => f.write_str(id.as_str()),
            Self::Selector(token) => f.write_str(token.as_str()),
            Self::Prefix {
                network,
                prefix_length,
            } => write!(f, "{network}/{prefix_length}"),
        }
    }
}

/// One thing that happened, named rather than rendered.
///
/// A call site emits this and a [`Sink`](crate::Sink) decides how it reads. The
/// alternative — a call site that formats its own line — throws away the
/// attribute structure an OpenTelemetry record is, and there is no way to
/// recover it afterwards short of rewriting every site.
///
/// `C` is the refusal cause text in the two forms [`Refusal`](crate::Refusal)
/// documents; the default is the one a call site mints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<C = &'static str> {
    Domain {
        domain: Domain,
        state: DomainState,
        detail: DomainDetail<C>,
    },
    /// One configuration value changed as part of a commit. Unchanged values
    /// produce no record, so the volume of a commit is the size of its diff.
    ConfigChange {
        generation: u32,
        sequence: u32,
        change: ChangeKind,
        object: ObjectKind,
        key: Identifier,
        field: Field,
        /// Absent exactly when the object was added.
        from: Option<Value>,
        /// Absent exactly when the object was removed.
        to: Option<Value>,
    },
    ConfigGeneration {
        generation: u32,
        outcome: GenerationOutcome,
        changes: u32,
    },
    /// A document was refused. Names where and why, never the attacker's bytes.
    ConfigRejected {
        generation: u32,
        reason: RejectReason,
        offset: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{string::String, vec::Vec};

    /// The property every console vocabulary owes an operator: `ALL` is the
    /// variants in discriminant order — so nothing is missing from the middle
    /// of it — and no two of them read the same.
    fn assert_vocabulary<const N: usize>(slots: [usize; N], names: [&str; N]) {
        for (index, slot) in slots.into_iter().enumerate() {
            assert_eq!(slot, index, "ALL is not in discriminant order");
        }
        let mut sorted: Vec<&str> = names.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), count, "two variants share a console token");
        assert!(
            names.iter().all(|name| !name.is_empty()),
            "a variant renders as nothing"
        );
    }

    /// The console spells a primitive with hyphens and the metrics surface
    /// with underscores, and the two lists live in different crates because
    /// the dependency runs one way only. This is the place that can see both,
    /// so it is where they are held equal — a primitive added to one and not
    /// the other fails here rather than shipping a console name no metric
    /// carries.
    #[test]
    fn the_metric_label_values_are_this_vocabulary_transliterated() {
        let underscored: Vec<String> = Primitive::ALL
            .iter()
            .map(|primitive| primitive.name().replace('-', "_"))
            .collect();
        assert_eq!(underscored, lfw_metrics::CRYPTO_PRIMITIVES);
    }

    macro_rules! check_vocabulary {
        ($name:ident) => {
            assert_vocabulary(
                $name::ALL.map(|variant| variant as usize),
                $name::ALL.map(|variant| variant.name()),
            )
        };
    }

    #[test]
    fn every_console_vocabulary_names_each_variant_once() {
        check_vocabulary!(Domain);
        check_vocabulary!(DomainState);
        check_vocabulary!(Ownership);
        check_vocabulary!(ChangeKind);
        check_vocabulary!(ObjectKind);
        check_vocabulary!(Field);
        check_vocabulary!(GenerationOutcome);
        check_vocabulary!(RejectReason);
        check_vocabulary!(DialOutcome);
        check_vocabulary!(NextHopVia);
        check_vocabulary!(OnboardEnd);
        check_vocabulary!(OnboardOutcome);
        check_vocabulary!(OnboardRoute);
        check_vocabulary!(OnboardRefusal);
        check_vocabulary!(TlsIncompatible);
        check_vocabulary!(TlsRefusal);
    }

    #[test]
    fn a_vocabulary_displays_as_its_console_token() {
        for reason in RejectReason::ALL {
            assert_eq!(std::format!("{reason}"), reason.name());
        }
        assert_eq!(std::format!("{}", Domain::NicDriver), "nic-driver");
        assert_eq!(std::format!("{}", Field::PrefixLength), "prefix-length");
    }

    #[test]
    fn every_value_variant_renders_its_own_shape() {
        let id = Identifier::new(b"wan").expect("the alphabet accepts it");
        let cases = [
            (Value::Port(3), "3"),
            (
                Value::Ipv4(Ipv4Address::from_octets([10, 0, 0, 1])),
                "10.0.0.1",
            ),
            (
                Value::Mac(MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x50])),
                "52:54:00:12:34:50",
            ),
            (Value::PrefixLength(24), "24"),
            (Value::Bool(true), "true"),
            (Value::Bool(false), "false"),
            (Value::Generation(7), "7"),
            (Value::Count(0), "0"),
            (Value::Id(id), "wan"),
        ];
        for (value, expected) in cases {
            assert_eq!(std::format!("{value}"), expected);
        }
    }
}
