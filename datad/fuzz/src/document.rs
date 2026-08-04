//! `config` under the management-plane attacker.
//!
//! # The adversary and the surface
//!
//! The management-plane attacker chooses every byte of a
//! configuration document, so the input here *is* the document: no length
//! prefix, no operation selector, no prologue this harness supplies, and no
//! filter on encoding. A corpus entry is a file, which is what lets the
//! appliance's own `systems/qemu-x86_64/configuration.xml` be a seed.
//!
//! The whole chain is driven rather than the reader alone, because each stage
//! is only safe given the next: a parse that returns is safe only if the model
//! it returns cannot then be turned into a runtime artifact the dataplane
//! cannot hold, and an artifact is safe only if the domain that reads it
//! accepts it. The last link is the one worth having — `image_from` feeding
//! [`wire::ConfigImage::check`] and then the consumer's own
//! [`pd_runtime::router_from`] is the configuration domain and the forwarding
//! domain disagreeing, which no test inside either crate can observe.
//!
//! # What the adversary may express here
//!
//! Everything a byte string can be. The document is passed through unshaped:
//! invalid UTF-8, an absent or lying prologue, a document larger than
//! [`MAX_DOCUMENT_BYTES`], nesting past [`MAX_DEPTH`], a DTD, an entity
//! declaration, and an expansion attack are all ordinary inputs, and the
//! assertion is that the reader's *own* bounds refuse them. Capping the input
//! here would delete exactly the region those bounds exist for, so
//! nothing is capped: the seeds deliberately include a document past the size
//! bound so the refusal itself is exercised rather than assumed.
//!
//! # What is asserted
//!
//! * **Totality.** Every byte string is answered — one typed rejection, or a
//!   model. Both halves are total separately, so a syntactically clean document
//!   that the rules refuse is still a rejection rather than a panic.
//! * **Boundedness, which is the expansion claim.** The reader never yields
//!   more events than the document has room for, and the attribute bytes it
//!   materialises never exceed the document's own length. A billion-laughs
//!   expansion is precisely a document whose materialised bytes outgrow it, so
//!   the second of those is the invariant that would catch one — and it is
//!   asserted rather than inferred from the run merely finishing. Every
//!   declared bound ([`MAX_DEPTH`], [`MAX_NAME_LEN`], [`MAX_ATTRIBUTES`],
//!   [`MAX_ATTRIBUTE_VALUE_LEN`]) is checked against what the reader actually
//!   handed back.
//! * **A rejection points into the document.** An offset past the end is a
//!   position an operator cannot go and look at.
//! * **Determinism.** The same bytes yield the same answer, and an accepted
//!   document yields the same hash every time it is read. Configuration is
//!   keyed by that hash, so a hash that moved between two reads
//!   of one file would make an unchanged document look like a change.
//! * **Canonicality.** A model never differs from itself: the diff of an
//!   accepted model against itself is empty, and it does not overflow the
//!   caller's buffer while being empty.
//! * **Agreement across the boundary.** Every accepted document builds a
//!   handover image the consuming domain accepts, and the forwarding table that
//!   domain builds out of it carries the same entries the document named.
//! * **Agreement between the two front doors.** [`Datastore::stage`] accepts
//!   exactly what [`load`] accepts and refuses it for the same reason, so the
//!   versioned path cannot come to admit a document the direct one refuses.

use config::{
    Change, ConfigError, Datastore, Generation, MAX_ATTRIBUTE_VALUE_LEN, MAX_ATTRIBUTES, MAX_DEPTH,
    MAX_NAME_LEN, Model, PORT_COUNT, Reader, content_hash, diff, image_from, load, parse, validate,
};

/// Generations an accepted model is turned into an image under.
///
/// Not drawn from the input: the generation is assigned by the datastore, not
/// by whoever wrote the document, so taking it from the adversary's bytes would
/// model authority nobody has. Zero and the saturating ceiling are the two the
/// counter's own edges make interesting.
const GENERATIONS: [u32; 2] = [0, u32::MAX];

/// Read one document, and carry every accepted model through to the artifacts
/// the dataplane is handed.
pub fn document_harness(document: &[u8]) {
    assert_reader_is_bounded(document);

    let loaded = load(document);
    assert_eq!(
        loaded,
        load(document),
        "reading one document twice gave two answers"
    );

    // Staging is the datastore's own front door onto the same bytes. It must
    // not be more permissive than the direct one, or a document could reach a
    // candidate generation without having satisfied the rules.
    let mut store = Datastore::new();
    assert_eq!(
        store.stage(document).map(|staged| staged.model),
        loaded,
        "staging and loading disagreed about the same document"
    );
    assert_eq!(
        store.validate_document(document),
        loaded.map(|_| ()),
        "validating and loading disagreed about the same document"
    );

    let model = match loaded {
        Ok(model) => model,
        Err(error) => {
            assert_rejection_is_locatable(error, document);
            // Which half refused it is itself a claim: a document faulted for
            // its shape must be refused by the reader alone, and one faulted
            // for what it says must have got past the reader intact. The two
            // halves never mixing is what keeps each of them reviewable.
            match error {
                ConfigError::Document(fault) => assert_eq!(
                    parse(document),
                    Err(fault),
                    "a shape fault was decided somewhere other than the reader"
                ),
                ConfigError::Semantic(fault) => {
                    let model = parse(document)
                        .expect("a semantic fault means the reader accepted the document");
                    assert_eq!(
                        validate(&model),
                        Err(fault),
                        "the rules disagreed with the rules"
                    );
                    assert_model_fits_the_handover_image(&model);
                }
            }
            return;
        }
    };

    assert_model_fits_the_handover_image(&model);
    assert!(
        validate(&model).is_ok(),
        "a model that was accepted does not satisfy the rules it was accepted by"
    );
    assert_eq!(
        parse(document),
        Ok(model),
        "parsing alone did not produce the model loading produced"
    );

    let hash = content_hash(&model);
    assert_eq!(
        hash,
        content_hash(&parse(document).expect("the document parsed a moment ago")),
        "one document hashed to two contents"
    );

    let mut records: Vec<Change> = Vec::new();
    let counted = diff(&model, &model, &mut |change: Change| records.push(change));
    assert_eq!(
        counted, 0,
        "a configuration differs from itself in {counted} places"
    );
    assert!(
        records.is_empty(),
        "an empty diff still handed out {} records",
        records.len()
    );

    assert_artifacts_agree(&model);
}

/// Drive the reader itself, so the bounds it declares are checked against what
/// it handed back rather than against the model the schema assembled from it.
fn assert_reader_is_bounded(document: &[u8]) {
    let Ok(reader) = Reader::new(document) else {
        // The only refusal `new` makes is the size bound, and it makes it
        // before looking at a byte — which is the point of having it there.
        assert!(
            document.len() > config::MAX_DOCUMENT_BYTES,
            "the reader refused a document inside its own size bound"
        );
        return;
    };

    let mut events = 0usize;
    let mut depth = 0usize;
    let mut materialised = 0usize;
    let mut refused = false;

    for event in reader {
        assert!(
            !refused,
            "the reader kept reading a document it had refused"
        );
        match event {
            Ok(config::Event::Start(element)) => {
                events = events.saturating_add(1);
                depth = depth.saturating_add(1);
                assert!(
                    depth <= MAX_DEPTH,
                    "an element opened at depth {depth}, past the reader's own bound"
                );
                assert!(
                    element.name.len() <= MAX_NAME_LEN,
                    "an element name of {} bytes passed a {MAX_NAME_LEN}-byte bound",
                    element.name.len()
                );
                assert!(
                    element.attribute_count() <= MAX_ATTRIBUTES,
                    "an element carried {} attributes past a bound of {MAX_ATTRIBUTES}",
                    element.attribute_count()
                );
                materialised = materialised.saturating_add(element.name.len());
                for attribute in element.attributes() {
                    assert!(
                        attribute.name.len() <= MAX_NAME_LEN,
                        "an attribute name of {} bytes passed a {MAX_NAME_LEN}-byte bound",
                        attribute.name.len()
                    );
                    assert!(
                        attribute.value.len() <= MAX_ATTRIBUTE_VALUE_LEN,
                        "an attribute value of {} bytes passed a {MAX_ATTRIBUTE_VALUE_LEN}-byte \
                         bound",
                        attribute.value.len()
                    );
                    assert!(
                        (attribute.name_offset as usize) < document.len()
                            && (attribute.value_offset as usize) <= document.len(),
                        "an attribute was reported outside the document it came from"
                    );
                    materialised = materialised.saturating_add(attribute.value.len());
                }
            }
            Ok(config::Event::End { name, offset }) => {
                events = events.saturating_add(1);
                depth = depth
                    .checked_sub(1)
                    .expect("the reader closed an element it never opened");
                assert!(
                    name.len() <= MAX_NAME_LEN,
                    "an end tag named {} bytes past a {MAX_NAME_LEN}-byte bound",
                    name.len()
                );
                assert!(
                    (offset as usize) <= document.len(),
                    "an element was reported closing outside the document"
                );
            }
            Err(error) => {
                assert!(
                    (error.offset as usize) <= document.len(),
                    "a rejection at offset {} points past a {}-byte document",
                    error.offset,
                    document.len()
                );
                refused = true;
            }
        }
    }

    // The reader is fused on a rejection, so a refused document must have
    // stopped there; a clean one must have closed everything it opened.
    if !refused {
        assert_eq!(depth, 0, "the reader ran out with an element still open");
    }

    // The two boundedness claims, counted over markup events — the terminal
    // rejection is one item and no work. An element costs at least the four
    // bytes of `<x/>` for the two events it produces, and an attribute costs at
    // least the four bytes of `x=""` around whatever its value expands to, so
    // neither quantity can outgrow the document unless something in the reader
    // is manufacturing work from nothing, which is what an expansion attack is.
    assert!(
        events.saturating_mul(2) <= document.len(),
        "{events} events came out of a {}-byte document",
        document.len()
    );
    assert!(
        materialised <= document.len(),
        "the reader materialised {materialised} bytes from a {}-byte document",
        document.len()
    );
}

/// A rejection an operator can act on: a reason, and somewhere to look.
///
/// The offset is the whole of what a refusal says about position — the bytes
/// are deliberately not carried onto any exposed surface — so an offset outside the document is
/// a refusal nobody can act on. The size refusal is reported at the bound
/// rather than at a scanned position, and it is only reached by a document
/// longer than that, so it lies inside too and needs no exemption here.
fn assert_rejection_is_locatable(error: ConfigError, document: &[u8]) {
    // `reason()` is total over the closed vocabulary by construction; what is
    // worth asserting is the position, which is a computed value.
    let _ = error.reason();
    if let ConfigError::Document(fault) = error {
        assert!(
            (fault.offset as usize) <= document.len(),
            "a rejection at offset {} points past a {}-byte document",
            fault.offset,
            document.len()
        );
    }
}

/// A model the reader accepted must fit the region the dataplane reads it out
/// of. The reader is what enforces this, so it is asserted against the reader's
/// output rather than trusted from its source.
fn assert_model_fits_the_handover_image(model: &Model) {
    assert!(
        model.interface_count() <= wire::MAX_INTERFACES,
        "an accepted model holds {} interfaces, past the {} the image carries",
        model.interface_count(),
        wire::MAX_INTERFACES
    );
    assert!(
        model.neighbour_count() <= wire::MAX_NEIGHBOURS,
        "an accepted model holds {} neighbours, past the {} the image carries",
        model.neighbour_count(),
        wire::MAX_NEIGHBOURS
    );
}

/// The cross-crate claim in one direction: what this crate accepts, the domain
/// that consumes its output accepts. A validator able to produce an image its
/// own reader refused would fail the appliance closed for a reason nobody could
/// act on.
///
/// Only that direction, and the other one matters more: an image the consumer
/// accepts must be one the rules would have accepted, because the domain writing
/// that region is the one parsing the bytes below and a rule only this crate
/// enforced would not survive a compromise of it. A document is the wrong input
/// to assert it from — it reaches the region only through a validator that has
/// already refused everything — so it is asserted over arbitrary *images*
/// instead, by `config`'s own
/// `every_image_the_consumer_accepts_is_one_validation_would_have_accepted`.
fn assert_artifacts_agree(model: &Model) {
    for generation in GENERATIONS {
        let image = image_from(model, Generation::from_bits(generation))
            .expect("a validated model builds a handover image");
        assert_eq!(image.generation, generation);
        // Built sealed, which is what the consumer's own digest check is against:
        // a builder that left the image unsealed would have every generation
        // refused on the far side of the region.
        assert_eq!(image.digest, image.computed_digest());

        let checked = image
            .check(PORT_COUNT)
            .expect("the consuming domain refused an image this crate produced");
        assert_eq!(checked.generation(), generation);
        assert_eq!(checked.interface_count(), model.interface_count());
        assert_eq!(checked.neighbour_count(), model.neighbour_count());

        // The table the consuming domain builds out of the image it was handed
        // — the only one any traffic is decided by. Every entry the consumer
        // decodes must reach it on the port the document's own reference
        // resolved to, which nothing but a build of both sides can observe.
        let table: routing::Router<{ wire::MAX_INTERFACES }, { wire::MAX_NEIGHBOURS }> =
            pd_runtime::router_from(&checked)
                .expect("the consuming domain could not hold an image it accepted");
        for interface in checked.interfaces() {
            let entry = table
                .interface(routing::PortId(interface.port()))
                .expect("an interface the image carries is one the table routes on");
            assert_eq!(entry.mac.0, interface.mac());
            assert_eq!(entry.address.octets(), interface.address());
            assert_eq!(entry.prefix_length, interface.prefix_length());
            assert_eq!(entry.enabled, interface.enabled());
        }
        for neighbour in checked.neighbours() {
            let entry = table
                .neighbour(
                    routing::PortId(neighbour.port()),
                    net_headers::Ipv4Address::from_octets(neighbour.address()),
                )
                .expect("a neighbour the image carries is one the table can send to");
            assert_eq!(entry.mac.0, neighbour.mac());
        }
    }
}
