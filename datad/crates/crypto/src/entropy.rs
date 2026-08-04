/// The appliance's source of randomness, as the only shape anything here takes
/// it in.
///
/// A trait rather than the generator itself, and a shared borrow rather than a
/// mutable one, for two reasons that point the same way. The generator has
/// state and the domain that owns it is the only place that may hold that
/// state mutably — so the seam is here. And the TLS library's own randomness
/// interface is this exact shape, which means the appliance has one source and
/// not two: what keys a session is what proved its own vectors at boot.
///
/// Infallible by contract. A generator that cannot answer is not one a caller
/// can do anything about at the point of the call — the node has no second
/// source — so the failure belongs at seeding, where it refuses the domain,
/// and not at every draw.
pub trait Entropy: Send + Sync {
    fn fill(&self, out: &mut [u8]);
}
