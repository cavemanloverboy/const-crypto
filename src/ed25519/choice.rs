/// The `Choice` struct represents a choice for use in conditional
/// assignment.
///
/// It is a wrapper around a `u8`, which should have the value either
/// `1` (true) or `0` (false).
///
/// The conversion from `u8` to `Choice` passes the value through an
/// optimization barrier, as a best-effort attempt to prevent the
/// compiler from inferring that the `Choice` value is a boolean. This
/// strategy is based on Tim Maclean's
/// [work on `rust-timing-shield`][rust-timing-shield], which attempts
/// to provide a more comprehensive approach for preventing software
/// side-channels in Rust code.
///
/// The `Choice` struct implements operators for AND, OR, XOR, and NOT,
/// to allow combining `Choice` values. These operations do not
/// short-circuit.
///
/// [rust-timing-shield]:
/// https://www.chosenplaintext.ca/open-source/rust-timing-shield/security
#[derive(Copy, Clone, Debug)]
pub struct Choice(u8);

impl Choice {
    /// Unwrap the `Choice` wrapper to reveal the underlying `u8`.
    ///
    /// # Note
    ///
    /// This function only exists as an **escape hatch** for the rare
    /// case where it's not possible to use one of the
    /// `subtle`-provided trait impls.
    ///
    /// **To convert a `Choice` to a `bool`, use the `From`
    /// implementation instead.**
    #[inline]
    pub const fn unwrap_u8(&self) -> u8 {
        self.0
    }

    pub const fn into(self) -> bool {
        self.0 != 0
    }

    #[inline]
    pub(crate) const fn from_u8(input: u8) -> Choice {
        Choice(input)
    }
}

impl From<Choice> for bool {
    /// Convert the `Choice` wrapper into a `bool`, depending on whether
    /// the underlying `u8` was a `0` or a `1`.
    ///
    /// # Note
    ///
    /// This function exists to avoid having higher-level cryptographic
    /// protocol implementations duplicating this pattern.
    ///
    /// The intended use case for this conversion is at the _end_ of a
    /// higher-level primitive implementation: for example, in checking
    /// a keyed MAC, where the verification should happen in
    /// constant-time (and thus use a `Choice`) but it is safe to
    /// return a `bool` at the end of the verification.
    #[inline]
    fn from(source: Choice) -> bool {
        debug_assert!((source.0 == 0u8) | (source.0 == 1u8));
        source.0 != 0
    }
}
