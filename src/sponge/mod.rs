use ark_ff::PrimeField;
use ark_nonnative_field::NonNativeFieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_sponge::{
    constraints::CryptographicSpongeVar, poseidon::PoseidonSponge, CryptographicSponge,
};

pub mod poseidon;

pub trait CryptographicSpongeParameters {
    fn from_rate(rate: usize) -> Self;
}

pub trait CryptographicSpongeWithRate: CryptographicSponge
where
    <Self as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
{
    fn from_rate(rate: usize) -> Self {
        let params =
            <<Self as CryptographicSponge>::Parameters as CryptographicSpongeParameters>::from_rate(
                rate,
            );

        <Self as CryptographicSponge>::new(&params)
    }
}

impl<F: PrimeField> CryptographicSpongeWithRate for PoseidonSponge<F> {}

pub trait CryptographicSpongeVarNonNative<F: PrimeField, CF: PrimeField, S: CryptographicSponge>:
    CryptographicSpongeVar<CF, S>
where
    <Self as CryptographicSpongeVar<CF, S>>::Parameters: CryptographicSpongeParameters,
{
    fn from_rate(cs: ConstraintSystemRef<CF>, rate: usize) -> Self {
        let params =
            <<Self as CryptographicSpongeVar<CF, S>>::Parameters as CryptographicSpongeParameters>::from_rate(
                rate,
            );

        <Self as CryptographicSpongeVar<CF, S>>::new(cs, &params)
    }

    /// Absorb non native `CF` elements
    fn absorb_nonnative(
        &mut self,
        input: &[NonNativeFieldVar<F, CF>],
    ) -> Result<(), SynthesisError>;
}
