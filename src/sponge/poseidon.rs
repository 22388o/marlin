use core::marker::PhantomData;

use ark_ff::{FpParameters, PrimeField};
use ark_sponge::poseidon::PoseidonParameters;

use super::CryptographicSpongeParameters;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoseidonArguments<F: PrimeField> {
    pub prime_bits: u64,
    pub full_rounds: u32,
    pub partial_rounds: u32,
    pub skip_matrices: u64,

    _field: PhantomData<F>,
}

impl<F: PrimeField> PoseidonArguments<F> {
    pub const DEFAULT: Self = Self {
        prime_bits: F::Params::MODULUS_BITS as u64,
        full_rounds: 8,
        partial_rounds: 60,
        skip_matrices: 0,
        _field: PhantomData,
    };
}

impl<F: PrimeField> CryptographicSpongeParameters for PoseidonParameters<F> {
    fn from_rate(rate: usize) -> Self {
        let PoseidonArguments {
            prime_bits,
            full_rounds,
            partial_rounds,
            skip_matrices,
            ..
        } = PoseidonArguments::<F>::DEFAULT;

        // TODO consume the arguments
        let capacity = 1;
        let alpha = 5;
        let _ = (rate, prime_bits, skip_matrices);

        // TODO generate secure constants
        let ark = F::one();
        let ark = vec![ark; 3];
        let ark = vec![ark; (full_rounds + partial_rounds) as usize];

        // TODO generate secure matrix
        let mds = F::one();
        let mds = vec![mds; rate + capacity];
        let mds = vec![mds; rate + capacity];

        Self::new(full_rounds, partial_rounds, alpha, mds, ark)
    }
}
