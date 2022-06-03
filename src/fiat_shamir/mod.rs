use crate::{CryptographicSpongeParameters, CryptographicSpongeWithRate, Vec};
use ark_ff::{BigInteger, PrimeField};
use ark_nonnative_field::params::{get_params, OptimizationType};
use ark_nonnative_field::AllocatedNonNativeFieldVar;
use ark_sponge::{Absorb, CryptographicSponge};
use ark_std::marker::PhantomData;
use ark_std::rand::{RngCore, SeedableRng};
use core::cmp;
use digest::Digest;
use rand_chacha::ChaChaRng;

/// The constraints for Fiat-Shamir
pub mod constraints;

/// a macro for computing ceil(log2(x))+1 for a field element x
#[doc(hidden)]
#[macro_export]
macro_rules! overhead {
    ($x:expr) => {{
        use ark_ff::BigInteger;
        let num = $x;
        let num_bits = num.into_repr().to_bits_be();
        let mut skipped_bits = 0;
        for b in num_bits.iter() {
            if *b == false {
                skipped_bits += 1;
            } else {
                break;
            }
        }

        let mut is_power_of_2 = true;
        for b in num_bits.iter().skip(skipped_bits + 1) {
            if *b == true {
                is_power_of_2 = false;
            }
        }

        if is_power_of_2 {
            num_bits.len() - skipped_bits
        } else {
            num_bits.len() - skipped_bits + 1
        }
    }};
}

/// use a ChaCha stream cipher to generate the actual pseudorandom bits
/// use a digest funcion to do absorbing
pub struct FiatShamirChaChaRng<F: PrimeField, CF: PrimeField, D: Digest> {
    pub r: ChaChaRng,
    pub seed: Vec<u8>,
    #[doc(hidden)]
    field: PhantomData<F>,
    representation_field: PhantomData<CF>,
    digest: PhantomData<D>,
}

impl<F: PrimeField, CF: PrimeField, D: Digest> Clone for FiatShamirChaChaRng<F, CF, D> {
    fn clone(&self) -> Self {
        Self {
            r: self.r.clone(),
            seed: self.seed.clone(),
            field: PhantomData,
            representation_field: PhantomData,
            digest: PhantomData,
        }
    }
}

impl<F: PrimeField, CF: PrimeField, D: Digest> RngCore for FiatShamirChaChaRng<F, CF, D> {
    fn next_u32(&mut self) -> u32 {
        self.r.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.r.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.r.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.r.try_fill_bytes(dest)
    }
}

impl<F: PrimeField, CF: PrimeField, D: Digest> CryptographicSponge
    for FiatShamirChaChaRng<F, CF, D>
{
    type Parameters = ();

    fn new(_params: &Self::Parameters) -> Self {
        let seed = [0; 32];
        let r = ChaChaRng::from_seed(seed);

        Self {
            r,
            seed: seed.to_vec(),
            field: PhantomData,
            representation_field: PhantomData,
            digest: PhantomData,
        }
    }

    fn absorb(&mut self, input: &impl Absorb) {
        let bytes = input.to_sponge_bytes_as_vec();

        self.seed = D::digest(&bytes).to_vec();

        let l = cmp::min(32, self.seed.len());
        let mut seed = [0u8; 32];

        (&mut seed[..l]).copy_from_slice(&self.seed[..l]);

        self.r = ChaChaRng::from_seed(seed);
    }

    fn squeeze_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let mut output = vec![0u8; num_bytes];

        self.fill_bytes(output.as_mut_slice());

        output
    }

    fn squeeze_bits(&mut self, num_bits: usize) -> Vec<bool> {
        self.squeeze_bytes(num_bits)
            .into_iter()
            .map(|b| (b & 0x01) == 1)
            .collect()
    }
}

/// rng from any algebraic sponge
pub struct FiatShamirRng<F: PrimeField, CF: PrimeField, S: CryptographicSpongeWithRate>
where
    <S as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
{
    pub s: S,
    #[doc(hidden)]
    f_phantom: PhantomData<F>,
    cf_phantom: PhantomData<CF>,
}

impl<F: PrimeField, CF: PrimeField, S: CryptographicSpongeWithRate> FiatShamirRng<F, CF, S>
where
    CF: Absorb,
    <S as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
{
    pub fn new(rate: usize) -> Self {
        Self {
            s: S::from_rate(rate),
            f_phantom: PhantomData,
            cf_phantom: PhantomData,
        }
    }

    /// compress every two elements if possible. Provides a vector of (limb, num_of_additions), both of which are P::BaseField.
    pub fn compress_elements(src_limbs: &[(CF, CF)], ty: OptimizationType) -> Vec<CF> {
        let capacity = CF::size_in_bits() - 1;
        let mut dest_limbs = Vec::<CF>::new();

        let params = get_params(F::size_in_bits(), CF::size_in_bits(), ty);

        let adjustment_factor_lookup_table = {
            let mut table = Vec::<CF>::new();

            let mut cur = CF::one();
            for _ in 1..=capacity {
                table.push(cur);
                cur.double_in_place();
            }

            table
        };

        let mut i = 0;
        let src_len = src_limbs.len();
        while i < src_len {
            let first = &src_limbs[i];
            let second = if i + 1 < src_len {
                Some(&src_limbs[i + 1])
            } else {
                None
            };

            let first_max_bits_per_limb = params.bits_per_limb + overhead!(first.1 + &CF::one());
            let second_max_bits_per_limb = if let Some(second) = second {
                params.bits_per_limb + overhead!(second.1 + &CF::one())
            } else {
                0
            };

            if let Some(second) = second {
                if first_max_bits_per_limb + second_max_bits_per_limb <= capacity {
                    let adjustment_factor =
                        &adjustment_factor_lookup_table[second_max_bits_per_limb];

                    dest_limbs.push(first.0 * adjustment_factor + &second.0);
                    i += 2;
                } else {
                    dest_limbs.push(first.0);
                    i += 1;
                }
            } else {
                dest_limbs.push(first.0);
                i += 1;
            }
        }

        dest_limbs
    }

    /// push elements to sponge, treated in the non-native field representations.
    pub fn push_elements_to_sponge(sponge: &mut S, src: &[F], ty: OptimizationType) {
        let mut src_limbs = Vec::<(CF, CF)>::new();

        for elem in src.iter() {
            let limbs =
                AllocatedNonNativeFieldVar::<F, CF>::get_limbs_representations(elem, ty).unwrap();
            for limb in limbs.iter() {
                src_limbs.push((*limb, CF::one()));
                // specifically set to one, since most gadgets in the constraint world would not have zero noise (due to the relatively weak normal form testing in `alloc`)
            }
        }

        let dest_limbs = Self::compress_elements(&src_limbs, ty);
        sponge.absorb(&dest_limbs);
    }

    /// obtain random elements from hashchain.
    /// not guaranteed to be uniformly distributed, should only be used in certain situations.
    pub fn get_elements_from_sponge(
        sponge: &mut S,
        num_elements: usize,
        outputs_short_elements: bool,
    ) -> Vec<F> {
        let num_bits_per_nonnative = if outputs_short_elements {
            128
        } else {
            F::size_in_bits() - 1 // also omit the highest bit
        };
        let bits = sponge.squeeze_bits(num_bits_per_nonnative * num_elements);

        let mut lookup_table = Vec::<F>::new();
        let mut cur = F::one();
        for _ in 0..num_bits_per_nonnative {
            lookup_table.push(cur);
            cur.double_in_place();
        }

        let mut dest_elements = Vec::<F>::new();
        bits.chunks_exact(num_bits_per_nonnative)
            .for_each(|per_nonnative_bits| {
                // technically, this can be done via BigInterger::from_bits; here, we use this method for consistency with the gadget counterpart
                let mut res = F::zero();

                for (i, bit) in per_nonnative_bits.iter().rev().enumerate() {
                    if *bit {
                        res += &lookup_table[i];
                    }
                }

                dest_elements.push(res);
            });

        dest_elements
    }
}

impl<F: PrimeField, CF: PrimeField, S: CryptographicSpongeWithRate> RngCore
    for FiatShamirRng<F, CF, S>
where
    <S as CryptographicSponge>::Parameters: CryptographicSpongeParameters,
{
    fn next_u32(&mut self) -> u32 {
        assert!(
            CF::size_in_bits() > 128,
            "The native field of the algebraic sponge is too small."
        );

        let mut dest = [0u8; 4];
        self.fill_bytes(&mut dest);

        u32::from_be_bytes(dest)
    }

    fn next_u64(&mut self) -> u64 {
        assert!(
            CF::size_in_bits() > 128,
            "The native field of the algebraic sponge is too small."
        );

        let mut dest = [0u8; 8];
        self.fill_bytes(&mut dest);

        u64::from_be_bytes(dest)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        assert!(
            CF::size_in_bits() > 128,
            "The native field of the algebraic sponge is too small."
        );

        let capacity = CF::size_in_bits() - 128;
        let len = dest.len() * 8;

        let num_of_elements = (capacity + len - 1) / len;
        let elements: Vec<CF> = self.s.squeeze_field_elements(num_of_elements);

        let mut bits = Vec::<bool>::new();
        for elem in elements.iter() {
            let mut elem_bits = elem.into_repr().to_bits_be();
            elem_bits.reverse();
            bits.extend_from_slice(&elem_bits[0..capacity]);
        }

        bits.truncate(len);
        bits.chunks_exact(8)
            .enumerate()
            .for_each(|(i, bits_per_byte)| {
                let mut byte = 0;
                for (j, bit) in bits_per_byte.iter().enumerate() {
                    if *bit {
                        byte += 1 << j;
                    }
                }
                dest[i] = byte;
            });
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        assert!(
            CF::size_in_bits() > 128,
            "The native field of the algebraic sponge is too small."
        );

        self.fill_bytes(dest);
        Ok(())
    }
}
