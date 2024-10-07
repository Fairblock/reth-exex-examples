use std::fmt;

use ark_bls12_381::{
    g1, g2, Bls12_381, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::crypto::data::{ExtractedKey, G2_DOMAIN};
use sha2;

pub fn extract(share: Vec<u8>, id: Vec<u8>, index: u32) -> Result<Vec<u8>, String> {
    let share_scalar = ScalarField::from_be_bytes_mod_order(&share);
    let mapper = MapToCurveBasedHasher::<
        short_weierstrass::Projective<g2::Config>,
        DefaultFieldHasher<sha2::Sha256, 128>,
        WBMap<g2::Config>,
    >::new(G2_DOMAIN)
    .unwrap();
    let m = mapper.hash(&id).unwrap();
    let qid = G2Projective::from(m);
    let keyshare = qid * share_scalar;
    let key = ExtractedKey { sk: keyshare, index };
    let mut serialized = serde_json::to_string(&key).unwrap();
    let mut s = Vec::new();
    unsafe {
        s = serialized.as_mut_vec().to_vec();
    }
    return Ok(s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr as ScalarField;
    use ark_ff::Field;

    #[test]
    fn test_extract_valid() {
        let share = vec![
            106, 250, 237, 43, 170, 164, 149, 131, 44, 186, 221, 46, 51, 171, 92, 234, 183, 38, 31,
            236, 170, 108, 135, 170, 164, 223, 177, 98, 121, 129, 93, 244,
        ];
        let id = vec![51, 48, 48];
        let index = 3;

        let result = extract(share, id, index);

        assert!(result.is_ok(), "Expected Ok result, got Err");
        let extracted_data = result.unwrap();
        let expected_sk = vec![
            185, 4, 20, 236, 114, 8, 167, 114, 231, 89, 101, 163, 212, 107, 168, 114, 89, 28, 161,
            66, 22, 184, 62, 148, 38, 161, 47, 198, 149, 180, 141, 33, 10, 11, 230, 78, 129, 106,
            150, 114, 157, 149, 66, 82, 238, 32, 175, 133, 3, 65, 11, 146, 37, 246, 169, 192, 22,
            147, 140, 187, 211, 106, 246, 174, 36, 25, 74, 116, 197, 52, 241, 154, 179, 190, 211,
            196, 97, 67, 54, 45, 215, 97, 49, 42, 76, 91, 90, 91, 103, 84, 34, 145, 139, 28, 92,
            119,
        ];
        let sk = G2Projective::deserialize_compressed(expected_sk.as_slice()).unwrap();
        let key = ExtractedKey { sk, index };
        let mut serialized = serde_json::to_string(&key).unwrap();
        let mut s = Vec::new();
        unsafe {
            s = serialized.as_mut_vec().to_vec();
        }
        assert_eq!(extracted_data, s);
    }
}
