use ark_bls12_381::Fr as ScalarField;
use ark_bls12_381::G1Projective;

use crate::crypto::data::{ExtractedKey,Commitment};
use crate::crypto::data::G2_DOMAIN;
use ark_bls12_381::{g1, g2, Bls12_381, G1Affine, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2;


pub fn aggregate_sk(
    received_shares: Vec<ExtractedKey>,
    commitments: Vec<Commitment>,
    id: &[u8],
) -> (G2Projective, Vec<u32>) {
    let mut sk_shares: Vec<G2Projective> = Vec::new();
    let mut invalid: Vec<u32> = Vec::new();
    let mut valid: Vec<u32> = Vec::new();
    let mut valid_share: Vec<ExtractedKey> = Vec::new();

    for (i, received_share) in received_shares.iter().enumerate() {
        let commitment = &commitments[i];

        // let mapper = MapToCurveBasedHasher::<
        //     short_weierstrass::Projective<g2::Config>,
        //     DefaultFieldHasher<sha2::Sha256, 128>,
        //     WBMap<g2::Config>,
        // >::new(G2_DOMAIN)
        // .unwrap();

       // let q_id = G2Projective::from(mapper.hash(&id).unwrap());
        // if verify_share(commitment, received_share, q_id) {
        if true {
            valid.push(received_share.index);
            valid_share.push(received_share.clone());
        } else {
            invalid.push(commitment.index);
        }
    }

    for r in valid_share {
        let processed_share = process_sk(r, &valid);
        sk_shares.push(processed_share.sk);
    }

    let sk = aggregate(sk_shares);
    (sk, invalid)
}


fn process_sk(share: ExtractedKey, s: &[u32]) -> ExtractedKey {
    let lagrange_coef = lagrange_coefficient(share.index, s);
    let identity_key = share.sk * lagrange_coef;
    ExtractedKey { sk: identity_key, index: share.index }
}


fn aggregate(keys: Vec<G2Projective>) -> G2Projective {
    let mut sk = keys[0].clone();
    for key in keys.iter().skip(1) {
        sk = sk + key;
    }
    sk
}

fn lagrange_coefficient(signer: u32, s: &[u32]) -> ScalarField {
    let mut nominator = ScalarField::from(1 as i64);
    let mut denominator = ScalarField::from(1 as i64);

    for &si in s {
        if si != signer {
            let temp = ScalarField::from(si as i64);
            nominator = nominator * temp;

            let temp_si = ScalarField::from(si as i64);
            let temp_signer = ScalarField::from(signer as i64);
            let diff = temp_si - temp_signer;

            denominator = denominator * diff;
        }
    }

    let out_scalar = nominator / denominator;

    out_scalar
}

// // Function to verify a share using pairing operations
// fn verify_share(

//     commitment: &Commitment,
//     share: &ExtractedKey,
//     qid: G1Projective
// ) -> bool {
//     let a = commitment.commitment_point * qid;
//     let b = G1Projective::default() * share.sk;
//     a == b
// }

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{G1Projective, G2Projective};
    use ark_ff::UniformRand;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::thread_rng;

    use crate::crypto::data::ExtractedKey;

    #[test]
    fn test_aggregate_sk() {
       
        let mut rng = thread_rng();
        let id = b"test_identifier";

        let commitments = vec![
            Commitment { index: 1, commitment_point: G1Projective::rand(&mut rng) },
            Commitment { index: 2, commitment_point: G1Projective::rand(&mut rng) },
        ];
        let sk1: Vec<u8> = vec![
            134, 204, 168, 146, 231, 90, 225, 93, 242, 197, 163, 242, 245, 17, 151, 152, 184, 49,
            253, 23, 48, 82, 225, 52, 18, 141, 237, 6, 34, 118, 110, 200, 228, 94, 24, 223, 70,
            204, 244, 254, 154, 144, 238, 36, 253, 70, 18, 158, 9, 150, 26, 40, 126, 64, 36, 142,
            94, 165, 197, 5, 5, 19, 178, 22, 169, 43, 184, 28, 164, 205, 163, 39, 27, 224, 153,
            215, 119, 223, 3, 177, 173, 10, 64, 201, 14, 212, 21, 122, 59, 230, 229, 221, 247, 153,
            250, 198,
        ];
        let sk2: Vec<u8> = vec![
            143, 211, 212, 47, 82, 229, 172, 29, 188, 3, 188, 192, 46, 37, 145, 221, 180, 16, 132,
            65, 173, 239, 239, 183, 142, 141, 215, 87, 52, 218, 222, 144, 238, 59, 215, 110, 88,
            112, 209, 158, 22, 175, 80, 198, 164, 19, 193, 41, 5, 82, 191, 71, 139, 206, 124, 38,
            18, 65, 121, 180, 26, 61, 192, 184, 160, 98, 45, 34, 136, 248, 27, 80, 95, 216, 201,
            60, 202, 73, 77, 62, 26, 224, 101, 114, 75, 220, 61, 10, 137, 95, 146, 159, 218, 171,
            0, 89,
        ];
        let received_shares = vec![
            ExtractedKey {
                sk: G2Projective::deserialize_compressed(sk1.as_slice()).unwrap(),
                index: 1,
            },
            ExtractedKey {
                sk: G2Projective::deserialize_compressed(sk2.as_slice()).unwrap(),
                index: 3,
            },
        ];
        let expected_sk = vec![
            144, 23, 207, 26, 116, 2, 169, 145, 130, 9, 165, 13, 125, 119, 87, 43, 201, 243, 85,
            166, 24, 7, 237, 120, 202, 99, 33, 108, 218, 26, 93, 133, 204, 172, 33, 76, 149, 202,
            34, 231, 81, 126, 38, 49, 98, 85, 237, 182, 10, 97, 160, 10, 31, 125, 151, 77, 70, 107,
            214, 233, 81, 199, 141, 75, 100, 229, 83, 216, 90, 77, 130, 18, 80, 110, 107, 70, 55,
            21, 121, 39, 248, 229, 27, 238, 128, 27, 233, 43, 18, 58, 228, 106, 143, 36, 115, 172,
        ];
        
        let (aggregated_sk, invalid) = aggregate_sk(received_shares.clone(), commitments, id);
        let mut s = Vec::new();
        let _ = aggregated_sk.serialize_compressed(&mut s);
        assert_eq!(s, expected_sk);
    }
}
