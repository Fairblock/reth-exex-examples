
use std::fmt;

use ark_bls12_381::{
    g1, g2, Bls12_381, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{
    de::{self, SeqAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};


// Constand variables
pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
pub const G2_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// Structs
#[derive(Clone)]
pub struct ExtractedKey {
    pub(crate) sk: G2Projective, 
    pub(crate) index: u32,       
}

impl Serialize for ExtractedKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        
        let mut state = serializer.serialize_struct("ExtractedKey", 2)?;

        
        let mut compressed_sk = Vec::new();
        self.sk.serialize_compressed(&mut compressed_sk).map_err(serde::ser::Error::custom)?; 
        state.serialize_field("sk", &compressed_sk)?; 

        
        state.serialize_field("index", &self.index)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for ExtractedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ExtractedKeyVisitor;

        impl<'de> Visitor<'de> for ExtractedKeyVisitor {
            type Value = ExtractedKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ExtractedKey")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
               
                let sk_bytes: Vec<u8> =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let sk =
                    G2Projective::deserialize_compressed(&*sk_bytes).map_err(de::Error::custom)?;

              
                let index: u32 =
                    seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;

                Ok(ExtractedKey { sk, index })
            }
        }

        deserializer.deserialize_struct("ExtractedKey", &["sk", "index"], ExtractedKeyVisitor)
    }
}

pub struct Commitment {
    pub(crate) index: u32,
    pub(crate) commitment_point: G1Projective,
}