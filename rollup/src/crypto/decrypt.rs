use ic_bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use std::{
    io::{Error, ErrorKind},
    result,
    str::FromStr,
    vec,
};

use base64::{engine::general_purpose, write::EncoderWriter, Engine};
use chacha20poly1305::{
    aead::{self, generic_array::typenum::Len, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};

use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::io::{self, BufRead, BufReader};
use std::io::{Read, Result, Write};

use aead::Aead;

// Constants
const INTRO: &str = "age-encryption.org/v1";

const RECIPIENT_PREFIX: &[u8] = b"->";

const FOOTER_PREFIX: &[u8] = b"---";

const COLUMNS_PER_LINE: usize = 64;
const BYTES_PER_LINE: usize = COLUMNS_PER_LINE / 4 * 3;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16; // Poly1305 tag size in bytes
const ENC_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;
const LAST_CHUNK_FLAG: u8 = 0x01;
const kyber_point_len: usize = 48;
const cipher_v_len: usize = 32;
const cipher_w_len: usize = 32;


pub struct Ciphertext {
    pub u: G1Affine,
    pub v: Vec<u8>,
    pub w: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn it_works() {
        let c = [
            97, 103, 101, 45, 101, 110, 99, 114, 121, 112, 116, 105, 111, 110, 46, 111, 114, 103,
            47, 118, 49, 10, 45, 62, 32, 100, 105, 115, 116, 73, 66, 69, 10, 114, 119, 108, 71,
            114, 52, 87, 104, 109, 51, 99, 108, 73, 107, 120, 69, 47, 70, 87, 72, 114, 89, 75, 51,
            68, 76, 88, 118, 65, 109, 107, 54, 98, 97, 75, 118, 54, 54, 86, 104, 77, 73, 88, 101,
            120, 105, 117, 105, 75, 115, 57, 97, 113, 51, 73, 65, 120, 121, 118, 86, 113, 122, 71,
            113, 10, 67, 97, 71, 105, 102, 77, 67, 98, 52, 52, 97, 114, 88, 83, 52, 112, 116, 47,
            90, 82, 55, 107, 99, 53, 119, 67, 116, 56, 117, 83, 78, 80, 112, 51, 106, 81, 43, 84,
            76, 87, 113, 110, 69, 83, 43, 119, 73, 80, 82, 57, 89, 98, 120, 65, 47, 85, 102, 105,
            120, 81, 111, 121, 84, 48, 10, 54, 106, 120, 70, 115, 119, 108, 78, 71, 81, 50, 85, 57,
            111, 89, 117, 112, 47, 83, 57, 112, 81, 10, 45, 45, 45, 32, 82, 71, 75, 80, 115, 55,
            88, 66, 107, 54, 72, 48, 83, 77, 74, 113, 82, 122, 105, 66, 86, 103, 87, 102, 82, 48,
            53, 68, 104, 97, 110, 105, 75, 48, 66, 114, 50, 116, 78, 99, 121, 99, 56, 10, 152, 214,
            234, 209, 59, 136, 118, 65, 151, 122, 93, 188, 167, 183, 26, 167, 161, 112, 12, 1, 100,
            175, 60, 231, 243, 212, 87, 231, 69, 134, 44, 102, 192, 116, 173, 224, 188, 200, 215,
            193, 167, 157, 199, 46, 170, 65, 46, 6, 157, 208, 104, 12, 188, 112, 7, 18, 16, 169,
            92, 172, 126, 78, 40, 149, 215,
        ];
        let mut cursor = Cursor::new(c);

        let skbytes = [
            180, 94, 231, 64, 60, 139, 63, 77, 251, 219, 173, 163, 74, 124, 6, 10, 129, 139, 151,
            186, 102, 134, 86, 99, 150, 127, 59, 169, 18, 212, 67, 132, 48, 180, 58, 172, 181, 219,
            30, 166, 33, 104, 186, 198, 23, 29, 20, 141, 15, 107, 179, 56, 147, 33, 220, 105, 191,
            20, 32, 206, 3, 203, 206, 179, 228, 207, 247, 100, 37, 47, 155, 29, 212, 118, 240, 159,
            79, 249, 88, 182, 208, 106, 20, 154, 236, 61, 92, 86, 122, 253, 31, 5, 161, 65, 125,
            200,
        ];
        // let skey_vec:&[u8] = skbytes.as_mut();
        let sk = G2Affine::from_compressed(&skbytes).unwrap();

      

        let reader = Decrypt(&sk, &mut cursor);

        match String::from_utf8(reader) {
            Ok(s) => assert_eq!(s, "Decyption Test For Arbitrum Works"),
            Err(e) => eprintln!("Invalid UTF-8 sequence: {}", e),
        }
    }
}


pub fn decrypt_tx(tx: &[u8], skbytes: &[u8; 96]) -> Vec<u8> {
    let sk = G2Affine::from_compressed(skbytes).unwrap();

    let mut cursor = Cursor::new(tx);
    let decrypted = Decrypt(&sk, &mut cursor);
    return decrypted;
}


struct Header {
    recipients: Vec<Box<Stanza>>, // Vec of boxed (heap-allocated) Stanza objects
    mac: Vec<u8>,                 // Vec<u8> is equivalent to a slice of bytes ([]byte in Go)
}

fn split_args(line: &[u8]) -> (String, Vec<String>) {
    let line_str = String::from_utf8_lossy(line);
    let trimmed_line = line_str.trim_end_matches('\n');
    let parts: Vec<String> = trimmed_line.split_whitespace().map(String::from).collect();

    if !parts.is_empty() {
        (parts[0].clone(), parts[1..].to_vec())
    } else {
        (String::new(), Vec::new())
    }
}

fn decode_string(s: &str) -> Vec<u8> {
    general_purpose::STANDARD_NO_PAD.decode(s).unwrap()
}

fn is_valid_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars().all(|c| (33..=126).contains(&(c as u32)))
}

fn parse<'a, R: Read + 'a>(input: R) -> io::Result<(Header, Box<dyn Read + 'a>)> {
    let mut rr = BufReader::new(input);
    let mut line = String::new();

    // Read the intro line
    rr.read_line(&mut line)?;
    if line.trim_end() != INTRO {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected intro: {} {}", line, line.trim_end()),
        ));
    }

    let mut h = Header {
        recipients: Vec::new(),
        mac: Vec::new(),
    };
    let mut r: Option<Stanza> = None;

    loop {
        let mut line_bytes = Vec::new();
        let bytes_read = rr.read_until(b'\n', &mut line_bytes)?;
        if bytes_read == 0 {
            break;
        } // End of file or error

        let line = String::from_utf8_lossy(&line_bytes).into_owned();

        if line.as_bytes().starts_with(FOOTER_PREFIX) {
            if r.is_some() {
                return Err(io::Error::new(io::ErrorKind::Other, format!("malformed body line {}: reached footer without previous stanza being closed", line)));
            }
            let (prefix, args) = split_args(&line.as_bytes());
            if prefix.as_bytes() != FOOTER_PREFIX || args.len() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("malformed closing line: {}", line),
                ));
            }
            h.mac = decode_string(&args[0]); // Assuming decode_string is defined
            break;
        } else if line.as_bytes().starts_with(RECIPIENT_PREFIX) {
            if r.is_some() {
                return Err(io::Error::new(io::ErrorKind::Other, format!("malformed body line {}: new stanza started without previous stanza being closed", line)));
            }
            r = Some(Stanza {
                type_: String::new(),
                args: Vec::new(),
                body: Vec::new(),
            });
            let (prefix, args) = split_args(&line.as_bytes());

            if prefix.as_bytes() != RECIPIENT_PREFIX || args.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("malformed recipient: {}", line),
                ));
            }
            if args.iter().any(|a| !is_valid_string(a)) {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("malformed recipient: {}", line),
                ));
            }

            let stanza = r.as_mut().unwrap();
            stanza.type_ = args[0].clone();
            stanza.args = args[1..].to_vec();

            h.recipients.push(Box::new(stanza.clone()));
        } else if let Some(stanza) = r.as_mut() {
            let b = decode_string(&line.trim_end());
            if b.len() > BYTES_PER_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("malformed body line {}: too long", line),
                ));
            }
            h.recipients[0].body.extend_from_slice(&b);

            if b.len() < BYTES_PER_LINE {
                r = None; // Only the last line of a body can be short
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected line: {}", line),
            ));
        }
    }

    let mut payload = if rr.buffer().is_empty() {
        Box::new(rr.into_inner()) as Box<dyn Read>
    } else {
        let buffer = rr.buffer().to_vec();
        let remaining_input = rr.into_inner();
        Box::new(io::Cursor::new(buffer).chain(remaining_input)) as Box<dyn Read>
    };

    Ok((h, payload))
}
fn process_chunks_and_append(data: &[u8]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 64;
    let mut result = Vec::new();

    for chunk in data.chunks(CHUNK_SIZE) {
        // Append the chunk to the result vector.
        result.extend_from_slice(chunk);
        // Append [10] after the chunk.
        if (chunk.len() == 64) {
            result.push(10);
        }
    }

    result
}
impl Stanza {
    fn marshal<'a, W: Write>(&'a self, w: &'a mut W) -> &mut W {
        write!(w, "{}", "->");

        write!(w, " {}", self.type_);

        for arg in &self.args {
            write!(w, " {}", arg);
        }
        writeln!(w);
        let b = self.body.clone();
        let encoded: String = general_purpose::STANDARD_NO_PAD.encode(b.as_slice());
        let l = encoded.as_bytes().len() - 2;
        let enc = &encoded.as_bytes()[..l];
        let mut enc2 = &encoded.as_bytes()[l..];
        // panic!("{:?}", encoded.as_bytes());
        let new = process_chunks_and_append(enc);

        let mut ff: String = String::from_str("").unwrap();
        new.as_slice().read_to_string(&mut ff);
        write!(w, "{}", ff);

        let mut f: String = String::from_str("").unwrap();
        enc2.read_to_string(&mut f);
        write!(w, "{}", f);
        writeln!(w);
        // writeln!(w);
        w
    }
}
struct HmacWriter(Hmac<Sha256>);

impl HmacWriter {
    fn new(hmac: Hmac<Sha256>) -> Self {
        HmacWriter(hmac)
    }
}

impl Write for HmacWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
// Additional helper functions and modules (like 'armor' and 'parse') would be needed based on the actual 'ibe' package
impl Header {
    fn marshal_without_mac<W: Write>(&self, w: &mut W) -> io::Result<()> {
        writeln!(w, "{}", INTRO)?;
        for r in &self.recipients {
            r.marshal(w);
        }
        write!(w, "{}", "---")
    }
}

fn header_mac(file_key: &[u8], hdr: &Header) -> Vec<u8> {
    let h = Hkdf::<Sha256>::new(None, file_key);
    let mut hmac_key = [0u8; 32];
    h.expand(b"header", &mut hmac_key);

    let mut hh = Hmac::<Sha256>::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
    let mut hmac_writer = HmacWriter::new(hh.clone());
    hdr.marshal_without_mac(&mut hmac_writer);
    hh = hmac_writer.0;
    hh.finalize().into_bytes().to_vec()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stanza {
    type_: String, // 'type' is a reserved keyword in Rust, so we use 'type_'
    args: Vec<String>,
    body: Vec<u8>,
}

// Additional functions translated from the Go code
fn new_reader<R: Read>(key: &[u8], mut src: R) -> Vec<u8> {
    let aead_key = Key::from_slice(key);
    let a = ChaCha20Poly1305::new(aead_key);

    let mut s: Vec<u8> = vec![0];
    src.read_to_end(&mut s);

    let nonce = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let plain = a.decrypt(&Nonce::from_slice(&nonce), &s[1..]).unwrap();

    plain
}

fn stream_key(file_key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let h = Hkdf::<Sha256>::new(Some(nonce), file_key);
    let mut stream_key = vec![0u8; 32];

    h.expand(b"payload", &mut stream_key)
        .expect("age: internal error: failed to read from HKDF");

    stream_key
}

fn Decrypt<'a>( sk: &G2Affine, src: &'a mut dyn Read) -> Vec<u8> {
    // Parsing header and payload
    let (hdr, mut payload) = parse(src).unwrap();

    let file_key = unwrap(sk, &[*hdr.recipients[0].clone()]).unwrap();

    //   let mac = header_mac(file_key.clone(), hdr.recipients[0].clone().type_,hdr.recipients[0].clone().args,hdr.recipients[0].clone().body,hdr.recipients.clone(),hdr.mac.clone());
    let mac = header_mac(&file_key.clone(), &hdr);

    if mac != hdr.mac {
        // Handle MAC mismatch
        panic!("calculated mac: {:?} vs mac: {:?}", mac, hdr.mac)
    }

    let mut nonce = vec![0u8; 16];

    payload.read_exact(&mut nonce).unwrap(); // Handle potential errors properly

    // Creating a decrypted data stream let r_gid = pairing(&ciphertext.u, signature);

    new_reader(&stream_key(&file_key, &nonce), payload)
}

fn unwrap(sk: &G2Affine, stanzas: &[Stanza]) -> Result<Vec<u8>> {
    // Check stanza length and type
    if stanzas.len() != 1 {
        return Err(Error::new(ErrorKind::Other, "Stanza validation failed"));
    }

    // Convert bytes to ciphertext and perform the unlock operation
    let ciphertext = bytes_to_ciphertext(&stanzas[0].body);

    Ok(unlock(sk, &ciphertext))
}

fn convert_slice_to_array(slice: &[u8]) -> &[u8; 48] {
    if slice.len() != 48 {
        return &[0u8; 48];
    }

    let array_ref: &[u8; 48] = slice.try_into().map_err(|_| "Failed to convert").unwrap();
    array_ref
}

// The Rust function
fn bytes_to_ciphertext(b: &[u8]) -> Ciphertext {
    let exp_len = kyber_point_len + cipher_v_len + cipher_w_len;
    if b.len() != exp_len {
        return Ciphertext {
            u: todo!(),
            v: todo!(),
            w: todo!(),
        };
    }

    let kyber_point = &b[0..kyber_point_len];
    let cipher_v = &b[kyber_point_len..kyber_point_len + cipher_v_len];
    let cipher_w = &b[kyber_point_len + cipher_v_len..];

    let u: G1Affine = G1Affine::from_compressed(convert_slice_to_array(kyber_point)).unwrap();

    let ct = Ciphertext {
        u,
        v: cipher_v.to_vec(),
        w: cipher_w.to_vec(),
    };

    ct
}

fn unlock(signature: &G2Affine, ciphertext: &Ciphertext) -> Vec<u8> {
    let data = decrypt_ibe(signature, ciphertext);
    data
}

pub fn decrypt_ibe(
    signature: &G2Affine,
    ciphertext: &Ciphertext
) -> Vec<u8> {
    let r_gid = pairing(&ciphertext.u, signature);
   
    let sigma = {
        let mut hash = sha2::Sha256::new();

        hash.update(b"IBE-H2");
        hash.update(r_gid.to_bytes().to_vec());

        let h_r_git: &[u8] = &hash.finalize().to_vec()[0..32];

        xor(h_r_git, &ciphertext.v)
    };

    let msg = {
        let mut hash = sha2::Sha256::new();
        hash.update(b"IBE-H4");
        hash.update(&sigma);
        let h_sigma = &hash.finalize()[0..32];
        xor(h_sigma, &ciphertext.w)
    };

 
    let verify_res = verify(sigma, msg.clone(), ciphertext.u);

    if !verify_res {
        return vec![];
    }

    (msg)
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}
pub fn verify(
    sigma: Vec<u8>,
    msg: Vec<u8>,
    cu: G1Affine,
) -> bool {
    if sigma.len() != 32 || msg.len() != 32 {
       
        return false;
    }

    let r_g = {
        let r = h3(sigma.to_vec(), msg.to_vec());
        let rs_ct = Scalar::from_bytes(&r.try_into().unwrap());
        if rs_ct.is_some().unwrap_u8() == 0 {
           return false;
        }
        let rs = rs_ct.unwrap();
        let g1_base_projective = G1Projective::from(G1Affine::generator());
        g1_base_projective * rs
    };

    let result_affine = G1Affine::from(r_g);
    (result_affine.to_compressed().to_vec() == cu.to_compressed().to_vec())
}

pub fn h3(sigma: Vec<u8>, msg: Vec<u8>) -> Vec<u8> {
let mut hasher = sha2::Sha256::new();

// Hashing H3Tag, sigma and msg
hasher.update(b"IBE-H3");
hasher.update(sigma);
hasher.update(msg);
let buffer = hasher.finalize_reset();

// Create a BigInt for hashable
let mut hashable = BigInt::new(Sign::Plus, Vec::new());
let canonical_bit_len = (hashable.bits() + 7) / 8 * 8;
let actual_bit_len = hashable.bits();
let to_mask = canonical_bit_len - actual_bit_len;

for i in 1..65535u16 {
    let iter = i.to_le_bytes();
    hasher.update(&iter);
    hasher.update(&buffer);
    let mut hashed = hasher.finalize_reset().to_vec();

    // Applying masking
    if hashable.to_bytes_be().1[0] & 0x80 != 0 {
        hashed[0] >>= to_mask;
    } else {
        let l = hashed.len();
        hashed[l - 1] >>= to_mask;
    }

    hashed[0] = hashed[0] / 2;
    hashed.reverse();

    // Unmarshal and check if within the modulo
    let v = BigInt::from_bytes_le(Sign::Plus, &hashed);
    let vec = v.to_bytes_le().1;
    if vec.len() < 32 {
       return vec![];
    }

    let array: [u8; 32] = vec[..32].try_into().unwrap();

    let sc = Scalar::from_bytes(&array);

    if sc.is_some().into() {
        return (array.to_vec());
    }
}

return vec![];
}
