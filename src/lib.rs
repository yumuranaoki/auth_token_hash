use base64::prelude::*;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io;
use std::io::Read;

pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
}

#[derive(Debug)]
pub enum Error {
    UnmatchedHashError,
    IoError(io::Error),
}

type DigestResult = std::result::Result<Vec<u8>, Error>;

pub fn get_hash(token: String, alg: Algorithm) -> Result<String, Error> {
    let token_bytes = token.as_bytes();

    let get_digest_value_result = match alg {
        Algorithm::HS256 | Algorithm::RS256 | Algorithm::ES256 | Algorithm::PS256 => {
            generate_sha256_hash(token_bytes)?
        }
        Algorithm::HS384 | Algorithm::RS384 | Algorithm::ES384 | Algorithm::PS384 => {
            generate_sha384_hash(token_bytes)?
        }
        Algorithm::HS512 | Algorithm::RS512 | Algorithm::ES512 | Algorithm::PS512 => {
            generate_sha512_hash(token_bytes)?
        }
    };

    Ok(base64_encode_first_half(get_digest_value_result))
}

pub fn validate_hash(actual_hash: String, token: String, alg: Algorithm) -> Result<(), Error> {
    let expected = get_hash(token, alg)?;
    if expected == actual_hash {
        Ok(())
    } else {
        Err(Error::UnmatchedHashError)
    }
}

fn generate_sha256_hash(token: &[u8]) -> DigestResult {
    let mut hasher = Sha256::new();
    hasher.update(token);
    let result = hasher.finalize();
    match result.bytes().collect() {
        Ok(value) => Ok(value),
        Err(e) => Err(Error::IoError(e)),
    }
}

fn generate_sha384_hash(token: &[u8]) -> DigestResult {
    let mut hasher = Sha384::new();
    hasher.update(token);
    let result = hasher.finalize();
    match result.bytes().collect() {
        Ok(value) => Ok(value),
        Err(e) => Err(Error::IoError(e)),
    }
}

fn generate_sha512_hash(token: &[u8]) -> DigestResult {
    let mut hasher = Sha512::new();
    hasher.update(token);
    let result = hasher.finalize();
    match result.bytes().collect() {
        Ok(value) => Ok(value),
        Err(e) => Err(Error::IoError(e)),
    }
}

fn base64_encode_first_half(value: Vec<u8>) -> String {
    let half_length = value.len() / 2;
    let get_first_half_value_result: Vec<u8> = value.into_iter().take(half_length).collect();
    BASE64_URL_SAFE_NO_PAD.encode(get_first_half_value_result)
}

#[cfg(test)]
mod tests {
    use crate::{get_hash, validate_hash, Algorithm};

    #[test]
    fn test_get_hash_rs256() {
        let access_token = String::from("wDUTUjpF9JE6hjAp7qlAZWT7");
        let result = get_hash(access_token, Algorithm::RS256).unwrap();
        assert_eq!(result, "6OxYdTpaKInKq2g_Yv0uDA");
    }

    #[test]
    fn test_get_hash_rs384() {
        let access_token = String::from("9qYow+QJ86wvSaesQNuakI5k");
        let result = get_hash(access_token, Algorithm::RS384).unwrap();
        assert_eq!(result, "omlaMtF_NrVlsg-OlgIJGmZMj4dT25pP");
    }

    #[test]
    fn test_get_hash_rs512() {
        let access_token = String::from("FAcZI6RSe/898iwgY4wZCEIc");
        let result = get_hash(access_token, Algorithm::RS512).unwrap();
        assert_eq!(result, "H8EfPz7LUXwQj376qpyYZy6U_Ah-WxE0WLkqvm0N5e8");
    }

    #[test]
    fn test_validate_hash_rs256() {
        let actual_hash = String::from("6OxYdTpaKInKq2g_Yv0uDA");
        let access_token = String::from("wDUTUjpF9JE6hjAp7qlAZWT7");
        let result = validate_hash(actual_hash, access_token, Algorithm::RS256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hash_rs384() {
        let actual_hash = String::from("omlaMtF_NrVlsg-OlgIJGmZMj4dT25pP");
        let access_token = String::from("9qYow+QJ86wvSaesQNuakI5k");
        let result = validate_hash(actual_hash, access_token, Algorithm::RS384);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_hash_rs512() {
        let actual_hash = String::from("H8EfPz7LUXwQj376qpyYZy6U_Ah-WxE0WLkqvm0N5e8");
        let access_token = String::from("FAcZI6RSe/898iwgY4wZCEIc");
        let result = validate_hash(actual_hash, access_token, Algorithm::RS512);
        assert!(result.is_ok());
    }
}
