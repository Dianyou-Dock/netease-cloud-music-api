//
// encrypt.rs
// Copyright (C) 2019 gmg137 <gmg137@live.com>
// Distributed under terms of the GPLv3 license.
//
use base64::{engine::general_purpose, Engine as _};
use lazy_static::lazy_static;


use rand::rngs::OsRng;
use rand::RngCore;
use urlqstring::QueryParams;


use aes::Aes128;

use block_padding::Pkcs7;

use cbc::cipher::{BlockEncryptMut, KeyIvInit};

use rsa::pkcs8::DecodePublicKey;

use rsa::{Pkcs1v15Encrypt, RsaPublicKey};


type Aes128CbcEnc = cbc::Encryptor<Aes128>;

lazy_static! {
    static ref IV: Vec<u8> = "0102030405060708".as_bytes().to_vec();
    static ref PRESET_KEY: Vec<u8> = "0CoJUm6Qyw8W8jud".as_bytes().to_vec();
    static ref LINUX_API_KEY: Vec<u8> = "rFgB&h#%2?^eDg:Q".as_bytes().to_vec();
    static ref BASE62: Vec<u8> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".as_bytes().to_vec();
    static ref RSA_PUBLIC_KEY: Vec<u8> = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ37BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvaklV8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44oncaTWz7OBGLbCiK45wIDAQAB\n-----END PUBLIC KEY-----".as_bytes().to_vec();
    static ref EAPIKEY: Vec<u8> = "e82ckenh8dichen8".as_bytes().to_vec();
}

#[allow(non_snake_case)]
pub struct Crypto;

#[allow(dead_code, non_camel_case_types)]
pub enum HashType {
    md5,
}

#[allow(non_camel_case_types)]
#[derive(Clone)]
pub enum AesMode {
    cbc,
    ecb,
}

#[allow(dead_code, clippy::redundant_closure)]
impl Crypto {
    pub fn hex_random_bytes(&self, n: usize) -> String {
        let mut data: Vec<u8> = Vec::with_capacity(n);
        OsRng.fill_bytes(&mut data);
        hex::encode(data)
    }

    pub fn eapi(&self, url: &str, text: &str) -> String {
        let message = format!("nobody{}use{}md5forencrypt", url, text);


        let digest = md5::compute(message.as_bytes()).0;

        let digest_hex =  hex::encode(digest);

        let data = format!("{}-36cd479b6b5-{}-36cd479b6b5-{}", url, text, digest_hex);
        let params = self.aes_encrypt(&data, &EAPIKEY, AesMode::ecb, None, |t: &Vec<u8>| {
            hex::encode_upper(t)
        });
        QueryParams::from(vec![("params", params.as_str())]).stringify()
    }

    pub fn weapi(&self, text: &str) -> String {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        let key: Vec<u8> = secret_key
            .iter()
            .map(|i| BASE62[(i % 62) as usize])
            .collect();

        let params1 = self.aes_encrypt(text, &PRESET_KEY, AesMode::cbc, Some(&*IV), |t: &Vec<u8>| {
            general_purpose::STANDARD.encode(t)
        });

        let params = self.aes_encrypt(&params1, &key, AesMode::cbc, Some(&*IV), |t: &Vec<u8>| {
            general_purpose::STANDARD.encode(t)
        });

        let enc_sec_key = self.rsa_encrypt(
            std::str::from_utf8(&key.iter().rev().copied().collect::<Vec<u8>>()).unwrap(),
            &RSA_PUBLIC_KEY,
        );

        QueryParams::from(vec![
            ("params", params.as_str()),
            ("encSecKey", enc_sec_key.as_str()),
        ])
        .stringify()
    }

    pub fn linuxapi(&self, text: &str) -> String {
        let params = self.aes_encrypt(text, &LINUX_API_KEY, AesMode::ecb, None, |t: &Vec<u8>| {
            hex::encode(t)
        })
        .to_uppercase();
        QueryParams::from(vec![("eparams", params.as_str())]).stringify()
    }

    pub fn aes_encrypt(
        &self,
        data: &str,
        key: &[u8],
        mode: AesMode,
        iv: Option<&[u8]>,
        encode: fn(&Vec<u8>) -> String,
    ) -> String {
        self.aes_encrypt_no_ossl(data, key, mode, iv, encode)
    }


    pub fn aes_encrypt_no_ossl(
        &self,
        data: &str,
        key: &[u8],
        mode: AesMode,
        iv: Option<&[u8]>,
        encode: fn(&Vec<u8>) -> String,
    ) -> String {
        let res = match mode {
            AesMode::cbc => {
                // iv must exist
                self.aes_encrypt_cbc(data, key, iv.unwrap())
            }
            AesMode::ecb => {
                self.aes_encrypt_ecb(data, key)
            }
        };

        encode(&res)
    }

    fn aes_encrypt_ecb(&self, data: &str, key: &[u8]) -> Vec<u8> {

        let res = Aes128CbcEnc::new_from_slices(key, vec![].as_slice()).unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes());
        res
    }

    fn aes_encrypt_cbc(&self, data: &str, key: &[u8], iv: &[u8]) -> Vec<u8> {
        let res = Aes128CbcEnc::new_from_slices(key, iv).unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(data.as_bytes());
        res
    }


    pub fn rsa_encrypt(&self, data: &str, key: &[u8]) -> String {
        self.rsa_encrypt_no_ossl(data, key)
    }


    pub fn rsa_encrypt_no_ossl(&self, data: &str, key: &[u8]) -> String {
        let pem = general_purpose::STANDARD.encode(key);
        let public_key = RsaPublicKey::from_public_key_pem(&pem).unwrap();

        // 使用填充方案 PKCS1v15
        let encrypted_data = public_key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, data.as_bytes()).unwrap();

        hex::encode(encrypted_data)
    }

}
