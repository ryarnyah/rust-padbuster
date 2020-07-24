use log::{error, info};

/// Errors which can occured in encrypt / decrypt
#[derive(Debug)]
pub enum PadbusterError {
    /// Occured when parameters are invalid.
    ValidationError(&'static str),
    /// Occured when oracle is unable to find a specific byte.
    UnableFindByteError(u8, Box<PadbusterError>),
    /// Occured when oracle is unable to decryt specific byte.
    UnableDecryptByteError(Vec<u8>, u8),
    /// Must occured in oracle function.
    BadPaddingError(Vec<u8>, String),
    /// Occured When error is not specified.
    Unspecified(&'static str),
}

impl std::fmt::Display for PadbusterError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            PadbusterError::ValidationError(ref s) => write!(f, "{}", s),
            PadbusterError::UnableFindByteError(ref byte, ref origin) => {
                write!(f, "Unable to find {} byte: {}", byte, origin)
            }
            PadbusterError::UnableDecryptByteError(ref block, ref max_retries) => write!(
                f,
                "Could not decrypt byte in {:?} within maximum allowed retries ({})",
                block, max_retries
            ),
            PadbusterError::BadPaddingError(ref ciphertext, ref origin) => {
                write!(f, "Bad Padding for ciphertext {:?}: {}", ciphertext, origin)
            }
            PadbusterError::Unspecified(ref s) => write!(f, "Unexpected error occured: {}", s),
        }
    }
}

/// `PaddingOracle` represent an instance of padding oracle
pub struct PaddingOracle {
    oracle: fn(Vec<u8>) -> Result<(), PadbusterError>,
    block_size: u8,
    max_retries: u8,
}

impl PaddingOracle {
    /// Return a PaddingOracle with the given function
    ///
    /// # Arguments
    ///
    /// * `block_size` - Size of CBC block (8, 16, 32).
    /// * `max_retries` - Maximal number of retries if it had an error.
    /// * `oracle` - Oracle function must return `PadbusterError::BadPaddingError` in case of padding error.
    ///
    pub fn new(
        block_size: u8,
        max_retries: u8,
        oracle: fn(Vec<u8>) -> Result<(), PadbusterError>,
    ) -> Self {
        PaddingOracle {
            oracle,
            block_size,
            max_retries,
        }
    }

    /// Encrypt the given plaintext & iv using oracle
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Plaintext to use.
    /// * `iv` - IV to use if known empty Vec<u8> if not.
    ///
    pub fn encrypt(&self, plaintext: &[u8], iv: &[u8]) -> Result<Vec<u8>, PadbusterError> {
        info!("Starting Encrypt Mode");

        if plaintext.is_empty() {
            return Err(PadbusterError::ValidationError(
                "Cannot encrypt empty plaintext",
            ));
        }
        let mut pad = ((self.block_size as usize) - (plaintext.len() % (self.block_size as usize)))
            % (self.block_size as usize);
        if pad == 0 {
            pad = self.block_size as usize;
        }
        let mut used_iv = iv.to_owned();
        let mut ptext = plaintext.to_owned();
        let mut padding = vec![pad as u8; pad];
        ptext.append(&mut padding);

        info!("Attempting to encrypt {:?} bytes", ptext);
        if used_iv.is_empty() {
            used_iv = vec![0u8; self.block_size as usize];
        }
        let mut encrypted = used_iv;
        let mut block = encrypted.clone();

        let mut n = ptext.len();
        while n > 0 {
            info!("*** Starting Block {} ***", n / (self.block_size as usize));
            let intermediate_bytes = match self.bust(&mut block) {
                Err(e) => return Err(e),
                Ok(r) => r,
            };
            let current_intermediate_bytes = intermediate_bytes.clone();

            block = xor_data(
                intermediate_bytes,
                ptext[(n - (self.block_size as usize))..n].to_vec(),
            );
            let current_block = block.clone();

            let mut current_encrypted = encrypted.clone();
            encrypted = block.clone();
            encrypted.append(&mut current_encrypted);

            info!(
                "Block {} Results:
            [+] New Cipher Text (HEX): {}
            [+] Intermediate Bytes (HEX): {}",
                n / (self.block_size as usize),
                hex::encode(current_block),
                hex::encode(current_intermediate_bytes)
            );

            n -= self.block_size as usize;
        }

        info!(
            "*** Finished ***
        [+] Encrypted value is: {}",
            base64::encode(&encrypted)
        );

        Ok(encrypted)
    }

    /// Decrypt the given ciphertext & iv using oracle
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Ciphertext to use.
    /// * `iv` - IV to use if known empty Vec<u8> if not.
    ///
    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, PadbusterError> {
        info!("Starting Decrypt Mode");
        info!("Attempting to decrypt {:?} bytes", ciphertext);

        if ciphertext.len() % (self.block_size as usize) != 0 {
            return Err(PadbusterError::ValidationError(
                "Ciphertext not of block size",
            ));
        }

        if iv.is_empty() && ciphertext.len() < (self.block_size as usize) * 2 {
            return Err(PadbusterError::ValidationError(
                "Ciphertext not at least 2 * block size",
            ));
        }

        let mut used_iv = iv.to_owned();
        let mut ctext = ciphertext.to_owned();
        if iv.is_empty() {
            used_iv = ciphertext[..(self.block_size as usize)].to_vec();
            ctext = ciphertext[(self.block_size as usize)..].to_vec();
        }

        let mut decrypted = vec![0u8; ctext.len()];

        let mut n = 0;
        while !ctext.is_empty() {
            info!("*** Starting Block {} ***\n", n / self.block_size);
            let mut block = ctext[0..(self.block_size as usize)].to_vec();
            ctext = ctext[(self.block_size as usize)..].to_vec();
            let next_iv = block.clone();

            let current_block = block.clone();

            let intermediate_bytes = match self.bust(&mut block) {
                Err(e) => return Err(e),
                Ok(r) => r,
            };
            let current_intermediate_bytes = intermediate_bytes.clone();

            let mut decrypted_block = xor_data(intermediate_bytes, used_iv);
            let current_decrypted_block = decrypted_block.clone();
            decrypted.append(&mut decrypted_block);

            used_iv = next_iv;
            n += self.block_size;

            info!(
                "Block {} Results:
            [+] New Cipher Text (HEX): {}
            [+] Intermediate Bytes (HEX): {}
            [+] Plain Text: {}",
                n / self.block_size,
                hex::encode(current_block),
                hex::encode(current_intermediate_bytes),
                std::str::from_utf8(&current_decrypted_block).unwrap()
            );
        }

        info!(
            "*** Finished ***
        [+] Decrypted value (ASCII): {}
        [+] Decrypted value (HEX): {}
        [+] Decrypted value (Base64): {}",
            std::str::from_utf8(&decrypted).unwrap(),
            hex::encode(&decrypted),
            base64::encode(&decrypted)
        );

        Ok(decrypted)
    }

    fn try_bust(&self, block: &mut Vec<u8>) -> Result<Vec<u8>, PadbusterError> {
        let mut intermediate_bytes = vec![0u8; self.block_size as usize];
        let mut test_bytes = vec![0u8; self.block_size as usize];
        test_bytes.append(block);

        let mut byte_num = self.block_size;
        while byte_num > 0 {
            let mut try_number = 0;
            let mut r = 255u8;
            let mut i = r as i16;
            while i >= 0 {
                // Fuzz the test byte
                test_bytes[(byte_num - 1) as usize] = r;
                // Decrement r for the next loop
                r -= 1;

                // If a padding oracle could not be identified from the
                // response, this indicates the padding bytes we sent
                // were correct.
                let oracle_test_bytes = test_bytes.clone();
                try_number += 1;
                if let Err(e) = (self.oracle)(oracle_test_bytes) {
                    if r == 0 {
                        return Err(PadbusterError::UnableFindByteError(byte_num, Box::new(e)));
                    }
                    if let PadbusterError::BadPaddingError(_, _) = e {
                        i -= 1;
                        continue;
                    }
                    error!("{}", e);
                    return Err(e);
                }

                let current_pad_byte = (self.block_size - (byte_num - 1)) as u8;
                let next_pad_byte = self.block_size - (byte_num - 1) + 1;
                let decrypted_byte = test_bytes[(byte_num - 1) as usize] ^ current_pad_byte;

                intermediate_bytes[(byte_num - 1) as usize] = decrypted_byte;

                let mut k = byte_num - 1;
                while k < self.block_size {
                    // XOR the current test byte with the padding value
                    // for this round to recover the decrypted byte
                    test_bytes[k as usize] ^= current_pad_byte;
                    // XOR it again with the padding byte for the
                    // next round
                    test_bytes[k as usize] ^= next_pad_byte;

                    k += 1;
                }
                info!("[+] Success: ({}/256) [Byte {}]", try_number, byte_num);
                break;
            }

            byte_num -= 1;
        }

        Ok(intermediate_bytes)
    }

    fn bust(&self, block: &mut Vec<u8>) -> Result<Vec<u8>, PadbusterError> {
        info!("Processing block {:?}", block);

        for retry in 0..self.max_retries {
            match self.try_bust(block) {
                Ok(r) => return Ok(r),
                Err(e) => {
                    error!(
                        "[+] Retrying {}/{} unable to bust block {:?} {}",
                        retry, self.max_retries, block, e
                    );
                }
            };
        }
        Err(PadbusterError::UnableDecryptByteError(
            block.to_vec(),
            self.max_retries,
        ))
    }
}

/// `xor_data` xor data with key
fn xor_data(data: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut res = vec![0u8; data.len()];
    for (index, b) in data.iter().enumerate() {
        res[index] = b ^ key[index % key.len()];
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::Aes128;
    use block_modes::block_padding::Pkcs7;
    use block_modes::{BlockMode, Cbc};
    use hex_literal::hex;

    extern crate simple_logger;

    type Aes128Cbc = Cbc<Aes128, Pkcs7>;

    fn unpad(b: Vec<u8>, block_size: usize) -> Result<Vec<u8>, &'static str> {
        if block_size == 0 {
            return Err("Invalid block size");
        }
        if b.is_empty() {
            return Err("Invalid PKCS7 data");
        }
        if b.len() % block_size != 0 {
            return Err("Invalid PKCS7 data");
        }
        let c = b[b.len() - 1];
        if c == 0 || c > (b.len() as u8) {
            return Err("Invalid PKCS7 padding");
        }
        for i in 0..(c as usize) {
            if b[b.len() - (c as usize) + i] != c {
                return Err("Invalid PKCS7 padding");
            }
        }
        Ok(b[..(b.len() - (c as usize))].to_vec())
    }

    fn oracle_fn(data: Vec<u8>) -> Result<(), PadbusterError> {
        // re-create cipher mode instance
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let iv = &data[..16];
        let ciphertext = &data[16..];
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        let mut buf = ciphertext.to_vec();
        match cipher.decrypt(&mut buf) {
            Ok(_) => Ok(()),
            Err(e) => Err(PadbusterError::BadPaddingError(
                ciphertext.to_vec(),
                format!("{}", e),
            )),
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        let _ = simple_logger::init_with_level(log::Level::Info);

        let plaintext = b"Hello world!Hello world!";
        let current_plaintext = *plaintext;
        let oracle = PaddingOracle::new(16, 1, oracle_fn);

        let iv: Vec<u8> = [].to_vec();

        let ciphertext = oracle.encrypt(&plaintext.to_vec(), &iv).unwrap();
        let plaintext = oracle.decrypt(&ciphertext, &iv).unwrap();
        assert_eq!(
            current_plaintext.to_vec(),
            unpad(plaintext[32..].to_vec(), 16).unwrap()
        );
    }

    #[test]
    fn test_decrypt() {
        let _ = simple_logger::init_with_level(log::Level::Info);

        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = b"Hello world!Hello world!";
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        // buffer must have enough space for message+padding
        let mut buffer = vec![0u8; plaintext.len() + (16 - plaintext.len() % 16) % 16];
        // copy message to the buffer
        let pos = plaintext.len();
        buffer[..pos].copy_from_slice(plaintext);
        let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
        let mut to_decrypt = iv.to_vec();
        to_decrypt.append(&mut ciphertext.to_vec());

        let iv: Vec<u8> = [].to_vec();
        let oracle = PaddingOracle::new(16, 1, oracle_fn);
        let decrypted = oracle.decrypt(&to_decrypt, &iv).unwrap();

        assert_eq!(unpad(decrypted[32..].to_vec(), 16).unwrap(), plaintext);
    }

    #[test]
    fn test_xor_data() {
        let v1: Vec<u8> = vec![1, 0, 0, 1];
        let v2: Vec<u8> = vec![1, 1];
        let expected: Vec<u8> = vec![0, 1, 1, 0];

        assert_eq!(xor_data(v1, v2), expected);
    }

    #[test]
    fn test_aes_crypt() {
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let iv = hex!("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = b"Hello world!";
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        // buffer must have enough space for message+padding
        let mut buffer = vec![0u8; plaintext.len() + (16 - plaintext.len() % 16) % 16];
        // copy message to the buffer
        let pos = plaintext.len();
        buffer[..pos].copy_from_slice(plaintext);
        let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();

        assert_eq!(ciphertext, hex!("1b7a4c403124ae2fb52bedc534d82fa8"));

        // re-create cipher mode instance
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        let mut buf = ciphertext.to_vec();
        let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

        assert_eq!(decrypted_ciphertext, plaintext);
    }
}
