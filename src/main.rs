use std::env;

enum TeaMode {
    ECB,
    CBC,
    CFB,
}

struct Tea {
    mode: TeaMode,
    _padding: bool,

    key: [u8; 16],
    chain: [u8; 8],
}

impl Tea {
    pub fn new(key: &[u8], chain: [u8; 8], mode: TeaMode, padding: bool) -> Result<Tea, ()> {
        let mut tea = Tea {
            mode: mode,
            _padding: padding,
            key: [0; 16],
            chain: [0; 8],
        };

        if key.is_empty() {
            return Err(());
        }
        
        tea.key = key[0..16].try_into().unwrap();

        tea.chain = chain;
        Ok(tea)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let block_len = self.chain.len();
        if data.len() % block_len != 0 {
            return Err(());
        }

        let mut output = Vec::new();
        let block_size = data.len() / block_len;

        let mut key = [0 as u32; 4];
        key[0] = u32::from_be_bytes(self.key[0..4].try_into().unwrap());
        key[1] = u32::from_be_bytes(self.key[4..8].try_into().unwrap());
        key[2] = u32::from_be_bytes(self.key[8..12].try_into().unwrap());
        key[3] = u32::from_be_bytes(self.key[12..16].try_into().unwrap());

        match self.mode {
            TeaMode::ECB => {
                for i in 0..block_size {
                    let block = &data[i * block_len..(i + 1) * block_len];
                    let encrypted = self.encrypt_block(&key, block)?;
                    output.extend_from_slice(&encrypted);
                }
            }
            TeaMode::CBC => {
                let mut chain = self.chain;
                for i in 0..block_size {
                    let block = &data[i * block_len..(i + 1) * block_len];
                    let block = Tea::xor_bytes(&chain, block);
                    let encrypted = self.encrypt_block(&key, &block)?;
                    output.extend_from_slice(&encrypted);
                    chain = encrypted[0..8].try_into().unwrap();
                }
            }
            TeaMode::CFB => {
                let mut chain = self.chain;
                for i in 0..block_size {
                    let block = &data[i * block_len..(i + 1) * block_len];
                    let encrypted = self.encrypt_block(&key, &chain)?;
                    let encrypted = Tea::xor_bytes(&encrypted, block);
                    output.extend_from_slice(&encrypted);
                    chain = encrypted[0..8].try_into().unwrap();
                }
            }
        }
        
        Ok(output)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        let block_len = self.chain.len();
        if data.len() % block_len != 0 {
            return Err(());
        }

        let mut output = Vec::new();
        let block_size = data.len() / block_len;

        let mut key = [0 as u32; 4];
        key[0] = u32::from_be_bytes(self.key[0..4].try_into().unwrap());
        key[1] = u32::from_be_bytes(self.key[4..8].try_into().unwrap());
        key[2] = u32::from_be_bytes(self.key[8..12].try_into().unwrap());
        key[3] = u32::from_be_bytes(self.key[12..16].try_into().unwrap());

        match self.mode {
            TeaMode::ECB => {
                for i in 0..block_size {
                    let block = &data[i * block_len..(i + 1) * block_len];
                    let encrypted = self.decrypt_block(&key, block)?;
                    output.extend_from_slice(&encrypted);
                }
            }
            TeaMode::CBC => {
                let mut chain = self.chain;
                for i in 0..block_size {
                    let block = &data[i * block_len..(i + 1) * block_len];
                    let encrypted = self.decrypt_block(&key, block)?;
                    let encrypted = Tea::xor_bytes(&chain, &encrypted);
                    output.extend_from_slice(&encrypted);
                    chain = block.try_into().unwrap();
                }
            }
            TeaMode::CFB => {
                let mut chain = self.chain;
                for i in 0..block_size {
                    let block = &data[i * block_len..(i + 1) * block_len];
                    let encrypted = self.encrypt_block(&key, &chain)?;
                    let encrypted = Tea::xor_bytes(&encrypted, block);
                    output.extend_from_slice(&encrypted);
                    chain = block.try_into().unwrap();
                }
            }
        }
        
        Ok(output)
    }

    fn encrypt_block(&self, key: &[u32; 4], block: &[u8]) -> Result<Vec<u8>, ()> {
        let mut left = u32::from_be_bytes(block[0..4].try_into().unwrap());
        let mut right = u32::from_be_bytes(block[4..8].try_into().unwrap());

        let mut n:u32 = 0;
        for _ in 0..32 {
            left = left.overflowing_add(
                (((right << 4) ^ (right >> 5)).overflowing_add(right).0)
                ^ (n.overflowing_add(key[(n as usize) & 3]).0)
            ).0;

            n = n.overflowing_add(0x9e3779b9u32).0;

            right = right.overflowing_add(
                (((left << 4) ^ (left >> 5)).overflowing_add(left).0)
                ^ (n.overflowing_add(key[((n >> 11) as usize) & 3]).0)
            ).0;
        }

        let mut output = Vec::new();
        output.extend_from_slice(&left.to_be_bytes());
        output.extend_from_slice(&right.to_be_bytes());
        Ok(output)
    }

    fn decrypt_block(&self, key: &[u32; 4], block: &[u8]) -> Result<Vec<u8>, ()> {
        let mut left = u32::from_be_bytes(block[0..4].try_into().unwrap());
        let mut right = u32::from_be_bytes(block[4..8].try_into().unwrap());

        let mut n:u32 = 0xc6ef3720u32;
        for _ in 0..32 {
            right = right.overflowing_sub(
                (((left << 4) ^ (left >> 5)).overflowing_add(left).0)
                ^ (n.overflowing_add(key[((n >> 11) as usize) & 3]).0)
            ).0;

            n = n.overflowing_add(0x61c88647u32).0;

            left = left.overflowing_sub(
                (((right << 4) ^ (right >> 5)).overflowing_add(right).0)
                ^ (n.overflowing_add(key[(n as usize) & 3]).0)
            ).0;
        }

        let mut output = Vec::new();
        output.extend_from_slice(&left.to_be_bytes());
        output.extend_from_slice(&right.to_be_bytes());
        Ok(output)
    }

    fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        for i in 0..a.len() {
            output.push(a[i] ^ b[i]);
        }
        output
    }

}

fn main() {
    let key = "qortmddkqortmdck";

    let args = env::args().collect::<Vec<String>>();
    if args.len() < 3 {
        println!("Usage: ./df-password [dec|enc] <password>");
        std::process::exit(1);
    }

    // check args
    if args[1] != "dec" && args[1] != "enc" {
        println!("Usage: ./df-password [dec|enc] <password>");
        std::process::exit(1);
    }

    // check password length
    if args[1] == "enc" && args[2].len() > 20 {
        println!("Password too long");
        std::process::exit(1);
    }
    
    if args[1] == "enc" {
        let password = args[2].as_bytes();
        let password = &password[0..20.min(password.len())];

        let mut data = [0u8; 24];
        for i in 0..password.len() {
            data[i] = password[i];
        }

        let tea = Tea::new(key.as_bytes(), [1; 8], TeaMode::ECB, false).unwrap();

        let encrypted = tea.encrypt(&data).unwrap();
        println!("{}", hex::encode(encrypted));
    } else if args[1] == "dec" {
        let data = hex::decode(&args[2]).unwrap();
        let data = &data[0..24.min(data.len())];

        let tea = Tea::new(key.as_bytes(), [1; 8], TeaMode::ECB, false).unwrap();
        let decrypted = tea.decrypt(&data).unwrap();
        println!("{}", String::from_utf8(decrypted).unwrap());
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = "qortmddkqortmdck";
        let password = "password";
        let mut data = [0u8; 24];
        for i in 0..password.len() {
            data[i] = password.as_bytes()[i];
        }

        let tea = Tea::new(key.as_bytes(), [1; 8], TeaMode::ECB, false).unwrap();
        let encrypted = tea.encrypt(&data).unwrap();
        let decrypted = tea.decrypt(&encrypted).unwrap();
        assert_eq!(data, decrypted[..]);
    }

    #[test]
    fn test_encrypt_decrypt_cbc() {
        let key = "qortmddkqortmdck";
        let password = "password";
        let mut data = [0u8; 24];
        for i in 0..password.len() {
            data[i] = password.as_bytes()[i];
        }

        let tea = Tea::new(key.as_bytes(), [1; 8], TeaMode::CBC, false).unwrap();
        let encrypted = tea.encrypt(&data).unwrap();
        let decrypted = tea.decrypt(&encrypted).unwrap();
        assert_eq!(data, decrypted[..]);
    }

    #[test]
    fn test_encrypt_decrypt_cfb() {
        let key = "qortmddkqortmdck";
        let password = "password";
        let mut data = [0u8; 24];
        for i in 0..password.len() {
            data[i] = password.as_bytes()[i];
        }

        let tea = Tea::new(key.as_bytes(), [1; 8], TeaMode::CFB, false).unwrap();
        let encrypted = tea.encrypt(&data).unwrap();
        let decrypted = tea.decrypt(&encrypted).unwrap();
        assert_eq!(data, decrypted[..]);
    }
}