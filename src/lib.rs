//! # SHA-0 (Secure Hash Algorithm 0) Disclaimer
//!
//! SHA-0 is the original version of the Secure Hash Algorithm, published in 1993.
//! It was quickly replaced by SHA-1 due to a discovered flaw in its design.
//! SHA-0 is considered obsolete and insecure, and **should not be used for any important or security-critical purposes**.
//!
//! ## Example: Hashing a string
//!
//! ```rust
//! use sha0::Sha0;
//!
//! let mut hasher = Sha0::new();
//! hasher.update(b"hello world");
//! let digest = hasher.finalize();
//! println!("SHA-0 digest: {}", digest);
//! ```
//!
//! ## Example: Hashing a file
//!
//! ```rust
//! use sha0::Sha0;
//! use std::fs::File;
//! use std::io::{Read, BufReader};
//!
//! let file = File::open("myfile.txt").unwrap();
//! let mut reader = BufReader::new(file);
//! let mut hasher = Sha0::new();
//! let mut buffer = [0u8; 4096];
//! loop {
//!     let n = reader.read(&mut buffer).unwrap();
//!     if n == 0 { break; }
//!     hasher.update(&buffer[..n]);
//! }
//! let digest = hasher.finalize();
//! println!("SHA-0 digest: {}", digest);
//! ```
//!
//! ## Example: Incremental updates
//!
//! ```rust
//! use sha0::Sha0;
//!
//! let mut hasher = Sha0::new();
//! hasher.update(b"hello ");
//! hasher.update(b"world");
//! let digest = hasher.finalize();
//! println!("SHA-0 digest: {}", digest);
//! ```
pub struct Sha0 {
    h: [u32; 5], // Hash state
    data: Vec<u8>, // Data buffer
    length: u64, // Total length of input data in bits
}

impl Sha0 {
    /// Create a new SHA-0 instance
    pub fn new() -> Self {
        Self {
            h: [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476,
                0xc3d2e1f0,
            ],
            data: Vec::new(),
            length: 0,
        }
    }
    /// Update the hash with new data
    pub fn update(&mut self, input: &[u8]) {
        self.length += (input.len() as u64) * 8;
        self.data.extend_from_slice(input);
        while self.data.len() >= 64 {
            let block = self.data[..64].to_vec();
            self.process_block(&block);
            self.data.drain(..64);
        }
    }
    /// Finalize the hash and produce the digest as a hex string
    pub fn finalize(mut self) -> String {
        self.pad();
        while self.data.len() >= 64 {
            let block = self.data[..64].to_vec();
            self.process_block(&block);
            self.data.drain(..64);
        }
        self.h.iter().map(|word| format!("{:08x}", word)).collect()
    }
    /// Pad the data buffer as per SHA-0 specification
    fn pad(&mut self) {
        self.data.push(0x80); // Append 1 bit (0x80 = 10000000)
        while (self.data.len() % 64) != 56 {
            self.data.push(0x00);
        }
        self.data.extend_from_slice(&self.length.to_be_bytes()); // Append length as 64-bit big endian
    }
    /// Process a 512-bit (64-byte) block
    fn process_block(&mut self, block: &[u8]) {
        assert_eq!(block.len(), 64);
        // Prepare the message schedule
        let mut w = [0u32; 80];
        for (i, chunk) in block.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }
        // No rotation in SHA-0, but we need to extend the message schedule
        for t in 16..80 {
            w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
        }
        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        // Constants
        let k1 = 0x5a827999;
        let k2 = 0x6ed9eba1;
        let k3 = 0x8f1bbcdc;
        let k4 = 0xca62c1d6;
        // Main loop
        for t in 0..80 {
            let (f, k) = match t {
                0..=19 => ((b & c) | ((!b) & d), k1),
                20..=39 => (b ^ c ^ d, k2),
                40..=59 => ((b & c) | (b & d) | (c & d), k3),
                _ => (b ^ c ^ d, k4),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[t]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        // Update the hash state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha0_known_vectors() {
        let mut hasher = Sha0::new();
        hasher.update(b"abc");
        let digest = hasher.finalize();
        assert_eq!(digest, "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");

        let mut hasher = Sha0::new();
        hasher.update(b"");
        let digest = hasher.finalize();
        assert_eq!(digest, "f96cea198ad1dd5617ac084a3d92c6107708c0ef");

        let mut hasher = Sha0::new();
        hasher.update(b"The quick brown fox jumps over the lazy dog");
        let digest = hasher.finalize();
        assert_eq!(digest, "b03b401ba92d77666221e843feebf8c561cea5f7");
    }
}
