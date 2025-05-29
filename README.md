# sha0

**Disclaimer:**  
SHA-0 is the original version of the Secure Hash Algorithm, published in 1993. It was quickly replaced by SHA-1 due to a discovered flaw in its design. SHA-0 is considered obsolete and insecure, and **should not be used for any important or security-critical purposes**. This crate is for educational and compatibility purposes only.

## Usage

Add to your `Cargo.toml`:

```toml
sha0 = "0.1.12"
```

### Hashing a string

```rust
use sha0::Sha0;

let mut hasher = Sha0::new();
hasher.update(b"hello world");
let digest = hasher.finalize();
println!("SHA-0 digest: {:?}", digest);
```

### Hashing a file

```rust
use sha0::Sha0;
use std::fs::File;
use std::io::{Read, BufReader};

let file = File::open("myfile.txt").unwrap();
let mut reader = BufReader::new(file);
let mut hasher = Sha0::new();
let mut buffer = [0u8; 4096];
loop {
    let n = reader.read(&mut buffer).unwrap();
    if n == 0 { break; }
    hasher.update(&buffer[..n]);
}
let digest = hasher.finalize();
println!("SHA-0 digest: {:?}", digest);
```

### Incremental updates

```rust
use sha0::Sha0;

let mut hasher = Sha0::new();
hasher.update(b"hello ");
hasher.update(b"world");
let digest = hasher.finalize();
println!("SHA-0 digest: {:?}", digest);
```

## License

MIT

## Repository

[https://github.com/Polycarbohydrate/sha0](https://github.com/Polycarbohydrate/sha0)
