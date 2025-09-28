# hana-vault-format
A Rust crate simplifying the cryptography and IO operations on .hev files in the Hana Encrypted Vault format.

## The Format
This section describes how the format actually works and how it's supposed to be used.

### File Extensions
`.hev` is the only used extension at the moment.

### Data structure
```
vault.hev
├── Header (unencrypted, 80 bytes)
│   ├── Version: u32 (4 bytes, little-endian)
│   ├── Vault ID: UUID (16 bytes, RFC4122, raw bytes)
│   ├── Created: u64 (8 bytes, Unix timestamp, little-endian)
│   ├── Modified: u64 (8 bytes, Unix timestamp, little-endian)
│   ├── Checksum: [u8; 32] (32 bytes, SHA256 of encrypted data)
│   └── Metadata size: u32 (4 bytes, little-endian)
├── Encrypted Metadata (variable size, see Metadata size)
│   ├── Vault name
│   ├── Description
│   ├── Sync settings
│   └── Index/manifest
└── Encrypted Data Chunks
    ├── Connections chunk
    ├── SSH keys chunk
    ├── Snippets chunk
    ├── Settings chunk
    └── Custom data chunks
```

#### Binary Header Layout

| Offset | Field         | Type     | Size (bytes) | Description                     |
| ------ | ------------- | -------- | ------------ | ------------------------------- |
| 0      | Version       | u32      | 4            | File format version (LE)        |
| 4      | Vault ID      | [u8; 16] | 16           | UUID (RFC4122, raw bytes)       |
| 20     | Created       | u64      | 8            | Unix timestamp (LE)             |
| 28     | Modified      | u64      | 8            | Unix timestamp (LE)             |
| 36     | Checksum      | [u8; 32] | 32           | SHA256 of encrypted data        |
| 68     | Metadata size | u32      | 4            | Size of encrypted metadata (LE) |
| 72     | ...           | ...      | ...          | (Encrypted metadata follows)    |

All integer fields are little-endian. UUID is stored as 16 raw bytes. Timestamps are seconds since Unix epoch.

### Encryption
The HEV format uses industry-standard encryption to protect vault data:

- **Algorithm**: AES-256-GCM for authenticated encryption
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **Salt**: 32-byte random salt stored with encrypted data
- **IV/Nonce**: 12-byte random nonce for each encryption operation

#### Encryption Process
1. Generate random 32-byte salt
2. Derive 256-bit key from password using PBKDF2
3. Generate random 12-byte nonce
4. Encrypt data using AES-256-GCM
5. Store salt + nonce + encrypted_data + auth_tag

### Data Chunks
Each data chunk follows this structure:
```
Chunk
├── Chunk ID: u32 (4 bytes, identifies chunk type)
├── Chunk Size: u32 (4 bytes, size of encrypted data)
├── Salt: [u8; 32] (32 bytes, for key derivation)
├── Nonce: [u8; 12] (12 bytes, for AES-GCM)
├── Encrypted Data: [u8; N] (variable size)
└── Auth Tag: [u8; 16] (16 bytes, GCM authentication tag)
```

#### Standard Chunk Types
| ID | Name        | Description                           |
|----|-------------|---------------------------------------|
| 1  | Connections | SSH/database connection configurations |
| 2  | SSH Keys    | Private/public SSH key pairs         |
| 3  | Snippets    | Code snippets and templates           |
| 4  | Settings    | Application settings and preferences  |
| 5+ | Custom      | User or application-defined chunks    |

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hana-vault-format = "0.1.0"
```

## Usage

### Basic Example

```rust
use hana_vault_format::{HevVault, VaultError};
use std::path::Path;

// Create a new vault
let mut vault = HevVault::new("My Vault", "Optional description");

// Add some data
vault.set_connection("prod_db", b"host=prod.example.com user=admin");
vault.set_ssh_key("server_key", b"-----BEGIN PRIVATE KEY-----...");

// Save to file with password
vault.save_to_file(Path::new("my_vault.hev"), "secure_password")?;

// Load from file
let loaded_vault = HevVault::load_from_file(
    Path::new("my_vault.hev"), 
    "secure_password"
)?;

// Access data
if let Some(connection) = loaded_vault.get_connection("prod_db") {
    println!("Connection: {}", String::from_utf8_lossy(connection));
}
```

### Working with Chunks

```rust
use hana_vault_format::{HevVault, ChunkType};

let mut vault = HevVault::new("Test Vault", "");

// Add data to different chunk types
vault.add_chunk_data(ChunkType::Connections, "db1", b"connection_string");
vault.add_chunk_data(ChunkType::SshKeys, "key1", b"private_key_data");
vault.add_chunk_data(ChunkType::Snippets, "script1", b"#!/bin/bash\necho 'Hello'");

// Retrieve data
let connections = vault.get_chunk_data(ChunkType::Connections);
for (key, value) in connections {
    println!("{}: {}", key, String::from_utf8_lossy(value));
}
```

### Custom Chunks

```rust
use hana_vault_format::{HevVault, ChunkType};

let mut vault = HevVault::new("Custom Vault", "");

// Add custom chunk type
let custom_chunk_id = ChunkType::Custom(100);
vault.add_chunk_data(custom_chunk_id, "my_data", b"custom application data");

// Retrieve custom data
if let Some(data) = vault.get_chunk_entry(custom_chunk_id, "my_data") {
    println!("Custom data: {}", String::from_utf8_lossy(data));
}
```

## API Reference

### `HevVault`

The main struct for working with HEV files.

#### Methods

- `new(name: &str, description: &str) -> Self` - Create a new vault
- `load_from_file(path: &Path, password: &str) -> Result<Self, VaultError>` - Load vault from file
- `save_to_file(&self, path: &Path, password: &str) -> Result<(), VaultError>` - Save vault to file
- `get_vault_id(&self) -> &Uuid` - Get vault UUID
- `get_name(&self) -> &str` - Get vault name
- `get_description(&self) -> &str` - Get vault description
- `set_name(&mut self, name: &str)` - Set vault name
- `set_description(&mut self, description: &str)` - Set vault description

#### Data Access Methods

- `add_chunk_data(&mut self, chunk_type: ChunkType, key: &str, data: &[u8])` - Add data to chunk
- `get_chunk_data(&self, chunk_type: ChunkType) -> HashMap<String, Vec<u8>>` - Get all chunk data
- `get_chunk_entry(&self, chunk_type: ChunkType, key: &str) -> Option<&[u8]>` - Get specific entry
- `remove_chunk_entry(&mut self, chunk_type: ChunkType, key: &str) -> bool` - Remove entry

#### Convenience Methods

- `set_connection(&mut self, name: &str, data: &[u8])` - Add connection config
- `get_connection(&self, name: &str) -> Option<&[u8]>` - Get connection config
- `set_ssh_key(&mut self, name: &str, key_data: &[u8])` - Add SSH key
- `get_ssh_key(&self, name: &str) -> Option<&[u8]>` - Get SSH key
- `set_snippet(&mut self, name: &str, code: &[u8])` - Add code snippet
- `get_snippet(&self, name: &str) -> Option<&[u8]>` - Get code snippet

### `ChunkType`

Enum representing different chunk types:

```rust
pub enum ChunkType {
    Connections,
    SshKeys,
    Snippets,
    Settings,
    Custom(u32),
}
```

### `VaultError`

Error type for vault operations:

```rust
pub enum VaultError {
    IoError(std::io::Error),
    EncryptionError(String),
    DecryptionError(String),
    InvalidFormat(String),
    InvalidPassword,
    CorruptedData(String),
}
```

## Security Considerations

- **Password Strength**: Use strong, unique passwords for each vault
- **Key Derivation**: PBKDF2 with 100,000 iterations provides good protection against brute force
- **Memory Safety**: Sensitive data is cleared from memory when possible
- **File Permissions**: Ensure .hev files have appropriate file system permissions
- **Backup Strategy**: Keep encrypted backups of important vaults

## Format Versioning

The HEV format uses semantic versioning in the header:
- Version 1.x.x: Initial format specification
- Backward compatibility maintained within major versions
- Migration tools provided for major version upgrades

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows Rust conventions
- Security implications are considered
- Documentation is updated

## License

This project is licensed under the MIT License - see the LICENSE file for details.
