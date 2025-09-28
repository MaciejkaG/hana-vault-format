//! # Hana Vault Format
//!
//! A Rust crate for working with .hev (Hana Encrypted Vault) files.
//! Provides secure storage for connections, SSH keys, snippets, and other sensitive data.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use thiserror::Error;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

/// Current format version
pub const FORMAT_VERSION: u32 = 0;

/// Header size in bytes
pub const HEADER_SIZE: usize = 72;

/// PBKDF2 iterations for key derivation
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt size for key derivation
pub const SALT_SIZE: usize = 32;

/// Nonce size for AES-GCM
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size for AES-GCM
pub const TAG_SIZE: usize = 16;

/// Key size for AES-256
pub const KEY_SIZE: usize = 32;

/// Error types for vault operations
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    
    #[error("Decryption error: {0}")]
    DecryptionError(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    
    #[error("Invalid password")]
    InvalidPassword,
    
    #[error("Corrupted data: {0}")]
    CorruptedData(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Represents different types of data chunks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChunkType {
    Connections,
    SshKeys,
    Snippets,
    Settings,
    Custom(u32),
}

impl ChunkType {
    /// Convert chunk type to u32 ID
    pub fn to_id(self) -> u32 {
        match self {
            ChunkType::Connections => 1,
            ChunkType::SshKeys => 2,
            ChunkType::Snippets => 3,
            ChunkType::Settings => 4,
            ChunkType::Custom(id) => id,
        }
    }

    /// Create chunk type from u32 ID
    pub fn from_id(id: u32) -> Self {
        match id {
            1 => ChunkType::Connections,
            2 => ChunkType::SshKeys,
            3 => ChunkType::Snippets,
            4 => ChunkType::Settings,
            id => ChunkType::Custom(id),
        }
    }
}

/// Vault metadata stored in encrypted form
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultMetadata {
    name: String,
    description: String,
    sync_settings: HashMap<String, String>,
    index: HashMap<u32, Vec<String>>, // chunk_id -> list of keys
}

/// A single encrypted data chunk
#[derive(Debug, Clone)]
struct EncryptedChunk {
    chunk_id: u32,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    encrypted_data: Vec<u8>,
    auth_tag: [u8; TAG_SIZE],
}

/// Raw file header structure
#[derive(Debug, Clone)]
struct HevHeader {
    version: u32,
    vault_id: [u8; 16],
    created: u64,
    modified: u64,
    checksum: [u8; 32],
    metadata_size: u32,
}

impl HevHeader {
    /// Serialize header to bytes
    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        
        bytes[0..4].copy_from_slice(&self.version.to_le_bytes());
        bytes[4..20].copy_from_slice(&self.vault_id);
        bytes[20..28].copy_from_slice(&self.created.to_le_bytes());
        bytes[28..36].copy_from_slice(&self.modified.to_le_bytes());
        bytes[36..68].copy_from_slice(&self.checksum);
        bytes[68..72].copy_from_slice(&self.metadata_size.to_le_bytes());
        
        bytes
    }

    /// Deserialize header from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() < HEADER_SIZE {
            return Err(VaultError::InvalidFormat("Header too short".to_string()));
        }

        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&bytes[4..20]);
        let created = u64::from_le_bytes([
            bytes[20], bytes[21], bytes[22], bytes[23],
            bytes[24], bytes[25], bytes[26], bytes[27]
        ]);
        let modified = u64::from_le_bytes([
            bytes[28], bytes[29], bytes[30], bytes[31],
            bytes[32], bytes[33], bytes[34], bytes[35]
        ]);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&bytes[36..68]);
        let metadata_size = u32::from_le_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]);

        Ok(HevHeader {
            version,
            vault_id,
            created,
            modified,
            checksum,
            metadata_size,
        })
    }
}

/// Secure key material for encryption/decryption
#[derive(Clone, ZeroizeOnDrop)]
struct SecretKey {
    key: [u8; KEY_SIZE],
}

impl SecretKey {
    /// Derive key from password and salt using PBKDF2
    fn derive_from_password(password: &str, salt: &[u8]) -> Self {
        let mut key = [0u8; KEY_SIZE];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
        SecretKey { key }
    }

    /// Get the raw key bytes
    fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

/// Main vault structure for working with HEV files
#[derive(Debug, Clone)]
pub struct HevVault {
    vault_id: Uuid,
    created: u64,
    modified: u64,
    metadata: VaultMetadata,
    chunks: HashMap<u32, HashMap<String, Vec<u8>>>,
}

impl HevVault {
    /// Create a new vault with the given name and description
    pub fn new(name: &str, description: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = VaultMetadata {
            name: name.to_string(),
            description: description.to_string(),
            sync_settings: HashMap::new(),
            index: HashMap::new(),
        };

        Self {
            vault_id: Uuid::new_v4(),
            created: now,
            modified: now,
            metadata,
            chunks: HashMap::new(),
        }
    }

    /// Load vault from file with password
    pub fn load_from_file(path: &Path, password: &str) -> Result<Self, VaultError> {
        let mut file = File::open(path)?;
        
        // Read header
        let mut header_bytes = [0u8; HEADER_SIZE];
        file.read_exact(&mut header_bytes)?;
        let header = HevHeader::from_bytes(&header_bytes)?;

        // Validate version
        if header.version != FORMAT_VERSION {
            return Err(VaultError::InvalidFormat(
                format!("Unsupported version: {}", header.version)
            ));
        }

        // Read encrypted metadata
        let mut encrypted_metadata = vec![0u8; header.metadata_size as usize];
        file.read_exact(&mut encrypted_metadata)?;

        // Read remaining data (chunks)
        let mut chunks_data = Vec::new();
        file.read_to_end(&mut chunks_data)?;

        // Verify checksum
        let mut hasher = Sha256::default();
        hasher.update(&encrypted_metadata);
        hasher.update(&chunks_data);
        let computed_checksum = hasher.finalize();
        
        if computed_checksum.as_slice() != header.checksum {
            return Err(VaultError::CorruptedData("Checksum mismatch".to_string()));
        }

        // Decrypt metadata
        let metadata = Self::decrypt_metadata(&encrypted_metadata, password)?;

        // Parse chunks
        let chunks = Self::parse_chunks(&chunks_data, password)?;

        Ok(Self {
            vault_id: Uuid::from_bytes(header.vault_id),
            created: header.created,
            modified: header.modified,
            metadata,
            chunks,
        })
    }

    /// Save vault to file with password
    pub fn save_to_file(&self, path: &Path, password: &str) -> Result<(), VaultError> {
        // Update modified timestamp
        let mut vault = self.clone();
        vault.modified = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Encrypt metadata
        let encrypted_metadata = vault.encrypt_metadata(password)?;

        // Encrypt chunks
        let chunks_data = vault.encrypt_chunks(password)?;

        // Calculate checksum
        let mut hasher = Sha256::default();
        hasher.update(&encrypted_metadata);
        hasher.update(&chunks_data);
        let checksum = hasher.finalize();
        let mut checksum_array = [0u8; 32];
        checksum_array.copy_from_slice(&checksum);

        // Create header
        let header = HevHeader {
            version: FORMAT_VERSION,
            vault_id: *vault.vault_id.as_bytes(),
            created: vault.created,
            modified: vault.modified,
            checksum: checksum_array,
            metadata_size: encrypted_metadata.len() as u32,
        };

        // Write to file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        file.write_all(&header.to_bytes())?;
        file.write_all(&encrypted_metadata)?;
        file.write_all(&chunks_data)?;

        Ok(())
    }

    /// Get vault ID
    pub fn get_vault_id(&self) -> &Uuid {
        &self.vault_id
    }

    /// Get vault name
    pub fn get_name(&self) -> &str {
        &self.metadata.name
    }

    /// Get vault description
    pub fn get_description(&self) -> &str {
        &self.metadata.description
    }

    /// Set vault name
    pub fn set_name(&mut self, name: &str) {
        self.metadata.name = name.to_string();
    }

    /// Set vault description
    pub fn set_description(&mut self, description: &str) {
        self.metadata.description = description.to_string();
    }

    /// Add data to a specific chunk
    pub fn add_chunk_data(&mut self, chunk_type: ChunkType, key: &str, data: &[u8]) {
        let chunk_id = chunk_type.to_id();
        
        // Add to chunks
        self.chunks
            .entry(chunk_id)
            .or_insert_with(HashMap::new)
            .insert(key.to_string(), data.to_vec());

        // Update index
        self.metadata.index
            .entry(chunk_id)
            .or_insert_with(Vec::new)
            .push(key.to_string());
    }

    /// Get all data from a chunk
    pub fn get_chunk_data(&self, chunk_type: ChunkType) -> HashMap<String, Vec<u8>> {
        let chunk_id = chunk_type.to_id();
        self.chunks.get(&chunk_id).cloned().unwrap_or_default()
    }

    /// Get specific entry from a chunk
    pub fn get_chunk_entry(&self, chunk_type: ChunkType, key: &str) -> Option<&[u8]> {
        let chunk_id = chunk_type.to_id();
        self.chunks
            .get(&chunk_id)?
            .get(key)
            .map(|v| v.as_slice())
    }

    /// Remove entry from a chunk
    pub fn remove_chunk_entry(&mut self, chunk_type: ChunkType, key: &str) -> bool {
        let chunk_id = chunk_type.to_id();
        
        let removed = self.chunks
            .get_mut(&chunk_id)
            .map(|chunk| chunk.remove(key).is_some())
            .unwrap_or(false);

        if removed {
            // Update index
            if let Some(index) = self.metadata.index.get_mut(&chunk_id) {
                index.retain(|k| k != key);
            }
        }

        removed
    }

    // Convenience methods for standard chunk types

    /// Add connection configuration
    pub fn set_connection(&mut self, name: &str, data: &[u8]) {
        self.add_chunk_data(ChunkType::Connections, name, data);
    }

    /// Get connection configuration
    pub fn get_connection(&self, name: &str) -> Option<&[u8]> {
        self.get_chunk_entry(ChunkType::Connections, name)
    }

    /// Add SSH key
    pub fn set_ssh_key(&mut self, name: &str, key_data: &[u8]) {
        self.add_chunk_data(ChunkType::SshKeys, name, key_data);
    }

    /// Get SSH key
    pub fn get_ssh_key(&self, name: &str) -> Option<&[u8]> {
        self.get_chunk_entry(ChunkType::SshKeys, name)
    }

    /// Add code snippet
    pub fn set_snippet(&mut self, name: &str, code: &[u8]) {
        self.add_chunk_data(ChunkType::Snippets, name, code);
    }

    /// Get code snippet
    pub fn get_snippet(&self, name: &str) -> Option<&[u8]> {
        self.get_chunk_entry(ChunkType::Snippets, name)
    }

    // Private helper methods

    /// Encrypt metadata with password
    fn encrypt_metadata(&self, password: &str) -> Result<Vec<u8>, VaultError> {
        let data = serde_json::to_vec(&self.metadata)?;
        Self::encrypt_with_password(&data, password)
    }

    /// Decrypt metadata with password
    fn decrypt_metadata(encrypted_data: &[u8], password: &str) -> Result<VaultMetadata, VaultError> {
        let data = Self::decrypt_with_password(encrypted_data, password)?;
        let metadata: VaultMetadata = serde_json::from_slice(&data)?;
        Ok(metadata)
    }

    /// Encrypt all chunks
    fn encrypt_chunks(&self, password: &str) -> Result<Vec<u8>, VaultError> {
        let mut result = Vec::new();

        for (chunk_id, chunk_data) in &self.chunks {
            let serialized = serde_json::to_vec(chunk_data)?;
            let encrypted = Self::encrypt_with_password(&serialized, password)?;

            // Write chunk header
            result.extend_from_slice(&chunk_id.to_le_bytes());
            result.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
            result.extend_from_slice(&encrypted);
        }

        Ok(result)
    }

    /// Parse chunks from encrypted data
    fn parse_chunks(data: &[u8], password: &str) -> Result<HashMap<u32, HashMap<String, Vec<u8>>>, VaultError> {
        let mut chunks = HashMap::new();
        let mut offset = 0;

        while offset < data.len() {
            if offset + 8 > data.len() {
                break;
            }

            // Read chunk header
            let chunk_id = u32::from_le_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            ]);
            let chunk_size = u32::from_le_bytes([
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]
            ]) as usize;

            offset += 8;

            if offset + chunk_size > data.len() {
                return Err(VaultError::CorruptedData("Invalid chunk size".to_string()));
            }

            // Decrypt chunk data
            let encrypted_chunk = &data[offset..offset + chunk_size];
            let decrypted = Self::decrypt_with_password(encrypted_chunk, password)?;
            let chunk_data: HashMap<String, Vec<u8>> = serde_json::from_slice(&decrypted)?;

            chunks.insert(chunk_id, chunk_data);
            offset += chunk_size;
        }

        Ok(chunks)
    }

    /// Encrypt data with password (includes salt and nonce)
    fn encrypt_with_password(data: &[u8], password: &str) -> Result<Vec<u8>, VaultError> {
        // Generate salt and nonce
        let mut salt = [0u8; SALT_SIZE];
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        // Derive key
        let secret_key = SecretKey::derive_from_password(password, &salt);
        let key = Key::<Aes256Gcm>::from_slice(secret_key.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher.encrypt(nonce, data)
            .map_err(|e| VaultError::EncryptionError(e.to_string()))?;

        // Combine: salt + nonce + ciphertext
        let mut result = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data with password
    fn decrypt_with_password(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>, VaultError> {
        if encrypted_data.len() < SALT_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(VaultError::DecryptionError("Data too short".to_string()));
        }

        // Extract components
        let salt = &encrypted_data[0..SALT_SIZE];
        let nonce_bytes = &encrypted_data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
        let ciphertext = &encrypted_data[SALT_SIZE + NONCE_SIZE..];

        // Derive key
        let secret_key = SecretKey::derive_from_password(password, salt);
        let key = Key::<Aes256Gcm>::from_slice(secret_key.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::InvalidPassword)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_create_vault() {
        let vault = HevVault::new("Test Vault", "A test vault");
        assert_eq!(vault.get_name(), "Test Vault");
        assert_eq!(vault.get_description(), "A test vault");
    }

    #[test]
    fn test_add_and_get_data() {
        let mut vault = HevVault::new("Test Vault", "");
        
        vault.set_connection("db1", b"host=localhost");
        vault.set_ssh_key("key1", b"ssh-rsa AAAAB3...");
        vault.set_snippet("script1", b"#!/bin/bash\necho 'test'");

        assert_eq!(vault.get_connection("db1"), Some(b"host=localhost".as_slice()));
        assert_eq!(vault.get_ssh_key("key1"), Some(b"ssh-rsa AAAAB3...".as_slice()));
        assert_eq!(vault.get_snippet("script1"), Some(b"#!/bin/bash\necho 'test'".as_slice()));
    }

    #[test]
    fn test_custom_chunks() {
        let mut vault = HevVault::new("Test Vault", "");
        
        let custom_chunk = ChunkType::Custom(100);
        vault.add_chunk_data(custom_chunk, "custom_key", b"custom_data");

        assert_eq!(
            vault.get_chunk_entry(custom_chunk, "custom_key"),
            Some(b"custom_data".as_slice())
        );
    }

    #[test]
    fn test_save_and_load() -> Result<(), VaultError> {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        // Create and save vault
        let mut original_vault = HevVault::new("Test Vault", "Test Description");
        original_vault.set_connection("prod_db", b"host=prod.example.com");
        original_vault.set_ssh_key("server_key", b"-----BEGIN PRIVATE KEY-----");
        
        original_vault.save_to_file(path, "test_password")?;

        // Load vault
        let loaded_vault = HevVault::load_from_file(path, "test_password")?;

        // Verify data
        assert_eq!(loaded_vault.get_name(), "Test Vault");
        assert_eq!(loaded_vault.get_description(), "Test Description");
        assert_eq!(loaded_vault.get_connection("prod_db"), Some(b"host=prod.example.com".as_slice()));
        assert_eq!(loaded_vault.get_ssh_key("server_key"), Some(b"-----BEGIN PRIVATE KEY-----".as_slice()));

        Ok(())
    }

    #[test]
    fn test_wrong_password() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();

        let vault = HevVault::new("Test Vault", "");
        vault.save_to_file(path, "correct_password").unwrap();

        // Try to load with wrong password
        let result = HevVault::load_from_file(path, "wrong_password");
        assert!(matches!(result, Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn test_chunk_types() {
        assert_eq!(ChunkType::Connections.to_id(), 1);
        assert_eq!(ChunkType::SshKeys.to_id(), 2);
        assert_eq!(ChunkType::Snippets.to_id(), 3);
        assert_eq!(ChunkType::Settings.to_id(), 4);
        assert_eq!(ChunkType::Custom(100).to_id(), 100);

        assert_eq!(ChunkType::from_id(1), ChunkType::Connections);
        assert_eq!(ChunkType::from_id(100), ChunkType::Custom(100));
    }

    #[test]
    fn test_remove_entry() {
        let mut vault = HevVault::new("Test Vault", "");
        vault.set_connection("db1", b"connection1");
        vault.set_connection("db2", b"connection2");

        assert!(vault.remove_chunk_entry(ChunkType::Connections, "db1"));
        assert!(!vault.remove_chunk_entry(ChunkType::Connections, "db1")); // Already removed
        
        assert_eq!(vault.get_connection("db1"), None);
        assert_eq!(vault.get_connection("db2"), Some(b"connection2".as_slice()));
    }
}
