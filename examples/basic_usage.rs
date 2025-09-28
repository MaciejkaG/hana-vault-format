//! Basic usage example for the hana-vault-format crate.
//! 
//! This example demonstrates how to create a vault, add data to it,
//! save it to a file, and load it back.

use hana_vault::{HevVault, ChunkType, VaultError};
use std::path::Path;

fn main() -> Result<(), VaultError> {
    println!("=== Hana Vault Format Example ===\n");

    // Create a new vault
    println!("1. Creating a new vault...");
    let mut vault = HevVault::new("My Personal Vault", "A vault for storing my secrets");
    println!("   Vault ID: {}", vault.get_vault_id());
    println!("   Name: {}", vault.get_name());
    println!("   Description: {}\n", vault.get_description());

    // Add some connection configurations
    println!("2. Adding connection configurations...");
    vault.set_connection("production_db", b"host=prod.example.com port=5432 dbname=myapp user=admin password=secret123");
    vault.set_connection("staging_db", b"host=staging.example.com port=5432 dbname=myapp user=staging password=test456");
    println!("   Added production_db and staging_db connections\n");

    // Add SSH keys
    println!("3. Adding SSH keys...");
    vault.set_ssh_key("server_key", b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ...\n-----END PRIVATE KEY-----");
    vault.set_ssh_key("deploy_key", b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7... user@example.com");
    println!("   Added server_key and deploy_key\n");

    // Add code snippets
    println!("4. Adding code snippets...");
    vault.set_snippet("backup_script", b"#!/bin/bash\n# Database backup script\npg_dump -h $DB_HOST -U $DB_USER $DB_NAME > backup_$(date +%Y%m%d).sql");
    vault.set_snippet("deploy_script", b"#!/bin/bash\n# Deployment script\ngit pull origin main\nnpm install\nnpm run build\nsudo systemctl restart myapp");
    println!("   Added backup_script and deploy_script\n");

    // Add a custom chunk
    println!("5. Adding custom data...");
    let api_keys_chunk = ChunkType::Custom(1000);
    vault.add_chunk_data(api_keys_chunk, "github_token", b"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    vault.add_chunk_data(api_keys_chunk, "aws_access_key", b"AKIAIOSFODNN7EXAMPLE");
    println!("   Added API keys to custom chunk\n");

    // Save the vault to a file
    let vault_path = Path::new("example_vault.hev");
    let password = "my_super_secure_password_123!";
    
    println!("6. Saving vault to file...");
    vault.save_to_file(vault_path, password)?;
    println!("   Vault saved to: {}\n", vault_path.display());

    // Load the vault from file
    println!("7. Loading vault from file...");
    let loaded_vault = HevVault::load_from_file(vault_path, password)?;
    println!("   Vault loaded successfully!\n");

    // Verify the data
    println!("8. Verifying loaded data...");
    
    // Check connections
    if let Some(prod_config) = loaded_vault.get_connection("production_db") {
        println!("   Production DB: {}", String::from_utf8_lossy(prod_config));
    }
    
    // Check SSH keys
    if let Some(server_key) = loaded_vault.get_ssh_key("server_key") {
        let key_preview = String::from_utf8_lossy(server_key);
        let preview = if key_preview.len() > 50 {
            format!("{}...", &key_preview[..47])
        } else {
            key_preview.to_string()
        };
        println!("   Server key: {}", preview);
    }
    
    // Check snippets
    if let Some(backup_script) = loaded_vault.get_snippet("backup_script") {
        println!("   Backup script: {}", String::from_utf8_lossy(backup_script));
    }
    
    // Check custom chunk
    if let Some(github_token) = loaded_vault.get_chunk_entry(api_keys_chunk, "github_token") {
        let token = String::from_utf8_lossy(github_token);
        let masked_token = format!("{}...{}", &token[..8], &token[token.len()-4..]);
        println!("   GitHub token: {}", masked_token);
    }

    println!("\n9. Listing all connections:");
    let connections = loaded_vault.get_chunk_data(ChunkType::Connections);
    for (name, _) in connections {
        println!("   - {}", name);
    }

    // Clean up
    if vault_path.exists() {
        std::fs::remove_file(vault_path).ok();
        println!("\n10. Cleaned up example file");
    }

    println!("\n=== Example completed successfully! ===");
    Ok(())
}
