#  Analisi del Codice di Crittografia File con AES-GCM in Rust

Questo script Rust crittografa ricorsivamente file sensibili all’interno della directory utente su Windows, utilizzando **AES-256 in modalità GCM**. Salva inoltre metadati e chiave in un file JSON per successiva decrittazione.

---

## Importazioni

```rust
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;
```

- `aes_gcm`: Crate per AES-GCM. `Aes256Gcm` rappresenta il cifrario, `Aead` fornisce i metodi `encrypt` e `decrypt`.
- `rand`: Per generare chiavi casuali e nonce sicuri.
- `serde`: Per serializzare e deserializzare dati in JSON.
- `std::fs`, `std::io`: Per operazioni di I/O su file.
- `uuid`: Genera UUID univoci per identificare le sessioni di cifratura.
- `walkdir`: Scansiona directory ricorsivamente.

---

## 🧩 Strutture Dati

```rust
#[derive(Serialize, Deserialize)]
struct KeyData {
    id: String,
    aes_key: Vec<u8>,
    files: Vec<FileMetadata>,
}
```

- `KeyData`: Rappresenta i dati salvati in JSON: identificativo della sessione, chiave AES, metadati file.

```rust
#[derive(Serialize, Deserialize)]
struct FileMetadata {
    path: String,
    nonce: Vec<u8>,
    extension: String,
}
```

- `FileMetadata`: Contiene percorso del file cifrato, il nonce AES-GCM usato e l’estensione originale del file.

---

## 🔑 Generazione Chiave AES

```rust
fn generate_aes_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    thread_rng().fill(&mut key);
    key.to_vec()
}
```

- Genera una chiave AES-256 (32 byte) usando un CSPRNG (`thread_rng`).
- Ritorna un `Vec<u8>` con la chiave.

---

## 🔒 Crittografia di un File

```rust
fn encrypt_file(...) -> Result<(Vec<u8>, Vec<u8>, String), Box<dyn std::error::Error>> { ... }
```

1. Legge i dati del file (`File::open`, `read_to_end`).
2. Inizializza `Aes256Gcm` con la chiave passata.
3. Genera un `nonce` casuale di 12 byte.
4. Esegue `encrypt` con il nonce e il contenuto.
5. Ritorna:
   - Dati cifrati con nonce pre-pendato.
   - Il nonce separatamente.
   - L’estensione del file.

---

## 🧾 Salvataggio della Chiave e Metadati

```rust
fn store_key_data(...) -> Result<String, Box<dyn std::error::Error>> { ... }
```

1. Crea un `KeyData` con UUID.
2. Serializza in JSON.
3. Scrive il JSON su disco come `key_data_<uuid>.json`.
4. Ritorna l’ID della sessione.

---

## 📂 Selezione File da Crittografare

```rust
fn select_files(root: &str) -> Vec<String> { ... }
```

1. Scansiona ricorsivamente `root` (es. `C:\Users\<utente>`).
2. Filtra solo file con estensione `txt`, `pdf`, `docx`.
3. Esclude percorsi comuni di sistema (Windows, Program Files, AppData, ecc.).
4. Ritorna una lista di percorsi assoluti.

---

## 🔓 Decrittografia

```rust
fn decrypt_file(...) -> Result<Vec<u8>, Box<dyn std::error::Error>> { ... }
```

1. Inizializza `Aes256Gcm` con la chiave.
2. Crea un `Nonce` dai byte forniti.
3. Esegue `decrypt` con nonce e dati cifrati.
4. Ritorna il contenuto originale del file.

---

## 🏁 Funzione Principale

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> { ... }
```

1. Recupera il nome utente da variabile d’ambiente (`USER` o `USERNAME`).
2. Costruisce `target_dir` (es. `C:\Users\Username`).
3. Genera una nuova chiave AES-256.
4. Seleziona i file da cifrare nella directory utente.
5. Per ogni file:
   - Cifra e salva la versione `.enc`.
   - Sovrascrive con 1 KB di dati casuali.
   - Elimina il file originale.
   - Registra metadati.
6. Salva i metadati e la chiave su JSON.
7. **Test di decrittografia**:
   - Rilegge il JSON appena salvato.
   - Decifra ogni file usando la chiave e nonce.
   - Ripristina i file con estensione originale.

---


## 📌 Possibili Miglioramenti

- Cancellazione sicura con `sdelete` o similar tool.
- Uso di `zeroize` per cancellare chiavi dalla RAM.
- Supporto per chunk di file grandi (streaming).
- Aggiunta di autenticazione dei file (tag GCM).
- Logging delle operazioni.
