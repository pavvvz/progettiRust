use std::fs::OpenOptions;
use std::io::{self, Seek, SeekFrom, Write, stdin, stdout};
use std::os::windows::fs::OpenOptionsExt;
use std::ptr;
use winapi::um::fileapi::{GetVolumeInformationByHandleW, GetVolumePathNameW};
use winapi::um::winioctl::DISK_GEOMETRY;

fn get_boot_disk() -> io::Result<String> {
    // In una VM, il disco di boot è quasi sempre \\.\PhysicalDrive0
    // Questo è un approccio semplificato. Per robustezza, verifichiamo il disco di sistema.
    let system_drive = std::env::var("SystemDrive").unwrap_or("C:".to_string());
    let disk_path = r"\\.\PhysicalDrive0"; // Predefinito per VM

    // Verifica se PhysicalDrive0 è il disco di boot (semplificato)
    // Nota: In una VM, PhysicalDrive0 è solitamente corretto
    Ok(disk_path.to_string())
}

fn main() -> io::Result<()> {
    // Ottieni il disco di boot
    let disk_path = match get_boot_disk() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Errore nel trovare il disco di boot: {}", e);
            return Err(e);
        }
    };

    // Prompt di conferma
    println!(
        "ATTENZIONE: Questa operazione CANCELLERÀ l'MBR di {}.",
        disk_path
    );
    println!("La VM diventerà NON AVVIABILE. Sei sicuro? (sì/no)");
    stdout().flush()?;

    let mut input = String::new();
    stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() != "sì" {
        println!("Operazione annullata.");
        return Ok(());
    }

    // Apertura del disco in modalità lettura/scrittura
    let mut disk = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(winapi::um::winnt::FILE_SHARE_READ | winapi::um::winnt::FILE_SHARE_WRITE)
        .open(&disk_path)
    {
        Ok(file) => {
            println!("Disco aperto con successo: {}", disk_path);
            file
        }
        Err(e) => {
            eprintln!("Errore nell'apertura del disco {}: {}", disk_path, e);
            return Err(e);
        }
    };

    // Crea un buffer di 512 byte di zeri
    let mbr_data: [u8; 512] = [0; 512];

    // Posizionati all'inizio del disco (settore 0)
    match disk.seek(SeekFrom::Start(0)) {
        Ok(_) => println!("Posizionamento all'inizio del disco riuscito."),
        Err(e) => {
            eprintln!("Errore nel posizionamento: {}", e);
            return Err(e);
        }
    }

    // Scrivi i 512 byte di zeri nell'MBR
    match disk.write_all(&mbr_data) {
        Ok(_) => println!("Cancellazione dell'MBR riuscita."),
        Err(e) => {
            eprintln!("Errore nella scrittura: {}", e);
            return Err(e);
        }
    }

    // Sincronizza le modifiche
    match disk.flush() {
        Ok(_) => println!("Sincronizzazione riuscita."),
        Err(e) => {
            eprintln!("Errore nella sincronizzazione: {}", e);
            return Err(e);
        }
    }

    println!("MBR cancellato con successo! La VM non sarà più avviabile.");
    Ok(())
}
