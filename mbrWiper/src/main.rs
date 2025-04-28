use std::fs::OpenOptions;
use std::io::{Write, Seek, SeekFrom, stdin, stdout, Write as IoWrite};
use std::os::windows::fs::OpenOptionsExt;
use rand::Rng;

fn main() -> std::io::Result<()> {
    // Specifica il disco (es. \\.\PhysicalDrive1 o percorso del file .vdi)
    let disk_path = r"\\.\PhysicalDrive1"; // Oppure es. r"C:\VMs\mia_vm.vdi"

    // Prompt di conferma
    println!("ATTENZIONE: Questa operazione sovrascriverà l'MBR di {}.", disk_path);
    println!("Il sistema diventerà NON AVVIABILE. Sei sicuro? (sì/no)");
    stdout().flush()?;

    let mut input = String::new();
    stdin().read_line(&mut input)?;
    if input.trim().to_lowercase() != "sì" {
        println!("Operazione annullata.");
        return Ok(());
    }

    // Apertura del disco in modalità lettura/scrittura
    let mut disk = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(winapi::um::winnt::FILE_SHARE_READ | winapi::um::winnt::FILE_SHARE_WRITE)
        .open(disk_path)?;

    // Genera 512 byte casuali
    let mut rng = rand::thread_rng();
    let mbr_data: [u8; 512] = rng.gen::<[u8; 512]>();

    // Posizionati all'inizio del disco (settore 0)
    disk.seek(SeekFrom::Start(0))?;

    // Scrivi i dati casuali nell'MBR
    disk.write_all(&mbr_data)?;
    disk.flush()?;

    println!("MBR riempito con dati casuali con successo! Il sistema non sarà più avviabile.");
    Ok(())
}
