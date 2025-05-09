use clap::{Parser, Subcommand};
use rand::Rng;
use regex::Regex;
use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::str;

// Struttura per gli argomenti della riga di comando
#[derive(Parser, Debug)]
#[clap(about = "Strumento di MAC spoofing per sistemi Unix")]
struct Args {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Lista le interfacce di rete disponibili
    List,
    /// Modifica o ripristina l'indirizzo MAC
    Spoof {
        /// Interfaccia di rete da utilizzare
        #[clap(short, long)]
        interface: String,
        /// Indirizzo MAC specifico (opzionale)
        #[clap(short, long)]
        mac: Option<String>,
        /// Genera un MAC casuale
        #[clap(short, long, action)]
        random: bool,
        /// Ripristina l'indirizzo MAC originale
        #[clap(long, action)]
        restore: bool,
    },
}

// Struttura principale per gestire il MAC spoofing
struct MacSpoofer {
    current_mac: Option<String>,
    interface: Option<String>,
    is_root: bool,
}

impl MacSpoofer {
    // Inizializza un nuovo oggetto MacSpoofer
    fn new() -> Self {
        // Verifica se l'utente è root utilizzando la crate whoami
        let is_root = whoami::uid() == 0;
        MacSpoofer {
            current_mac: None,
            interface: None,
            is_root,
        }
    }

    // Ottiene la lista delle interfacce di rete disponibili
    fn get_interfaces(&self) -> Result<Vec<String>, String> {
        // Esegue il comando 'ip link show' per ottenere le interfacce
        let output = Command::new("ip")
            .args(["link", "show"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Errore esecuzione 'ip link show': {}", e))?;

        if output.status.success() {
            let stdout = str::from_utf8(&output.stdout)
                .map_err(|e| format!("Errore decodifica output: {}", e))?;
            let mut interfaces = Vec::new();
            // Regex per estrarre i nomi delle interfacce (esclude interfacce virtuali come lo@)
            let re = Regex::new(r"^\d+: ([^:]+):").unwrap();

            for line in stdout.lines() {
                if let Some(captures) = re.captures(line.trim()) {
                    let iface = captures.get(1).unwrap().as_str();
                    if !iface.contains('@') {
                        interfaces.push(iface.to_string());
                    }
                }
            }

            if !interfaces.is_empty() {
                return Ok(interfaces);
            }
        }

        // Fallback su 'ifconfig' per sistemi BSD o più vecchi
        let output = Command::new("ifconfig")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Errore esecuzione 'ifconfig': {}", e))?;

        if output.status.success() {
            let stdout = str::from_utf8(&output.stdout)
                .map_err(|e| format!("Errore decodifica output: {}", e))?;
            let mut interfaces = Vec::new();
            let re = Regex::new(r"^([a-zA-Z0-9]+):").unwrap();

            for line in stdout.lines() {
                if !line.starts_with(' ') {
                    if let Some(captures) = re.captures(line) {
                        interfaces.push(captures[1].to_string());
                    }
                }
            }
            Ok(interfaces)
        } else {
            Err("Impossibile ottenere le interfacce di rete.".to_string())
        }
    }

    // Ottiene l'indirizzo MAC attuale per l'interfaccia specificata
    fn get_current_mac(&self, interface: &str) -> Result<Option<String>, String> {
        // Prova con 'ip link show <interface>'
        let output = Command::new("ip")
            .args(["link", "show", interface])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Errore esecuzione 'ip link show {}': {}", interface, e))?;

        if output.status.success() {
            let stdout = str::from_utf8(&output.stdout)
                .map_err(|e| format!("Errore decodifica output: {}", e))?;
            let re = Regex::new(r"link/ether ([0-9a-f:]{17})").unwrap();
            if let Some(captures) = re.captures(stdout) {
                return Ok(Some(captures[1].to_string()));
            }
        }

        // Fallback su 'ifconfig <interface>'
        let output = Command::new("ifconfig")
            .arg(interface)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("Errore esecuzione 'ifconfig {}': {}", interface, e))?;

        if output.status.success() {
            let stdout = str::from_utf8(&output.stdout)
                .map_err(|e| format!("Errore decodifica output: {}", e))?;
            let re = Regex::new(r"(ether|HWaddr|lladdr) ([0-9a-f:]{17})").unwrap();
            if let Some(captures) = re.captures(stdout) {
                return Ok(Some(captures[2].to_string()));
            }
        }

        Err(format!(
            "Impossibile ottenere l'indirizzo MAC per {}",
            interface
        ))
    }

    // Genera un indirizzo MAC casuale
    fn generate_mac(&self, vendor_prefix: Option<&str>) -> Result<String, String> {
        let mut rng = rand::thread_rng();

        let prefix = if let Some(prefix) = vendor_prefix {
            // Verifica il formato del prefisso del venditore
            let re = Regex::new(r"^([0-9a-f]{2}:){2}[0-9a-f]{2}$").unwrap();
            if !re.is_match(prefix.to_lowercase().as_str()) {
                return Err(
                    "Il prefisso del venditore deve essere nel formato XX:XX:XX".to_string()
                );
            }
            prefix.to_lowercase()
        } else {
            // Genera un prefisso casuale con bit locale amministrato
            let byte1 = rng.gen_range(0..=254);
            let byte1 = (byte1 & 0xFE) | 0x02; // Forza il bit locale amministrato
            format!(
                "{:02x}:{:02x}:{:02x}",
                byte1,
                rng.gen::<u8>(),
                rng.gen::<u8>()
            )
        };

        // Genera i restanti 3 byte
        let suffix: String = (0..3)
            .map(|_| format!("{:02x}", rng.gen::<u8>()))
            .collect::<Vec<String>>()
            .join(":");
        Ok(format!("{}:{}", prefix, suffix))
    }

    // Cambia l'indirizzo MAC dell'interfaccia specificata
    fn change_mac(
        &mut self,
        interface: &str,
        new_mac: Option<String>,
    ) -> Result<(bool, String), String> {
        if !self.is_root {
            return Ok((
                false,
                "Devi essere root per cambiare l'indirizzo MAC".to_string(),
            ));
        }

        self.interface = Some(interface.to_string());

        // Verifica che l'interfaccia esista
        let interfaces = self.get_interfaces()?;
        if !interfaces.contains(&interface.to_string()) {
            return Ok((false, format!("L'interfaccia {} non esiste", interface)));
        }

        // Ottiene l'indirizzo MAC attuale
        self.current_mac = self.get_current_mac(interface)?;
        if self.current_mac.is_none() {
            return Ok((
                false,
                format!(
                    "Impossibile ottenere l'indirizzo MAC attuale per {}",
                    interface
                ),
            ));
        }

        // Determina il nuovo MAC
        let new_mac = if let Some(mac) = new_mac {
            // Verifica il formato del MAC
            let re = Regex::new(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$").unwrap();
            if !re.is_match(mac.to_lowercase().as_str()) {
                return Ok((
                    false,
                    "Il formato MAC non è valido. Usa XX:XX:XX:XX:XX:XX".to_string(),
                ));
            }
            mac.to_lowercase()
        } else {
            self.generate_mac(None)?
        };

        // Prova a cambiare il MAC con 'ip'
        println!("[*] Disattivazione dell'interfaccia {}...", interface);
        let status = Command::new("ip")
            .args(["link", "set", interface, "down"])
            .status()
            .map_err(|e| format!("Errore disattivazione interfaccia: {}", e))?;

        if !status.success() {
            return Ok((
                false,
                "Errore durante la disattivazione dell'interfaccia".to_string(),
            ));
        }

        println!("[*] Cambiamento dell'indirizzo MAC a {}...", new_mac);
        let status = Command::new("ip")
            .args(["link", "set", interface, "address", &new_mac])
            .status()
            .map_err(|e| format!("Errore cambiamento MAC: {}", e))?;

        if !status.success() {
            // Fallback su 'ifconfig'
            println!("[*] Tentativo con ifconfig...");
            let status = Command::new("ifconfig")
                .arg(interface)
                .arg("down")
                .status()
                .map_err(|e| format!("Errore disattivazione ifconfig: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante la disattivazione con ifconfig".to_string(),
                ));
            }

            let status = Command::new("ifconfig")
                .arg(interface)
                .args(["hw", "ether", &new_mac])
                .status()
                .map_err(|e| format!("Errore cambiamento MAC con ifconfig: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante il cambiamento MAC con ifconfig".to_string(),
                ));
            }

            let status = Command::new("ifconfig")
                .arg(interface)
                .arg("up")
                .status()
                .map_err(|e| format!("Errore riattivazione ifconfig: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante la riattivazione con ifconfig".to_string(),
                ));
            }
        } else {
            println!("[*] Riattivazione dell'interfaccia {}...", interface);
            let status = Command::new("ip")
                .args(["link", "set", interface, "up"])
                .status()
                .map_err(|e| format!("Errore riattivazione interfaccia: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante la riattivazione dell'interfaccia".to_string(),
                ));
            }
        }

        // Verifica il cambiamento
        let new_current_mac = self.get_current_mac(interface)?;
        if let Some(current) = new_current_mac {
            if current.to_lowercase() == new_mac.to_lowercase() {
                Ok((
                    true,
                    format!(
                        "Indirizzo MAC cambiato con successo da {} a {}",
                        self.current_mac.as_ref().unwrap(),
                        new_mac
                    ),
                ))
            } else {
                Ok((
                    false,
                    format!(
                        "Impossibile verificare il cambio MAC. MAC attuale: {}",
                        current
                    ),
                ))
            }
        } else {
            Ok((
                false,
                "Impossibile ottenere il nuovo MAC dopo il cambio".to_string(),
            ))
        }
    }

    // Ripristina l'indirizzo MAC originale
    fn restore_mac(&mut self) -> Result<(bool, String), String> {
        if !self.is_root {
            return Ok((
                false,
                "Devi essere root per ripristinare l'indirizzo MAC".to_string(),
            ));
        }

        let interface = match &self.interface {
            Some(iface) => iface,
            None => {
                return Ok((
                    false,
                    "Nessun indirizzo MAC precedente da ripristinare".to_string(),
                ));
            }
        };
        let original_mac = match &self.current_mac {
            Some(mac) => mac,
            None => {
                return Ok((
                    false,
                    "Nessun indirizzo MAC precedente da ripristinare".to_string(),
                ));
            }
        };

        // Disattiva l'interfaccia
        let status = Command::new("ip")
            .args(["link", "set", interface, "down"])
            .status()
            .map_err(|e| format!("Errore disattivazione interfaccia: {}", e))?;

        if !status.success() {
            return Ok((
                false,
                "Errore durante la disattivazione dell'interfaccia".to_string(),
            ));
        }

        // Ripristina il MAC
        let status = Command::new("ip")
            .args(["link", "set", interface, "address", original_mac])
            .status()
            .map_err(|e| format!("Errore ripristino MAC: {}", e))?;

        if !status.success() {
            // Fallback su 'ifconfig'
            let status = Command::new("ifconfig")
                .arg(interface)
                .arg("down")
                .status()
                .map_err(|e| format!("Errore disattivazione ifconfig: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante la disattivazione con ifconfig".to_string(),
                ));
            }

            let status = Command::new("ifconfig")
                .arg(interface)
                .args(["hw", "ether", original_mac])
                .status()
                .map_err(|e| format!("Errore ripristino MAC con ifconfig: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante il ripristino MAC con ifconfig".to_string(),
                ));
            }

            let status = Command::new("ifconfig")
                .arg(interface)
                .arg("up")
                .status()
                .map_err(|e| format!("Errore riattivazione ifconfig: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante la riattivazione con ifconfig".to_string(),
                ));
            }
        } else {
            let status = Command::new("ip")
                .args(["link", "set", interface, "up"])
                .status()
                .map_err(|e| format!("Errore riattivazione interfaccia: {}", e))?;

            if !status.success() {
                return Ok((
                    false,
                    "Errore durante la riattivazione dell'interfaccia".to_string(),
                ));
            }
        }

        // Verifica il ripristino
        let new_current_mac = self.get_current_mac(interface)?;
        if let Some(current) = new_current_mac {
            if current.to_lowercase() == original_mac.to_lowercase() {
                let temp_interface = self.interface.take();
                self.current_mac = None;
                Ok((
                    true,
                    format!(
                        "Indirizzo MAC dell'interfaccia {} ripristinato con successo",
                        temp_interface.unwrap()
                    ),
                ))
            } else {
                Ok((
                    false,
                    format!(
                        "Impossibile verificare il ripristino MAC. MAC attuale: {}",
                        current
                    ),
                ))
            }
        } else {
            Ok((
                false,
                "Impossibile ottenere il MAC dopo il ripristino".to_string(),
            ))
        }
    }
}

// Funzione principale
fn main() -> Result<(), String> {
    let args = Args::parse();
    let mut spoofer = MacSpoofer::new();

    if !spoofer.is_root {
        println!("[!] Questo programma deve essere eseguito come root (sudo).");
        return Ok(());
    }

    match args.command {
        Some(Commands::List) => {
            // Lista le interfacce disponibili
            let interfaces = spoofer.get_interfaces()?;
            println!("\nInterfacce di rete disponibili:");
            for iface in interfaces {
                let mac = spoofer.get_current_mac(&iface)?;
                println!(
                    "  - {}: {}",
                    iface,
                    mac.unwrap_or("MAC non disponibile".to_string())
                );
            }
            println!();
            Ok(())
        }
        Some(Commands::Spoof {
            interface,
            mac,
            random,
            restore,
        }) => {
            // Gestisce il cambio o il ripristino del MAC
            let current_mac = spoofer.get_current_mac(&interface)?;
            if let Some(mac) = current_mac {
                println!("[*] Indirizzo MAC attuale per {}: {}", interface, mac);
            }

            if restore {
                let (success, message) = spoofer.restore_mac()?;
                println!("[{}] {}", if success { "✓" } else { "✗" }, message);
                return Ok(());
            }

            if random || mac.is_some() {
                let (success, message) = spoofer.change_mac(&interface, mac)?;
                println!("[{}] {}", if success { "✓" } else { "✗" }, message);
                Ok(())
            } else {
                println!("[!] Specifica --random per un MAC casuale o --mac per un MAC specifico.");
                let interfaces = spoofer.get_interfaces()?;
                println!("\nInterfacce disponibili:");
                for iface in interfaces {
                    let mac = spoofer.get_current_mac(&iface)?;
                    println!(
                        "  - {}: {}",
                        iface,
                        mac.unwrap_or("MAC non disponibile".to_string())
                    );
                }
                println!("\nUtilizzo: sudo macspoofer --interface <interfaccia> [opzioni]\n");
                Ok(())
            }
        }
        None => {
            // Nessun comando specificato, mostra le interfacce disponibili
            let interfaces = spoofer.get_interfaces()?;
            println!("\nSpecifica un'interfaccia tra queste:");
            for iface in interfaces {
                let mac = spoofer.get_current_mac(&iface)?;
                println!(
                    "  - {}: {}",
                    iface,
                    mac.unwrap_or("MAC non disponibile".to_string())
                );
            }
            println!("\nUtilizzo: sudo macspoofer --interface <interfaccia> [opzioni]\n");
            Ok(())
        }
    }
}
