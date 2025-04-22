// src/main.rs

// Definizione di una struttura con metodi
struct Persona {
    nome: String,
    eta: u8,
}

impl Persona {
    fn saluta(&self) {
        println!("Ciao, mi chiamo {} e ho {} anni.", self.nome, self.eta);
    }

    fn invecchia(&mut self) {
        self.eta += 1;
    }
}

// Funzione principale
fn main() {
    println!("Benvenuto nel programma Rust!");

    // Variabili e mutabilità
    let mut numero = 5;
    println!("Il numero iniziale è: {}", numero);

    // Funzione che prende ownership
    stampa_numero(numero);
    // println!("{}", numero); // ERRORE: numero non è più valido

    // Variabile mutabile
    let mut numero_mut = 10;
    incrementa(&mut numero_mut);
    println!("Dopo incremento: {}", numero_mut);

    // Controllo del flusso con if
    if numero_mut > 10 {
        println!("Il numero è maggiore di 10");
    } else {
        println!("Il numero è 10 o meno");
    }

    // Ciclo while
    let mut contatore = 0;
    while contatore < 3 {
        println!("Contatore: {}", contatore);
        contatore += 1;
    }

    // Ciclo for
    for i in 1..=3 {
        println!("Iterazione: {}", i);
    }

    // Utilizzo della struttura Persona
    let mut persona = Persona {
        nome: String::from("Luca"),
        eta: 30,
    };

    persona.saluta();
    persona.invecchia();
    persona.saluta();
}

// Funzione che prende ownership
fn stampa_numero(n: i32) {
    println!("Numero ricevuto: {}", n);
}

// Funzione che prende un riferimento mutabile
fn incrementa(n: &mut i32) {
    *n += 1;
}
