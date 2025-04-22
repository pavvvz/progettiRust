use std::io; //serve ad importare dalla standard library la libreria IO per l'input
fn main() {
    println!("Guess the number");
    println!("Input the guess");
    let mut guess = String::new();
    io::stdin()
        .read_line(&mut guess)
        .expect("Something went wrong"); //avoid possible errors

    println!("The number you guessed is {}", guess)
}
