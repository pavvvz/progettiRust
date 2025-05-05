1. Generare una coppia di chiavi RSA con OpenSSL

    Chiave privata RSA:

openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

Questo comando genera una chiave privata RSA di 2048 bit e la salva nel file private.pem.

Chiave pubblica RSA:

openssl rsa -pubout -in private.pem -out public.pem

Questo comando estrae la chiave pubblica dalla chiave privata e la salva nel file public.pem.


| Su Linux         | Su Windows                                                                  |
| ---------------- | --------------------------------------------------------------------------- |
| `private.pem`    | Copia nella cartella del .exe                                               |
| `public.pem`     | Serve solo per cifrare la chiave AES                                        |
| `aes.key`        | 🔒 *Non copiarla su Windows mai in chiaro*                                  |
| `key.bin.enc`    | ✅ Copia su Windows                                                          |
| Programma `.exe` | ✅ Esegui su Windows con `key.bin.enc` e `private.pem` nella stessa cartella |
