# PGP Kriptografski Pipeline - Tehnička Specifikacija 

Ovaj dokument služi kao kontrolna lista (Checklist) i tehnička specifikacija za implementaciju kriptografskog pipeline-a. Nakon faze potpisivanja, podaci prelaze u čist binarni oblik (`bytes`) gde se informacije (poput flega za kompresiju) lepe direktno na bajt stream.

---

## DEO 1: Priprema podataka, Autentikacija i Kompresija

### - [ ] 1. (Obavezno) Kreiranje komponente poruke (`create_message_component`)
Ova funkcija uzima sirovi sadržaj fajla i pakuje ga sa metapodacima (ime fajla i vreme).

* **Potpis funkcije:**
    ```python
    def create_message_component(data: str, filename: str) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `data` (`str`): Tekst iz datoteke koja se šalje.
    * `filename` (`str`): Naziv originalne datoteke.

* **Povratna vrednost (`dict`):**
    ```python
    {
        'filename': str,      # Naziv fajla
        'timestamp': int,     # Vreme kreiranja
        'data': bytes         # Sirovi podaci fajla
    }
    ```

### - [ ] 1b. (Obavezno) Unwarp komponente poruke (`extract_message_component`)
Ova funkcija predstavlja obrnuti tok za `create_message_component`. Prima serijalizovan ili pakovan sadržaj poruke i vraća originalni skup metapodataka i sirovih bajtova.

* **Potpis funkcije:**
    ```python
    def extract_message_component(packed_message: dict) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `packed_message` (`dict`): Pakovana poruka dobijena nakon pripreme podataka.
* **Povratna vrednost (`dict`):**
    ```python
    {
        'filename': str,      # Naziv fajla
        'timestamp': int,     # Vreme kreiranja
        'data': str        # Originalni sirovi podaci fajla
    }
    ```

---

### - [ ] 2. (Opciono) Digitalno potpisivanje (`sign_message`)
Ukoliko je izabrana opcija potpisivanja, ova funkcija generiše SHA-1 hash nad celokupnom komponentom poruke, šifruje ga privatnim ključem pošiljaoca i generiše potpis.

* **Potpis funkcije:**
    ```python
    def sign_message(message_component: dict, sender_private_key: object, sender_key_id: str) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `message_component` (`dict`): Rečnik dobijen iz funkcije `create_message_component`.
    * `sender_private_key` (`object`): RSA privatni ključ pošiljaoca.
    * `sender_key_id` (`str`): ID javnog ključa pošiljaoca (8 bajtova u heksadecimalnom formatu).
* **Povratna vrednost (`dict`):**
    ```python
    {
        'sender_key_id': str,     # ID ključa kojim je poruka potpisana
        'sig_timestamp': int,     # Vreme nastanka digitalnog potpisa
        'leading_octets': bytes,  # Prva 2 bajta hash-a (za brzu proveru ispravnosti)
        'encrypted_hash': bytes,  # SHA-1 hash šifrovan pomoću sender_private_key
        'message_comp': dict      # Originalni rečnik komponente poruke
    }
    ```

### - [ ] 2b. (Opciono) Verifikacija potpisa (`verify_signature`)
Ova funkcija predstavlja obrnuti tok za `sign_message`. Ona proverava da li je digitalni potpis validan koristeći javni ključ pošiljaoca i da li hash poruke odgovara potpisanim podacima. Ako je potpis ispravan, vraća originalnu komponentu poruke i rezultat provere.

* **Potpis funkcije:**
    ```python
    def verify_signature(signed_packet: dict, sender_public_key: object) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `signed_packet` (`dict`): Rečnik dobijen iz `sign_message`.
    * `sender_public_key` (`object`): RSA javni ključ pošiljaoca.
* **Povratna vrednost (`dict`):**
    ```python
    {
        'is_valid': bool,           # Rezultat provere potpisa
        'sender_key_id': str,       # ID ključa pošiljaoca
        'message_comp': dict        # Originalna komponenta poruke iz potpisanog paketa
    }
    ```

---

### - [ ] 3. (Obavezno) Serijalizacija i opciona kompresija (`compress_data`)
Ova funkcija prima paket u obliku rečnika, prvo ga interno serijalizuje u bajtove, zatim ga opciono kompresuje. Na početak bajt stream-a dodaje se 1 bajt koji označava da li je kompresija rađena.

* **Potpis funkcije:**
    ```python
    def compress_data(packet: dict, is_signed: bool, perform_compression: bool) -> bytes:
        pass
    ```
* **Ulazni argumenti:**
    * `packet` (`dict`): Paket koji treba serijalizovati. Može biti obična komponenta poruke ili potpisani paket.
    * `is_signed` (`bool`): Oznaka da li je prosleđeni paket potpisani paket.
    * `perform_compression` (`bool`): Oznaka da li korisnik želi da se nad serijalizovanim podacima izvrši ZIP kompresija.
* **Povratna vrednost (`bytes`):**
    * Niz bajtova koji na poziciji `[0]` ima fleg o kompresiji, a u nastavku podatke.
    * Ukoliko je `perform_compression=True`: Vraća `b'\x01' + zip_compressed_serialized_packet`
    * Ukoliko je `perform_compression=False`: Vraća `b'\x00' + serialized_packet`

### - [ ] 3b. (Obavezno) Opciona dekompresija i deserijalizacija (`decompress_data`)
Ova funkcija prima bajtove dobijene nakon dekripcije, skida fleg kompresije, po potrebi dekompresuje sadržaj i zatim interno deserijalizuje paket.

* **Potpis funkcije:**
    ```python
    def decompress_data(compressed_bytes: bytes) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `compressed_bytes` (`bytes`): Bajtovi iz `decode_radix64` ili `decrypt_message`, sa flegom kompresije na početku.
* **Povratna vrednost (`dict`):**
    * Deserijalizovani paket.
    * Ako paket nije bio potpisan, vraća običnu komponentu poruke.
    * Ako je paket bio potpisan, vraća potpisani paket.

## DEO 2: Tajnost (Enkripcija) i Radix-64 Prenos

### - [x] 4. Enkripcija poruke i ključa sesije (`encrypt_message`)
Ova funkcija generiše jednokratni ključ sesije ($K_s$) za izabrani simetrični algoritam. Ona uzima kompletan niz bajtova iz koraka kompresije (zajedno sa zalepljenim flegom) i simetrično ga šifruje. Ključ sesije se šifruje javnim ključem primaoca.

* **Potpis funkcije:**
    ```python
    def encrypt_message(compressed_bytes: bytes, receiver_public_key: object, symmetric_algo: str) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `compressed_bytes` (`bytes`): Finalni niz bajtova dobijen iz `compress_data` (sadrži fleg na početku).
    * `receiver_public_key` (`object`): RSA javni ključ primaoca poruke.
    * `receiver_key_id` (`str`): Hex vrednost id-ja
    * `symmetric_algo` (`str`): Naziv izabranog simetričnog algoritma (npr. `'AES128'`, `'3DES'`).
* **Povratna vrednost (`dict`):**
    ```python
    {
        'receiver_key_id': bytes,     # Poslednjih 8 bajtova serijalizovanog javnog ključa primaoca
        'session_key': bytes,         # Ključ sesije (Ks) šifrovan pomoću receiver_public_key
        'symmetric_algo': str,        # Naziv algoritma korišćenog za enkripciju podataka
        'encrypted_data': bytes       # Simetrično šifrovan ceo niz [E(Ks, compressed_bytes)]
    }
    ```

### - [x] 4b. Dekripcija poruke i ključa sesije (`decrypt_message`)
Ova funkcija predstavlja obrnuti korak od `encrypt_message`. Prvo koristi privatni ključ primaoca da dešifruje ključ sesije, a zatim koristi dobijeni ključ i metadata o algoritmu da simetrično dešifruje podatke.

* **Potpis funkcije:**
    ```python
    def decrypt_message(encrypted_message: dict, receiver_private_key: object) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `encrypted_message` (`dict`): Rečnik dobijen iz `encrypt_message`.
    * `receiver_private_key` (`object`): RSA privatni ključ primaoca poruke.
* **Povratna vrednost (`dict`):**
    ```python
    {
        'decrypted_data': bytes,     # Originalni bajtovi pre enkripcije
        'symmetric_algo': str        # Simetrični algoritam koji je korišćen
    }
    ```

---
## DEO 3: Serijalizacija, Radix-64 i Prenos
Ovaj deo definiše dva alternativna izlaza za isti ulazni rečnik iz prethodne faze. Korisnik ili implementacija bira jedan od dva formata:
* čista binarna serijalizacija preko `serialize_final_packet`
* ASCII oklop preko `encode_radix64`, koji koristi isti ulazni `data_dict` i interno prvo radi serijalizaciju, pa onda Base64 omotavanje

### - [x] 5. Čista serijalizacija finalnog paketa (`serialize_final_packet`)


**Format (Big-Endian):**
(Fiksna struktura - 26 bajtova + podaci)
1. **Fleg (1 bajt):** `0x01` ako je paket enkriptovan, `0x00` ako nije.
2. **Ako je enkriptovan :**
    - `receiver_key_id` (8 bajtova, poslednjih 8 bajtova serijalizovanog javnog ključa)
    - `symmetric_algo` (1 bajt, enum vrednost u skladu sa implementacijom AES128(0x00), Cast5(0x01))
    - `encrypted_key_length` (dužina šifrovanog sesijskog ključa)
    - `encrypted_key` (2 bajta, Duzina zavisna od prethodne vrednosti)
    - `encrypted_data` (Varijabilna dužina)
3. **Ako nije enkriptovan:**
    - `encrypted_data` (Varijabilna dužina)

* **Potpis:** `def serialize_final_packet(data_dict: dict, is_encrypted: bool) -> bytes:`

### - [x] 5b. Unwrap finalnog paketa (`deserialize_final_packet`)
Parsira binarni stream i rekonstruiše rečnik.

* **Potpis:** `def deserialize_final_packet(serialized_packet: bytes) -> dict:`

### - [x] 6. Radix-64 kodiranje (`encode_radix64`)
Opcioni korak koji uzima isti ulazni rečnik kao `serialize_final_packet`, interno ga serijalizuje i zatim konvertuje binarni izlaz u Base64 ASCII string sa PGP zaglavljima.

* **Potpis:** `def encode_radix64(serialized_data) -> str:`
* **Struktura:**
    ```text
    -----BEGIN PGP MESSAGE-----
    [Base64 kodirani binarni paket]
    -----END PGP MESSAGE-----
    ```

### - [x] 6b. Radix-64 dekodiranje (`decode_radix64`)
Skida PGP zaglavlja i dekodira Base64 u originalni binarni niz bajtova.

* **Potpis:** `def decode_radix64(armored_message: str) -> bytes:`


