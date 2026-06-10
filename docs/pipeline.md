# PGP Kriptografski Pipeline - Tehnička Specifikacija 

Ovaj dokument služi kao kontrolna lista (Checklist) i tehnička specifikacija za implementaciju kriptografskog pipeline-a. Nakon faze potpisivanja, podaci prelaze u čist binarni oblik (`bytes`) gde se informacije (poput flega za kompresiju) lepe direktno na bajt stream.

---

## DEO 1: Priprema podataka, Autentikacija i Kompresija

### - [ ] 1. Kreiranje komponente poruke (`create_message_component`)
Ova funkcija uzima sirovi sadržaj fajla i pakuje ga sa metapodacima (ime fajla i vreme).

* **Potpis funkcije:**
    ```python
    def create_message_component(data: bytes, filename: str, timestamp: int) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `data` (`bytes`): Sirovi binarni podaci ili tekst iz datoteke koja se šalje.
    * `filename` (`str`): Naziv originalne datoteke.
    * `timestamp` (`int`): UNIX timestamp koji označava vreme kreiranja/slanja poruke.
* **Povratna vrednost (`dict`):**
    ```python
    {
        'filename': str,      # Naziv fajla
        'timestamp': int,     # Vreme kreiranja
        'data': bytes         # Sirovi podaci fajla
    }
    ```

---

### - [ ] 2. Digitalno potpisivanje (`sign_message`)
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

---

### - [ ] 3. Kompresija i postavljanje flega (`compress_data`)
Ova funkcija prima serijalizovane bajtove (bilo samo poruke, bilo paketa sa potpisom) i opciono ih kompresuje. Unutar funkcije se na sam početak bajt streama dodaje 1 bajt koji označava da li je kompresija rađena.

* **Potpis funkcije:**
    ```python
    def compress_data(serialized_data: bytes, perform_compression: bool) -> bytes:
        pass
    ```
* **Ulazni argumenti:**
    * `serialized_data` (`bytes`): Prethodno serijalizovani podaci (bajtovi uspešno pretvoreni iz rečnika koraka 1 ili koraka 2).
    * `perform_compression` (`bool`): Oznaka da li korisnik želi da se nad podacima izvrši ZIP kompresija.
* **Povratna vrednost (`bytes`):**
    * Niz bajtova koji na poziciji `[0]` ima fleg o kompresiji, a u nastavku podatke.
    * Ukoliko je `perform_compression=True`: Vraća `b'\x01' + zip_compressed_bytes`
    * Ukoliko je `perform_compression=False`: Vraća `b'\x00' + serialized_data`

---

## DEO 2: Tajnost (Enkripcija) i Radix-64 Prenos

### - [ ] 4. Enkripcija poruke i ključa sesije (`encrypt_message`)
Ova funkcija generiše jednokratni ključ sesije ($K_s$) za izabrani simetrični algoritam. Ona uzima kompletan niz bajtova iz koraka kompresije (zajedno sa zalepljenim flegom) i simetrično ga šifruje. Ključ sesije se šifruje javnim ključem primaoca.

* **Potpis funkcije:**
    ```python
    def encrypt_message(compressed_bytes: bytes, receiver_public_key: object, receiver_key_id: str, symmetric_algo: str) -> dict:
        pass
    ```
* **Ulazni argumenti:**
    * `compressed_bytes` (`bytes`): Finalni niz bajtova dobijen iz `compress_data` (sadrži fleg na početku).
    * `receiver_public_key` (`object`): RSA javni ključ primaoca poruke.
    * `receiver_key_id` (`str`): ID javnog ključa primaoca poruke.
    * `symmetric_algo` (`str`): Naziv izabranog simetričnog algoritma (npr. `'AES128'`, `'3DES'`).
* **Povratna vrednost (`dict`):**
    ```python
    {
        'receiver_key_id': str,       # ID ključa primaoca
        'session_key': bytes,         # Ključ sesije (Ks) šifrovan pomoću receiver_public_key
        'symmetric_algo': str,        # Naziv algoritma korišćenog za enkripciju podataka
        'encrypted_data': bytes       # Simetrično šifrovan ceo niz [E(Ks, compressed_bytes)]
    }
    ```

---

### - [ ] 5. Radix-64 kodiranje (`encode_radix64`)
Finalni korak koji uzima rečnik iz faze enkripcije, serijalizuje ga u jedinstven niz bajtova (komponenta ključa sesije + enkriptovani podaci) i pretvara ga u čitljiv ASCII format oklopljen PGP zaglavljima. Ako enkripcija nije bila selektovana, funkcija direktno uzima izlaz iz koraka 3 (`compress_data`) i radi Radix-64.

* **Potpis funkcije:**
    ```python
    def encode_radix64(final_packet_dict: dict, is_encrypted: bool) -> str:
        pass
    ```
* **Ulazni argumenti:**
    * `final_packet_dict` (`dict`): Rečnik iz koraka 4 (ako ima enkripcije). Ako nema enkripcije, ovde se može proslediti prigodan rečnik koji sadrži samo bajtove iz koraka 3 radi konzistentnosti API-ja.
    * `is_encrypted` (`bool`): Indikator da li prosleđeni paket sadrži šifrovane komponente ključa sesije ili ne (određuje format serijalizacije).
* **Povratna vrednost (`str`):**
    * ASCII string sa standardnim PGP omotačem:
    ```text
    -----BEGIN PGP MESSAGE-----
    [Radix-64 tekstualni sadržaj]
    -----END PGP MESSAGE-----
    ```