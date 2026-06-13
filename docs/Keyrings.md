# RSA Keyrings

## Cilj modula

Modul `rsa_keyring` služi za lokalno čuvanje i upravljanje RSA ključevima koji se koriste u PGP aplikaciji.

Aplikacija koristi dva prstena ključeva:

- `Public Key Ring`
- `Private Key Ring`

`Public Key Ring` čuva javne ključeve koji se koriste za enkripciju poruka i verifikaciju potpisa.

`Private Key Ring` čuva lokalne privatne ključeve koji se koriste za dekripciju poruka i digitalno potpisivanje.

Web of Trust se ne implementira.

Ne implementiraju se `ownertrust`, `sigtrust`, sertifikati javnih ključeva, potpisi nad javnim ključevima, automatsko računanje poverenja, niti revocation certificate mehanizam.

## Organizacija modula

```text
rsa_keyring/
    __init__.py
    keyring_models.py
    keyring_storage.py
    keyring_utils.py
    keyring_services.py
```

## Osnovna ideja

Ključevi mogu da nastanu na dva načina:

1. Generisanjem novog RSA para ključeva u aplikaciji.
2. Uvozom javnog ključa ili celog para ključeva iz `.pem` fajla.

Svi podaci se čuvaju lokalno u JSON fajlovima.

Privatni ključ se ne čuva u otvorenom obliku u keyring-u. U `private_keyring.json` čuva se kao šifrovani PEM string.

Svaki pristup privatnom ključu zahteva lozinku.

`keyring_services.py` je glavni interface sloj koji koristi GUI. GUI treba da koristi funkcije iz `keyring_services.py`, a ne direktno `keyring_storage.py` i `keyring_utils.py`.

## Key ID

Svaki ključ ima `key_id`.

`key_id` se računa iz javnog ključa.

U JSON fajlovima se `key_id` čuva kao heksadecimalni string.

Primer:

```text
A1B2C3D4E5F60708
```

Ako `key_id` u aplikaciju dođe kao `bytes`, servisni sloj ga normalizuje u hex string pomoću `key_id_to_hex`.

## Lokalno čuvanje

Prstenovi se čuvaju u `data/` direktorijumu.

```text
data/
    public_keyring.json
    private_keyring.json
```

JSON fajlovi koriste mapu oblika:

```python
dict[str, dict]
```

Ključ mape je `key_id`, a vrednost je entry rečnik.

Početni sadržaj fajlova je:

```json
{}
```

## Public Key Ring

`public_keyring.json` čuva javne ključeve.

Struktura jednog zapisa:

```python
PublicKeyEntry = {
    "key_id": str,
    "user_name": str,
    "email": str,
    "timestamp": int,
    "key_size": int,
    "public_key_pem": str
}
```

Primer:

```json
{
    "A1B2C3D4E5F60708": {
        "key_id": "A1B2C3D4E5F60708",
        "user_name": "Petar Rancic",
        "email": "petar@example.com",
        "timestamp": 1717000000,
        "key_size": 2048,
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    }
}
```

## Private Key Ring

`private_keyring.json` čuva lokalne privatne ključeve.

Struktura jednog zapisa:

```python
PrivateKeyEntry = {
    "key_id": str,
    "user_name": str,
    "email": str,
    "timestamp": int,
    "key_size": int,
    "public_key_pem": str,
    "encrypted_private_key_pem": str
}
```

Primer:

```json
{
    "A1B2C3D4E5F60708": {
        "key_id": "A1B2C3D4E5F60708",
        "user_name": "Petar Rancic",
        "email": "petar@example.com",
        "timestamp": 1717000000,
        "key_size": 2048,
        "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
        "encrypted_private_key_pem": "-----BEGIN ENCRYPTED PRIVATE KEY-----\n...\n-----END ENCRYPTED PRIVATE KEY-----\n"
    }
}
```

## keyring_models.py

Sadrži osnovne konstante.

```python
PUBLIC_KEYRING_PATH = "data/public_keyring.json"
PRIVATE_KEYRING_PATH = "data/private_keyring.json"

SUPPORTED_RSA_KEY_SIZES = [1024, 2048]
```

## keyring_storage.py

`keyring_storage.py` radi samo sa JSON fajlovima.

GUI ne koristi ovaj fajl direktno.

```python
def ensure_keyring_storage() -> None:
    pass
```

```python
def load_public_keyring(path: str = PUBLIC_KEYRING_PATH) -> dict[str, dict]:
    pass
```

```python
def save_public_keyring(public_keyring: dict[str, dict], path: str = PUBLIC_KEYRING_PATH) -> None:
    pass
```

```python
def load_private_keyring(path: str = PRIVATE_KEYRING_PATH) -> dict[str, dict]:
    pass
```

```python
def save_private_keyring(private_keyring: dict[str, dict], path: str = PRIVATE_KEYRING_PATH) -> None:
    pass
```

## keyring_utils.py

`keyring_utils.py` sadrži pomoćne funkcije za RSA ključeve, PEM format i `key_id`.

Ovaj fajl ne čuva ništa u `data/`.

```python
def generate_rsa_key_pair(key_size: int):
    pass
```

```python
def calculate_key_id(public_key) -> bytes:
    pass
```

```python
def calculate_key_id_hex(public_key) -> str:
    pass
```

```python
def serialize_public_key_to_pem(public_key) -> str:
    pass
```

```python
def serialize_private_key_to_encrypted_pem(private_key, password: str) -> str:
    pass
```

```python
def load_public_key_from_pem(public_key_pem: str):
    pass
```

```python
def load_private_key_from_pem(private_key_pem: str, password: str | None = None):
    pass
```

```python
def load_private_key_from_encrypted_pem(encrypted_private_key_pem: str, password: str):
    pass
```

```python
def get_key_size_from_public_key(public_key) -> int:
    pass
```

```python
def key_id_to_hex(key_id: str | bytes) -> str:
    pass
```

```python
def key_id_to_bytes(key_id: str | bytes) -> bytes:
    pass
```

## keyring_services.py

`keyring_services.py` je javni interface sloj za GUI.

GUI treba da koristi funkcije iz ovog fajla.

Servisni sloj interno:

- kreira JSON fajlove ako ne postoje
- učitava public/private key ring u memoriju
- koristi `dict[str, dict]` strukturu indeksiranu po `key_id`
- generiše nove RSA parove
- importuje javni ključ
- importuje ceo par ključeva
- exportuje javni ključ
- exportuje ceo par ključeva
- pronalazi ključeve po `key_id`
- vraća RSA public/private key objekte kada su potrebni
- automatski snima izmene u JSON fajlove

Interno stanje:

```python
_public_keyring: dict[str, dict] = {}
_private_keyring: dict[str, dict] = {}
```

## Inicijalizacija

GUI treba jednom pri pokretanju aplikacije da pozove:

```python
def initialize_keyrings() -> None:
    pass
```

Ručno snimanje oba prstena:

```python
def save_keyrings() -> None:
    pass
```

U normalnom radu GUI ne mora ručno da poziva `save_keyrings()`, jer funkcije koje menjaju stanje same snimaju odgovarajući JSON fajl.

## Dobijanje ključeva za prikaz

```python
def get_public_keys() -> list[dict]:
    pass
```

```python
def get_private_keys() -> list[dict]:
    pass
```

Ove funkcije vraćaju kopije entry-ja iz memorije.

## Generisanje RSA para

```python
def generate_key_pair(user_name: str, email: str, key_size: int, password: str) -> tuple[dict, dict]:
    pass
```

Funkcija generiše novi RSA par ključeva.

Javni deo se dodaje u `Public Key Ring`.

Privatni ključ se šifruje lozinkom i dodaje u `Private Key Ring`.

Oba prstena se odmah snimaju u JSON fajlove.

Povratna vrednost:

```python
(public_entry, private_entry)
```

## Import javnog ključa

```python
def import_public_key(file_path: str, user_name: str = "", email: str = "") -> dict:
    pass
```

Funkcija učitava javni ključ iz `.pem` fajla i dodaje ga u `Public Key Ring`.

PEM fajl mora da sadrži public key blok:

```text
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

Povratna vrednost:

```python
public_entry
```

## Import celog para ključeva

```python
def import_key_pair(
    file_path: str,
    user_name: str = "",
    email: str = "",
    private_key_pem_password: str | None = None,
    keyring_password: str = ""
) -> tuple[dict, dict]:
    pass
```

Funkcija učitava ceo par ključeva iz jednog `.pem` fajla.

PEM fajl treba da sadrži javni i privatni blok:

```text
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

ili šifrovani privatni blok:

```text
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
...
-----END ENCRYPTED PRIVATE KEY-----
```

`private_key_pem_password` je lozinka za privatni ključ u PEM fajlu koji se importuje.

`keyring_password` je lozinka kojom će privatni ključ biti šifrovan pre čuvanja u `private_keyring.json`.

Povratna vrednost:

```python
(public_entry, private_entry)
```

## Export javnog ključa

```python
def export_public_key(key_id: str | bytes, file_path: str) -> None:
    pass
```

Funkcija pronalazi javni ključ po `key_id` i upisuje njegov PEM u fajl.

Exportovani fajl sadrži samo public key blok.

## Export celog para ključeva

```python
def export_key_pair(key_id: str | bytes, unlock_password: str, file_path: str) -> None:
    pass
```

Funkcija pronalazi par ključeva po `key_id`.

`unlock_password` se koristi za otključavanje privatnog ključa iz `Private Key Ring`.

Exportovani fajl sadrži:

```text
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

Privatni ključ se pri exportu trenutno izvozi bez enkripcije.

## Pretraga ključeva

```python
def find_public_key(key_id: str | bytes) -> dict | None:
    pass
```

```python
def find_private_key(key_id: str | bytes) -> dict | None:
    pass
```

Funkcije vraćaju entry rečnik ili `None`.

Pretraga je direktna preko `dict` strukture indeksirane po `key_id`.

## Dobijanje RSA objekata

```python
def get_public_key_object(key_id: str | bytes):
    pass
```

Vraća RSA public key objekat iz `public_key_pem`.

```python
def unlock_private_key(key_id: str | bytes, password: str):
    pass
```

Otključava privatni ključ iz `encrypted_private_key_pem` i vraća RSA private key objekat.

Ako lozinka nije dobra, funkcija baca grešku.

## Brisanje ključeva

```python
def delete_public_key(key_id: str | bytes) -> bool:
    pass
```

Briše samo javni ključ iz `Public Key Ring`.

```python
def delete_key_pair(key_id: str | bytes) -> bool:
    pass
```

Briše i javni i privatni zapis za dati `key_id`.

Funkcije vraćaju `True` ako je nešto obrisano, a `False` ako ključ nije pronađen.

## Primer korišćenja u GUI-ju

```python
from rsa_keyring.keyring_services import initialize_keyrings
from rsa_keyring.keyring_services import get_public_keys
from rsa_keyring.keyring_services import get_private_keys
from rsa_keyring.keyring_services import generate_key_pair
from rsa_keyring.keyring_services import import_public_key
from rsa_keyring.keyring_services import import_key_pair
from rsa_keyring.keyring_services import export_public_key
from rsa_keyring.keyring_services import export_key_pair
from rsa_keyring.keyring_services import find_public_key
from rsa_keyring.keyring_services import find_private_key
from rsa_keyring.keyring_services import get_public_key_object
from rsa_keyring.keyring_services import unlock_private_key
from rsa_keyring.keyring_services import delete_public_key
from rsa_keyring.keyring_services import delete_key_pair
```

```python
initialize_keyrings()
```

```python
public_keys = get_public_keys()
private_keys = get_private_keys()
```

```python
public_entry, private_entry = generate_key_pair(
    user_name="Petar Rancic",
    email="petar@example.com",
    key_size=2048,
    password="password"
)
```

```python
receiver_public_key = get_public_key_object(public_entry["key_id"])
```

```python
sender_private_key = unlock_private_key(private_entry["key_id"], "password")
```

```python
export_public_key(public_entry["key_id"], "petar_public.pem")
```

```python
export_key_pair(private_entry["key_id"], "password", "petar_pair.pem")
```

