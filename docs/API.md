# CryptoCore — API документация

---

## 1. Обзор библиотеки

### CryptoCore — это криптографическая библиотека на Python, предоставляющая полный набор функций для безопасной работы с данными.

### Основные возможности:
- **Шифрование**: AES-128/192/256 в режимах ECB, CBC, CFB, OFB, CTR, GCM
- **Аутентифицированное шифрование**: GCM и Encrypt-then-MAC (AEAD)
- **Хеширование**: SHA-256 и SHA3-256
- **Аутентификация сообщений**: HMAC-SHA256
- **Получение ключей**: PBKDF2-HMAC-SHA256 и HKDF

### Архитектура модулей:
```
src/
├── crypto/ # Ядро шифрования
│ ├── core.py # Основной API для работы с файлами
│ ├── aes_ecb.py # Базовый AES-ECB + PKCS#7
│ └── modes/ # Режимы работы AES
│ ├── base_mode.py # Абстрактный базовый класс
│ ├── cbc.py, cfb.py, ofb.py, ctr.py
│ ├── gcm.py # GCM с аутентификацией
│ └── aead.py # Encrypt-then-MAC AEAD
├── hash/ # Хеш-функции
├── kdf/ # Получение ключей
├── mac/ # HMAC
├── utils/ # Вспомогательные утилиты
├── file_io.py # Работа с файлами
└── cli_parser.py # Парсер командной строки
```

---

## 2. Модуль `cryptocore.crypto` — ядро шифрования

### 2.1. Основной API: `core.py`

#### Функция `get_crypto_mode(mode: str, key: bytes)`
**Что делает:** Создаёт экземпляр класса режима шифрования.

**Параметры:**
- `mode` (str): Режим работы: 'ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm', 'encrypt-then-mac'
- `key` (bytes): Ключ шифрования (16, 24 или 32 байта)

#### Функция `encrypt_file_aes(input_path: str, output_path: str, key: bytes, mode: str = 'ecb', aad: bytes = b"")`

**Что делает:** Шифрует файл с использованием AES.

**Параметры:**

input_path (str): Путь к исходному файлу

output_path (str): Путь для сохранения зашифрованного файла

key (bytes): Ключ шифрования

mode (str): Режим работы (по умолчанию 'ecb')

aad (bytes): Дополнительные аутентифицированные данные (для GCM/AEAD)

**Особенности:**

Для режимов кроме ECB генерируется случайный IV/nonce

Для GCM всегда генерируется случайный 12-байтный nonce

Формат выходного файла зависит от режима

#### Функция `decrypt_file_aes(input_path: str, output_path: str, key: bytes, mode: str = 'ecb', iv_hex: str = None, aad: bytes = b"")`

**Что делает:** Дешифрует файл с проверкой аутентификации (для GCM/AEAD).

**Параметры:**

input_path (str): Путь к зашифрованному файлу

output_path (str): Путь для сохранения расшифрованного файла

key (bytes): Ключ шифрования

mode (str): Режим работы

iv_hex (str): IV/nonce в hex формате (опционально)

aad (bytes): AAD данные (для GCM/AEAD)

**Важно:**

Для GCM при ошибке аутентификации файл не создаётся

IV может быть в файле (первые байты) или передаваться отдельно

### 2.2. Базовый AES-ECB: aes_ecb.py

Класс `AES_ECB_MODE(key: bytes)`

**Что делает:** Реализация AES в режиме ECB с поддержкой паддинга PKCS#7.

**Методы:**

#### `encrypt(plaintext: bytes) -> bytes`
Шифрует данные с автоматическим добавлением паддинга PKCS#7.

#### `decrypt(ciphertext: bytes) -> bytes`
Дешифрует данные с удалением паддинга PKCS#7.

### 2.3. Абстрактный базовый класс: base_mode.py

#### Абстрактный класс `BaseMode(key: bytes)`

**Что делает:** Базовый класс для всех режимов шифрования.

**Свойства:**

key: Ключ шифрования

block_size: Размер блока (16 байт для AES)

#### Абстрактные методы:

`encrypt(plaintext: bytes, iv: bytes = None) -> bytes`

`decrypt(ciphertext: bytes, iv: bytes = None) -> bytes`

#### Вспомогательные методы:

`_pad(data: bytes) -> bytes: Добавляет PKCS#7 паддинг`

`_unpad(data: bytes) -> bytes: Удаляет PKCS#7 паддинг`

### 2.4. Режимы CBC, CFB, OFB, CTR

Все эти режимы наследуются от BaseMode и имеют одинаковый интерфейс

**Особенности режимов:**

CBC, ECB: Требует паддинг, использует IV

CFB, OFB, CTR: Потоковые режимы, не требуют паддинга, используют IV

### 2.5. GCM (Galois/Counter Mode): gcm.py

**Что делает:** Аутентифицированное шифрование с использованием GCM.

**Методы:**

`encrypt(plaintext: bytes, iv: bytes = None, aad: bytes = b"") -> bytes`
Шифрует данные с аутентификацией.

**Параметры:**

plaintext: Данные для шифрования

iv: 12-байтный nonce (генерируется автоматически если None)

aad: Дополнительные аутентифицированные данные

**Возвращает:**

bytes: 12-байтный nonce + ciphertext + 16-байтный тег

`decrypt(data: bytes, iv: bytes = None, aad: bytes = b"") -> bytes`
Дешифрует и проверяет аутентификацию данных.

**Параметры:**

data: Данные в формате nonce + ciphertext + tag

iv: Nonce (если не включён в data)

aad: Те же AAD данные, что при шифровании

**Возвращает:**

bytes: Расшифрованные данные

**Выбрасывает:**

AuthenticationError: если аутентификация не пройдена

### 2.6. Encrypt-then-MAC AEAD: aead.py

Класс `AEAD_EncryptThenMAC(key, mode='ctr', hash_algo='sha256')`

**Что делает:** AEAD конструкция Encrypt-then-Mac.

**Параметры конструктора:**

key: Основной ключ

mode: Режим шифрования ('ctr' или 'cbc')

hash_algo: Алгоритм хеширования (только 'sha256')

Особенности:

Автоматически создаёт отдельные ключи для шифрования и MAC

Использует HMAC-SHA256 для аутентификации

**Методы:**

`encrypt(plaintext, aad=b"", iv=None) -> bytes`
Шифрует данные и вычисляет MAC.

`decrypt(data, aad=b"", iv=None) -> bytes`
Проверяет MAC и дешифрует данные.

---

## 3. Модуль cryptocore.hash — хеш-функции
### 3.1. SHA-256: sha256.py

Класс `SHA256()`

**Что делает:** Вычисляет SHA-256 хеш.

**Методы:**

`update(data: bytes)`
Добавляет данные для хеширования.

`digest() -> bytes`
Возвращает итоговый хеш в бинарном формате.

`hexdigest() -> str`
Возвращает итоговый хеш в hex формате.

### 3.2. SHA3-256: sha3_256.py
Аналогичный интерфейс для `SHA3-256`.

---

## 4. Модуль cryptocore.mac — аутентификация сообщений

### 4.1. HMAC-SHA256: hmac.py

Класс `HMAC(key, hash_function='sha256')`

**Что делает:** Вычисляет HMAC с использованием SHA-256.

**Методы:**

`compute(message: bytes) -> str`
Вычисляет HMAC и возвращает hex строку.

`compute_bytes(message: bytes) -> bytes`
Вычисляет HMAC и возвращает байты.

`compute_file(file_path: str, chunk_size=8192) -> str`
Вычисляет HMAC для файла (обрабатывает большие файлы).

`verify(message: bytes, hmac_to_check: str) -> bool`
Проверяет HMAC.

---

## 5. Модуль cryptocore.kdf — получение ключей

### 5.1. PBKDF2-HMAC-SHA256: pbkdf2.py

#### Функция `pbkdf2_hmac_sha256(password, salt, iterations, dklen)`

**Что делает:** Генерирует ключ из пароля с использованием PBKDF2.

**Параметры:**

password: Пароль (bytes или str)

salt: Соль (bytes или str)

iterations: Количество итераций

dklen: Длина получаемого ключа в байтах

**Возвращает:**

bytes: Производный ключ

### 5.2. HKDF для иерархии ключей: hkdf.py

#### Функция `derive_key(master_key: bytes, context: str, length: int = 32) -> bytes`

**Что делает:** Создаёт ключ из мастер-ключа для определённого контекста.

---

## 6. Модуль cryptocore.utils — вспомогательные утилиты

### 6.1. Криптостойкий ГСЧ: csprng.py

#### Функция `generate_random_bytes(num_bytes: int) -> bytes`

**Что делает:** Генерирует криптостойкие случайные байты.


### 6.2. Валидация данных: validation.py

```
python
from cryptocore.utils.validation import (
    validate_hex_key,
    validate_file_exists,
    is_weak_key,
    validate_gcm_nonce
)
```

### 6.3. Логирование: logging_setup.py

```
python
from cryptocore.utils.logging_setup import setup_logger
logger = setup_logger()
```

---

## 7. Модуль `cryptocore.file_io` — работа с файлами

**Что делает:** Читает файл чанками (генератор).

**Зачем:** Для обработки больших файлов без загрузки в память целиком.
