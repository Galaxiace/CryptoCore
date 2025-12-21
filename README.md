# CryptoCore

## Командная утилита для шифрования и дешифрования файлов с использованием алгоритма AES в различных режимах.

# Установка

```Установка из исходного кода```
```bash

pip install .
```

```Или установка зависимостей напрямую```
```bash

pip install -r requirements.txt
```

## Минимальная установка (только криптографические функции)
```bash

pip install pycryptodome==3.23.0
```

## Полная установка (с возможностью тестирования)
```bash

pip install pycryptodome==3.23.0 pytest==8.4.2
```

# Зависимости

### Обязательные:

Python 3.12.3

pycryptodome == 3.23.0

### Опциональные (для тестирования):

pytest == 8.4.2

# Поддерживаемые режимы:
```
ecb - Electronic Codebook (базовый режим)

cbc - Cipher Block Chaining (требует padding)

cfb - Cipher Feedback (потоковый режим)

ofb - Output Feedback (потоковый режим)

ctr - Counter (потоковый режим)
```
## Работа с IV (Initialization Vector):
### Шифрование - IV генерируется автоматически и сохраняется в начало файла:

```

python cryptocore.py -algorithm aes -mode cbc -encrypt -key 00112233445566778899aabbccddeeff -input plaintext.txt -output ciphertext.bin
```
### Дешифрование без указания IV - IV читается из начала файла:

```

python cryptocore.py -algorithm aes -mode cbc -decrypt -key 00112233445566778899aabbccddeeff -input ciphertext.bin -output decrypted.txt
```
### Дешифрование с указанием IV - для работы с внешними инструментами:

```

python cryptocore.py -algorithm aes -mode cbc -decrypt -key 00112233445566778899aabbccddeeff -iv AABBCCDDEEFF00112233445566778899 -input ciphertext_only.bin -output decrypted.txt
```
### Формат ключа и IV
```
Ключ: 32-символьная hex-строка (16 байт)

Пример: 00112233445566778899aabbccddeeff

IV: 32-символьная hex-строка (16 байт)

Пример: AABBCCDDEEFF00112233445566778899
```

# Тестирование
## Базовое тестирование

```bash

python -m pytest tests/ -v
```

## Автоматический тест всех режимов

### CBC Mode

```bash

rm -f test.txt test_cbc.enc test_cbc.dec
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt
python cryptocore.py -algorithm aes -mode cbc -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output test_cbc.enc
python cryptocore.py -algorithm aes -mode cbc -decrypt -key 00112233445566778899aabbccddeeff -input test_cbc.enc -output test_cbc.dec
diff test.txt test_cbc.dec && echo "CBC: SUCCESS" || echo "CBC: FAILED"
```

### CFB Mode

```bash

rm -f test.txt test_cfb.enc test_cfb.dec
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt
python cryptocore.py -algorithm aes -mode cfb -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output test_cfb.enc
python cryptocore.py -algorithm aes -mode cfb -decrypt -key 00112233445566778899aabbccddeeff -input test_cfb.enc -output test_cfb.dec
diff test.txt test_cfb.dec && echo "CFB: SUCCESS" || echo "CFB: FAILED"
```

### OFB Mode

```bash

rm -f test.txt test_ofb.enc test_ofb.dec
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt
python cryptocore.py -algorithm aes -mode ofb -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output test_ofb.enc
python cryptocore.py -algorithm aes -mode ofb -decrypt -key 00112233445566778899aabbccddeeff -input test_ofb.enc -output test_ofb.dec
diff test.txt test_ofb.dec && echo "OFB: SUCCESS" || echo "OFB: FAILED"
```

### CTR Mode

```bash

rm -f test.txt test_ctr.enc test_ctr.dec
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt
python cryptocore.py -algorithm aes -mode ctr -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output test_ctr.enc
python cryptocore.py -algorithm aes -mode ctr -decrypt -key 00112233445566778899aabbccddeeff -input test_ctr.enc -output test_ctr.dec
diff test.txt test_ctr.dec && echo "CTR: SUCCESS" || echo "CTR: FAILED"
```

### ECB Mode

```bash

rm -f test.txt test_ecb.enc test_ecb.dec
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt
python cryptocore.py -algorithm aes -mode ecb -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output test_ecb.enc
python cryptocore.py -algorithm aes -mode ecb -decrypt -key 00112233445566778899aabbccddeeff -input test_ecb.enc -output test_ecb.dec
diff test.txt test_ecb.dec && echo "ECB: SUCCESS" || echo "ECB: FAILED"
```

## Тестирование работы с IV

```bash

rm -f test.txt test_with_iv.enc test_with_iv.dec
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt

# Шифруем файл
python cryptocore.py -algorithm aes -mode cbc -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output test_with_iv.enc

# Извлекаем IV из зашифрованного файла
dd if=test_with_iv.enc of=extracted_iv.bin bs=16 count=1
IV_HEX=$(xxd -p extracted_iv.bin | tr -d '\n')

# Извлекаем ciphertext (без IV)
dd if=test_with_iv.enc of=ciphertext_only.bin bs=16 skip=1

# Дешифруем с явным указанием IV
python cryptocore.py -algorithm aes -mode cbc -decrypt -key 00112233445566778899aabbccddeeff -iv $IV_HEX -input ciphertext_only.bin -output test_with_iv.dec

# Проверяем
diff test.txt test_with_iv.dec && echo "IV Decryption: SUCCESS" || echo "IV Decryption: FAILED"
```

## Тестирование совместимости с OpenSSL
### Our tool → OpenSSL

```bash

rm -f test.txt our_encrypted.bin openssl_decrypted.txt iv.bin ciphertext_only.bin
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt

# Шифруем нашим инструментом
python cryptocore.py -algorithm aes -mode cbc -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output our_encrypted.bin

# Извлекаем IV и ciphertext
dd if=our_encrypted.bin of=iv.bin bs=16 count=1
dd if=our_encrypted.bin of=ciphertext_only.bin bs=16 skip=1

# Дешифруем через OpenSSL - передаем ТОЛЬКО ciphertext (без IV)
openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $(xxd -p iv.bin | tr -d '\n') -in ciphertext_only.bin -out openssl_decrypted.txt

# Проверяем
diff test.txt openssl_decrypted.txt && echo "Our->OpenSSL: SUCCESS" || echo "Our->OpenSSL: FAILED"
```

### OpenSSL → Our tool

```bash

rm -f test.txt openssl_encrypted.bin our_decrypted.txt
echo "Это тестовое сообщение для проверки работы алгоритма" > test.txt

# Шифруем через OpenSSL (НЕ добавляет IV в файл)
openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff -in test.txt -out openssl_encrypted.bin

# Дешифруем нашим инструментом с ЯВНЫМ указанием IV
python cryptocore.py -algorithm aes -mode cbc -decrypt -key 00112233445566778899aabbccddeeff -iv 00112233445566778899aabbccddeeff -input openssl_encrypted.bin -output our_decrypted.txt

diff test.txt our_decrypted.txt && echo "OpenSSL->Our: SUCCESS" || echo "OpenSSL->Our: FAILED"
```

## Тестирование особых случаев
### Пустые файлы

```bash

rm -f empty.txt
touch empty.txt
python cryptocore.py -algorithm aes -mode cbc -encrypt -key 00112233445566778899aabbccddeeff -input empty.txt -output empty.enc
python cryptocore.py -algorithm aes -mode cbc -decrypt -key 00112233445566778899aabbccddeeff -input empty.enc -output empty.dec
diff empty.txt empty.dec && echo "Empty file: SUCCESS" || echo "Empty file: FAILED"
```

### Большие файлы

```bash

# Создаем большой файл (1MB)
dd if=/dev/urandom of=large.bin bs=1M count=1

# Тестируем потоковый режим
python cryptocore.py -algorithm aes -mode ctr -encrypt -key 00112233445566778899aabbccddeeff -input large.bin -output large.enc
python cryptocore.py -algorithm aes -mode ctr -decrypt -key 00112233445566778899aabbccddeeff -input large.enc -output large.dec

# Проверяем
diff large.bin large.dec && echo "Large file: SUCCESS" || echo "Large file: FAILED"
```

## Негативные тесты: Несовпадающие ключи для всех режимов

### Тестирование обнаружения неправильных ключей

```bash

echo "Test data for key mismatch tests" > test.txt

# Функция для тестирования несовпадающих ключей
test_key_mismatch_improved() {
    local mode=$1
    local mode_name=$2
    echo "=== Testing Key Mismatch: $mode_name ==="
    
    # Шифруем с правильным ключом
    python cryptocore.py -algorithm aes -mode $mode -encrypt -key 00112233445566778899aabbccddeeff -input test.txt -output test_${mode}.enc
    
    # Пробуем дешифровать с неправильным ключом
    python cryptocore.py -algorithm aes -mode $mode -decrypt -key FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -input test_${mode}.enc -output test_${mode}.dec 2>&1 > /dev/null
    
    # Проверяем результат
    if [ $? -ne 0 ]; then
        # Команда завершилась с ошибкой (обнаружен неправильный ключ)
        echo "✅ $mode_name: Correctly rejected wrong key (error detected)"
    else
        # Команда завершилась успешно, проверяем содержимое
        if cmp -s test.txt test_${mode}.dec; then
            echo "❌ $mode_name: CRITICAL - Wrong key produced correct decryption!"
        else
            echo "⚠️  $mode_name: Wrong key produced garbage (expected for stream modes)"
            # Показываем разницу
            echo "    Original: '$(cat test.txt)'"
            echo "    Decrypted: '$(cat test_${mode}.dec 2>/dev/null | head -c 50)'..."
        fi
    fi
    echo
}

# Тестируем все режимы
test_key_mismatch_improved "ecb" "ECB Mode"
test_key_mismatch_improved "cbc" "CBC Mode" 
test_key_mismatch_improved "cfb" "CFB Mode"
test_key_mismatch_improved "ofb" "OFB Mode"
test_key_mismatch_improved "ctr" "CTR Mode"
```

## Генерация ключа при шифровании
```bash

python cryptocore.py -algorithm aes -mode cbc -encrypt -input test.txt -output test.enc
```

## NIST-тесты

### Генерация файла 10 МБ от CSPRNG

```bash

python3 -c "from tests.test_csprng import generate_nist_test_file; generate_nist_test_file()"
```

### Запуск NIST 1,000,000 бит на каждый (10шт) битовый поток

```bash

cd nist-sts/sts && (echo -e "0\ndata/nist_test_data.bin\n1\n0\n10\n1" | ./assess 1000000; sleep 2) && echo "=== NIST RESULTS ===" && cat experiments/AlgorithmTesting/finalAnalysisReport.txt
```

### Ввод параметров в интерактивном режиме NIST

```
0 → data/nist_test_data.bin → 1 → 0 → 10 → 1

0 - Выбор "Input File" (тестировать данные из файла)

data/nist_test_data.bin - Путь к тестовому файлу

1 - Запустить ВСЕ 15 статистических тестов

0 - Продолжить без изменения параметров тестов

10 - 10 битовых потоков (каждый по 1,000,000 бит)

1 - Бинарный формат данных (данные в бинарном виде)
```

## Тесты хеширования sha256

### Базовое хеширование файла

```bash

rm -f test_file.txt
echo "Hello, World! This is a test file for CryptoCore." > test_file.txt
python cryptocore.py dgst -algorithm sha256 -input test_file.txt
```

### Вывод хеша в файл

```bash

rm -f test_file.txt
echo "Hello, World! This is a test file for CryptoCore." > test_file.txt
python cryptocore.py dgst -algorithm sha256 -input test_file.txt -output test_hash.sha256
cat test_hash.sha256
```

### Пустой файл

```bash

rm -f empty.txt
echo -n "" > empty.txt
python cryptocore.py dgst -algorithm sha256 -input empty.txt
```

### Совместимость с системными утилитами

```bash

# Реализация
python cryptocore.py dgst -algorithm sha256 -input test_file.txt > our_hash.txt

# Системная утилита
sha256sum test_file.txt > system_hash.txt

# Сравнение
echo "===Our hash===" && cat our_hash.txt && echo "===System hash===" && cat system_hash.txt && echo "===Difference===" && diff our_hash.txt system_hash.txt
```

## Тесты хеширования sha3_256

### Базовое хеширование файла

```bash

rm -f test_file.txt
echo "Hello, World! This is a test file for CryptoCore." > test_file.txt
python cryptocore.py dgst -algorithm sha3-256 -input test_file.txt
```

### Вывод хеша в файл

```bash

rm -f test_file.txt
echo "Hello, World! This is a test file for CryptoCore." > test_file.txt
python cryptocore.py dgst -algorithm sha3-256 -input test_file.txt -output test_hash.sha3
cat test_hash.sha3
```

### Пустой файл

```bash

rm -f empty.txt
echo -n "" > empty.txt
python cryptocore.py dgst -algorithm sha3-256 -input empty.txt
```

### Сравнение с системными утилитами

```bash

rm -f diff_test.txt our_sha3.txt python_sha3.txt
echo "Test data for diff comparison" > diff_test.txt
python cryptocore.py dgst -algorithm sha3-256 -input diff_test.txt > our_sha3.txt
python3 -c "import hashlib; data = open('diff_test.txt', 'rb').read(); print(hashlib.sha3_256(data).hexdigest() + '  diff_test.txt')" > python_sha3.txt
echo "Our implementation:" && cat our_sha3.txt && echo "Python hashlib:" && cat python_sha3.txt && echo "===Difference===" && diff our_sha3.txt python_sha3.txt
```

## Тесты hmac

### Проверка hmac

```bash

# Создаем тестовый файл
echo -n "Test message for HMAC verification" > test_message.txt

# 1. Генерация HMAC
python cryptocore.py dgst -algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff -input test_message.txt

# 2. Сохраним HMAC в файл
python cryptocore.py dgst -algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff -input test_message.txt > test.hmac

# 3. Проверка HMAC (должен быть OK)
python cryptocore.py dgst -algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff -input test_message.txt --verify test.hmac
echo "Exit code for success: $?"
```

### 4. Тест с неправильным ключом (должен быть ERROR)

```bash

python cryptocore.py dgst -algorithm sha256 --hmac --key ffffffffffffffffffffffffffffffff -input test_message.txt --verify test.hmac
echo "Exit code for failure: $?"
```

### 5. Тест с измененным файлом

```bash

echo "Modified" >> test_message.txt
python cryptocore.py dgst -algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff -input test_message.txt --verify test.hmac
echo "Exit code for tampered file: $?"
```

## Тесты GCM/AEAD

### Базовая функциональность GCM

```bash

echo "Testing GCM basic encryption/decryption..."
rm -f test.txt
echo "test" > test.txt
python cryptocore.py -algorithm aes -mode gcm -encrypt -key 00000000000000000000000000000000 -input test.txt -output test.gcm
python cryptocore.py -algorithm aes -mode gcm -decrypt -key 00000000000000000000000000000000 -input test.gcm -output test_dec.txt
diff test.txt test_dec.txt && echo "   ✅ PASS" || echo "   ❌ FAIL"
```

### GCM with AAD

```bash

echo "Testing GCM with AAD..."
rm -f test.txt
echo "test" > test.txt
python cryptocore.py -algorithm aes -mode gcm -encrypt -key 00000000000000000000000000000000 -input test.txt -output test_aad.gcm -aad 6d795f6161645f64617461
python cryptocore.py -algorithm aes -mode gcm -decrypt -key 00000000000000000000000000000000 -input test_aad.gcm -output test_aad_dec.txt -aad 6d795f6161645f64617461
diff test.txt test_aad_dec.txt && echo "   ✅ PASS" || echo "   ❌ FAIL"
```

### Катастрофический отказ аутентификации

```bash

echo "Testing GCM authentication failure..."
python cryptocore.py -algorithm aes -mode gcm -decrypt -key 00000000000000000000000000000000 -input test_aad.gcm -output should_not_exist.txt -aad 7726f6e675f616164 2>&1 >/dev/null
[ -f should_not_exist.txt ] && echo "   ❌ FAIL (file was created)" || echo "   ✅ PASS (no file on auth failure)"
```

### Уникальность Nonce

```bash

echo "Testing nonce uniqueness..."
rm -f test.txt
echo "test" > test.txt
python cryptocore.py -algorithm aes -mode gcm -encrypt -key 00000000000000000000000000000000 -input test.txt -output test1.gcm
python cryptocore.py -algorithm aes -mode gcm -encrypt -key 00000000000000000000000000000000 -input test.txt -output test2.gcm
python3 -c "
import sys
with open('test1.gcm', 'rb') as f1, open('test2.gcm', 'rb') as f2:
    if f1.read(12) != f2.read(12):
        print('   ✅ PASS (nonces are unique)')
    else:
        print('   ❌ FAIL (nonces are identical)')
"
```

### Пустой AAD

```bash

echo "Testing empty AAD..."
rm -f test.txt
echo "" > test.txt
python cryptocore.py -algorithm aes -mode gcm -encrypt -key 00000000000000000000000000000000 -input test.txt -output test_empty.gcm -aad ""
python cryptocore.py -algorithm aes -mode gcm -decrypt -key 00000000000000000000000000000000 -input test_empty.gcm -output test_empty_dec.txt -aad ""
diff test.txt test_empty_dec.txt && echo "   ✅ PASS" || echo "   ❌ FAIL"
```

## PBKDF2 (Password-Based Key Derivation)

### Базовая проверка работы PBKDF2

```bash

python cryptocore.py derive --password "MySecurePassword123!" --iterations 1000 # Генерация ключа с паролем и случайной солью

python cryptocore.py derive --password "test" --salt 73616c74 --iterations 1000 --length 32 # Генерация ключа с указанной солью (hex формат)

python cryptocore.py derive --password "database_key" --iterations 50000 --output secret.key # Сохранение ключа в файл
```

### Проверка детерминированности

```bash

# Дважды запустить с одинаковыми параметрами - результат должен совпадать
python cryptocore.py derive --password "identical" --salt a1b2c3d4 --iterations 100 --length 16
python cryptocore.py derive --password "identical" --salt a1b2c3d4 --iterations 100 --length 16
```

### Сравнение с Python hashlib

```bash

# Сравнение с Python reference implementation
python3 -c "
import hashlib
result = hashlib.pbkdf2_hmac('sha256', b'test', b'salt', 1000, 32)
print('Hashlib result:', result.hex())
"

python cryptocore.py derive --password "test" --salt 73616c74 --iterations 1000 --length 32
```

### Проверка HKDF через Python

```bash

python3 -c "
from src.kdf.hkdf import derive_key
k1 = derive_key(b'0'*32, 'test1', 16)
k2 = derive_key(b'0'*32, 'test2', 16)
print('Key1:', k1.hex()[:16], '...')
print('Key2:', k2.hex()[:16], '...')
print('Different:', 'YES' if k1 != k2 else 'NO')
"
```

# Возможности
### 1) Шифрование AES-128 в различных режимах:

```
ECB (Electronic Codebook)

CBC (Cipher Block Chaining)

CFB (Cipher Feedback)

OFB (Output Feedback)

CTR (Counter)
```

### 2) Автоматическая генерация и управление IV

### 3) Поддержка паддинга PKCS#7 (для ECB и CBC)

### 4) Потоковые режимы без паддинга (CFB, OFB, CTR)

### 5) Полная совместимость с OpenSSL

### 6) Работа с бинарными файлами

### 7) Комплексная обработка ошибок

### 8) Полное тестовое покрытие

# Обработка ошибок
## Четкие сообщения об ошибках для:

```
1) Неверных ключей (неправильная длина или формат)

2) Отсутствующих входных файлов

3) Проблем с правами доступа к файлам

4) Неверного паддинга при дешифровании

5) Неверного формата IV

6) Файлов слишком коротких для извлечения IV
```

# Технические детали

```
1) Алгоритм: AES-128

2) Режимы: ECB, CBC, CFB, OFB, CTR

3) Паддинг: PKCS#7 (только для ECB и CBC)

4) Формат ключа: Hex-строка (32 символа)

5) Формат IV: Hex-строка (32 символа)

6) Библиотека: pycryptodome

7) Генерация IV: os.urandom(16)
```

# Структура проекта
```
cryptocore/
│
├── docs/ # Документация проекта для разных категорий пользователей
│   │
│   ├── API.md # Техническая документация API библиотеки
│   │
│   ├── DEVELOPMENT.md # Руководство для разработчиков проекта
│   │
│   └── USERGUIDE.md # Руководство для конечных пользователей CLI
│
├── nist-sts/ # Тесты NIST STS
│
├── src/ # Исходный код
│   │ 
│   ├── crypto/ # Ядро криптографии
│   │ │
│   │ ├── init.py
│   │ │
│   │ ├── aes_ecb.py # Реализация AES-ECB + паддинг
│   │ │
│   │ ├── core.py # Основные функции шифрования/дешифрования
│   │ │
│   │ └── modes/ # Режимы работы AES
│   │     │
│   │     ├── init.py
│   │     │
│   │     ├── aead.py # Encrypt-then-MAC AEAD
│   │     │
│   │     ├── base_mode.py # Базовый класс режима
│   │     │
│   │     ├── cbc.py # CBC режим
│   │     │
│   │     ├── cfb.py # CFB режим
│   │     │
│   │     ├── ofb.py # OFB режим
│   │     │
│   │     ├── gcm.py # GCM режим
│   │     │
│   │     └── ctr.py # CTR режим
│   │
│   ├── hash/ # Хеш-функции
│   │     │
│   │     ├── init.py
│   │     │
│   │     ├── sha3_256.py # Реализация SHA-256 хеш-функции
│   │     │
│   │     └── sha256.py # Реализация SHA3-256 хеш-функции
│   │
│   ├── kdf/ # Функции получения ключей
│   │     │
│   │     ├── init.py
│   │     │
│   │     ├── hkdf.py # Реализация HKDF для иерархии ключей
│   │     │
│   │     └── pbkdf2.py # Реализация PBKDF2-HMAC-SHA256
│   │
│   ├── mac/ # Коды аутентификации
│   │     │
│   │     ├── init.py
│   │     │
│   │     └── hmac.py # Реализация HMAC-SHA256
│   │
│   ├── utils/ # Вспомогательные утилиты
│   │     │
│   │     ├── init.py
│   │     │
│   │     ├── csprng.py # Криптостойкий RNG
│   │     │
│   │     ├── validation.py # Валидация ключей и файлов
│   │     │
│   │     └── logging_setup.py # Настройка логирования
│   │
│   ├── file_io.py # Работа с файлами
│   │
│   ├── cli_parser.py # Парсер аргументов CLI
│   │
│   └── init.py
│   
├── tests/ # Тесты
│   │
│   ├── init.py
│   │
│   ├── conftest.py # Фикстуры pytest
│   │
│   ├── performance_test_pbkdf2.py # Тестирование производительности PBKDF2
│   │
│   ├── test_aead.py # Тесты Encrypt-then-MAC AEAD
│   │
│   ├── test_aes_ecb.py # Тесты AES-ECB
│   │
│   ├── test_cli.py # Тесты CLI
│   │
│   ├── test_csprng.py # Тесты RNG
│   │
│   ├── test_gcm.py # Тесты GCM режима
│   │
│   ├── test_hash.py # Тесты хеш-функций
│   │
│   ├── test_hkdf.py # Тесты HKDF
│   │
│   ├── test_hmac.py # Тесты HMAC
│   │
│   ├── test_integration.py # Интеграционные тесты
│   │
│   ├── test_pbkdf2.py # Тесты PBKDF2
│   │
│   ├── test_pbkdf2_openssl.py # Тесты совместимости PBKDF2 с OpenSSL
│   │
│   └── test_sha3_256.py # Тесты SHA3-256
│
├── cryptocore.py # Главный CLI интерфейс
│
├── setup.py # Конфигурация пакета
│
├── README.md # Основная документация проекта
│
└── requirements.txt # Зависимости
```