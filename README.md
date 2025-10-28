# CryptoCore

## Командная утилита для шифрования и дешифрования файлов с использованием алгоритма AES в режиме ECB.

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
    ├── src/                 # Исходный код
    │   ├── crypto/          # ЯДРО КРИПТОГРАФИИ
    │   │   ├── __init__.py
    │   │   ├── aes_ecb.py   # Реализация AES-ECB + паддинг
    │   │   ├── core.py      # Функции шифрования/дешифрования файлов
    │   │   └── modes/       # Другие режимы
    │   │       ├── __init__.py
    │   │       ├── base_mode.py
    │   │       ├── cbc.py
    │   │       ├── cfb.py
    │   │       ├── ofb.py
    │   │       └── ctr.py
    │   ├── utils/           # Вспомогательные утилиты
    │   │   ├── __init__.py
    │   │   ├── validation.py    # Валидация ключей и файлов
    │   │   └── logging_setup.py # Настройка логирования
    │   │   
    │   ├── file_io.py       # Чтение/запись файлов
    │   ├── cli_parser.py    # Парсер аргументов CLI
    │   └── __init__.py
    ├── tests/               # Тесты
    │   ├── __init__.py
    │   ├── conftest.py      # Фикстуры pytest
    │   ├── test_aes_ecb.py  # Тесты AES-ECB
    │   ├── test_cli.py      # Тесты CLI
    │   └── test_integration.py # Интеграционные тесты
    ├── cryptocore.py        # ГЛАВНЫЙ CLI ИНТЕРФЕЙС
    ├── setup.py             # Конфигурация пакета
    ├── README.md
    └── requirements.txt     # Зависимости
```