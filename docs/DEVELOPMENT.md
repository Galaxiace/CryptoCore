# CryptoCore — Руководство разработчика

---

## 1. Структура проекта

### 1.1. Иерархия каталогов

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

---

## 2 Зависимости проекта

```
pycryptodome==3.23.0      # Криптографические функции
pytest==8.4.2             # Тестирование
```

---

## 3. Архитектура системы

### 3.1. Основные компоненты

#### Core Components:

```
cryptocore.py — Точка входа CLI

src/cli_parser.py — Парсер аргументов командной строки

src/crypto/core.py — Основной API для шифрования/дешифрования

src/crypto/modes/ — Реализации режимов AES
```

### 3.2. Поток выполнения

Шифрование файла:

`Пользователь → cryptocore.py → cli_parser.py → core.py → режим шифрования → file_io.py`

---

## 4. Разработка новых функций

### 4.1. Добавление нового режима шифрования

```
Шаг 1: Создание файла режима
Шаг 2: Добавление в init.py
Шаг 3: Добавление поддержки в core.py
Шаг 4: Добавление в cli_parser.py
```

### 4.2. Добавление новой хеш-функции

```
Шаг 1: Создание файла хеш-функции
Шаг 2: Добавление поддержки в CLI
```

---

## 5. Тестирование

### 5.1. Запуск тестов

#### Все тесты

```bash

python -m pytest tests/ -v
```

#### Быстрые тесты

```bash

python -m pytest tests/ -q
```

#### Конкретный тест

```bash

python -m pytest tests/test_aes_ecb.py -v
```

### 5.2 Структура тестов

```
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
```

---

## 6. Стиль кода

```
Классы: CamelCase (например, CBC_MODE, HMAC)

Функции/методы: snake_case (например, encrypt_file_aes)

Константы: UPPER_CASE (например, BLOCK_SIZE)

Частные методы: _leading_underscore (например, _pad)
```