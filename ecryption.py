import os
import base64

# Функция для добавления PKCS#7 паддинга
def pkcs7_padding(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding

# Функция для удаления PKCS#7 паддинга
def pkcs7_unpadding(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Функция шифрования с использованием шифра Виженера в режиме CBC
def encrypt(key, message):
    if not isinstance(key, bytes):
        raise TypeError("Ключ должен быть в байтовом формате.")
    block_size = len(key)

    # Преобразуем сообщение в байты
    message_bytes = message.encode('utf-8')

    # Добавляем PKCS#7 паддинг
    message_bytes = pkcs7_padding(message_bytes, block_size)

    num_blocks = len(message_bytes) // block_size

    # Генерируем случайный IV
    iv = os.urandom(block_size)

    # Инициализируем предыдущий шифроблок IV
    prev_cipher_block = iv

    ciphertext_blocks = []

    for i in range(num_blocks):
        block_start = i * block_size
        block_end = block_start + block_size
        plaintext_block = message_bytes[block_start:block_end]

        # Xi = Pi XOR Ci-1
        x_i = bytes([pb ^ cb for pb, cb in zip(plaintext_block, prev_cipher_block)])

        # Ci = (Xi + K) mod 256
        cipher_block = bytes([(xb + kb) % 256 for xb, kb in zip(x_i, key)])

        # Добавляем шифроблок в список
        ciphertext_blocks.append(cipher_block)

        # Обновляем предыдущий шифроблок
        prev_cipher_block = cipher_block

    # Соединяем IV и шифроблоки
    ciphertext = iv + b''.join(ciphertext_blocks)

    # Возвращаем шифротекст в виде строки Base64
    return base64.b64encode(ciphertext).decode('utf-8')

# Функция дешифрования с использованием шифра Виженера в режиме CBC
def decrypt(key, b64_ciphertext):
    # Декодируем Base64, чтобы получить байтовый шифротекст
    ciphertext = base64.b64decode(b64_ciphertext)

    if not isinstance(key, bytes):
        raise TypeError("Ключ должен быть в байтовом формате.")
    block_size = len(key)

    # Извлекаем IV
    iv = ciphertext[:block_size]
    ciphertext_blocks = [ciphertext[i:i+block_size] for i in range(block_size, len(ciphertext), block_size)]

    num_blocks = len(ciphertext_blocks)

    # Инициализируем предыдущий шифроблок IV
    prev_cipher_block = iv

    plaintext_blocks = []

    for i in range(num_blocks):
        cipher_block = ciphertext_blocks[i]

        # Xi = (Ci - K) mod 256
        x_i = bytes([(cb - kb) % 256 for cb, kb in zip(cipher_block, key)])

        # Pi = Xi XOR Ci-1
        plaintext_block = bytes([xb ^ pcb for xb, pcb in zip(x_i, prev_cipher_block)])

        plaintext_blocks.append(plaintext_block)

        # Обновляем предыдущий шифроблок
        prev_cipher_block = cipher_block

    # Соединяем блоки с расшифрованным текстом
    plaintext_bytes = b''.join(plaintext_blocks)

    # Убираем PKCS#7 паддинг
    try:
        plaintext_bytes = pkcs7_unpadding(plaintext_bytes)
    except Exception:
        raise ValueError("Ошибка при удалении паддинга. Возможно, неверный ключ или поврежден шифротекст.")

    # Преобразуем байты в строку
    return plaintext_bytes.decode('utf-8')

# Основная часть программы
if __name__ == "__main__":
    # Ввод ключа и сообщения
    key_input = input("Введите ключ для шифрования: ")
    key_bytes = key_input.encode('utf-8')

    message = input("Введите текст для шифрования: ")

    # Шифрование
    encrypted = encrypt(key_bytes, message)
    print("\nЗашифрованный текст (Base64):\n", encrypted)

    # Дешифрование
    decrypted = decrypt(key_bytes, encrypted)
    print("\nРасшифрованный текст:\n", decrypted)