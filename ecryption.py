import os
import base64
import hashlib
import hmac

# Функция для добавления PKCS#7 паддинга
def pkcs7_padding(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding

# Функция для удаления PKCS#7 паддинга
def pkcs7_unpadding(data):
    pad_len = data[-1]
    if pad_len > len(data):
        raise ValueError("Неверный паддинг.")
    return data[:-pad_len]

# Функция для генерации раундовых ключей из основного ключа
def generate_round_keys(key, num_rounds, block_size):
    round_keys = []
    for i in range(num_rounds):
        # Используем HMAC-SHA256 для генерации раундовых ключей
        h = hmac.new(key, i.to_bytes(4, 'big'), hashlib.sha256)
        round_key = h.digest()[:block_size]
        round_keys.append(round_key)
    return round_keys

# Функция F для сети Фейстеля
def F(Ri, Ki):
    # Используем HMAC-SHA256 в качестве функции F
    h = hmac.new(Ki, Ri, hashlib.sha256)
    return h.digest()[:len(Ri)]

# Функция шифрования с использованием сети Фейстеля
def encrypt(key, plaintext):
    block_size = 8  # Размер половины блока в байтах
    num_rounds = 16  # Количество раундов

    # Добавляем PKCS#7 паддинг к сообщению
    plaintext_bytes = pkcs7_padding(plaintext.encode('utf-8'), block_size * 2)

    # Разбиваем сообщение на блоки
    blocks = [plaintext_bytes[i:i + block_size * 2] for i in range(0, len(plaintext_bytes), block_size * 2)]

    ciphertext = b''

    # Генерируем раундовые ключи
    round_keys = generate_round_keys(key, num_rounds, block_size)

    for block in blocks:
        # Инициализируем L и R
        L = block[:block_size]
        R = block[block_size:]

        # Раунды сети Фейстеля
        for i in range(num_rounds):
            # Сохраняем значение R для следующей итерации
            temp_R = R
            # Вычисляем F функцию
            f_output = F(R, round_keys[i])
            # Новый L — это R
            R = bytes([l ^ f for l, f in zip(L, f_output)])
            L = temp_R

        # Объединяем L и R (без финального обмена)
        ciphertext_block = L + R
        ciphertext += ciphertext_block

    # Возвращаем шифротекст в виде строки Base64
    return base64.b64encode(ciphertext).decode('utf-8')

# Функция дешифрования с использованием сети Фейстеля
def decrypt(key, b64_ciphertext):
    ciphertext = base64.b64decode(b64_ciphertext)
    block_size = 8  # Размер половины блока в байтах
    num_rounds = 16  # Количество раундов

    # Разбиваем шифротекст на блоки
    blocks = [ciphertext[i:i + block_size * 2] for i in range(0, len(ciphertext), block_size * 2)]

    plaintext = b''

    # Генерируем раундовые ключи
    round_keys = generate_round_keys(key, num_rounds, block_size)

    for block in blocks:
        # Инициализируем L и R
        L = block[:block_size]
        R = block[block_size:]

        # Обратные раунды сети Фейстеля
        for i in reversed(range(num_rounds)):
            # Сохраняем значение L для следующей итерации
            temp_L = L
            # Вычисляем F функцию
            f_output = F(L, round_keys[i])
            # Новый R — это L
            L = bytes([r ^ f for r, f in zip(R, f_output)])
            R = temp_L

        # Объединяем L и R (без финального обмена)
        plaintext_block = L + R
        plaintext += plaintext_block

    # Убираем PKCS#7 паддинг
    try:
        plaintext_bytes = pkcs7_unpadding(plaintext)
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