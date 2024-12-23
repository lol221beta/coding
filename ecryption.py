# Функция для размножения ключа до длины сообщения
def extend_key(key, length):
    repeated_key = (key * (length // len(key) + 1))[:length]
    return repeated_key

# Функция шифрования шифром Виженера
def encrypt(key, message):
    # Размножаем ключ до длины сообщения
    extended_key = extend_key(key, len(message))
    # Шифруем каждый символ
    encrypted_chars = []
    for m_char, k_char in zip(message, extended_key):
        encrypted_char = chr((ord(m_char) + ord(k_char)) % 65536)
        encrypted_chars.append(encrypted_char)
    return ''.join(encrypted_chars)

# Функция дешифрования шифра Виженера
def decrypt(key, ciphertext):
    # Размножаем ключ до длины шифротекста
    extended_key = extend_key(key, len(ciphertext))
    # Дешифруем каждый символ
    decrypted_chars = []
    for c_char, k_char in zip(ciphertext, extended_key):
        decrypted_char = chr((ord(c_char) - ord(k_char)) % 65536)
        decrypted_chars.append(decrypted_char)
    return ''.join(decrypted_chars)

# Основная часть программы
if __name__ == "__main__":
    # Запрашиваем у пользователя ключ и текст для шифрования
    key = input("Введите ключ для шифрования (строка): ")
    message = input("Введите текст для шифрования: ")

    # Шифруем текст
    encrypted_text = encrypt(key, message)
    print("\nЗашифрованный текст:\n", encrypted_text)

    # Дешифруем текст
    decrypted_text = decrypt(key, encrypted_text)
    print("\nРасшифрованный текст:\n", decrypted_text)