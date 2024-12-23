import os
import base64

# Функция шифрования с использованием OTP
def encrypt(message, key):
    if len(key) != len(message.encode('utf-8')):
        raise ValueError("Длина ключа должна совпадать с длиной сообщения.")

    # Преобразуем сообщение в байты
    message_bytes = message.encode('utf-8')

    # Применяем XOR между каждым байтом сообщения и ключа
    encrypted_bytes = bytes([m ^ k for m, k in zip(message_bytes, key)])
    return encrypted_bytes

# Функция дешифрования с использованием OTP
def decrypt(ciphertext, key):
    if len(key) != len(ciphertext):
        raise ValueError("Длина ключа должна совпадать с длиной шифротекста.")

    # Применяем XOR между каждым байтом шифротекста и ключа
    decrypted_bytes = bytes([c ^ k for c, k in zip(ciphertext, key)])
    # Декодируем байты в строку
    try:
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Не удалось декодировать расшифрованный текст. Возможно, ключ или шифротекст повреждены.")

# Основная часть программы
if __name__ == "__main__":
    # Запрашиваем у пользователя текст для шифрования
    message = input("Введите текст для шифрования: ")

    # Преобразуем сообщение в байты
    message_bytes = message.encode('utf-8')

    # Генерируем ключ той же длины, что и байтовое представление сообщения
    key = os.urandom(len(message_bytes))
    print("\nСгенерированный ключ (в Base64):\n", base64.b64encode(key).decode('utf-8'))

    # Шифруем текст
    encrypted_bytes = encrypt(message, key)
    print("\nЗашифрованный текст (в Base64):\n", base64.b64encode(encrypted_bytes).decode('utf-8'))

    # Дешифруем текст
    try:
        decrypted_text = decrypt(encrypted_bytes, key)
        print("\nРасшифрованный текст:\n", decrypted_text)
    except ValueError as e:
        print("\nОшибка при расшифровке текста:\n", e)