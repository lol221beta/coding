# Функция шифрования обобщенным шифром Цезаря
def encrypt(k, m):
    return ''.join(map(chr, [(ord(c) + k) % 65536 for c in m]))

# Функция дешифрования обобщенным шифром Цезаря
def decrypt(k, m):
    return ''.join(map(chr, [(ord(c) - k) % 65536 for c in m]))

# Функция взлома шифра Цезаря с использованием частотного анализа
def break_cipher(text):
    from collections import Counter

    # Находим самый часто встречающийся символ в шифротексте
    counter = Counter(text)
    most_common_char, _ = counter.most_common(1)[0]

    # Код символа самого частого символа в шифротексте
    cipher_most_common_code = ord(most_common_char)

    # Код символа пробела
    space_code = ord(' ')

    # Вычисляем предполагаемый ключ
    key = (cipher_most_common_code - space_code) % 65536

    # Дешифруем текст с найденным ключом
    decrypted_text = decrypt(key, text)

    return decrypted_text, key

# Основная часть программы
if __name__ == "__main__":
    # Запрашиваем у пользователя ключ и текст для шифрования
    key = int(input("Введите ключ для шифрования (целое число): "))
    plain_text = input("Введите текст для шифрования: ")

    # Шифруем текст
    encrypted_text = encrypt(key, plain_text)
    print("\nЗашифрованный текст:\n", encrypted_text)

    # Взламываем шифр без знания ключа
    recovered_text, recovered_key = break_cipher(encrypted_text)
    print("\nВосстановленный текст без знания ключа:\n", recovered_text)
    print("\nНайденный ключ:", recovered_key)