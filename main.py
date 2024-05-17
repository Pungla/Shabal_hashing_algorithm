import os
import hashlib
import hmac


# Упрощенная структура для демонстрации
class Shabal:
    def __init__(self):
        self.state = [0] * 16  # Инициализация состояния

    def update(self, data):
        # Упрощенная версия обновления состояния на основе данных
        for byte in data:
            self.state[byte % 16] ^= byte

    def digest(self):
        # Генерация хэш-значения на основе состояния
        return bytes(self.state)


# Функция для хэширования данных
def shabal_hash(data):
    hasher = Shabal()
    hasher.update(data)
    return hasher.digest()


def hash_data_blocks(data_blocks):
    shabal = Shabal()
    for block in data_blocks:
        shabal.update(block)
    return shabal.digest()


# Функция для диверсификации ключа с использованием PBKDF2
def key_derivation(password, salt, iterations=100000, key_length=32, hash_name='sha256'):
    # Внутренняя функция для выполнения HMAC с использованием указанного алгоритма хеширования
    def prf(key, data):
        return hmac.new(key, data, getattr(hashlib, hash_name)).digest()

    # Конвертируем пароль в байты, если он еще не в байтах
    password = password.encode()  # Конвертируем пароль в байты
    # Конвертируем соль в байты, если она передана в виде строки
    salt = salt.encode() if isinstance(salt, str) else salt

    # Список для хранения блоков ключа
    key_blocks = []
    # Вычисляем количество блоков, необходимых для получения ключа нужной длины
    # Длина одного блока определяется длиной выходного значения функции prf
    block_count = (key_length + len(prf(password, salt)) - 1) // len(prf(password, salt))

    # Цикл по количеству блоков
    for block_index in range(1, block_count + 1):
        # Формируем первый блок с добавлением счетчика блоков к соли
        block = prf(password, salt + block_index.to_bytes(4, 'big'))
        result = block

        # Выполняем оставшиеся итерации PBKDF2
        for _ in range(1, iterations):
            block = prf(password, block)  # Вычисляем HMAC для текущего блока
            # XOR-им текущий блок с результатом предыдущей итерации
            result = bytes(x ^ y for x, y in zip(result, block))

        # Добавляем итоговый блок в список блоков ключа
        key_blocks.append(result)

    # Объединяем блоки и обрезаем до нужной длины ключа
    derived_key = b''.join(key_blocks)[:key_length]
    return derived_key


# Функция для хэширования файла
def hash_file(file_path):
    shabal = Shabal()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            shabal.update(chunk)
    return shabal.digest()


# Функция для рекурсивного хэширования директории
def hash_directory(directory_path, shabal=None):
    # Если не передан объект Shabal, создаем новый
    if shabal is None:
        shabal = Shabal()

    # Перебираем все элементы в директории
    for entry in os.listdir(directory_path):
        # Получаем полный путь к элементу
        full_path = os.path.join(directory_path, entry)

        # Проверяем, является ли элемент поддиректорией
        if os.path.isdir(full_path):
            # Рекурсивно хэшируем поддиректорию
            hash_directory(full_path, shabal)
        # Проверяем, является ли элемент файлом
        elif os.path.isfile(full_path):
            # Хэшируем файл и обновляем состояние Shabal
            shabal.update(hash_file(full_path))

    # Возвращаем итоговый хэш директории
    return shabal.digest()


# Функция для сохранения ключевого материала в файл
def save_key_material(file_path, key_material):
    with open(file_path, 'wb') as f:
        f.write(key_material)


def main():
    data = b'342123'
    password = 'пароль'
    salt = os.urandom(16)

    # Хэширование данных
    data_hash = shabal_hash(data)
    print(f'Хэш Shabal данных: {data_hash.hex()}')

    # Диверсификация ключа
    key_material = key_derivation(password, salt)
    print(f'Диверсифицированный ключевой материал: {key_material.hex()}')

    # Хэширование блоков данных
    data_blocks = [b'Block 1', b'Block 2', b'Block 3']
    blocks_hash = hash_data_blocks(data_blocks)
    print(f'Хэш Shabal блоков данных: {blocks_hash.hex()}')

    # Хэширование файла
    file_path = input("Введите путь к файлу: ")
    if os.path.isfile(file_path):
        file_hash = hash_file(file_path)
        print(f'Хэш Shabal файла {file_path}: {file_hash.hex()}')
    else:
        print("Файл не найден. Пожалуйста, проверьте путь и попробуйте снова.")

    # Хэширование директории
    directory_path = input("Введите путь к директории: ")
    if os.path.isdir(directory_path):
        directory_hash = hash_directory(directory_path)
        print(f'Хэш Shabal директории {directory_path}: {directory_hash.hex()}')
    else:
        print("Директория не найдена. Пожалуйста, проверьте путь и попробуйте снова.")

    # Сохранение ключевого материала в файл
    save_key_material('key_material.bin', key_material)
    print(f'Ключевой материал сохранен в key_material.bin')


if __name__ == '__main__':
    main()
