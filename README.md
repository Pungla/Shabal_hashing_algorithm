# Shabal Hashing Algorithm in Python

This repository implements a simplified version of the Shabal hashing algorithm in Python. The Shabal algorithm is a cryptographic hash function designed for security and performance. This implementation includes basic functionalities such as hashing data, hashing files, deriving keys, and recursively hashing directories.

## Overview

The Shabal algorithm in this project is demonstrated with the following capabilities:

- **Data Hashing**: Hashing arbitrary data.
- **Block Hashing**: Hashing a sequence of data blocks.
- **File Hashing**: Hashing the contents of a file.
- **Directory Hashing**: Recursively hashing the contents of a directory.
- **Key Derivation**: Deriving cryptographic keys using the PBKDF2 algorithm with HMAC.

## Main Components

### Shabal Class

The `Shabal` class represents the state of the Shabal hash function. It provides methods to update the state with new data and generate the final hash digest.

```python
class Shabal:
    def __init__(self):
        self.state = [0] * 16  # Initialize the state

    def update(self, data):
        for byte in data:
            self.state[byte % 16] ^= byte  # Simplified state update

    def digest(self):
        return bytes(self.state)  # Generate the hash value based on the state
```

### Functions

#### shabal_hash(data)

Hashes arbitrary data using the Shabal algorithm.

```python
def shabal_hash(data):
    hasher = Shabal()
    hasher.update(data)
    return hasher.digest()
```

#### hash_data_blocks(data_blocks)

Hashes a sequence of data blocks using the Shabal algorithm.

```python
def hash_data_blocks(data_blocks):
    shabal = Shabal()
    for block in data_blocks:
        shabal.update(block)
    return shabal.digest()
```

#### key_derivation(password, salt, iterations=100000, key_length=32, hash_name='sha256')

Derives a cryptographic key from a password using the PBKDF2 algorithm with HMAC.

```python
def key_derivation(password, salt, iterations=100000, key_length=32, hash_name='sha256'):
    def prf(key, data):
        return hmac.new(key, data, getattr(hashlib, hash_name)).digest()

    password = password.encode()  # Convert password to bytes
    salt = salt.encode() if isinstance(salt, str) else salt

    key_blocks = []
    block_count = (key_length + len(prf(password, salt)) - 1) // len(prf(password, salt))

    for block_index in range(1, block_count + 1):
        block = prf(password, salt + block_index.to_bytes(4, 'big'))
        result = block

        for _ in range(1, iterations):
            block = prf(password, block)
            result = bytes(x ^ y for x, y in zip(result, block))

        key_blocks.append(result)

    derived_key = b''.join(key_blocks)[:key_length]
    return derived_key
```

#### hash_file(file_path)

Hashes the contents of a file using the Shabal algorithm.

```python
def hash_file(file_path):
    shabal = Shabal()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            shabal.update(chunk)
    return shabal.digest()
```

#### hash_directory(directory_path, shabal=None)

Recursively hashes the contents of a directory using the Shabal algorithm.

```python
def hash_directory(directory_path, shabal=None):
    if shabal is None:
        shabal = Shabal()

    for entry in os.listdir(directory_path):
        full_path = os.path.join(directory_path, entry)

        if os.path.isdir(full_path):
            hash_directory(full_path, shabal)
        elif os.path.isfile(full_path):
            shabal.update(hash_file(full_path))

    return shabal.digest()
```

#### save_key_material(file_path, key_material)

Saves the derived key material to a file.

```python
def save_key_material(file_path, key_material):
    with open(file_path, 'wb') as f:
        f.write(key_material)
```

## Main Function

The `main` function demonstrates the usage of the Shabal hashing algorithm and other functionalities provided in this project. It performs the following tasks:

1. **Hashes arbitrary data** and prints the hash.
2. **Derives a cryptographic key** using a password and salt, and prints the derived key.
3. **Hashes a sequence of data blocks** and prints the hash.
4. **Hashes a file** and prints the hash.
5. **Recursively hashes a directory** and prints the hash.
6. **Saves the derived key material** to a file.
