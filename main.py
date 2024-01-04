import os
import struct
from Crypto.Cipher import AES

def decrypt_file(file_path, output_directory):
    if os.path.basename(file_path) == ".meta":
        return
    data = open(file_path, "rb").read()

    key = data[:2]
    signatureBytes = data[2:15]
    generation = data[15]

    signatureBytes = bytearray(signatureBytes)
    for i in range(13):
        signatureBytes[i] ^= key[i % len(key)]

    try:
        signature = signatureBytes.decode("utf-8")
    except UnicodeDecodeError:
        print(f"Unable to decode signature for file: {file_path}")
        return
    if signature != "_GhostAssets_":
        print(f"Invalid signature for file: {file_path}")
        return
    generation ^= (key[0] ^ key[1])
    if generation != 1:
        print(f"Invalid generation for file: {file_path}")
        return

    ms = bytearray()
    value = 0
    blockCount = (len(data) - 0x10) // 0x10
    for i in range(blockCount + 1):
        if i % 0x40 == 0:
            value = 0x64 * ((i // 0x40) + 1)
        ms += struct.pack("<Q", value)
        ms += struct.pack("<Q", 0)
        value += 1

    aes = AES.new(b"6154e00f9E9ce46dc9054E07173Aa546", AES.MODE_ECB)
    keyBytes = aes.encrypt(ms)

    decrypted_bytes = bytearray(data[0x10:])
    for i in range(len(decrypted_bytes)):
        decrypted_bytes[i] ^= keyBytes[i]

    output_file_path = os.path.join(output_directory, f"decrypted_{os.path.basename(file_path)}")
    open(output_file_path, "wb").write(decrypted_bytes)
    print(f"Decrypted {file_path} and saved to {output_file_path}")

def decrypt_files_in_directory(directory, output_directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, output_directory)

output_directory = r"output"
if not os.path.exists(output_directory):
    os.makedirs(output_directory)
directory_to_search = r"octo\v1\1"

decrypt_files_in_directory(directory_to_search, output_directory)