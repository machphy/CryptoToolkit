import os
import hashlib

def calculate_hash(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return None
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

file_hash = calculate_hash("example.txt")
if file_hash:
    print("File Hash:", file_hash)
