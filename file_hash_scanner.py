from pathlib import Path
import hashlib


def calculate_sha256(file_path):
    hash_object = hashlib.sha256()

    with file_path.open("rb") as file:
        while True:
            file_data = file.read(4096)

            if not file_data:
                break

            hash_object.update(file_data)

    return hash_object.hexdigest()

file_path = Path(__file__).parent / "sample.txt"
file_hash = calculate_sha256(file_path)

print(file_hash)