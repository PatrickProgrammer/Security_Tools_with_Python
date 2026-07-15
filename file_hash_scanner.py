from pathlib import Path
import hashlib


file_path = Path(__file__).parent / "sample.txt"
ioc_file_path = Path(__file__).parent / "ioc.txt"
directory_path = Path(__file__).parent / "samples"


def calculate_sha256(file_path):
    hash_object = hashlib.sha256()

    try:
        with file_path.open("rb") as file:
            while True:
                chunk = file.read(4096)

                if not chunk:
                    break

                hash_object.update(chunk)

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except PermissionError:
        print(f"Permission denied: {file_path}")
        return None

    return hash_object.hexdigest()


def load_iocs(ioc_file_path):
    try:
        with ioc_file_path.open("r", encoding="utf-8") as file:
            return {
                line.strip()
                for line in file
                if line.strip()
            }

    except FileNotFoundError:
        print(f"IOC file not found: {ioc_file_path}")
        return set()


def scan_directory(directory_path, malicious_hashes):
    if not directory_path.exists():
        print(f"Directory not found: {directory_path}")
        return

    if not directory_path.is_dir():
        print(f"Path is not a directory: {directory_path}")
        return

    for file_path in directory_path.rglob("*"):
        if not file_path.is_file():
            continue

        file_hash = calculate_sha256(file_path)

        if file_hash is None:
            print(f"Could not scan file: {file_path}")
            continue

        if file_hash in malicious_hashes:
            print(
                f"ALERT: Malicious hash detected: "
                f"{file_hash} in file {file_path}"
            )
        else:
            print(
                f"No IOC match: {file_hash} in file {file_path}"
            )


malicious_hashes = load_iocs(ioc_file_path)

scan_directory(directory_path, malicious_hashes)