
import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def verify_sha256(file_path, expected_hash):
    """Check whether a file matches a trusted SHA-256 hash."""
    actual_hash = calculate_sha256(file_path)
    return actual_hash.lower() == expected_hash.strip().lower()
