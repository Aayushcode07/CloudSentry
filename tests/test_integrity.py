
from evidence.integrity import calculate_sha256, verify_sha256


def test_original_file_verifies(tmp_path):
    evidence_file = tmp_path / "evidence.txt"
    evidence_file.write_text("Original evidence", encoding="utf-8")

    original_hash = calculate_sha256(evidence_file)

    assert verify_sha256(evidence_file, original_hash)


def test_modified_file_fails_verification(tmp_path):
    evidence_file = tmp_path / "evidence.txt"
    evidence_file.write_text("Original evidence", encoding="utf-8")

    original_hash = calculate_sha256(evidence_file)

    evidence_file.write_text("Modified evidence", encoding="utf-8")

    assert not verify_sha256(evidence_file, original_hash)
