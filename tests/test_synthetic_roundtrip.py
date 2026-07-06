from pathlib import Path
import json
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import rtdx_save_codec as c


KEY = b"PEGASUS939564968"
WRONG_KEY = b"AAAAAAAAAAAAAAAA"


def make_valid_plain_save() -> bytes:
    payload = bytearray((i * 37 + 11) & 0xFF for i in range(c.ENCRYPT_TARGET_SIZE))
    json_doc = {
        "header_": {
            "dataVersion": 51,
            "dungeonSaveVersion": 10,
            "nativeVersion": 1,
        },
        "test": True,
    }
    json_body = json.dumps(json_doc, separators=(",", ":")).encode("utf-16le")
    payload[c.JSON_LENGTH_OFFSET:c.JSON_LENGTH_OFFSET + 4] = len(json_body).to_bytes(4, "little")
    payload[c.JSON_BODY_OFFSET:c.JSON_BODY_OFFSET + len(json_body)] = json_body
    fingerprint = bytes((0xA5 ^ i) & 0xFF for i in range(c.FINGERPRINT_SIZE))
    return bytes(payload) + fingerprint


def test_synthetic_aes_roundtrip():
    decoded = make_valid_plain_save()
    encrypted = c.encode_save(decoded, KEY)
    assert c.decode_save(encrypted, KEY) == decoded


def test_synthetic_json_validation_accepts_correct_key():
    decoded = make_valid_plain_save()
    encrypted = c.encode_save(decoded, KEY)
    plain = c.decode_save(encrypted, KEY)
    c.validate_plain_save(plain)


def test_synthetic_json_validation_rejects_wrong_key():
    decoded = make_valid_plain_save()
    encrypted = c.encode_save(decoded, KEY)
    wrong_plain = c.decode_save(encrypted, WRONG_KEY)
    try:
        c.validate_plain_save(wrong_plain)
    except c.CodecError:
        return
    raise AssertionError("wrong key unexpectedly passed JSON validation")


def test_cli_roundtrip_and_wrong_key_rejection(tmp_path: Path):
    decoded = make_valid_plain_save()
    encrypted = c.encode_save(decoded, KEY)
    encrypted_path = tmp_path / "encrypted.bin"
    roundtrip_path = tmp_path / "roundtrip.bin"
    encrypted_path.write_bytes(encrypted)

    script = Path(__file__).resolve().parents[1] / "src" / "rtdx_save_codec.py"
    ok = subprocess.run(
        [sys.executable, str(script), "roundtrip", str(encrypted_path), "--key", KEY.decode(), "--no-prompt", "-o", str(roundtrip_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr + ok.stdout
    assert roundtrip_path.read_bytes() == encrypted

    bad = subprocess.run(
        [sys.executable, str(script), "roundtrip", str(encrypted_path), "--key", WRONG_KEY.decode(), "--no-prompt"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert bad.returncode != 0
    assert "JSON length" in bad.stderr or "JSON block" in bad.stderr
