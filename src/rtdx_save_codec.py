#!/usr/bin/env python3
"""
RTDX Yuzu save codec for Pokémon Mystery Dungeon: Rescue Team DX.

Decodes and re-encodes pegasus_save_master_data.bin by decrypting/encrypting
only the 0x13FF80-byte AES-CBC region and preserving the final 0x80-byte
fingerprint/signature block.

This tool is intentionally conservative. It does not recalculate the final
fingerprint block; it preserves it from the decoded file or from an explicitly
provided original save.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:  # pragma: no cover - handled at runtime
    Cipher = None  # type: ignore[assignment]
    algorithms = None  # type: ignore[assignment]
    modes = None  # type: ignore[assignment]

SAVE_FILE_NAME = "pegasus_save_master_data.bin"
EXPECTED_SAVE_SIZE = 0x140000
ENCRYPT_TARGET_SIZE = 0x13FF80
FINGERPRINT_SIZE = 0x80
JSON_LENGTH_OFFSET = 0x100000
JSON_BODY_OFFSET = 0x100400
JSON_BODY_END = ENCRYPT_TARGET_SIZE
KNOWN_KEY = "PEGASUS939564968"
KEY_REGEX = re.compile(rb"PEGASUS[0-9]{6,16}")


class CodecError(RuntimeError):
    """User-facing codec error."""


@dataclass(frozen=True)
class SaveParts:
    payload: bytes
    fingerprint: bytes


def _read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CodecError(f"Could not read {path}: {exc}") from exc


def _write(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError as exc:
        raise CodecError(f"Could not write {path}: {exc}") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_aes_backend() -> None:
    if Cipher is None or algorithms is None or modes is None:
        raise CodecError(
            "Missing dependency: cryptography. Install it with `python -m pip install cryptography`, "
            "or use a release binary built by GitHub Actions."
        )


def aes_cbc_crypt(data: bytes, key: bytes, *, decrypt: bool) -> bytes:
    require_aes_backend()
    if len(key) != 16:
        raise CodecError(f"AES key must be exactly 16 bytes. Got {len(key)} bytes.")
    if len(data) % 16 != 0:
        raise CodecError(f"AES-CBC input size must be a multiple of 16. Got {len(data)} bytes.")
    cipher = Cipher(algorithms.AES(key), modes.CBC(key))
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def split_save(data: bytes, *, strict_size: bool = True) -> SaveParts:
    if strict_size and len(data) != EXPECTED_SAVE_SIZE:
        raise CodecError(
            f"Unexpected save size: {len(data):#x} bytes. Expected {EXPECTED_SAVE_SIZE:#x} bytes. "
            "Use --allow-size-mismatch only if you know this is intentional."
        )
    if len(data) < ENCRYPT_TARGET_SIZE + FINGERPRINT_SIZE:
        raise CodecError("File is too small to contain the RTDX encrypted payload and fingerprint block.")
    return SaveParts(data[:ENCRYPT_TARGET_SIZE], data[ENCRYPT_TARGET_SIZE:ENCRYPT_TARGET_SIZE + FINGERPRINT_SIZE])


def decode_save(encrypted_save: bytes, key: bytes, *, strict_size: bool = True) -> bytes:
    parts = split_save(encrypted_save, strict_size=strict_size)
    plain_payload = aes_cbc_crypt(parts.payload, key, decrypt=True)
    return plain_payload + parts.fingerprint


def encode_save(decoded_save: bytes, key: bytes, *, strict_size: bool = True, fingerprint_from: bytes | None = None) -> bytes:
    parts = split_save(decoded_save, strict_size=strict_size)
    fingerprint = parts.fingerprint
    if fingerprint_from is not None:
        fingerprint = split_save(fingerprint_from, strict_size=strict_size).fingerprint
    encrypted_payload = aes_cbc_crypt(parts.payload, key, decrypt=False)
    return encrypted_payload + fingerprint


def find_global_metadata_files(rom_root: Path) -> list[Path]:
    if rom_root.is_file() and rom_root.name == "global-metadata.dat":
        return [rom_root]
    if not rom_root.exists():
        return []
    matches: list[Path] = []
    for root, dirs, files in os.walk(rom_root):
        # Skip noisy folders that cannot reasonably be part of an extracted ROM dump.
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        if "global-metadata.dat" in files:
            matches.append(Path(root) / "global-metadata.dat")
    return sorted(matches, key=_metadata_score, reverse=True)


def _metadata_score(path: Path) -> tuple[int, int, str]:
    parts = [p.lower() for p in path.parts]
    score = 0
    if "metadata" in parts:
        score += 8
    if "managed" in parts:
        score += 4
    if "data" in parts:
        score += 2
    if "romfs" in parts:
        score += 1
    return (score, -len(path.parts), str(path))


def prompt_for_path(prompt: str, *, must_exist: bool = True) -> Path:
    while True:
        answer = input(prompt).strip().strip('"')
        if not answer:
            raise CodecError("No path was supplied.")
        path = Path(answer).expanduser()
        if not must_exist or path.exists():
            return path
        print(f"Path does not exist: {path}", file=sys.stderr)


def choose_metadata_path(
    *,
    rom_dump: Optional[Path],
    metadata: Optional[Path],
    no_prompt: bool = False,
) -> Path:
    if metadata:
        if not metadata.exists():
            raise CodecError(f"global-metadata.dat was not found at: {metadata}")
        return metadata

    if rom_dump:
        matches = find_global_metadata_files(rom_dump)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            # Prefer the highest-scored candidate, but make interactive use explicit.
            if no_prompt or not sys.stdin.isatty():
                return matches[0]
            print("Multiple global-metadata.dat files were found:", file=sys.stderr)
            for i, p in enumerate(matches, start=1):
                print(f"  {i}. {p}", file=sys.stderr)
            raw = input(f"Select 1-{len(matches)} [1]: ").strip()
            if not raw:
                return matches[0]
            try:
                idx = int(raw)
            except ValueError as exc:
                raise CodecError("Invalid selection.") from exc
            if not 1 <= idx <= len(matches):
                raise CodecError("Selection is out of range.")
            return matches[idx - 1]

    if no_prompt or not sys.stdin.isatty():
        raise CodecError(
            "Could not locate global-metadata.dat. Re-run with --rom-dump PATH, --metadata PATH, or --key PEGASUS939564968."
        )
    return prompt_for_path("Path to global-metadata.dat: ")


def extract_candidate_keys_from_metadata(metadata_bytes: bytes) -> list[str]:
    candidates: list[str] = []

    for match in KEY_REGEX.finditer(metadata_bytes):
        try:
            s = match.group(0).decode("ascii")
        except UnicodeDecodeError:
            continue
        if len(s.encode("utf-8")) == 16 and s not in candidates:
            candidates.append(s)

    # Some metadata dumps can store strings as UTF-16LE. This pass is intentionally broad.
    try:
        text16 = metadata_bytes.decode("utf-16le", errors="ignore")
        for s in re.findall(r"PEGASUS[0-9]{6,16}", text16):
            if len(s.encode("utf-8")) == 16 and s not in candidates:
                candidates.append(s)
    except Exception:
        pass

    if KNOWN_KEY not in candidates and KNOWN_KEY.encode("ascii") in metadata_bytes:
        candidates.append(KNOWN_KEY)

    return candidates


def resolve_key(
    *,
    key: Optional[str],
    rom_dump: Optional[Path],
    metadata: Optional[Path],
    no_prompt: bool = False,
) -> bytes:
    if key:
        key_bytes = key.encode("utf-8")
        if len(key_bytes) != 16:
            raise CodecError("--key must encode to exactly 16 bytes for AES-128.")
        return key_bytes

    metadata_path = choose_metadata_path(rom_dump=rom_dump, metadata=metadata, no_prompt=no_prompt)
    metadata_bytes = _read(metadata_path)
    candidates = extract_candidate_keys_from_metadata(metadata_bytes)

    if len(candidates) == 1:
        return candidates[0].encode("ascii")
    if len(candidates) > 1:
        if no_prompt or not sys.stdin.isatty():
            return candidates[0].encode("ascii")
        print("Multiple PEGASUS-like 16-byte key candidates were found:", file=sys.stderr)
        for i, c in enumerate(candidates, start=1):
            print(f"  {i}. {c}", file=sys.stderr)
        raw = input(f"Select 1-{len(candidates)} [1]: ").strip()
        if not raw:
            return candidates[0].encode("ascii")
        try:
            idx = int(raw)
        except ValueError as exc:
            raise CodecError("Invalid selection.") from exc
        if not 1 <= idx <= len(candidates):
            raise CodecError("Selection is out of range.")
        return candidates[idx - 1].encode("ascii")

    if no_prompt or not sys.stdin.isatty():
        raise CodecError(
            f"No 16-byte PEGASUS key was found in {metadata_path}. "
            f"For RTDX the known key is usually {KNOWN_KEY!r}; pass it with --key if appropriate."
        )
    raw = input("No key candidate found. Enter 16-byte AES key manually: ").strip()
    if len(raw.encode("utf-8")) != 16:
        raise CodecError("Manual AES key must be exactly 16 bytes.")
    return raw.encode("utf-8")


def maybe_backup(path: Path) -> Optional[Path]:
    if not path.exists():
        return None
    backup = path.with_suffix(path.suffix + ".bak")
    n = 1
    while backup.exists():
        backup = path.with_suffix(path.suffix + f".bak{n}")
        n += 1
    shutil.copy2(path, backup)
    return backup


def decode_json_from_plain(plain_save: bytes) -> tuple[int, str]:
    if len(plain_save) < JSON_BODY_OFFSET:
        raise CodecError("Decoded save is too small to contain the JSON block.")
    raw_len = plain_save[JSON_LENGTH_OFFSET:JSON_LENGTH_OFFSET + 4]
    json_len = int.from_bytes(raw_len, "little")
    if json_len <= 0 or JSON_BODY_OFFSET + json_len > min(len(plain_save), JSON_BODY_END):
        raise CodecError(
            f"JSON length {json_len:#x} is outside the expected JSON body range. "
            "The file may not be decoded/plaintext, or this save uses a different layout."
        )
    raw = plain_save[JSON_BODY_OFFSET:JSON_BODY_OFFSET + json_len]
    try:
        return json_len, raw.decode("utf-16le")
    except UnicodeDecodeError as exc:
        raise CodecError("JSON block exists but could not be decoded as UTF-16LE.") from exc


def validate_plain_save(plain_save: bytes) -> None:
    """Sanity-check that a decrypted save is really RTDX plaintext.

    AES-CBC decrypts with any 16-byte key into some bytes, and decrypting then
    re-encrypting with the same wrong key can still roundtrip byte-identically.
    This validation checks the known RTDX UTF-16LE JSON block so wrong keys are
    rejected before writing or reporting success.
    """
    _, text = decode_json_from_plain(plain_save)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CodecError("JSON block was decoded but is not valid JSON; the AES key is probably wrong.") from exc
    if not isinstance(doc, dict) or "header_" not in doc:
        raise CodecError("JSON block does not look like RTDX save metadata; the AES key or layout may be wrong.")


def put_u16(buf: bytearray, offset: int, value: int) -> None:
    if not 0 <= value <= 0xFFFF:
        raise CodecError(f"u16 value out of range: {value}")
    buf[offset:offset + 2] = value.to_bytes(2, "little")


def put_u32(buf: bytearray, offset: int, value: int) -> None:
    if not 0 <= value <= 0xFFFFFFFF:
        raise CodecError(f"u32 value out of range: {value}")
    buf[offset:offset + 4] = value.to_bytes(4, "little")


def put_u8(buf: bytearray, offset: int, value: int) -> None:
    if not 0 <= value <= 0xFF:
        raise CodecError(f"u8 value out of range: {value}")
    buf[offset] = value


def apply_safe_mew_patch(plain_save: bytes, *, patch_dungeon_species: bool = True) -> bytes:
    """Apply the conservative hero Mew patch described in the research notes.

    This patches ground/menu records and known PLYR dungeon species copies only.
    It deliberately avoids active-dungeon stat/move cache edits.
    """
    if len(plain_save) < EXPECTED_SAVE_SIZE:
        raise CodecError("Plain save is too small for the known patch offsets.")
    b = bytearray(plain_save)

    # Species: Eevee -> Mew, but this writes Mew unconditionally.
    put_u16(b, 0x0350, 0x00C8)
    put_u16(b, 0x6F5B, 0x00C8)

    if patch_dungeon_species:
        for off in (0x08DDF0, 0x08DDF4, 0x08DDF8, 0x08DDFC):
            put_u32(b, off, 0x000000C8)

    # Abilities: Synchronize, Protean.
    for off, value in ((0x03AF, 0x0033), (0x03B1, 0x00A8), (0x6FBA, 0x0033), (0x6FBC, 0x00A8)):
        put_u16(b, off, value)

    # Stats: HP 50/50 and combat stats 30.
    for off in (0x030C, 0x030E, 0x6F39, 0x6F3B):
        put_u16(b, off, 50)
    for off in (0x0322, 0x0324, 0x0326, 0x0328, 0x032B, 0x032D, 0x032F, 0x0331, 0x6F4F, 0x6F51, 0x6F53, 0x6F55):
        put_u16(b, off, 30)
    for off in (0x032A, 0x0333, 0x6F57):
        put_u8(b, off, 30)

    # Moves: known IDs. Offsets are intentionally not hard-coded here because the
    # final research notes did not include stable exact move-slot offsets. Use
    # a separate patch JSON once those offsets are fully confirmed.
    return bytes(b)


def apply_patch_json(plain_save: bytes, patch_path: Path) -> bytes:
    """Apply a small declarative patch file.

    JSON shape:
    {
      "patches": [
        {"offset": "0x0350", "type": "u16", "value": "0x00C8"},
        {"offset": "0x08DDF0", "type": "u32", "value": 200},
        {"offset": "0x1234", "type": "bytes", "value": "C8 00"}
      ]
    }
    """
    try:
        doc = json.loads(_read(patch_path).decode("utf-8"))
    except Exception as exc:
        raise CodecError(f"Could not parse patch JSON {patch_path}: {exc}") from exc
    patches = doc.get("patches")
    if not isinstance(patches, list):
        raise CodecError("Patch JSON must contain a list field named 'patches'.")

    b = bytearray(plain_save)
    for i, p in enumerate(patches, start=1):
        if not isinstance(p, dict):
            raise CodecError(f"Patch #{i} must be an object.")
        offset = parse_int(p.get("offset"), f"patch #{i} offset")
        typ = str(p.get("type", "")).lower()
        value = p.get("value")
        if offset < 0 or offset >= len(b):
            raise CodecError(f"Patch #{i} offset is outside the file: {offset:#x}")
        if typ == "u8":
            put_u8(b, offset, parse_int(value, f"patch #{i} value"))
        elif typ == "u16":
            put_u16(b, offset, parse_int(value, f"patch #{i} value"))
        elif typ == "u32":
            put_u32(b, offset, parse_int(value, f"patch #{i} value"))
        elif typ == "bytes":
            if not isinstance(value, str):
                raise CodecError(f"Patch #{i} bytes value must be a hex string.")
            raw = bytes.fromhex(value.replace(" ", ""))
            if offset + len(raw) > len(b):
                raise CodecError(f"Patch #{i} byte patch overruns the file.")
            b[offset:offset + len(raw)] = raw
        else:
            raise CodecError(f"Patch #{i} has unsupported type {typ!r}. Use u8, u16, u32, or bytes.")
    return bytes(b)


def parse_int(value: object, label: str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise CodecError(f"Invalid integer for {label}: {value!r}") from exc
    raise CodecError(f"Invalid integer for {label}: {value!r}")


def print_file_summary(label: str, path: Path, data: bytes) -> None:
    print(f"{label}: {path}")
    print(f"  size:   {len(data)} bytes / {len(data):#x}")
    print(f"  sha256: {sha256_hex(data)}")


def add_common_key_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rom-dump", type=Path, help="Path to an extracted/decrypted RTDX ROM dump; searched recursively for global-metadata.dat.")
    parser.add_argument("--metadata", type=Path, help="Path directly to global-metadata.dat.")
    parser.add_argument("--key", help="Manual 16-byte AES key. For RTDX this is usually PEGASUS939564968.")
    parser.add_argument("--no-prompt", action="store_true", help="Do not ask interactively for missing metadata/key paths.")


def cmd_find_metadata(args: argparse.Namespace) -> int:
    matches = find_global_metadata_files(args.rom_dump)
    if not matches:
        raise CodecError(f"No global-metadata.dat was found under {args.rom_dump}")
    for p in matches:
        print(p)
    return 0


def cmd_key(args: argparse.Namespace) -> int:
    key = resolve_key(key=args.key, rom_dump=args.rom_dump, metadata=args.metadata, no_prompt=args.no_prompt)
    print(key.decode("ascii", errors="replace"))
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    key = resolve_key(key=args.key, rom_dump=args.rom_dump, metadata=args.metadata, no_prompt=args.no_prompt)
    encrypted = _read(args.save)
    decoded = decode_save(encrypted, key, strict_size=not args.allow_size_mismatch)
    if not args.no_validate_json:
        validate_plain_save(decoded)
    if args.backup and args.output.exists():
        backup = maybe_backup(args.output)
        if backup:
            print(f"Backed up existing output to: {backup}")
    _write(args.output, decoded)
    print_file_summary("Decoded", args.output, decoded)
    if args.json_out:
        json_len, text = decode_json_from_plain(decoded)
        _write(args.json_out, text.encode("utf-8"))
        print(f"Extracted UTF-16LE JSON block ({json_len:#x} bytes) to: {args.json_out}")
    return 0


def cmd_encode(args: argparse.Namespace) -> int:
    key = resolve_key(key=args.key, rom_dump=args.rom_dump, metadata=args.metadata, no_prompt=args.no_prompt)
    plain = _read(args.decoded)
    if not args.no_validate_json:
        validate_plain_save(plain)
    fingerprint_from = _read(args.fingerprint_from) if args.fingerprint_from else None
    encoded = encode_save(plain, key, strict_size=not args.allow_size_mismatch, fingerprint_from=fingerprint_from)
    if args.backup and args.output.exists():
        backup = maybe_backup(args.output)
        if backup:
            print(f"Backed up existing output to: {backup}")
    _write(args.output, encoded)
    print_file_summary("Encoded", args.output, encoded)
    return 0


def cmd_roundtrip(args: argparse.Namespace) -> int:
    key = resolve_key(key=args.key, rom_dump=args.rom_dump, metadata=args.metadata, no_prompt=args.no_prompt)
    original = _read(args.save)
    decoded = decode_save(original, key, strict_size=not args.allow_size_mismatch)
    if not args.no_validate_json:
        validate_plain_save(decoded)
    encoded = encode_save(decoded, key, strict_size=not args.allow_size_mismatch)
    ok = original == encoded
    print(f"roundtrip_equal: {str(ok).lower()}")
    print(f"original_sha256:  {sha256_hex(original)}")
    print(f"roundtrip_sha256: {sha256_hex(encoded)}")
    if args.output:
        _write(args.output, encoded)
        print(f"Wrote roundtrip output to: {args.output}")
    return 0 if ok else 2


def cmd_extract_json(args: argparse.Namespace) -> int:
    data = _read(args.input)
    if args.encrypted:
        key = resolve_key(key=args.key, rom_dump=args.rom_dump, metadata=args.metadata, no_prompt=args.no_prompt)
        data = decode_save(data, key, strict_size=not args.allow_size_mismatch)
    json_len, text = decode_json_from_plain(data)
    if args.output:
        _write(args.output, text.encode("utf-8"))
        print(f"Extracted UTF-16LE JSON block ({json_len:#x} bytes) to: {args.output}")
    else:
        print(text)
    return 0


def cmd_patch(args: argparse.Namespace) -> int:
    plain = _read(args.decoded)
    if args.safe_mew:
        plain = apply_safe_mew_patch(plain, patch_dungeon_species=not args.no_dungeon_species)
    if args.patch_json:
        for patch_path in args.patch_json:
            plain = apply_patch_json(plain, patch_path)
    _write(args.output, plain)
    print_file_summary("Patched decoded save", args.output, plain)
    print("Note: patch output is still decoded/plaintext. Re-encode it before replacing the Yuzu save.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rtdx-save-codec",
        description="Decode and encode Pokémon Mystery Dungeon: Rescue Team DX Yuzu save files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("find-metadata", help="Find global-metadata.dat under an extracted ROM dump.")
    p.add_argument("rom_dump", type=Path)
    p.set_defaults(func=cmd_find_metadata)

    p = sub.add_parser("key", help="Extract the AES key from global-metadata.dat or print the supplied key.")
    add_common_key_args(p)
    p.set_defaults(func=cmd_key)

    p = sub.add_parser("decode", help="Decrypt pegasus_save_master_data.bin into an editable decoded file.")
    p.add_argument("save", type=Path, help="Encrypted pegasus_save_master_data.bin")
    p.add_argument("-o", "--output", type=Path, default=Path("pegasus_save_master_data.decoded.bin"))
    p.add_argument("--json-out", type=Path, help="Also extract the UTF-16LE JSON block as UTF-8 text.")
    p.add_argument("--backup", action="store_true", help="Back up an existing output path before overwriting it.")
    p.add_argument("--allow-size-mismatch", action="store_true", help="Do not require the known 0x140000-byte save size.")
    p.add_argument("--no-validate-json", action="store_true", help="Do not verify the known RTDX JSON block after decryption.")
    add_common_key_args(p)
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("encode", help="Encrypt a decoded save back to pegasus_save_master_data.bin format.")
    p.add_argument("decoded", type=Path, help="Decoded/plaintext full save file")
    p.add_argument("-o", "--output", type=Path, default=Path(SAVE_FILE_NAME))
    p.add_argument("--fingerprint-from", type=Path, help="Original encrypted save whose final 0x80-byte fingerprint block should be preserved.")
    p.add_argument("--backup", action="store_true", help="Back up an existing output path before overwriting it.")
    p.add_argument("--allow-size-mismatch", action="store_true", help="Do not require the known 0x140000-byte save size.")
    p.add_argument("--no-validate-json", action="store_true", help="Do not verify the known RTDX JSON block before encryption.")
    add_common_key_args(p)
    p.set_defaults(func=cmd_encode)

    p = sub.add_parser("roundtrip", help="Verify decode -> encode produces a byte-identical save.")
    p.add_argument("save", type=Path)
    p.add_argument("-o", "--output", type=Path, help="Optional path to write the re-encoded output.")
    p.add_argument("--allow-size-mismatch", action="store_true", help="Do not require the known 0x140000-byte save size.")
    p.add_argument("--no-validate-json", action="store_true", help="Do not verify the known RTDX JSON block during the roundtrip test.")
    add_common_key_args(p)
    p.set_defaults(func=cmd_roundtrip)

    p = sub.add_parser("extract-json", help="Extract the UTF-16LE JSON block from a decoded or encrypted save.")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--encrypted", action="store_true", help="Input is encrypted; decode it first using key/metadata arguments.")
    p.add_argument("--allow-size-mismatch", action="store_true", help="Do not require the known 0x140000-byte save size when decoding encrypted input.")
    add_common_key_args(p)
    p.set_defaults(func=cmd_extract_json)

    p = sub.add_parser("patch", help="Patch a decoded/plaintext save. Re-encode afterward before using in Yuzu.")
    p.add_argument("decoded", type=Path)
    p.add_argument("-o", "--output", type=Path, default=Path("pegasus_save_master_data.patched.decoded.bin"))
    p.add_argument("--safe-mew", action="store_true", help="Apply conservative hero Mew patch from the research notes.")
    p.add_argument("--no-dungeon-species", action="store_true", help="With --safe-mew, skip known PLYR dungeon species copies.")
    p.add_argument("--patch-json", type=Path, action="append", help="Apply a declarative JSON patch file. Can be supplied multiple times.")
    p.set_defaults(func=cmd_patch)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CodecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
