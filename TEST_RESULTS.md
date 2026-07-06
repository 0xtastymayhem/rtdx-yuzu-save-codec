# Test Results

Tested on the local Linux runner on the uploaded `pegasus_save_master_data.bin` and `global-metadata.dat`.

## Source tests

Result: PASS.

Commands tested:

```bash
python -m pytest -q
python src/rtdx_save_codec.py find-metadata /mnt/data
python src/rtdx_save_codec.py key --rom-dump /mnt/data --no-prompt
python src/rtdx_save_codec.py decode /mnt/data/pegasus_save_master_data.bin --rom-dump /mnt/data --no-prompt -o decoded.bin
python src/rtdx_save_codec.py encode decoded.bin --rom-dump /mnt/data --no-prompt --fingerprint-from /mnt/data/pegasus_save_master_data.bin -o reencoded.bin
python src/rtdx_save_codec.py roundtrip /mnt/data/pegasus_save_master_data.bin --rom-dump /mnt/data --no-prompt -o roundtrip.bin
python src/rtdx_save_codec.py extract-json decoded.bin -o json.txt
```

Observed key extracted from metadata:

```text
PEGASUS939564968
```

Original encrypted save SHA-256:

```text
30e2583c9eaf3c766a8fd279d04bcea283447c4ee93ce4e4451765b1d2a747fb
```

Decoded save SHA-256:

```text
86659d18fe41f3b13f849f1133e5dc625d757838ab99f9d3e1b417d07fd1e7d0
```

Re-encoded save SHA-256:

```text
30e2583c9eaf3c766a8fd279d04bcea283447c4ee93ce4e4451765b1d2a747fb
```

Result: source decode -> encode is byte-identical to the uploaded encrypted save.

Wrong-key validation was tested with `AAAAAAAAAAAAAAAA`. Result: PASS; the codec rejected the save because the decrypted JSON block was invalid.

## Linux standalone binary test

A local Linux one-file PyInstaller executable was built with:

```bash
pyinstaller --onefile --clean --name rtdx-save-codec --collect-all cryptography src/rtdx_save_codec.py
```

Result: PASS.

The built Linux binary passed:

```text
--help
metadata key extraction
decode uploaded save
encode decoded save
roundtrip uploaded save
extract JSON
wrong-key rejection
safe patch command
patch JSON command
encode patched decoded save
roundtrip patched encrypted save
```

Linux binary file type:

```text
ELF 64-bit LSB executable, x86-64
```

Important note: Windows and macOS binaries cannot be executed on this Linux runner. The GitHub Actions workflow builds and smoke-tests those binaries on their native GitHub-hosted runners.

## GitHub Actions smoke test logic

The workflow smoke test was checked locally against the built Linux executable. It now creates a synthetic encrypted save containing a valid RTDX-like UTF-16LE JSON block, then tests:

```text
standalone executable --help
decode with correct key
encode with correct key
roundtrip equality
wrong-key rejection
```

Result: PASS locally for the Linux executable.

## Internal-origin wording scan

Result: PASS. Project source and documentation were scanned for prohibited internal-origin wording. No matches remain.
