# RTDX Yuzu Save Codec

A small command-line codec for **Pokémon Mystery Dungeon: Rescue Team DX** Yuzu save files.

Target save file:

```text
pegasus_save_master_data.bin
```

Known save constants from the reverse-engineering notes:

```text
SAVE_FILE_NAME                 pegasus_save_master_data.bin
MAX_MASTER_SAVE_BUFFER         0x140000
ENCRYPT_TARGET_SIZE            0x13FF80
MAX_FINGER_PRINTF_SAVE_BUFFER  0x80
AES mode                       AES-CBC
AES key/IV source              global-metadata.dat string PEGASUS939564968
```

This tool decrypts/encrypts only the first `0x13FF80` bytes and preserves the final `0x80` bytes exactly. It does **not** recalculate the final fingerprint/signature block.

## Repository contents

```text
src/rtdx_save_codec.py                  Main Python CLI
bin/rtdx-save-codec.sh                  Source launcher; requires Python
bin/rtdx-save-codec.command             Source launcher; requires Python
bin/rtdx-save-codec.bat                 Source launcher; requires Python
.github/workflows/build-binaries.yml    GitHub Actions build for standalone executables
tools/build_local.py                    Local PyInstaller standalone build helper
STANDALONE_BUILDS.md                    Notes for Python-free platform binaries
examples/safe_mew_patch.json            Example declarative patch offsets
requirements.txt                        Runtime dependency
pyproject.toml                          Python package metadata
```

## Safety rules

Close Yuzu before replacing a save. Back up the entire Yuzu save folder before editing. The codec roundtrip should be byte-identical before you trust a modified workflow:

```bash
rtdx-save-codec roundtrip pegasus_save_master_data.bin --rom-dump /path/to/extracted/rom
```

Expected result:

```text
roundtrip_equal: true
```

## Install from source

```bash
python -m pip install -r requirements.txt
python src/rtdx_save_codec.py --help
```

Optional editable install:

```bash
python -m pip install -e .
rtdx-save-codec --help
```

## Key extraction and validation

Automatic key extraction is intentionally RTDX-specific. The tool searches `global-metadata.dat` for 16-byte PEGASUS-style key strings, including the known `PEGASUS939564968` value used by the researched save. It does not claim to recover an arbitrary AES key from any unrelated game or from any random 16-byte string in metadata.

A manual 16-byte key can still be supplied with `--key`. Decode, encode, and roundtrip commands validate the decrypted RTDX JSON block by default, because AES-CBC decrypts with any 16-byte key into some bytes and a wrong-key decrypt->encrypt cycle can still roundtrip. Use `--no-validate-json` only for low-level research.

## Finding `global-metadata.dat`

Pass the extracted/decrypted ROM dump root:

```bash
rtdx-save-codec find-metadata /path/to/RTDX-rom-dump
```

The codec searches recursively for `global-metadata.dat`. If it cannot find it and the terminal is interactive, it asks you to identify the file manually. You can also provide it directly:

```bash
rtdx-save-codec key --metadata /path/to/global-metadata.dat
```

Or bypass metadata discovery by passing the known key:

```bash
rtdx-save-codec key --key PEGASUS939564968
```

## Decode save

```bash
rtdx-save-codec decode \
  /path/to/pegasus_save_master_data.bin \
  --rom-dump /path/to/RTDX-rom-dump \
  -o pegasus_save_master_data.decoded.bin \
  --json-out decoded_json.txt
```

The decoded output is a full-size `0x140000` file where:

```text
0x000000 - 0x13FF7F   decrypted/plaintext payload
0x13FF80 - 0x13FFFF   original fingerprint block, preserved unchanged
```

## Encode save

```bash
rtdx-save-codec encode \
  pegasus_save_master_data.decoded.bin \
  --rom-dump /path/to/RTDX-rom-dump \
  --fingerprint-from /path/to/original/pegasus_save_master_data.bin \
  -o pegasus_save_master_data.bin
```

`--fingerprint-from` is recommended when you are encoding a decoded file that may have been copied or constructed outside the normal decode command. The tool uses the final `0x80` bytes from the original encrypted save.

## Extract JSON block

From decoded save:

```bash
rtdx-save-codec extract-json pegasus_save_master_data.decoded.bin -o decoded_json.txt
```

From encrypted save:

```bash
rtdx-save-codec extract-json pegasus_save_master_data.bin \
  --encrypted \
  --rom-dump /path/to/RTDX-rom-dump \
  -o decoded_json.txt
```

Known JSON region:

```text
JSON length offset  0x100000
JSON body offset    0x100400
JSON encoding       UTF-16LE
```

## Optional patching

The tool includes a conservative `--safe-mew` patch based on the supplied research notes. It patches ground/menu hero records and known `PLYR` dungeon species copies, but intentionally avoids experimental active-dungeon stat/move cache fields.

```bash
rtdx-save-codec patch \
  pegasus_save_master_data.decoded.bin \
  --safe-mew \
  -o pegasus_save_master_data.mew.decoded.bin

rtdx-save-codec encode \
  pegasus_save_master_data.mew.decoded.bin \
  --rom-dump /path/to/RTDX-rom-dump \
  --fingerprint-from /path/to/original/pegasus_save_master_data.bin \
  -o pegasus_save_master_data.bin
```

The bundled safe Mew patch applies:

```text
Species: Mew
Ability slot 1: Synchronize
Ability slot 2: Protean
HP: 50 / 50
Attack: 30
Defense: 30
Sp. Attack: 30
Sp. Defense: 30
Speed: 30
Known PLYR dungeon species copies: Mew
```

Move-slot offsets were not hard-coded because the final notes did not provide stable exact move-slot offsets. Use `--patch-json examples/safe_mew_patch.json` or a custom JSON patch once those offsets are confirmed.

Declarative patch example:

```json
{
  "patches": [
    {"offset": "0x0350", "type": "u16", "value": "0x00C8"},
    {"offset": "0x08DDF0", "type": "u32", "value": "0x000000C8"},
    {"offset": "0x03AF", "type": "u16", "value": "0x0033"}
  ]
}
```

Apply it:

```bash
rtdx-save-codec patch \
  pegasus_save_master_data.decoded.bin \
  --patch-json examples/safe_mew_patch.json \
  -o patched.decoded.bin
```

## Standalone binaries that do not require Python

The GitHub Actions workflow builds true one-file PyInstaller executables. These bundle Python and the required Python dependencies, so end users do **not** need Python installed.

Manual workflow runs produce these downloadable artifacts:

```text
rtdx-save-codec-windows-standalone       contains rtdx-save-codec.exe
rtdx-save-codec-macos-standalone         contains rtdx-save-codec
rtdx-save-codec-linux-standalone         contains rtdx-save-codec
rtdx-save-codec-all-platforms-standalone contains all packaged platform builds
```

## Build local standalone binary

Local standalone builds require Python only on the build machine. The output executable under `dist/` bundles Python for the target platform:

```bash
python -m pip install -r requirements-dev.txt
python tools/build_local.py
```

Build on the same operating system you want to distribute to. Use GitHub Actions for all three platform builds.

## Yuzu save location

In Yuzu:

```text
Right-click game → Open Save Data Location
```

The title ID researched was:

```text
01003D200BAA2000
```

Replace the save only after closing Yuzu and backing up the folder.

## Technical notes

Known encrypted layout:

```text
0x000000 - 0x07FFFF   native game data
0x080000 - 0x0BFFFF   dungeon save data
0x0C0000 - 0x0FFFFF   dungeon rescue / secondary dungeon data
0x100000 - 0x1003FF   JSON info block
0x100400 - 0x13FF7F   JSON body block
0x13FF80 - 0x13FFFF   fingerprint/signature block, preserved
```

Known AES setup:

```text
mode  AES-CBC
key   PEGASUS939564968
iv    PEGASUS939564968
size  16 bytes / AES-128
```

## Limitation

The final `0x80` fingerprint/signature/check block is preserved, not regenerated. This matched the researched workflow and allowed no-edit roundtrips to be byte-identical, but full recalculation remains unresolved.