#!/usr/bin/env python3
"""
nyaa.py — toy-but-useful archiver:
- Packs files/dirs into a custom .nyaa format
- Compresses with Zstandard
- Optional AES-256-GCM encryption (password-based, via scrypt KDF)
- Commands: a (add), x (extract), t (list)
- Prints a random cat/weeb joke after successful archive creation

Requirements:
    pip install zstandard cryptography

Usage examples:
    python nyaa.py a archive.nyaa folder1 file2 --password
    python nyaa.py t archive.nyaa
    python nyaa.py x archive.nyaa -C ./unpacked --password

File format (v1):
    [0:6)    Magic: b"NYAA\x00\x01"
    [6:22)   Salt (16 bytes) for scrypt (zeros if no encryption)
    [22:34)  Nonce (12 bytes) for AES-GCM (zeros if no encryption)
    [34:42)  uint64 little-endian: length of payload (ciphertext if encrypted, else plaintext) L
    [42:42+L) Payload bytes:
                if encrypted: AES-GCM(cipher(zstd(tar(bytes))))
                else: zstd(tar(bytes))
    [42+L:54+L) GCM tag (16 bytes) if encrypted, else zeros
    [54+L:]  JSON footer (utf-8) with metadata (paths, sizes, timestamps, hashes), terminated by newline
"""
import argparse
import os
import sys
import tarfile
import io
import json
import time
import struct
import hashlib
import random
from dataclasses import dataclass
from typing import List, Tuple
from pathlib import Path

try:
    import zstandard as zstd
except ImportError:
    print("Error: 'zstandard' package not found. Install with: pip install zstandard", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
except ImportError:
    AESGCM = None
    Scrypt = None

MAGIC = b"NYAA\x00\x01"
HEADER_LEN = 42  # up to payload (not including)
TAG_LEN = 16
SALT_LEN = 16
NONCE_LEN = 12

JOKES = [
    "Nyaa~ archive complete. Pet the cat.",
    "Senpai, I compressed it… notice me!",
    "So tight it’s purring.",
    "UwU, those bytes got snuggled.",
    "Chibi-sized files, oni‑chan.",
    "Kawaii compression activated.",
    "I squished it gently… for you.",
    "Ara~ your data is neat now.",
    "I hid the bulk under a ribbon.",
    "Zipped? Nope. Nyaa'd.",
    "Files now fit in a bento box.",
    "Cute outside, dense inside. Like me~",
    "I touched your bits. They're fine.",
    "Ratio? Sugoi desu ne~",
    "Bitrate reduced, charm increased.",
    "So smol. So safe.",
    "Encrypted kisses inside.",
    "Zstd magic: purr‑formance edition.",
    "Just a normal archive… nyaaa~",
    "Your archive sparkles. ✨",
    "Soft on the outside, fierce on the inside.",
    "Comfy compression complete.",
    "I whispered 'compress' and it obeyed.",
    "Fluff removed. Style intact.",
    "No data harmed in this nyaa.",
    "Byte massage done. Relax.",
    "Cozy bits. Warm feelings.",
    "100% purr‑cent efficiency.",
    "Data tucked in with care.",
    "Ratio so tight it blushed.",
    "Files sorted, hugged, and stored.",
    "Too smol to fail.",
    "Now it fits in your heart. 💖",
    "Zipped? That’s so last season.",
    "Nyaa is love. Nyaa is storage.",
    "Soft shell, hard core.",
    "Bit reduction complete. 🍥",
    "I sprinkled moe on it.",
    "Just enough gap moe for tech.",
    "Squeeze me harder, oni‑chan~",
    "Compression-chan approves.",
    "Kyaa~ it's tiny!",
    "Gomen, your data is adorable now.",
    "Laced with fluff and magic.",
    "Tsundere compression successful.",
    "Yes, I packed it tight. Don't judge me.",
    "Zero-day hugs included.",
    "I didn’t delete—just cuddled the excess.",
    "Super flat. Still full of love.",
    "Files snug like a cat in a box.",
    "Now 2x more dere, 2x less size."
]

@dataclass
class FooterEntry:
    path: str
    size: int
    mtime: int
    sha256: str

def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def build_tar_bytes(paths: List[Path]) -> Tuple[bytes, List[FooterEntry]]:
    """Create a tar stream in-memory and collect metadata for footer."""
    buf = io.BytesIO()
    footer_entries: List[FooterEntry] = []
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for p in paths:
            p = p.resolve()
            if not p.exists():
                print(f"Warning: skip missing {p}", file=sys.stderr)
                continue
            if p.is_dir():
                for root, dirs, files in os.walk(p):
                    for name in files:
                        full = Path(root) / name
                        # preserve relative layout from the parent of the first item
                        arcname = str(full.relative_to(p.parent if p.parent.exists() else p))
                        tar.add(full, arcname=arcname, recursive=False)
                        try:
                            st = full.stat()
                            footer_entries.append(FooterEntry(
                                path=arcname.replace("\\", "/"),
                                size=st.st_size,
                                mtime=int(st.st_mtime),
                                sha256=_hash_file(full)
                            ))
                        except Exception as e:
                            print(f"Warning: metadata error for {full}: {e}", file=sys.stderr)
            else:
                arcname = p.name
                tar.add(p, arcname=arcname, recursive=False)
                st = p.stat()
                footer_entries.append(FooterEntry(
                    path=arcname.replace("\\", "/"),
                    size=st.st_size,
                    mtime=int(st.st_mtime),
                    sha256=_hash_file(p)
                ))
    return buf.getvalue(), footer_entries

def zstd_compress(data: bytes, level: int = 10) -> bytes:
    cctx = zstd.ZstdCompressor(level=level, threads=-1)
    return cctx.compress(data)

def zstd_decompress(data: bytes) -> bytes:
    dctx = zstd.ZstdDecompressor()
    return dctx.decompress(data)

def derive_key_scrypt(password: bytes, salt: bytes) -> bytes:
    if Scrypt is None:
        raise RuntimeError("cryptography not installed; encryption not available.")
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1, backend=default_backend())
    return kdf.derive(password)

def aead_encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data, aad)  # returns ciphertext||tag

def aead_decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, aad)

def write_archive(out_path: Path, inputs: List[str], level: int, password: str | None) -> None:
    print(f"• Packing {len(inputs)} path(s)...")
    tar_bytes, entries = build_tar_bytes([Path(p) for p in inputs])
    print(f"  - Tar size: {len(tar_bytes):,} bytes")
    comp = zstd_compress(tar_bytes, level=level)
    print(f"  - Compressed size: {len(comp):,} bytes (level={level})")

    salt = b"\x00" * SALT_LEN
    nonce = b"\x00" * NONCE_LEN
    encrypted = False
    payload = comp
    aad = MAGIC  # bind header magic as AAD

    if password:
        if AESGCM is None:
            raise RuntimeError("Encryption requested but 'cryptography' is not installed.")
        salt = os.urandom(SALT_LEN)
        nonce = os.urandom(NONCE_LEN)
        key = derive_key_scrypt(password.encode('utf-8'), salt)
        payload = aead_encrypt(key, nonce, comp, aad=aad)
        encrypted = True
        print("  - Encryption: AES-256-GCM (scrypt KDF)")

    # Footer JSON
    footer = {
        "version": 1,
        "created_utc": int(time.time()),
        "encrypted": encrypted,
        "zstd_level": level,
        "file_count": len(entries),
        "files": [e.__dict__ for e in entries],
    }
    footer_bytes = (json.dumps(footer, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")

    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(salt)   # 16
        f.write(nonce)  # 12
        f.write(struct.pack("<Q", len(payload)))
        f.write(payload)
        if encrypted:
            tag = payload[-TAG_LEN:]
            f.write(tag)
        else:
            f.write(b"\x00" * TAG_LEN)
        f.write(footer_bytes)

    print(f"✔ Wrote: {out_path} ({out_path.stat().st_size:,} bytes)")
    print(random.choice(JOKES))

def read_header(fp) -> tuple:
    magic = fp.read(6)
    if magic != MAGIC:
        raise ValueError("Not a NYAA archive or unsupported version.")
    salt = fp.read(SALT_LEN)
    nonce = fp.read(NONCE_LEN)
    (length,) = struct.unpack("<Q", fp.read(8))
    payload = fp.read(length)
    tag = fp.read(TAG_LEN)  # may be zeros if not encrypted
    footer_bytes = fp.read()  # rest is footer JSON
    footer = json.loads(footer_bytes.decode("utf-8"))
    return salt, nonce, payload, tag, footer

def extract_archive(archive: Path, outdir: Path, password: str | None) -> None:
    with open(archive, "rb") as f:
        salt, nonce, payload, tag, footer = read_header(f)

    encrypted = footer.get("encrypted", False)
    aad = MAGIC

    data = payload
    if encrypted:
        if AESGCM is None:
            raise RuntimeError("Encrypted archive, but 'cryptography' not installed.")
        if not password:
            raise RuntimeError("Password required to extract encrypted archive.")
        key = derive_key_scrypt(password.encode("utf-8"), salt)
        data = aead_decrypt(key, nonce, payload, aad=aad)

    # data is compressed tar
    tar_bytes = zstd_decompress(data)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as tar:
        def is_within_directory(directory, target):
            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)
            prefix = os.path.commonprefix([abs_directory, abs_target])
            return prefix == abs_directory

        def safe_extract(tarobj, path="."):
            for member in tarobj.getmembers():
                target_path = os.path.join(path, member.name)
                if not is_within_directory(path, target_path):
                    raise Exception("Blocked path traversal in tar member: " + member.name)
            tarobj.extractall(path=path)

        outdir.mkdir(parents=True, exist_ok=True)
        safe_extract(tar, str(outdir))

    print(f"✔ Extracted to: {outdir}")
    # Optional: verify hashes
    mismatches = []
    for entry in footer.get("files", []):
        p = outdir / entry["path"]
        if p.exists() and p.is_file():
            h = _hash_file(p)
            if h != entry["sha256"]:
                mismatches.append(entry["path"])
    if mismatches:
        print("⚠ Hash mismatches:", mismatches)
    else:
        print("✓ Hashes verified.")

def list_archive(archive: Path, password: str | None) -> None:
    with open(archive, "rb") as f:
        salt, nonce, payload, tag, footer = read_header(f)

    encrypted = footer.get("encrypted", False)
    print(f"Archive: {archive}")
    print(f"  Version: {footer.get('version')}  Encrypted: {encrypted}  Files: {footer.get('file_count')}")
    total = 0
    for e in footer.get("files", []):
        total += e["size"]
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(e["mtime"]))
        print(f"  {e['size']:>10}  {ts}  {e['path']}")
    print(f"  Total bytes: {total}")

def main():
    parser = argparse.ArgumentParser(prog="nyaa", description="NYAA archiver (zstd + optional AES-GCM)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("a", help="add/create archive")
    p_add.add_argument("archive", type=Path, help="output .nyaa file")
    p_add.add_argument("inputs", nargs="+", help="files/dirs to archive")
    p_add.add_argument("--level", type=int, default=10, help="zstd level (1..22), default 10")
    p_add.add_argument("--password", action="store_true", help="prompt for password to encrypt")

    p_list = sub.add_parser("t", help="list archive contents (metadata only)")
    p_list.add_argument("archive", type=Path, help="input .nyaa file")

    p_ext = sub.add_parser("x", help="extract archive")
    p_ext.add_argument("archive", type=Path, help="input .nyaa file")
    p_ext.add_argument("-C", "--outdir", type=Path, default=Path("./nyaa_out"), help="output directory")
    p_ext.add_argument("--password", action="store_true", help="prompt for password if encrypted")

    args = parser.parse_args()

    pwd = None
    if getattr(args, "password", False):
        import getpass
        pwd = getpass.getpass("Password: ")

    if args.cmd == "a":
        if not str(args.archive).lower().endswith(".nyaa"):
            print("Note: output file does not end with .nyaa — proceeding anyway.", file=sys.stderr)
        write_archive(args.archive, args.inputs, level=args.level, password=pwd)
    elif args.cmd == "x":
        extract_archive(args.archive, args.outdir, password=pwd)
    elif args.cmd == "t":
        list_archive(args.archive, password=pwd)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()