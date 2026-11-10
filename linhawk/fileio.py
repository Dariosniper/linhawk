"""File access helpers: compression detected by magic bytes (not by extension),
rotation-aware names (messages-20151013, dracut.log-20151013, secure.1.xz ...)."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import re
from datetime import date
from pathlib import Path
from typing import BinaryIO, Iterator

MAGIC = {
    b"\x1f\x8b": "gzip",
    b"BZh": "bz2",
    b"\xfd7zXZ\x00": "xz",
    b"\x28\xb5\x2f\xfd": "zstd",
}
COMPRESSED_EXT = (".gz", ".bz2", ".xz", ".zst", ".lzma", ".z")


def compression_of(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            head = fh.read(6)
    except OSError:
        return None
    for magic, kind in MAGIC.items():
        if head.startswith(magic):
            return kind
    return None


def open_binary(path: Path) -> BinaryIO:
    kind = compression_of(path)
    if kind == "gzip":
        return gzip.open(path, "rb")
    if kind == "bz2":
        return bz2.open(path, "rb")
    if kind == "xz":
        return lzma.open(path, "rb")
    if kind == "zstd":
        try:
            import zstandard  # optional dependency
        except ImportError as e:
            raise OSError("zstd-compressed file: pip install zstandard") from e
        return zstandard.ZstdDecompressor().stream_reader(open(path, "rb"))
    return open(path, "rb")


def open_text(path: Path) -> Iterator[str]:
    with open_binary(path) as raw:
        fh = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline=None)
        for line in fh:
            yield line.rstrip("\r\n")


def read_head(path: Path, n: int = 65536) -> bytes:
    try:
        with open_binary(path) as fh:
            return fh.read(n)
    except (OSError, EOFError, lzma.LZMAError, ValueError):
        return b""


RE_ROT_SUFFIX = re.compile(
    r"(?:[-_.]\d{8}(?:\d{2,6})?|[-_.]\d{4}-\d{2}-\d{2}|\.\d{1,3}|\.old|\.bak|\.save|~)$", re.I)
RE_ROT_DATE = re.compile(r"(?<!\d)(20\d{2}|19\d{2})-?(\d{2})-?(\d{2})(?:\d{2,6})?(?!\d)")


def strip_compression_ext(name: str) -> str:
    low = name.lower()
    for ext in COMPRESSED_EXT:
        if low.endswith(ext):
            return name[: -len(ext)]
    return name


def rotation_basename(path: Path) -> str:
    """'dracut.log-20151013' -> 'dracut.log', 'messages.2.gz' -> 'messages'."""
    name = strip_compression_ext(path.name)
    prev = None
    while prev != name:
        prev = name
        name = RE_ROT_SUFFIX.sub("", name) or prev
    return name


GENERIC_NAMES = {"history", "term", "error", "access", "main", "current", "eipp", "page", "debug", "server"}


def program_from_name(path: Path) -> str:
    """Program name for application logs: 'dracut.log-20151013' -> 'dracut',
    'apt/history.log.2.gz' -> 'apt/history', 'cups/error_log.1' -> 'cups/error'."""
    base = rotation_basename(path)
    for suf in (".log", "_log", ".txt", ".out", ".err"):
        if base.lower().endswith(suf) and len(base) > len(suf):
            base = base[: -len(suf)]
            break
    base = base or path.name
    if base.lower() in GENERIC_NAMES and path.parent.name:
        base = f"{path.parent.name}/{base}"
    return base


def rotation_date(path: Path) -> date | None:
    """Date stamped by logrotate `dateext` in the file name, if any."""
    m = RE_ROT_DATE.search(strip_compression_ext(path.name))
    if not m:
        return None
    try:
        return date(int(m[1]), int(m[2]), int(m[3]))
    except ValueError:
        return None
