"""OS-keystore protection for secrets at rest.

On Windows, sensitive blobs (the private identity keys in ``keys.json``) are
wrapped with DPAPI (``CryptProtectData``), tying them to the current user
account so a plain file copy off the disk is useless without that user's logon
credentials. On any other platform — or if DPAPI is unavailable — the functions
degrade to a transparent pass-through so the app still works (the file is then
only as protected as the filesystem permissions make it).

A short magic header marks a wrapped blob so callers can tell protected bytes
from legacy plaintext and migrate transparently. ``unprotect`` accepts either:
unwrapped bytes that carry the header, or any other bytes returned unchanged.
"""
import sys

_MAGIC = b"HELUDPAPI1\n"


def available() -> bool:
    """True when OS-level wrapping is actually in effect (Windows DPAPI)."""
    return sys.platform == "win32"


def is_protected(blob: bytes) -> bool:
    return blob[: len(_MAGIC)] == _MAGIC


# ---------------------------------------------------------------------------
# Windows DPAPI via ctypes (no third-party dependency)
# ---------------------------------------------------------------------------

def _dpapi(data: bytes, encrypt: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _to_blob(b: bytes) -> "_DataBlob":
        buf = ctypes.create_string_buffer(b, len(b))
        return _DataBlob(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    fn = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData

    blob_in = _to_blob(data)
    blob_out = _DataBlob()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1 — never pop a UI prompt (we run headless).
    if not fn(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
        raise OSError("DPAPI operation failed (CryptProtect/UnprotectData)")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def protect(data: bytes) -> bytes:
    """Wrap ``data`` for at-rest storage. Pass-through (with header) off Windows."""
    if not available():
        return data
    return _MAGIC + _dpapi(data, encrypt=True)


def unprotect(blob: bytes) -> bytes:
    """Reverse :func:`protect`. Bytes without the magic header are returned as-is."""
    if not is_protected(blob):
        return blob
    body = blob[len(_MAGIC):]
    return _dpapi(body, encrypt=False)
