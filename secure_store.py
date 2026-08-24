"""OS-keystore protection for secrets at rest.

On Windows, sensitive blobs (the private identity keys in ``keys.json``) are
wrapped with DPAPI (``CryptProtectData``), tying them to the current user
account so a plain file copy off the disk is useless without that user's logon
credentials. On any other platform - or if DPAPI is unavailable - the functions
degrade to a transparent pass-through so the app still works (the file is then
only as protected as the filesystem permissions make it).

A short magic header marks a wrapped blob so callers can tell protected bytes
from legacy plaintext and migrate transparently. ``unprotect`` accepts either:
unwrapped bytes that carry the header, or any other bytes returned unchanged.
"""
import logging
import sys

from constants.secure_store_constants import MAGIC

# Configure standard logger
logger = logging.getLogger("helucryptic.secure_store")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _formatter = logging.Formatter("[secure_store] %(message)s")
    _handler.setFormatter(_formatter)
    logger.addHandler(_handler)


def available() -> bool:
    """True when OS-level wrapping is actually in effect (Windows DPAPI)."""
    return sys.platform == "win32"


def is_protected(blob: bytes) -> bool:
    return blob[: len(MAGIC)] == MAGIC


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

    op_name = "CryptProtectData" if encrypt else "CryptUnprotectData"
    logger.debug("Executing DPAPI operation %s", op_name)

    blob_in = _to_blob(data)
    blob_out = _DataBlob()
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1 - never pop a UI prompt (we run headless).
    if not fn(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
        logger.error("DPAPI operation %s failed", op_name)
        raise OSError(f"DPAPI operation failed ({op_name})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def protect(data: bytes) -> bytes:
    """Wrap ``data`` for at-rest storage. Pass-through (with header) off Windows."""
    logger.info("Protecting sensitive data (len=%d)", len(data))
    if not available():
        logger.info("DPAPI not available on this platform; storing data as-is")
        return data
    try:
        protected = MAGIC + _dpapi(data, encrypt=True)
        logger.info("Successfully protected data using Windows DPAPI")
        return protected
    except Exception:
        logger.exception("Failed to protect data")
        raise


def unprotect(blob: bytes) -> bytes:
    """Reverse :func:`protect`. Bytes without the magic header are returned as-is."""
    if not is_protected(blob):
        logger.info("Data is not protected by DPAPI magic header; returning as-is")
        return blob
    logger.info("Unprotecting DPAPI-secured data")
    body = blob[len(MAGIC):]
    try:
        unprotected = _dpapi(body, encrypt=False)
        logger.info("Successfully unprotected DPAPI-secured data")
        return unprotected
    except Exception:
        logger.exception("Failed to unprotect DPAPI data")
        raise

