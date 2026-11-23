# Signed by JOE
"""Secret handling: resolve test credentials without persisting them.

Design goals (see README "Secret storage"):
  * Secrets are never written to the JSON configuration file.
  * Resolution order for the test password at run time:
      1. explicit value (e.g. ``--password`` / forwarded secret),
      2. environment variable ``AUTH_TEST_PASSWORD``,
      3. Windows Credential Manager (generic credential), on Windows,
      4. an interactive, masked prompt (getpass) if allowed.
  * The Windows Credential Manager helpers are best-effort and fully guarded so
    the module never crashes on non-Windows platforms or unsupported contexts.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

DEFAULT_CREDENTIAL_TARGET = "auth-browser-lab/test-credential"
ENV_PASSWORD_VAR = "AUTH_TEST_PASSWORD"
ENV_USERNAME_VAR = "AUTH_TEST_USERNAME"

_CRED_TYPE_GENERIC = 1  # CRED_TYPE_GENERIC


def is_windows() -> bool:
    return sys.platform.startswith("win")


def _windll():
    """Return ctypes.windll.advapi32 on Windows, else None (imported lazily)."""
    if not is_windows():
        return None
    try:
        import ctypes

        return ctypes.windll.advapi32
    except Exception:  # noqa: BLE001 - IDE/embedded terminals, etc.
        return None


def _string_to_unicode_blob(secret: str) -> bytes:
    """Encode a secret for Windows Credential Manager (UTF-16LE + NUL)."""
    return (secret + "\x00").encode("utf-16-le")


def _unicode_blob_to_string(blob: bytes) -> str:
    """Decode a UTF-16LE credential blob back to a string."""
    try:
        return blob.decode("utf-16-le").rstrip("\x00")
    except Exception:
        try:
            return blob.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return ""


def read_credential(target: str = DEFAULT_CREDENTIAL_TARGET) -> Optional[str]:
    """Read a generic credential secret from Windows Credential Manager.

    Returns None on any failure or on non-Windows platforms.
    """
    advapi = _windll()
    if advapi is None:
        return None
    try:
        import ctypes
        from ctypes import wintypes  # noqa: F401

        class CREDENTIALW(ctypes.Structure):
            _fields_ = [
                ("Flags", ctypes.c_ulong),
                ("Type", ctypes.c_ulong),
                ("TargetName", ctypes.c_wchar_p),
                ("Comment", ctypes.c_wchar_p),
                ("LastWritten", ctypes.c_ulonglong),
                ("CredentialBlobSize", ctypes.c_ulong),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", ctypes.c_ulong),
                ("AttributeCount", ctypes.c_ulong),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", ctypes.c_wchar_p),
                ("UserName", ctypes.c_wchar_p),
            ]

        cred_ptr = ctypes.POINTER(CREDENTIALW)()
        ok = advapi.CredReadW(
            ctypes.c_wchar_p(target),
            ctypes.c_ulong(_CRED_TYPE_GENERIC),
            ctypes.c_ulong(0),
            ctypes.byref(cred_ptr),
        )
        if not ok or not cred_ptr:
            return None

        cred = cred_ptr.contents
        size = int(cred.CredentialBlobSize)
        if size <= 0 or not cred.CredentialBlob:
            return None
        blob = ctypes.string_at(cred.CredentialBlob, size)
        return _unicode_blob_to_string(blob)
    except Exception:  # noqa: BLE001 - never crash on credential read
        return None


def write_credential(
    secret: str,
    target: str = DEFAULT_CREDENTIAL_TARGET,
    username: str = "test-account",
) -> bool:
    """Write a generic credential secret to Windows Credential Manager.

    Returns True on success; False on failure or unsupported platform.
    """
    advapi = _windll()
    if advapi is None:
        return False
    try:
        import ctypes

        class CREDENTIALW(ctypes.Structure):
            _fields_ = [
                ("Flags", ctypes.c_ulong),
                ("Type", ctypes.c_ulong),
                ("TargetName", ctypes.c_wchar_p),
                ("Comment", ctypes.c_wchar_p),
                ("LastWritten", ctypes.c_ulonglong),
                ("CredentialBlobSize", ctypes.c_ulong),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", ctypes.c_ulong),
                ("AttributeCount", ctypes.c_ulong),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", ctypes.c_wchar_p),
                ("UserName", ctypes.c_wchar_p),
            ]

        blob = _string_to_unicode_blob(secret)
        blob_buf = (ctypes.c_byte * len(blob)).from_buffer_copy(blob)

        cred = CREDENTIALW()
        cred.Type = _CRED_TYPE_GENERIC
        cred.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
        cred.TargetName = target
        cred.UserName = username
        cred.CredentialBlobSize = len(blob)
        cred.CredentialBlob = ctypes.cast(blob_buf, ctypes.POINTER(ctypes.c_byte))

        # Keep the buffer alive for the call duration.
        ok = advapi.CredWriteW(ctypes.byref(cred), ctypes.c_ulong(0))
        return bool(ok)
    except Exception:  # noqa: BLE001
        return False


def delete_credential(target: str = DEFAULT_CREDENTIAL_TARGET) -> bool:
    """Delete a generic credential from Windows Credential Manager."""
    advapi = _windll()
    if advapi is None:
        return False
    try:
        import ctypes

        ok = advapi.CredDeleteW(
            ctypes.c_wchar_p(target),
            ctypes.c_ulong(_CRED_TYPE_GENERIC),
            ctypes.c_ulong(0),
        )
        return bool(ok)
    except Exception:  # noqa: BLE001
        return False


def resolve_password(
    override: Optional[str] = None,
    target: str = DEFAULT_CREDENTIAL_TARGET,
    prompt_ok: bool = True,
    env: Optional[dict] = None,
) -> Optional[str]:
    """Resolve the test password using the documented precedence order.

    Args:
        override: explicit secret (highest precedence) or None.
        target: Windows Credential Manager target name.
        prompt_ok: allow an interactive masked prompt as the last resort.
        env: environment mapping (defaults to os.environ) — injectable for tests.
    """
    env = os.environ if env is None else env

    if override:
        return override

    from_env = env.get(ENV_PASSWORD_VAR)
    if from_env:
        return from_env

    cred = read_credential(target)
    if cred:
        return cred

    if prompt_ok:
        try:
            import getpass

            return getpass.getpass("Test password (input hidden): ")
        except Exception:  # noqa: BLE001
            return None

    return None


def resolve_username(config_username: str = "", env: Optional[dict] = None) -> str:
    """Resolve the test username: explicit config value, else env, else config."""
    env = os.environ if env is None else env
    return env.get(ENV_USERNAME_VAR) or config_username or ""
