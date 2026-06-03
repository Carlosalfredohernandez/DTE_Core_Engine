"""
Utilidades de cifrado simetrico para secretos de aplicacion.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.domain.exceptions import CertificateError

ENCRYPTED_PREFIX = "enc:v1:"


def _build_fernet(master_key: str | None) -> Fernet:
    if not master_key or not master_key.strip():
        raise CertificateError(
            "No se configuro CERT_MASTER_KEY para cifrar/descifrar certificados de empresa"
        )

    normalized = master_key.strip().encode("utf-8")
    key_material = hashlib.sha256(normalized).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    return Fernet(fernet_key)


def encrypt_secret(value: str, master_key: str | None) -> str:
    """Cifra un valor y devuelve un token versionado para almacenamiento."""
    if not value:
        return value
    fernet = _build_fernet(master_key)
    token = fernet.encrypt(value.encode("utf-8")).decode("utf-8")
    return f"{ENCRYPTED_PREFIX}{token}"


def decrypt_secret(value: str | None, master_key: str | None) -> str | None:
    """Descifra solo valores versionados. Si no estan cifrados, los retorna tal cual."""
    if value is None:
        return None
    if not value.startswith(ENCRYPTED_PREFIX):
        return value

    token = value[len(ENCRYPTED_PREFIX) :]
    fernet = _build_fernet(master_key)
    try:
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise CertificateError("No fue posible descifrar el secreto de certificado") from exc
