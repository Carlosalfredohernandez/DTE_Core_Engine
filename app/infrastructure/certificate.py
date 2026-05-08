"""
DTE Core Engine — Gestión segura de certificados digitales.

Carga archivos .pfx (PKCS#12), extrae la clave privada y el certificado X.509.
Provee la clave privada y certificado para firma de semilla y XMLDSIG.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from app.domain.exceptions import (
    CertificateExpiredError,
    CertificateNotFoundError,
    CertificatePasswordError,
)

import structlog

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class CertificateData:
    """Datos extraídos de un certificado PKCS#12."""

    private_key: PrivateKeyTypes
    certificate: Certificate
    friendly_name: str | None
    issuer: str
    subject: str
    serial_number: int
    not_valid_before: datetime.datetime
    not_valid_after: datetime.datetime

    @property
    def is_expired(self) -> bool:
        """Verifica si el certificado está expirado."""
        now = datetime.datetime.now(datetime.timezone.utc)
        return now > self.not_valid_after

    @property
    def days_until_expiry(self) -> int:
        """Días hasta la expiración del certificado."""
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = self.not_valid_after - now
        return delta.days

    @property
    def private_key_pem(self) -> bytes:
        """Clave privada en formato PEM (sin cifrar, para uso interno)."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def certificate_pem(self) -> bytes:
        """Certificado en formato PEM."""
        return self.certificate.public_bytes(serialization.Encoding.PEM)


def load_pfx_from_settings() -> CertificateData:
    """
    Carga un archivo PKCS#12 (.pfx) extrae clave privada + certificado.
    Prioriza leer desde la variable en Base64 (Cloud/Railway), y hace 
    fallback a leer el archivo físico (Desarrollo Local).
    """
    from app.config import get_settings
    settings = get_settings()

    import os
    pfx_bytes: bytes | None = None

    # Búsqueda ultra-flexible para ignorar espacios invisibles en el nombre de la variable
    raw_base64 = None
    for key, value in os.environ.items():
        if "CERT_PFX_BASE" in key:
            raw_base64 = value
            break
            
    raw_base64 = raw_base64 or settings.cert_pfx_base64

    if raw_base64 is not None:
        if not raw_base64.strip():
            raise CertificateError("La variable CERT_PFX_BASE64 existe en Railway pero está VACÍA (0 caracteres validos). Vuelve a copiarla.")
            
        import base64
        try:
            pfx_bytes = base64.b64decode(raw_base64)
        except Exception as e:
            raise CertificateError(f"Error decodificando CERT_PFX_BASE64: {str(e)}")
    elif settings.cert_pfx_path:
        path = Path(settings.cert_pfx_path).resolve()
        if not path.exists():
            # Error ultra detallado para saber exactamente por qué entró aquí
            raise CertificateNotFoundError(
                f"No se detectó la variable CERT_PFX_BASE64 en el sistema operativo. "
                f"El servidor hizo fallback a buscar el archivo físico pero falló: {str(path)}"
            )
        pfx_bytes = path.read_bytes()
    else:
        raise CertificateError("No se configuró CERT_PFX_BASE64 ni CERT_PFX_PATH")

    try:
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            pfx_bytes,
            settings.cert_pfx_password.encode("utf-8") if settings.cert_pfx_password else None,
        )
    except ValueError as e:
        if "password" in str(e).lower() or "mac" in str(e).lower():
            raise CertificatePasswordError() from e
        raise

    if private_key is None:
        raise CertificatePasswordError()

    if certificate is None:
        raise CertificatePasswordError()

    # Extraer metadatos del certificado
    subject = certificate.subject.rfc4514_string()
    issuer = certificate.issuer.rfc4514_string()

    cert_data = CertificateData(
        private_key=private_key,
        certificate=certificate,
        friendly_name=None,
        issuer=issuer,
        subject=subject,
        serial_number=certificate.serial_number,
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
    )

    # Advertir si está próximo a expirar
    if cert_data.is_expired:
        raise CertificateExpiredError(
            cert_data.not_valid_after.isoformat()
        )

    if cert_data.days_until_expiry < 30:
        logger.warning(
            "Certificado próximo a expirar",
            days_remaining=cert_data.days_until_expiry,
            expiry_date=cert_data.not_valid_after.isoformat(),
        )

    logger.info(
        "Certificado cargado exitosamente",
        subject=subject,
        issuer=issuer,
        days_until_expiry=cert_data.days_until_expiry,
    )

    return cert_data
def load_pfx_from_file(pfx_path: str, password: str) -> CertificateData:
    """
    Carga un archivo PFX desde una ruta local con una contraseña dada.
    """
    path = Path(pfx_path).resolve()
    if not path.exists():
        raise CertificateNotFoundError(str(path))
    
    pfx_bytes = path.read_bytes()
    
    try:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            pfx_bytes,
            password.encode("utf-8") if password else None,
        )
    except ValueError as e:
        if "password" in str(e).lower() or "mac" in str(e).lower():
            raise CertificatePasswordError() from e
        raise

    if not private_key or not certificate:
        raise CertificatePasswordError()

    return CertificateData(
        private_key=private_key,
        certificate=certificate,
        friendly_name=None,
        issuer=certificate.issuer.rfc4514_string(),
        subject=certificate.subject.rfc4514_string(),
        serial_number=certificate.serial_number,
        not_valid_before=certificate.not_valid_before_utc,
        not_valid_after=certificate.not_valid_after_utc,
    )
