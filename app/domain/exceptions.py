"""
DTE Core Engine — Excepciones personalizadas.

Jerarquía de excepciones que permite captura granular y mapeo a HTTP status codes.
"""

from __future__ import annotations


class DteEngineError(Exception):
    """Excepción base del motor DTE."""

    def __init__(self, message: str, code: str = "DTE_ERROR", details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


# ---------------------------------------------------------------------------
# Errores de autenticación SII
# ---------------------------------------------------------------------------
class SiiAuthError(DteEngineError):
    """Error durante la autenticación con el SII."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="SII_AUTH_ERROR", details=details)


class SiiSeedError(SiiAuthError):
    """Error al obtener la semilla del SII."""

    def __init__(self, message: str = "No se pudo obtener la semilla del SII", details: dict | None = None):
        super().__init__(message, details=details)


class SiiTokenError(SiiAuthError):
    """Error al obtener el token del SII."""

    def __init__(self, message: str = "No se pudo obtener el token del SII", details: dict | None = None):
        super().__init__(message, details=details)


# ---------------------------------------------------------------------------
# Errores de certificado digital
# ---------------------------------------------------------------------------
class CertificateError(DteEngineError):
    """Error relacionado con el certificado digital."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="CERTIFICATE_ERROR", details=details)


class CertificateNotFoundError(CertificateError):
    """Archivo de certificado no encontrado."""

    def __init__(self, path: str):
        super().__init__(
            message=f"Certificado no encontrado: {path}",
            details={"path": path},
        )


class CertificateExpiredError(CertificateError):
    """Certificado digital expirado."""

    def __init__(self, expiry_date: str):
        super().__init__(
            message=f"Certificado expirado el {expiry_date}",
            details={"expiry_date": expiry_date},
        )


class CertificatePasswordError(CertificateError):
    """Contraseña del certificado incorrecta."""

    def __init__(self):
        super().__init__(message="Contraseña del certificado incorrecta")


# ---------------------------------------------------------------------------
# Errores de XML / DTE
# ---------------------------------------------------------------------------
class XmlBuildError(DteEngineError):
    """Error al construir el XML del DTE."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="XML_BUILD_ERROR", details=details)


class XmlSignError(DteEngineError):
    """Error al firmar el XML."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="XML_SIGN_ERROR", details=details)


class XmlValidationError(DteEngineError):
    """Error de validación del XML contra XSD."""

    def __init__(self, message: str, errors: list[str] | None = None):
        super().__init__(
            message,
            code="XML_VALIDATION_ERROR",
            details={"validation_errors": errors or []},
        )


# ---------------------------------------------------------------------------
# Errores de CAF (folios)
# ---------------------------------------------------------------------------
class CafError(DteEngineError):
    """Error relacionado con CAF (Código de Autorización de Folios)."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="CAF_ERROR", details=details)


class CafNotFoundError(CafError):
    """No se encontró CAF para el tipo de DTE solicitado."""

    def __init__(self, tipo_dte: int):
        super().__init__(
            message=f"No hay CAF disponible para tipo DTE {tipo_dte}",
            details={"tipo_dte": tipo_dte},
        )


class CafFoliosAgotadosError(CafError):
    """Los folios del CAF se han agotado."""

    def __init__(self, tipo_dte: int, rango: str):
        super().__init__(
            message=f"Folios agotados para tipo DTE {tipo_dte} (rango: {rango})",
            details={"tipo_dte": tipo_dte, "rango": rango},
        )


# ---------------------------------------------------------------------------
# Errores de envío al SII
# ---------------------------------------------------------------------------
class SiiEnvioError(DteEngineError):
    """Error al enviar DTE al SII."""

    def __init__(self, message: str, status: int | None = None, details: dict | None = None):
        _details = details or {}
        if status is not None:
            _details["sii_status"] = status
        super().__init__(message, code="SII_ENVIO_ERROR", details=_details)


class SiiUploadError(SiiEnvioError):
    """Error en el upload HTTP al SII."""
    pass


class SiiRechazoError(SiiEnvioError):
    """DTE rechazado por el SII."""

    def __init__(self, glosa: str, status: int | None = None):
        super().__init__(
            message=f"DTE rechazado por SII: {glosa}",
            status=status,
            details={"glosa": glosa},
        )


# ---------------------------------------------------------------------------
# Errores de consulta
# ---------------------------------------------------------------------------
class SiiQueryError(DteEngineError):
    """Error al consultar estado en el SII."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message, code="SII_QUERY_ERROR", details=details)


# ---------------------------------------------------------------------------
# Errores de validación de negocio
# ---------------------------------------------------------------------------
class BusinessValidationError(DteEngineError):
    """Error de validación de reglas de negocio."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(
            message,
            code="BUSINESS_VALIDATION_ERROR",
            details={"field": field} if field else {},
        )


class RutInvalidoError(BusinessValidationError):
    """RUT con formato o dígito verificador inválido."""

    def __init__(self, rut: str):
        super().__init__(message=f"RUT inválido: {rut}", field="rut")


class MontoInvalidoError(BusinessValidationError):
    """Monto inválido (negativo, desbordamiento, etc.)."""

    def __init__(self, message: str, field: str = "monto"):
        super().__init__(message=message, field=field)
