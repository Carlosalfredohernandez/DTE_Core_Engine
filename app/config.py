"""
DTE Core Engine — Configuración centralizada.

Utiliza pydantic-settings para cargar variables de entorno con validación de tipos.
Soporta ambientes de certificación y producción del SII.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Ambiente(str, Enum):
    """Ambientes del SII."""

    CERTIFICACION = "certificacion"
    PRODUCCION = "produccion"


# ---------------------------------------------------------------------------
# Mapeo de hosts SII según ambiente
# ---------------------------------------------------------------------------
SII_HOSTS: dict[Ambiente, str] = {
    Ambiente.CERTIFICACION: "maullin.sii.cl",
    Ambiente.PRODUCCION: "palena.sii.cl",
}


class Settings(BaseSettings):
    """Configuración principal de la aplicación."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Ambiente SII ──────────────────────────────────────────────────────
    sii_ambiente: Ambiente = Ambiente.CERTIFICACION

    # ── Base de datos ─────────────────────────────────────────────────────
    database_url: str = "mysql+aiomysql://root:dXTVcVNqAodpcFhmaGyCsfBGfgJWQCoF@turntable.proxy.rlwy.net:51344/railway"

    # ── Datos Globales Emisor (Single-Tenant) ─────────────────────────────
    rut_emisor: str = "76123456-7"
    rut_envia: str = "76123456-7"  # RUT titular del certificado digital que firma
    razon_social_emisor: str = "Empresa SpA"
    giro_emisor: str = "Servicios Informáticos"
    acteco_emisor: int = 620200
    dir_origen: str = "Av. Principal 123"
    cmna_origen: str = "Santiago"
    ciudad_origen: str = "Santiago"

    # ── Resolución SII (Carátula EnvioBOLETA) ────────────────────────────
    sii_fecha_resolucion: str = "2024-04-02"  # Formato AAAA-MM-DD
    sii_numero_resolucion: int = 0

    # ── Certificado digital ───────────────────────────────────────────────
    cert_pfx_path: str | None = "./certs/certificado.pfx"
    cert_pfx_base64: str | None = None
    cert_pfx_password: str = ""

    # ── Seguridad API ─────────────────────────────────────────────────────
    api_key: str = "Vikingo80"
    jwt_secret_key: str = "Vikingo80"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # ── Logging ───────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"

    # ── SII Retry ─────────────────────────────────────────────────────────
    sii_max_retries: int = Field(default=3, ge=1, le=10)
    sii_retry_delay_seconds: float = Field(default=2.0, ge=0.5, le=30.0)

    # ── Token SII ─────────────────────────────────────────────────────────
    sii_token_ttl_minutes: int = Field(default=55, ge=1, le=59)

    # ── Debug / observabilidad ────────────────────────────────────────────
    sii_debug_tracking: bool = False

    # ── Propiedades derivadas ─────────────────────────────────────────────
    @property
    def sii_host(self) -> str:
        """Host del SII según el ambiente configurado."""
        return SII_HOSTS[self.sii_ambiente]

    @property
    def sii_base_url(self) -> str:
        """URL base HTTPS del SII."""
        return f"https://{self.sii_host}"

    @property
    def sii_wsdl_seed(self) -> str:
        return f"{self.sii_base_url}/DTEWS/CrSeed.jws?WSDL"

    @property
    def sii_wsdl_token(self) -> str:
        return f"{self.sii_base_url}/DTEWS/GetTokenFromSeed.jws?WSDL"

    @property
    def sii_wsdl_query_est_up(self) -> str:
        return f"{self.sii_base_url}/DTEWS/QueryEstUp.jws?WSDL"

    @property
    def sii_wsdl_query_est_dte(self) -> str:
        return f"{self.sii_base_url}/DTEWS/QueryEstDte.jws?WSDL"

    @property
    def sii_upload_url(self) -> str:
        return f"{self.sii_base_url}/cgi_dte/UPL/DTEUpload"

    @field_validator("database_url", mode="before")
    @classmethod
    def _fix_postgres_schema(cls, v: Any) -> Any:
        """Asegura que la URL use el driver asyncpg, vital para Railway."""
        if isinstance(v, str):
            if v.startswith("postgresql://"):
                return v.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif v.startswith("postgres://"):
                return v.replace("postgres://", "postgresql+asyncpg://", 1)
        return v

    @field_validator("cert_pfx_password")
    @classmethod
    def _warn_empty_password(cls, v: str) -> str:
        if not v:
            import warnings
            warnings.warn(
                "CERT_PFX_PASSWORD está vacío. Configúrelo en .env para operación real.",
                UserWarning,
                stacklevel=2,
            )
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retorna instancia singleton de Settings."""
    return Settings()
