"""
DTE Core Engine — Utilidades para multiempresa.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.domain.models import Caf, Dte, Empresa, SiiLog


@dataclass(frozen=True)
class EmpresaSnapshot:
    """Vista simple de una empresa para capas que no quieren depender del ORM."""

    id: int | None
    rut_emisor: str
    rut_envia: str
    razon_social_emisor: str
    giro_emisor: str
    acteco_emisor: int
    dir_origen: str
    cmna_origen: str
    ciudad_origen: str
    sii_ambiente: str
    sii_fecha_resolucion: str
    sii_numero_resolucion: int
    api_key: str | None
    cert_pfx_path: str | None
    cert_pfx_base64: str | None
    cert_pfx_password: str | None
    es_default: bool = False

    @classmethod
    def from_empresa(cls, empresa: Empresa) -> "EmpresaSnapshot":
        return cls(
            id=empresa.id,
            rut_emisor=empresa.rut_emisor,
            rut_envia=empresa.rut_envia,
            razon_social_emisor=empresa.razon_social_emisor,
            giro_emisor=empresa.giro_emisor,
            acteco_emisor=empresa.acteco_emisor,
            dir_origen=empresa.dir_origen,
            cmna_origen=empresa.cmna_origen,
            ciudad_origen=empresa.ciudad_origen,
            sii_ambiente=empresa.sii_ambiente,
            sii_fecha_resolucion=empresa.sii_fecha_resolucion,
            sii_numero_resolucion=empresa.sii_numero_resolucion,
            api_key=empresa.api_key,
            cert_pfx_path=empresa.cert_pfx_path,
            cert_pfx_base64=empresa.cert_pfx_base64,
            cert_pfx_password=empresa.cert_pfx_password,
            es_default=empresa.es_default,
        )

    @classmethod
    def from_settings(cls) -> "EmpresaSnapshot":
        settings = get_settings()
        return cls(
            id=None,
            rut_emisor=settings.rut_emisor,
            rut_envia=settings.rut_envia,
            razon_social_emisor=settings.razon_social_emisor,
            giro_emisor=settings.giro_emisor,
            acteco_emisor=settings.acteco_emisor,
            dir_origen=settings.dir_origen,
            cmna_origen=settings.cmna_origen,
            ciudad_origen=settings.ciudad_origen,
            sii_ambiente=settings.sii_ambiente.value,
            sii_fecha_resolucion=settings.sii_fecha_resolucion,
            sii_numero_resolucion=settings.sii_numero_resolucion,
            api_key=settings.api_key,
            cert_pfx_path=settings.cert_pfx_path,
            cert_pfx_base64=settings.cert_pfx_base64,
            cert_pfx_password=settings.cert_pfx_password,
            es_default=True,
        )


def _empresa_defaults_from_settings() -> dict[str, object]:
    settings = get_settings()
    return {
        "rut_emisor": settings.rut_emisor,
        "rut_envia": settings.rut_envia,
        "razon_social_emisor": settings.razon_social_emisor,
        "giro_emisor": settings.giro_emisor,
        "acteco_emisor": settings.acteco_emisor,
        "dir_origen": settings.dir_origen,
        "cmna_origen": settings.cmna_origen,
        "ciudad_origen": settings.ciudad_origen,
        "sii_ambiente": settings.sii_ambiente.value,
        "sii_fecha_resolucion": settings.sii_fecha_resolucion,
        "sii_numero_resolucion": settings.sii_numero_resolucion,
        "api_key": settings.api_key,
        "cert_pfx_path": settings.cert_pfx_path,
        "cert_pfx_base64": settings.cert_pfx_base64,
        "cert_pfx_password": settings.cert_pfx_password,
        "es_default": True,
        "activo": True,
    }


async def ensure_default_empresa(session: AsyncSession) -> Empresa:
    """Crea o recupera la empresa base para compatibilidad con despliegues actuales."""
    stmt = select(Empresa).where(Empresa.es_default == True).limit(1)
    result = await session.execute(stmt)
    empresa = result.scalar_one_or_none()
    if empresa:
        return empresa

    empresa = Empresa(**_empresa_defaults_from_settings())
    session.add(empresa)
    await session.commit()
    await session.refresh(empresa)
    return empresa


async def seed_default_empresa_data(session: AsyncSession) -> Empresa:
    """Asegura tenant base y reasigna registros huérfanos a esa empresa."""
    empresa = await ensure_default_empresa(session)

    await session.execute(
        update(Caf).where(Caf.empresa_id.is_(None)).values(empresa_id=empresa.id)
    )
    await session.execute(
        update(Dte).where(Dte.empresa_id.is_(None)).values(empresa_id=empresa.id)
    )
    await session.execute(
        update(SiiLog).where(SiiLog.empresa_id.is_(None)).values(empresa_id=empresa.id)
    )
    await session.commit()
    return empresa


async def resolve_empresa_by_api_key(session: AsyncSession, api_key: str) -> Empresa | None:
    """Busca la empresa activa que corresponde a una API key."""
    settings = get_settings()
    if not api_key:
        return None

    if api_key == settings.api_key:
        return await ensure_default_empresa(session)

    stmt = select(Empresa).where(Empresa.api_key == api_key, Empresa.activo == True).limit(1)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
