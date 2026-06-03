"""
DTE Core Engine — Utilidades para multiempresa.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import inspect, select, update
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
    brand_name: str | None = None
    brand_logo_url: str | None = None
    brand_accent_1: str | None = None
    brand_accent_2: str | None = None
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
            brand_name=empresa.brand_name,
            brand_logo_url=empresa.brand_logo_url,
            brand_accent_1=empresa.brand_accent_1,
            brand_accent_2=empresa.brand_accent_2,
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
            brand_name=settings.razon_social_emisor,
            brand_logo_url=None,
            brand_accent_1=None,
            brand_accent_2=None,
            es_default=True,
        )


def _normalize_text(value: str) -> str:
    return " ".join((value or "").strip().split())


def _empresa_initials(razon_social: str) -> str:
    words = [part for part in _normalize_text(razon_social).split(" ") if part]
    initials = "".join(word[0] for word in words[:2]).upper()
    return initials or "DTE"


def _color_pair(seed: str) -> tuple[str, str]:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()
    first = f"#{digest[:6]}"
    second = f"#{digest[6:12]}"
    return first, second


def build_empresa_branding(empresa: Empresa | None) -> dict[str, object]:
    """Construye branding visual sin requerir campos extra en la base."""
    if empresa is None:
        snapshot = EmpresaSnapshot.from_settings()
        source_id = snapshot.rut_emisor
    else:
        snapshot = EmpresaSnapshot.from_empresa(empresa)
        source_id = empresa.rut_emisor

    display_name = _normalize_text(snapshot.brand_name or snapshot.razon_social_emisor)
    accent_1, accent_2 = _color_pair(source_id)
    accent_1 = snapshot.brand_accent_1 or accent_1
    accent_2 = snapshot.brand_accent_2 or accent_2
    return {
        "display_name": display_name,
        "initials": _empresa_initials(display_name),
        "rut_emisor": snapshot.rut_emisor,
        "rut_envia": snapshot.rut_envia,
        "ambiente": snapshot.sii_ambiente,
        "es_default": snapshot.es_default,
        "subtitle": f"RUT {snapshot.rut_emisor} · {snapshot.giro_emisor}",
        "accent_1": accent_1,
        "accent_2": accent_2,
        "logo_url": snapshot.brand_logo_url,
        "tag": "Empresa base" if snapshot.es_default else "Empresa activa",
    }


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
        "brand_name": settings.razon_social_emisor,
        "brand_logo_url": None,
        "brand_accent_1": None,
        "brand_accent_2": None,
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

    async def _table_has_column(table_name: str, column_name: str) -> bool:
        def _inspect(sync_session):
            bind = sync_session.get_bind()
            try:
                inspector = inspect(bind)
                return column_name in [column["name"] for column in inspector.get_columns(table_name)]
            except Exception:
                return False

        return await session.run_sync(_inspect)

    if await _table_has_column("cafs", "empresa_id"):
        await session.execute(
            update(Caf).where(Caf.empresa_id.is_(None)).values(empresa_id=empresa.id)
        )
    if await _table_has_column("dtes", "empresa_id"):
        await session.execute(
            update(Dte).where(Dte.empresa_id.is_(None)).values(empresa_id=empresa.id)
        )
    if await _table_has_column("sii_log", "empresa_id"):
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
