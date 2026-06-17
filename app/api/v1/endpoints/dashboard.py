"""
DTE Core Engine — Panel web administrativo.
"""

from __future__ import annotations

import base64
import secrets
from math import ceil

from cryptography.hazmat.primitives.serialization import pkcs12
from fastapi import APIRouter, Cookie, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_api_key, get_current_empresa, get_db_session
from app.config import get_settings
from app.domain.models import Caf, Dte, Empresa
from app.infrastructure.secrets import encrypt_secret
from app.services.caf_service import CafService
from app.services.empresa_service import build_empresa_branding
from app.services.token_service import token_service

router = APIRouter()
settings = get_settings()
dashboard_cookie_name = "dte_dashboard_access"


class DashboardLoginRequest(BaseModel):
  password: str


class DteHistoryItem(BaseModel):
  id: int
  tipo_dte: int
  folio: int
  estado: str
  monto_total: float
  fecha_emision: str
  rut_receptor: str | None = None
  track_id: str | None = None
  glosa_sii: str | None = None


class DteHistoryResponse(BaseModel):
  items: list[DteHistoryItem]
  page: int
  page_size: int
  total_items: int
  total_pages: int
  has_next: bool
  has_prev: bool


class DashboardBrandingResponse(BaseModel):
  display_name: str
  initials: str
  rut_emisor: str
  rut_envia: str
  ambiente: str
  es_default: bool
  subtitle: str
  accent_1: str
  accent_2: str
  logo_url: str | None = None
  tag: str


class DashboardBrandingUpdateRequest(BaseModel):
  brand_name: str | None = None
  brand_logo_url: str | None = None
  brand_accent_1: str | None = None
  brand_accent_2: str | None = None


class DashboardEmpresaItem(BaseModel):
  id: int
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
  es_default: bool
  activo: bool
  caf_count: int = 0
  has_cert: bool = False
  ready: bool = False
  estado_operativo: str = "Pendiente"


class DashboardEmpresaUpsertRequest(BaseModel):
  rut_emisor: str
  rut_envia: str
  razon_social_emisor: str
  giro_emisor: str
  acteco_emisor: int
  dir_origen: str
  cmna_origen: str
  ciudad_origen: str
  sii_ambiente: str = "certificacion"
  sii_fecha_resolucion: str
  sii_numero_resolucion: int
  api_key: str | None = None
  brand_name: str | None = None
  brand_logo_url: str | None = None
  brand_accent_1: str | None = None
  brand_accent_2: str | None = None
  cert_pfx_path: str | None = None


def _empresa_to_item(empresa: Empresa) -> DashboardEmpresaItem:
  return DashboardEmpresaItem(
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
    es_default=empresa.es_default,
    activo=empresa.activo,
  )


async def _generate_unique_api_key(db: AsyncSession) -> str:
  while True:
    candidate = secrets.token_urlsafe(24)
    existing = await db.execute(select(Empresa.id).where(Empresa.api_key == candidate))
    if existing.scalar_one_or_none() is None:
      return candidate


def _dashboard_enabled() -> bool:
  return bool(settings.dashboard_password)


def _dashboard_authenticated(access_cookie: str | None) -> bool:
  if not _dashboard_enabled():
    return True
  return access_cookie == settings.dashboard_password


def _require_dashboard_access(
  access_cookie: str | None = Cookie(default=None, alias=dashboard_cookie_name),
) -> None:
  if not _dashboard_authenticated(access_cookie):
    raise HTTPException(status_code=401, detail="Debes desbloquear el panel para administrar empresas")


@router.get("/dashboard/session", include_in_schema=False)
async def dashboard_session(access_cookie: str | None = Cookie(default=None, alias=dashboard_cookie_name)) -> dict:
  enabled = _dashboard_enabled()
  return {
    "enabled": enabled,
    "authenticated": _dashboard_authenticated(access_cookie),
  }


@router.post("/dashboard/login", include_in_schema=False)
async def dashboard_login(payload: DashboardLoginRequest, request: Request, response: Response) -> dict:
  if not _dashboard_enabled():
    return {"enabled": False, "authenticated": True}

  if payload.password != settings.dashboard_password:
    raise HTTPException(status_code=401, detail="Contraseña del panel inválida")

  response.set_cookie(
    key=dashboard_cookie_name,
    value=settings.dashboard_password or "",
    httponly=True,
    samesite="lax",
    secure=request.url.scheme == "https",
    max_age=60 * 60 * 8,
  )
  return {"enabled": True, "authenticated": True}


@router.post("/dashboard/logout", include_in_schema=False)
async def dashboard_logout(response: Response) -> dict:
  response.delete_cookie(dashboard_cookie_name)
  return {"authenticated": False}


@router.get("/dashboard/dtes", include_in_schema=False, response_model=DteHistoryResponse)
async def dashboard_dtes_history(
  page: int = Query(default=1, ge=1),
  page_size: int = Query(default=10, ge=1, le=50),
  q: str | None = Query(default=None, max_length=120),
  estado: str | None = Query(default=None, max_length=30),
  tipo_dte: int | None = Query(default=None, ge=1),
  db: AsyncSession = Depends(get_db_session),
  empresa = Depends(get_current_empresa),
  _: str = Depends(get_api_key),
) -> DteHistoryResponse:
  filters = [Dte.empresa_id == empresa.id]
  if estado:
    filters.append(Dte.estado == estado)
  if tipo_dte is not None:
    filters.append(Dte.tipo_dte == tipo_dte)
  if q:
    like_q = f"%{q.strip()}%"
    filters.append(
      or_(
        cast(Dte.id, String).ilike(like_q),
        cast(Dte.folio, String).ilike(like_q),
        cast(Dte.track_id, String).ilike(like_q),
        cast(Dte.rut_receptor, String).ilike(like_q),
        cast(Dte.glosa_sii, String).ilike(like_q),
      )
    )

  count_stmt = select(func.count(Dte.id)).where(*filters)
  total_items = int((await db.execute(count_stmt)).scalar_one() or 0)
  total_pages = max(1, ceil(total_items / page_size))
  offset = (page - 1) * page_size

  stmt = (
    select(Dte)
    .where(*filters)
    .order_by(Dte.created_at.desc().nullslast(), Dte.id.desc())
    .offset(offset)
    .limit(page_size)
  )
  rows = (await db.execute(stmt)).scalars().all()

  items = [
    DteHistoryItem(
      id=row.id,
      tipo_dte=row.tipo_dte,
      folio=row.folio,
      estado=row.estado,
      monto_total=float(row.monto_total),
      fecha_emision=row.fecha_emision.isoformat(),
      rut_receptor=row.rut_receptor,
      track_id=row.track_id,
      glosa_sii=row.glosa_sii,
    )
    for row in rows
  ]

  return DteHistoryResponse(
    items=items,
    page=page,
    page_size=page_size,
    total_items=total_items,
    total_pages=total_pages,
    has_next=page < total_pages,
    has_prev=page > 1,
  )


@router.get("/dashboard/branding", include_in_schema=False, response_model=DashboardBrandingResponse)
async def dashboard_branding(
  empresa = Depends(get_current_empresa),
  _: str = Depends(get_api_key),
) -> DashboardBrandingResponse:
  return DashboardBrandingResponse(**build_empresa_branding(empresa))


@router.put("/dashboard/branding", include_in_schema=False, response_model=DashboardBrandingResponse)
async def dashboard_update_branding(
  payload: DashboardBrandingUpdateRequest,
  db: AsyncSession = Depends(get_db_session),
  empresa = Depends(get_current_empresa),
  _: str = Depends(get_api_key),
) -> DashboardBrandingResponse:
  if payload.brand_name is not None:
    empresa.brand_name = payload.brand_name.strip() or None
  if payload.brand_logo_url is not None:
    empresa.brand_logo_url = payload.brand_logo_url.strip() or None
  if payload.brand_accent_1 is not None:
    empresa.brand_accent_1 = payload.brand_accent_1.strip() or None
  if payload.brand_accent_2 is not None:
    empresa.brand_accent_2 = payload.brand_accent_2.strip() or None

  await db.commit()
  await db.refresh(empresa)
  return DashboardBrandingResponse(**build_empresa_branding(empresa))


@router.get("/dashboard/empresas", include_in_schema=False, response_model=list[DashboardEmpresaItem])
async def dashboard_list_empresas(
  include_inactive: bool = Query(default=False),
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> list[DashboardEmpresaItem]:
  caf_counts = (
    select(Caf.empresa_id.label("empresa_id"), func.count(Caf.id).label("caf_count"))
    .group_by(Caf.empresa_id)
    .subquery()
  )

  stmt = (
    select(Empresa, func.coalesce(caf_counts.c.caf_count, 0).label("caf_count"))
    .outerjoin(caf_counts, caf_counts.c.empresa_id == Empresa.id)
  )
  if not include_inactive:
    stmt = stmt.where(Empresa.activo == True)
  stmt = stmt.order_by(Empresa.es_default.desc(), Empresa.id.asc())
  rows = (await db.execute(stmt)).all()
  items: list[DashboardEmpresaItem] = []
  for empresa, caf_count in rows:
    has_cert = bool((empresa.cert_pfx_base64 or '').strip()) or bool((empresa.cert_pfx_path or '').strip())
    ready = bool(empresa.activo and caf_count and has_cert)
    if not empresa.activo:
      estado_operativo = 'Inactiva'
    elif ready:
      estado_operativo = 'Lista'
    elif not caf_count and not has_cert:
      estado_operativo = 'Falta CAF y certificado'
    elif not caf_count:
      estado_operativo = 'Falta CAF'
    elif not has_cert:
      estado_operativo = 'Falta certificado'
    else:
      estado_operativo = 'Pendiente'

    items.append(
      DashboardEmpresaItem(
        **_empresa_to_item(empresa).model_dump(exclude={"caf_count", "has_cert", "ready", "estado_operativo"}),
        caf_count=int(caf_count or 0),
        has_cert=has_cert,
        ready=ready,
        estado_operativo=estado_operativo,
      )
    )

  return items


@router.post("/dashboard/empresas", include_in_schema=False, response_model=DashboardEmpresaItem)
async def dashboard_create_empresa(
  payload: DashboardEmpresaUpsertRequest,
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> DashboardEmpresaItem:
  api_key = (payload.api_key or "").strip() or await _generate_unique_api_key(db)

  existing = await db.execute(select(Empresa).where(Empresa.api_key == api_key))
  if existing.scalar_one_or_none() is not None:
    raise HTTPException(status_code=409, detail="La API Key ya está en uso por otra empresa")

  empresa = Empresa(
    rut_emisor=payload.rut_emisor.strip(),
    rut_envia=payload.rut_envia.strip(),
    razon_social_emisor=payload.razon_social_emisor.strip(),
    giro_emisor=payload.giro_emisor.strip(),
    acteco_emisor=payload.acteco_emisor,
    dir_origen=payload.dir_origen.strip(),
    cmna_origen=payload.cmna_origen.strip(),
    ciudad_origen=payload.ciudad_origen.strip(),
    sii_ambiente=payload.sii_ambiente.strip() or "certificacion",
    sii_fecha_resolucion=payload.sii_fecha_resolucion.strip(),
    sii_numero_resolucion=payload.sii_numero_resolucion,
    api_key=api_key,
    brand_name=(payload.brand_name or "").strip() or payload.razon_social_emisor.strip(),
    brand_logo_url=(payload.brand_logo_url or "").strip() or None,
    brand_accent_1=(payload.brand_accent_1 or "").strip() or None,
    brand_accent_2=(payload.brand_accent_2 or "").strip() or None,
    cert_pfx_path=(payload.cert_pfx_path or "").strip() or None,
    es_default=False,
    activo=True,
  )
  db.add(empresa)
  await db.commit()
  await db.refresh(empresa)
  return _empresa_to_item(empresa)


@router.put("/dashboard/empresas/{empresa_id}", include_in_schema=False, response_model=DashboardEmpresaItem)
async def dashboard_update_empresa(
  empresa_id: int,
  payload: DashboardEmpresaUpsertRequest,
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> DashboardEmpresaItem:
  empresa = await db.get(Empresa, empresa_id)
  if empresa is None:
    raise HTTPException(status_code=404, detail="Empresa no encontrada")

  api_key = (payload.api_key or "").strip() or empresa.api_key
  if not api_key:
    api_key = await _generate_unique_api_key(db)

  existing = await db.execute(select(Empresa).where(Empresa.api_key == api_key, Empresa.id != empresa_id))
  if existing.scalar_one_or_none() is not None:
    raise HTTPException(status_code=409, detail="La API Key ya está en uso por otra empresa")

  empresa.rut_emisor = payload.rut_emisor.strip()
  empresa.rut_envia = payload.rut_envia.strip()
  empresa.razon_social_emisor = payload.razon_social_emisor.strip()
  empresa.giro_emisor = payload.giro_emisor.strip()
  empresa.acteco_emisor = payload.acteco_emisor
  empresa.dir_origen = payload.dir_origen.strip()
  empresa.cmna_origen = payload.cmna_origen.strip()
  empresa.ciudad_origen = payload.ciudad_origen.strip()
  empresa.sii_ambiente = payload.sii_ambiente.strip() or "certificacion"
  empresa.sii_fecha_resolucion = payload.sii_fecha_resolucion.strip()
  empresa.sii_numero_resolucion = payload.sii_numero_resolucion
  empresa.api_key = api_key
  empresa.brand_name = (payload.brand_name or "").strip() or payload.razon_social_emisor.strip()
  empresa.brand_logo_url = (payload.brand_logo_url or "").strip() or None
  empresa.brand_accent_1 = (payload.brand_accent_1 or "").strip() or None
  empresa.brand_accent_2 = (payload.brand_accent_2 or "").strip() or None
  empresa.cert_pfx_path = (payload.cert_pfx_path or "").strip() or None
  empresa.activo = True

  await db.commit()
  await db.refresh(empresa)
  return _empresa_to_item(empresa)


@router.delete("/dashboard/empresas/{empresa_id}", include_in_schema=False)
async def dashboard_delete_empresa(
  empresa_id: int,
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> dict:
  empresa = await db.get(Empresa, empresa_id)
  if empresa is None:
    raise HTTPException(status_code=404, detail="Empresa no encontrada")
  if empresa.es_default:
    raise HTTPException(status_code=400, detail="No se puede eliminar la empresa por defecto")

  empresa.activo = False
  empresa.api_key = None
  await db.commit()
  return {"deleted": True, "empresa_id": empresa_id}


@router.post("/dashboard/empresas/{empresa_id}/regenerate-key", include_in_schema=False, response_model=DashboardEmpresaItem)
async def dashboard_regenerate_empresa_key(
  empresa_id: int,
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> DashboardEmpresaItem:
  empresa = await db.get(Empresa, empresa_id)
  if empresa is None:
    raise HTTPException(status_code=404, detail="Empresa no encontrada")
  if not empresa.activo:
    raise HTTPException(status_code=400, detail="La empresa está inactiva, reactívala primero")

  empresa.api_key = await _generate_unique_api_key(db)
  await db.commit()
  await db.refresh(empresa)
  return _empresa_to_item(empresa)


@router.post("/dashboard/empresas/{empresa_id}/reactivate", include_in_schema=False, response_model=DashboardEmpresaItem)
async def dashboard_reactivate_empresa(
  empresa_id: int,
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> DashboardEmpresaItem:
  empresa = await db.get(Empresa, empresa_id)
  if empresa is None:
    raise HTTPException(status_code=404, detail="Empresa no encontrada")

  empresa.activo = True
  if not empresa.api_key:
    empresa.api_key = await _generate_unique_api_key(db)

  await db.commit()
  await db.refresh(empresa)
  return _empresa_to_item(empresa)


@router.post("/dashboard/empresas/{empresa_id}/caf", include_in_schema=False)
async def dashboard_upload_caf_empresa(
  empresa_id: int,
  file: UploadFile = File(...),
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> dict:
  empresa = await db.get(Empresa, empresa_id)
  if empresa is None or not empresa.activo:
    raise HTTPException(status_code=404, detail="Empresa no encontrada")
  if not file.filename.lower().endswith(".xml"):
    raise HTTPException(status_code=400, detail="El archivo debe ser .xml")

  content = await file.read()
  try:
    xml_str = content.decode("latin-1")
    caf_info = CafService.parse_caf_xml(xml_str)
  except Exception as exc:
    raise HTTPException(status_code=400, detail=f"CAF inválido: {str(exc)}") from exc

  nuevo_caf = Caf(
    empresa_id=empresa.id,
    tipo_dte=caf_info["tipo_dte"],
    rango_desde=caf_info["rango"]["desde"],
    rango_hasta=caf_info["rango"]["hasta"],
    folio_actual=caf_info["rango"]["desde"],
    ambiente=empresa.sii_ambiente,
    caf_xml=xml_str,
    activo=True,
  )
  db.add(nuevo_caf)
  await db.commit()
  await db.refresh(nuevo_caf)
  return {
    "message": "CAF cargado para la empresa",
    "empresa_id": empresa.id,
    "caf_id": nuevo_caf.id,
    "tipo_dte": nuevo_caf.tipo_dte,
    "rango": f"{nuevo_caf.rango_desde}-{nuevo_caf.rango_hasta}",
  }


@router.post("/dashboard/empresas/{empresa_id}/cert", include_in_schema=False)
async def dashboard_upload_cert_empresa(
  empresa_id: int,
  file: UploadFile = File(...),
  password: str = Form(...),
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> dict:
  empresa = await db.get(Empresa, empresa_id)
  if empresa is None or not empresa.activo:
    raise HTTPException(status_code=404, detail="Empresa no encontrada")
  if not file.filename.lower().endswith(".pfx"):
    raise HTTPException(status_code=400, detail="El archivo debe ser .pfx")
  if not settings.cert_master_key:
    raise HTTPException(status_code=400, detail="Falta CERT_MASTER_KEY para cifrar certificados")

  content = await file.read()
  try:
    private_key, certificate, _ = pkcs12.load_key_and_certificates(
      content,
      password.encode("utf-8") if password else None,
    )
    if not private_key or not certificate:
      raise HTTPException(status_code=400, detail="No se pudo leer el certificado .pfx")
  except ValueError as exc:
    raise HTTPException(status_code=400, detail="Contraseña de certificado inválida") from exc

  pfx_b64 = base64.b64encode(content).decode("utf-8")
  empresa.cert_pfx_base64 = encrypt_secret(pfx_b64, settings.cert_master_key)
  empresa.cert_pfx_password = encrypt_secret(password, settings.cert_master_key)
  empresa.cert_pfx_path = None

  await db.commit()
  await db.refresh(empresa)
  return {
    "message": "Certificado guardado para la empresa",
    "empresa_id": empresa.id,
    "subject": certificate.subject.rfc4514_string(),
    "issuer": certificate.issuer.rfc4514_string(),
    "not_valid_after": certificate.not_valid_after_utc.isoformat(),
  }


@router.post("/dashboard/empresas/{empresa_id}/token", include_in_schema=False)
async def dashboard_refresh_empresa_token(
  empresa_id: int,
  db: AsyncSession = Depends(get_db_session),
  _: None = Depends(_require_dashboard_access),
) -> dict:
  """Renueva y cachea el Token SII para la empresa indicada (solo desde el panel)."""
  empresa = await db.get(Empresa, empresa_id)
  if empresa is None:
    raise HTTPException(status_code=404, detail="Empresa no encontrada")
  try:
    token = await token_service.get_valid_token(force_refresh=True, empresa=empresa)
    preview = (token[:10] + '...') if token else None
    return {"message": "Token renovado exitosamente", "token_preview": preview}
  except Exception as e:
    raise HTTPException(status_code=400, detail=str(e))


@router.get("/dashboard", include_in_schema=False, response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    html = r"""
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Motor DTE | Panel</title>
  <style>
    :root {
      --bg: #0b1020;
      --bg-2: #101932;
      --panel: rgba(16, 25, 50, 0.72);
      --panel-strong: #17213f;
      --line: rgba(148, 163, 184, 0.18);
      --text: #e5eefc;
      --muted: #95a3bd;
      --primary: #65d6ff;
      --primary-2: #8b5cf6;
      --success: #34d399;
      --warning: #fbbf24;
      --danger: #fb7185;
      --shadow: 0 30px 80px rgba(0, 0, 0, 0.35);
      --radius: 22px;
    }

    * { box-sizing: border-box; }
    html, body { margin: 0; min-height: 100%; background:
      radial-gradient(circle at top left, rgba(101, 214, 255, 0.16), transparent 32%),
      radial-gradient(circle at 80% 10%, rgba(139, 92, 246, 0.18), transparent 28%),
      linear-gradient(180deg, #08101d 0%, var(--bg) 100%);
      color: var(--text); font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; }
    body::before {
      content: ""; position: fixed; inset: 0;
      background-image: linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
      background-size: 40px 40px; mask-image: linear-gradient(180deg, rgba(0,0,0,0.5), transparent 85%);
      pointer-events: none;
    }
    .shell { position: relative; max-width: 1520px; margin: 0 auto; padding: 28px; }
    .app-layout { display: grid; grid-template-columns: 290px minmax(0, 1fr); gap: 18px; align-items: start; }
    .sidebar-nav {
      position: sticky; top: 20px; padding: 18px; display: grid; gap: 12px;
      background: rgba(16, 25, 50, 0.86); border: 1px solid var(--line); border-radius: var(--radius);
      box-shadow: var(--shadow); backdrop-filter: blur(18px);
    }
    .brand-badge {
      display: inline-flex; align-items: center; gap: 12px; padding: 12px 14px;
      border-radius: 18px; border: 1px solid rgba(148,163,184,0.18);
      background: linear-gradient(135deg, rgba(101,214,255,0.12), rgba(139,92,246,0.10));
    }
    .brand-mark {
      width: 44px; height: 44px; border-radius: 14px; display: grid; place-items: center;
      color: white; font-size: 16px; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase;
      background: linear-gradient(135deg, var(--brand-accent-1), var(--brand-accent-2));
      box-shadow: 0 12px 30px rgba(0,0,0,0.24);
    }
    .brand-logo {
      width: 44px; height: 44px; border-radius: 14px; object-fit: cover;
      background: rgba(255,255,255,0.12); border: 1px solid rgba(255,255,255,0.12);
    }
    .brand-copy { display: grid; gap: 2px; }
    .brand-copy .name { font-size: 14px; font-weight: 800; }
    .brand-copy .meta { font-size: 12px; color: var(--muted); }
    .sidebar-nav .brand { font-size: 18px; font-weight: 800; letter-spacing: -0.03em; }
    .sidebar-nav .brand span { color: var(--primary); }
    .sidebar-nav .nav-link {
      width: 100%; text-align: left; padding: 12px 14px; border-radius: 14px; border: 1px solid transparent;
      background: rgba(255,255,255,0.04); color: var(--text); cursor: pointer; font-weight: 600;
    }
    .sidebar-nav .nav-link:hover, .sidebar-nav .nav-link.active {
      background: rgba(101,214,255,0.12); border-color: rgba(101,214,255,0.24);
    }
    .sidebar-nav .helper { color: var(--muted); font-size: 12px; line-height: 1.5; }
    .hero {
      display: grid; grid-template-columns: 1.6fr 0.9fr; gap: 18px; align-items: stretch;
      margin-bottom: 18px;
    }
    .hero-card, .card, .metric {
      background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius);
      box-shadow: var(--shadow); backdrop-filter: blur(18px);
    }
    .hero-card { padding: 26px; overflow: hidden; position: relative; }
    .hero-card::after {
      content: ""; position: absolute; inset: auto -100px -140px auto; width: 320px; height: 320px;
      background: radial-gradient(circle, color-mix(in srgb, var(--brand-accent-1) 50%, transparent), transparent 72%); pointer-events: none;
    }
    .eyebrow { display: inline-flex; gap: 10px; align-items: center; padding: 8px 12px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); font-size: 12px; letter-spacing: .06em; text-transform: uppercase; }
    h1 { margin: 14px 0 10px; font-size: clamp(34px, 4vw, 58px); line-height: 1.02; letter-spacing: -0.04em; }
    .lead { margin: 0; color: var(--muted); font-size: 15px; max-width: 72ch; line-height: 1.6; }
    .hero-grid { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 12px; margin-top: 18px; }
    .metric { padding: 16px; background: rgba(255,255,255,0.03); }
    .metric .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .metric .value { font-size: 24px; font-weight: 700; margin-top: 6px; }
    .theme-strip {
      height: 5px; border-radius: 999px; background: linear-gradient(90deg, var(--brand-accent-1), var(--brand-accent-2));
      margin-top: 12px;
    }
    .brand-edit-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
    }
    .sidebar { padding: 22px; display: grid; gap: 12px; align-content: start; }
    .panel-lock {
      position: fixed; inset: 0; display: none; align-items: center; justify-content: center;
      background: rgba(4, 8, 20, 0.72); backdrop-filter: blur(18px); z-index: 50; padding: 20px;
    }
    .panel-lock.visible { display: flex; }
    .panel-lock-card {
      width: min(520px, 100%); background: rgba(16, 25, 50, 0.94); border: 1px solid var(--line);
      border-radius: 28px; box-shadow: var(--shadow); padding: 24px;
    }
    .panel-lock-card h2 { margin: 0 0 8px; }
    .panel-lock-card .sub { margin-bottom: 0; }
    .sidebar .line { height: 1px; background: var(--line); margin: 2px 0; }
    .input, .textarea, .select {
      width: 100%; border: 1px solid rgba(148,163,184,0.18); border-radius: 16px;
      background: rgba(5, 10, 20, 0.55); color: var(--text); padding: 13px 14px; outline: none;
      transition: border-color .2s ease, transform .2s ease, background .2s ease;
    }
    .input:focus, .textarea:focus, .select:focus { border-color: rgba(101,214,255,0.6); background: rgba(7, 14, 28, 0.72); }
    .textarea { min-height: 150px; resize: vertical; }
    .btn {
      border: 0; border-radius: 14px; padding: 12px 16px; font-weight: 700; cursor: pointer;
      color: #07111f; background: linear-gradient(135deg, var(--primary), #b5f4ff); box-shadow: 0 10px 30px rgba(101,214,255,0.22);
    }
    .btn.secondary { background: rgba(255,255,255,0.08); color: var(--text); border: 1px solid var(--line); box-shadow: none; }
    .btn.danger { background: linear-gradient(135deg, #fb7185, #fda4af); }
    .grid { display: grid; grid-template-columns: repeat(12, minmax(0,1fr)); gap: 18px; }
    .card { padding: 18px; }
    .span-4 { grid-column: span 4; }
    .span-6 { grid-column: span 6; }
    .span-8 { grid-column: span 8; }
    .span-12 { grid-column: span 12; }
    .card h2 { margin: 0 0 14px; font-size: 18px; letter-spacing: -0.02em; }
    .card-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
    .card-toggle {
      border: 1px solid var(--line); background: rgba(255,255,255,0.05); color: var(--text);
      border-radius: 999px; padding: 8px 12px; cursor: pointer; font-weight: 700;
    }
    .card-body { margin-top: 14px; }
    .card.collapsed .card-body { display: none; }
    .card.collapsed .card-toggle::after { content: " +"; }
    .card .card-toggle::after { content: " -"; }
    .card.focused {
      border-color: rgba(101, 214, 255, 0.65);
      box-shadow: 0 0 0 1px rgba(101, 214, 255, 0.25), 0 24px 60px rgba(101, 214, 255, 0.10), var(--shadow);
      transform: translateY(-1px);
      transition: box-shadow 0.2s ease, border-color 0.2s ease, transform 0.2s ease;
    }
    .sub { color: var(--muted); font-size: 13px; margin-top: -8px; margin-bottom: 14px; line-height: 1.5; }
    .history-toolbar {
      display: grid; grid-template-columns: 1.4fr 0.8fr 0.8fr 0.8fr; gap: 10px; align-items: center;
    }
    .history-meta {
      display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; color: var(--muted); font-size: 12px;
      margin-top: 10px;
    }
    .history-table {
      width: 100%; border-collapse: collapse; border-spacing: 0; overflow: hidden; border-radius: 16px;
      border: 1px solid rgba(148,163,184,0.18); background: rgba(2, 8, 23, 0.72);
    }
    .history-table thead th {
      text-align: left; padding: 12px 12px; font-size: 12px; color: var(--muted);
      text-transform: uppercase; letter-spacing: .08em; border-bottom: 1px solid rgba(148,163,184,0.12);
    }
    .history-table tbody td {
      padding: 12px; border-bottom: 1px solid rgba(148,163,184,0.08); vertical-align: top; font-size: 13px;
    }
    .history-table tbody tr:hover { background: rgba(101,214,255,0.06); }
    .history-actions { display: flex; gap: 8px; flex-wrap: wrap; }
    .pill {
      display: inline-flex; align-items: center; padding: 6px 10px; border-radius: 999px;
      background: rgba(255,255,255,0.06); color: var(--text); border: 1px solid rgba(148,163,184,0.14);
      font-size: 12px; font-weight: 600;
    }
    .row { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 12px; }
    .row-3 { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 12px; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .result {
      margin-top: 14px; border-radius: 16px; border: 1px solid rgba(148,163,184,0.18);
      background: rgba(2, 8, 23, 0.72); padding: 14px; min-height: 88px; white-space: pre-wrap; word-break: break-word;
      color: #d9e8ff; overflow: auto;
    }
    .result.loading {
      opacity: 0.72;
      position: relative;
    }
    .result.loading::after {
      content: "";
      position: absolute;
      inset: auto 14px 14px auto;
      width: 14px;
      height: 14px;
      border-radius: 999px;
      border: 2px solid rgba(255,255,255,0.18);
      border-top-color: var(--primary);
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .result.ok { border-color: rgba(52, 211, 153, 0.35); }
    .result.err { border-color: rgba(251, 113, 133, 0.35); }
    .toast-zone {
      position: fixed;
      top: 18px;
      right: 18px;
      z-index: 70;
      display: grid;
      gap: 10px;
      width: min(360px, calc(100vw - 36px));
      pointer-events: none;
    }
    .toast {
      pointer-events: auto;
      border-radius: 16px;
      padding: 12px 14px;
      border: 1px solid rgba(148,163,184,0.18);
      background: rgba(9, 16, 32, 0.96);
      box-shadow: var(--shadow);
      backdrop-filter: blur(18px);
      color: var(--text);
      display: grid;
      gap: 4px;
      animation: toast-in 0.2s ease-out;
    }
    .toast.success { border-color: rgba(52, 211, 153, 0.45); }
    .toast.error { border-color: rgba(251, 113, 133, 0.45); }
    .toast.info { border-color: rgba(101, 214, 255, 0.45); }
    .toast-title { font-weight: 800; font-size: 13px; }
    .toast-message { color: var(--muted); font-size: 12px; line-height: 1.5; }
    @keyframes toast-in {
      from { transform: translateY(-8px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    .badge { display: inline-flex; align-items: center; gap: 8px; border-radius: 999px; padding: 7px 10px; background: rgba(255,255,255,0.06); color: var(--muted); font-size: 12px; }
    .status-dot { width: 8px; height: 8px; border-radius: 999px; background: var(--warning); box-shadow: 0 0 0 4px rgba(251,191,36,0.12); }
    .topbar { display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 18px; }
    .topbar .actions { align-items: center; }
    .topbar-empresa { display: grid; gap: 8px; justify-items: end; }
    .muted { color: var(--muted); }
    .mini { font-size: 12px; }
    @media (max-width: 1200px) { .app-layout, .hero, .grid, .hero-grid { grid-template-columns: 1fr; } .sidebar-nav { position: static; } .span-4, .span-6, .span-8, .span-12 { grid-column: span 12; } }
    @media (max-width: 760px) { .shell { padding: 16px; } .row, .row-3, .hero-grid { grid-template-columns: 1fr; } h1 { font-size: 34px; } }
  </style>
</head>
<body>
  <div class="panel-lock" id="panelLock">
    <div class="panel-lock-card">
      <div class="eyebrow">Acceso restringido</div>
      <h2>Desbloquea el panel</h2>
      <p class="sub">Ingresa la contraseña del panel para usar este gestor administrativo.</p>
      <div style="height:12px"></div>
      <input class="input" id="panelPassword" type="password" placeholder="Contraseña del panel" />
      <div class="actions" style="margin-top:12px;">
        <button class="btn" id="btnPanelLogin">Entrar</button>
      </div>
      <div class="result" id="result-panel-lock" style="min-height: 48px; margin-top: 14px;"></div>
    </div>
  </div>

  <div class="toast-zone" id="toastZone"></div>

  <div class="shell">
    <div class="topbar">
      <div class="badge"><span class="status-dot"></span><span>Motor DTE · Panel de operaciones</span></div>
      <div class="topbar-empresa" style="flex:1;">
        <div class="actions" style="justify-content:flex-end; gap:10px;">
          <select class="select" id="empresaActivaTop" style="max-width:340px; min-width:260px;"></select>
          <div class="badge" id="empresaEstadoBadge"><span class="status-dot"></span><span id="empresaEstadoText">Sin empresa seleccionada</span></div>
        </div>
        <div class="badge" id="empresaRestoreBadge"><span class="status-dot"></span><span id="empresaRestoreText">Sin empresa restaurada</span></div>
      </div>
      <div class="actions">
        <button class="btn secondary" id="btnHealth">Health</button>
        <button class="btn secondary" id="btnSaveKey">Guardar API Key</button>
        <button class="btn danger" id="btnClearKey">Limpiar</button>
      </div>
    </div>

    <div class="app-layout">
      <aside class="sidebar-nav">
        <div class="brand-badge">
          <img class="brand-logo" id="sidebarBrandLogo" alt="Logo empresa" style="display:none;" />
          <div class="brand-mark" id="sidebarBrandMark">DTE</div>
          <div class="brand-copy">
            <div class="name" id="sidebarBrandName">Motor DTE</div>
            <div class="meta" id="sidebarBrandMeta">Cargando empresa...</div>
          </div>
        </div>
        <button class="nav-link active" data-jump="section-token">Token SII</button>
        <button class="nav-link" data-jump="section-caf">CAF y folios</button>
        <button class="nav-link" data-jump="section-cert">Certificado</button>
        <button class="nav-link" data-jump="section-boleta">Boleta</button>
        <button class="nav-link" data-jump="section-tracking">Tracking</button>
        <button class="nav-link" data-jump="section-history">Historial</button>
        <button class="nav-link" data-jump="section-empresas">Empresas</button>
        <button class="nav-link" data-jump="section-flow">Flujo guiado</button>
        <button class="nav-link" data-jump="section-console">Consola</button>
        <div class="helper">Atajo: cada bloque se puede colapsar para trabajar más rápido.</div>
      </aside>

      <main>
    <section class="hero">
      <div class="hero-card">
        <div class="eyebrow">Gestor web unificado</div>
        <h1 id="heroTitle">Administra folios, boletas, certificado y tracking desde una interfaz moderna.</h1>
        <p class="lead" id="heroLead">Este panel consume la misma API que Swagger, pero con una experiencia más operativa: guarda tu API Key, ejecuta acciones frecuentes y revisa respuestas en vivo sin cambiar de pantalla.</p>
        <div class="hero-grid">
          <div class="metric"><div class="label">API Base</div><div class="value" id="metricBase">/</div></div>
          <div class="metric"><div class="label">Empresa</div><div class="value" id="metricEmpresa">Motor DTE</div></div>
          <div class="metric"><div class="label">Restaurada</div><div class="value" id="metricEmpresaRestore">Sin selección</div></div>
          <div class="metric"><div class="label">Estado</div><div class="value" id="metricHealth">Listo</div></div>
        </div>
        <div class="theme-strip"></div>
      </div>
      <div class="card sidebar">
        <h2>Acceso</h2>
        <div class="sub">La API Key se guarda solo en tu navegador.</div>
        <input class="input" id="apiKey" placeholder="X-API-Key" />
        <div class="line"></div>
        <div class="mini muted">Si dejas este campo vacío, las operaciones protegidas fallarán con 401.</div>
        <button class="btn" id="btnPing">Probar conexión</button>
      </div>
    </section>

    <section class="card span-12" id="section-branding">
      <div class="card-header"><h2>Branding por empresa</h2><button class="card-toggle" data-collapse="section-branding">Ocultar</button></div>
      <div class="sub card-body">Guarda el nombre visible, logo y colores de la empresa activa para que el panel se vea corporativo.</div>
      <div class="brand-edit-grid card-body">
        <input class="input" id="brandingName" placeholder="Nombre de marca" />
        <input class="input" id="brandingLogoUrl" placeholder="URL del logo" />
        <input class="input" id="brandingAccent1" placeholder="Color primario (#hex)" />
        <input class="input" id="brandingAccent2" placeholder="Color secundario (#hex)" />
      </div>
      <div class="actions card-body" style="margin-top:12px;">
        <button class="btn" id="btnSaveBranding">Guardar branding</button>
        <button class="btn secondary" id="btnResetBranding">Restaurar automático</button>
      </div>
      <div class="result" id="result-branding"></div>
    </section>

    <section class="card span-12" id="section-empresas">
      <div class="card-header"><h2>Administrador de empresas</h2><button class="card-toggle" data-collapse="section-empresas">Ocultar</button></div>
      <div class="sub card-body">Crea, edita y desactiva empresas. Desde aquí también puedes subir CAF y certificado digital por empresa.</div>
      <div class="row-3 card-body">
        <select class="select" id="empresaSelector"></select>
        <button class="btn secondary" id="btnEmpresasLoad">Cargar empresas</button>
        <button class="btn secondary" id="btnEmpresaNuevo">Limpiar formulario</button>
      </div>
      <div class="actions card-body" style="margin-top:8px;">
        <label class="pill"><input type="checkbox" id="empresaIncludeInactive" style="margin-right:8px;">Mostrar inactivas</label>
        <button class="btn secondary" id="btnEmpresaReactivar">Reactivar empresa</button>
        <button class="btn secondary" id="btnEmpresaRegenKey">Regenerar API Key</button>
      </div>
      <div style="height:12px" class="card-body"></div>
      <div class="row-3 card-body">
        <input class="input" id="empresaRutEmisor" placeholder="RUT emisor" />
        <input class="input" id="empresaRutEnvia" placeholder="RUT envía" />
        <input class="input" id="empresaRazon" placeholder="Razón social" />
      </div>
      <div style="height:12px" class="card-body"></div>
      <div class="row-3 card-body">
        <input class="input" id="empresaGiro" placeholder="Giro" />
        <input class="input" id="empresaActeco" placeholder="Acteco" />
        <input class="input" id="empresaApiKey" placeholder="API Key (vacío = autogenerar)" />
      </div>
      <div style="height:12px" class="card-body"></div>
      <div class="row-3 card-body">
        <input class="input" id="empresaDir" placeholder="Dirección" />
        <input class="input" id="empresaComuna" placeholder="Comuna" />
        <input class="input" id="empresaCiudad" placeholder="Ciudad" />
      </div>
      <div style="height:12px" class="card-body"></div>
      <div class="row-3 card-body">
        <select class="select" id="empresaAmbiente">
          <option value="certificacion">certificacion</option>
          <option value="produccion">produccion</option>
        </select>
        <input class="input" id="empresaFechaRes" placeholder="Fecha resolución (YYYY-MM-DD)" />
        <input class="input" id="empresaNumeroRes" placeholder="Número resolución" />
      </div>
      <div class="actions card-body" style="margin-top:12px;">
        <button class="btn" id="btnEmpresaCrear">Crear empresa</button>
        <button class="btn secondary" id="btnEmpresaGuardar">Guardar cambios</button>
        <button class="btn danger" id="btnEmpresaEliminar">Eliminar empresa</button>
      </div>

      <div class="line card-body" style="margin-top:10px;"></div>

      <div class="sub card-body">Carga de CAF para la empresa seleccionada.</div>
      <div class="row card-body">
        <input class="input" type="file" id="empresaCafFile" accept=".xml" />
        <button class="btn secondary" id="btnEmpresaSubirCaf">Subir CAF empresa</button>
      </div>

      <div class="sub card-body" style="margin-top:12px;">Carga de certificado digital para la empresa seleccionada.</div>
      <div class="row-3 card-body">
        <input class="input" type="file" id="empresaPfxFile" accept=".pfx" />
        <input class="input" id="empresaPfxPassword" placeholder="Contraseña PFX" type="password" />
        <button class="btn secondary" id="btnEmpresaSubirCert">Subir certificado empresa</button>
      </div>

      <div class="card-body" style="overflow-x:auto; margin-top:12px;">
        <table class="history-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Razón social</th>
              <th>RUT</th>
              <th>Ambiente</th>
              <th>Estado</th>
              <th>API Key</th>
              <th>Acción</th>
            </tr>
          </thead>
          <tbody id="empresasTableBody">
            <tr><td colspan="7" class="muted">Sin datos de empresas.</td></tr>
          </tbody>
        </table>
      </div>

      <div class="result" id="result-empresas"></div>
    </section>

    <section class="card span-12" id="section-flow">
      <div class="card-header"><h2>Flujo guiado</h2><button class="card-toggle" data-collapse="section-flow">Ocultar</button></div>
      <div class="sub card-body">Sigue este orden para dejar una empresa lista: crear, cargar CAF, subir certificado y probar emisión.</div>
      <div class="row-3 card-body">
        <div class="metric" style="margin:0;">
          <div class="label">Paso 1</div>
          <div class="value" style="font-size:18px;">Crear o seleccionar empresa</div>
          <div class="mini muted">Completa el formulario y guarda la empresa.</div>
        </div>
        <div class="metric" style="margin:0;">
          <div class="label">Paso 2</div>
          <div class="value" style="font-size:18px;">Subir CAF</div>
          <div class="mini muted">Carga el XML de folios autorizados de esa empresa.</div>
        </div>
        <div class="metric" style="margin:0;">
          <div class="label">Paso 3</div>
          <div class="value" style="font-size:18px;">Subir certificado</div>
          <div class="mini muted">Asocia el .pfx y su contraseña a la empresa.</div>
        </div>
      </div>
      <div class="actions card-body" style="margin-top:12px;">
        <button class="btn" id="btnFlowNewEmpresa">Ir a empresa</button>
        <button class="btn secondary" id="btnFlowCaf">Ir a CAF</button>
        <button class="btn secondary" id="btnFlowCert">Ir a certificado</button>
        <button class="btn secondary" id="btnFlowEmitir">Ir a boleta</button>
        <button class="btn secondary" id="btnFlowProbarEmpresa">Probar empresa</button>
      </div>
      <div class="row-3 card-body" style="margin-top:8px;">
        <div class="metric" style="margin:0;">
          <div class="label">CAF</div>
          <div class="value" style="font-size:18px;" id="flowCafStatus">Pendiente</div>
          <div class="mini muted" id="flowCafHint">Selecciona una empresa para ver el estado.</div>
        </div>
        <div class="metric" style="margin:0;">
          <div class="label">Certificado</div>
          <div class="value" style="font-size:18px;" id="flowCertStatus">Pendiente</div>
          <div class="mini muted" id="flowCertHint">Selecciona una empresa para ver el estado.</div>
        </div>
        <div class="metric" style="margin:0;">
          <div class="label">Listo para emitir</div>
          <div class="value" style="font-size:18px;" id="flowReadyStatus">No</div>
          <div class="mini muted" id="flowReadyHint">Selecciona una empresa y valida sus componentes.</div>
        </div>
      </div>
      <div class="result" id="result-flow">Selecciona un paso para moverte más rápido dentro del panel.</div>
    </section>

    <div class="grid">
      <section class="card span-4" id="section-token">
        <div class="card-header"><h2>Token SII</h2><button class="card-toggle" data-collapse="section-token">Ocultar</button></div>
        <div class="sub card-body">Estado del token, renovación manual y validación de certificado.</div>
        <div class="actions card-body">
          <button class="btn secondary" data-op="token-status">Ver estado</button>
          <button class="btn" data-op="token-refresh">Renovar token</button>
        </div>
        <div style="height:12px" class="card-body"></div>
        <div class="row card-body">
          <input class="input" id="certPath" placeholder="Ruta .pfx para validar" />
          <input class="input" id="certPassword" placeholder="Contraseña" />
        </div>
        <div class="actions card-body" style="margin-top:12px;">
          <button class="btn secondary" data-op="token-validate">Validar certificado</button>
        </div>
        <div class="result" id="result-token"></div>
      </section>

      <section class="card span-4" id="section-caf">
        <div class="card-header"><h2>CAF y folios</h2><button class="card-toggle" data-collapse="section-caf">Ocultar</button></div>
        <div class="sub card-body">Carga CAF XML y consulta el stock disponible por tipo de DTE.</div>
        <input class="input card-body" type="file" id="cafFile" accept=".xml" />
        <div style="height:12px" class="card-body"></div>
        <div class="row card-body">
          <select class="select" id="cafTipo">
            <option value="39">39 - Boleta afecta</option>
            <option value="41">41 - Boleta exenta</option>
          </select>
          <button class="btn secondary" data-op="caf-status">Ver stock</button>
        </div>
        <div class="actions card-body" style="margin-top:12px;">
          <button class="btn" data-op="caf-upload">Subir CAF</button>
        </div>
        <div class="result" id="result-caf"></div>
      </section>

      <section class="card span-4" id="section-cert">
        <div class="card-header"><h2>Certificado</h2><button class="card-toggle" data-collapse="section-cert">Ocultar</button></div>
        <div class="sub card-body">Recomendado en multiempresa: subir el .pfx a la empresa activa sin copiar/pegar. Base64 queda como opción legacy.</div>
        <div class="card-body" style="margin-top:0;">
          <span class="pill" id="certModeBadge">Modo detectado: cargando...</span>
        </div>
        <input class="input card-body" type="file" id="pfxFile" accept=".pfx" />
        <div style="height:12px" class="card-body"></div>
        <input class="input card-body" id="pfxPassword" placeholder="Contraseña del .pfx" />
        <div class="actions card-body" style="margin-top:12px;">
          <button class="btn" data-op="pfx-upload-empresa">Guardar en empresa activa</button>
          <button class="btn secondary" id="btnPfxLegacy" data-op="pfx-upload">Generar Base64 (legacy)</button>
        </div>
        <div class="result" id="result-pfx"></div>
      </section>

      <section class="card span-6" id="section-boleta">
        <div class="card-header"><h2>Boleta</h2><button class="card-toggle" data-collapse="section-boleta">Ocultar</button></div>
        <div class="sub card-body">Genera, consulta, descarga XML y envía la boleta al SII.</div>
        <div class="row-3 card-body">
          <select class="select" id="boletaTipo">
            <option value="39">39 - Boleta afecta</option>
            <option value="41">41 - Boleta exenta</option>
          </select>
          <span id="boletaFolioInfo" class="pill" style="margin-left:12px;">Folio disponible: -</span>
          <input class="input" id="boletaFecha" type="date" />
          <input class="input" id="boletaIdEnviar" placeholder="ID DTE para enviar" />
        </div>
        <div style="height:12px" class="card-body"></div>
        <div class="row card-body">
          <input class="input" id="receptorRut" placeholder="RUT receptor" />
          <input class="input" id="receptorRazon" placeholder="Razón social receptor" />
        </div>
        <div style="height:12px" class="card-body"></div>
        <textarea class="textarea card-body" id="detallesJson">[
  {"nombre":"Servicio de ejemplo","cantidad":1,"precio":1000,"monto_item":1000}
]</textarea>
        <div class="actions card-body" style="margin-top:12px;">
          <button class="btn" data-op="boleta-generar">Generar boleta</button>
          <button class="btn secondary" data-op="boleta-enviar">Enviar boleta</button>
        </div>
        <div style="height:12px" class="card-body"></div>
        <div class="row-3 card-body">
          <input class="input" id="boletaId" placeholder="ID DTE" />
          <input class="input" id="boletaComparar" placeholder="Comparar con ID" />
          <button class="btn secondary" data-op="boleta-obtener">Obtener boleta</button>
        </div>
        <div class="actions card-body" style="margin-top:12px;">
          <button class="btn secondary" data-op="boleta-xml">Ver XML</button>
          <button class="btn secondary" data-op="boleta-xml-raw">Ver XML crudo</button>
          <button class="btn secondary" data-op="boleta-log">Ver log</button>
          <button class="btn secondary" data-op="boleta-firma">Diagnóstico firma</button>
        </div>
        <div class="result" id="result-boleta"></div>
      </section>

      <section class="card span-6" id="section-tracking">
        <div class="card-header"><h2>Tracking</h2><button class="card-toggle" data-collapse="section-tracking">Ocultar</button></div>
        <div class="sub card-body">Consulta el estado del envío por TrackID y refresca los estados SII.</div>
        <div class="row card-body">
          <input class="input" id="trackingDteId" placeholder="ID DTE" />
          <button class="btn" data-op="tracking-estado">Consultar estado</button>
        </div>
        <div class="result" id="result-tracking"></div>
      </section>

      <section class="card span-12" id="section-history">
        <div class="card-header"><h2>Historial de DTEs</h2><button class="card-toggle" data-collapse="section-history">Ocultar</button></div>
        <div class="sub card-body">Busca por folio, TrackID, RUT receptor o texto libre y navega por páginas sin salir del panel.</div>
        <div class="history-toolbar card-body">
          <input class="input" id="historyQuery" placeholder="Buscar por folio, TrackID, RUT, glosa o estado" />
          <select class="select" id="historyEstado">
            <option value="">Todos los estados</option>
            <option value="GENERADO">GENERADO</option>
            <option value="FIRMADO">FIRMADO</option>
            <option value="ENVIADO">ENVIADO</option>
            <option value="ACEPTADO">ACEPTADO</option>
            <option value="RECHAZADO">RECHAZADO</option>
            <option value="REPARO">REPARO</option>
            <option value="ERROR_ENVIO">ERROR_ENVIO</option>
            <option value="ERROR_FIRMA">ERROR_FIRMA</option>
          </select>
          <select class="select" id="historyTipo">
            <option value="">Todos los tipos</option>
            <option value="39">39 - Boleta afecta</option>
            <option value="41">41 - Boleta exenta</option>
          </select>
          <select class="select" id="historyPageSize">
            <option value="5">5 por página</option>
            <option value="10" selected>10 por página</option>
            <option value="20">20 por página</option>
            <option value="50">50 por página</option>
          </select>
        </div>
        <div class="actions card-body" style="margin-top:0;">
          <button class="btn" id="btnHistorySearch">Buscar</button>
          <button class="btn secondary" id="btnHistoryPrev">Anterior</button>
          <button class="btn secondary" id="btnHistoryNext">Siguiente</button>
          <button class="btn secondary" id="btnHistoryRefresh">Refrescar</button>
        </div>
        <div class="history-meta card-body" id="historyMeta">
          <span>Sin datos todavía.</span>
          <span>Página 0 / 0</span>
        </div>
        <div class="result card-body" id="result-history" style="display:none;"></div>
        <div class="card-body" style="overflow-x:auto;">
          <table class="history-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Tipo</th>
                <th>Folio</th>
                <th>Estado</th>
                <th>Total</th>
                <th>Fecha</th>
                <th>Receptor</th>
                <th>TrackID</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody id="historyTableBody">
              <tr><td colspan="9" class="muted">Aún no has cargado resultados.</td></tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card span-12" id="section-console">
        <div class="card-header"><h2>Consola</h2><button class="card-toggle" data-collapse="section-console">Ocultar</button></div>
        <div class="sub card-body">Revisa aquí la respuesta de cada operación. Soporta JSON y texto plano.</div>
        <div class="result" id="result-console">Listo para operar.</div>
      </section>
    </div>
      </main>
    </div>
  </div>

  <script>
    const state = {
      apiKey: localStorage.getItem('dte_api_key') || '',
      baseUrl: window.location.origin,
      branding: null,
    };

    const persistedEmpresaId = Number(localStorage.getItem('dte_empresa_id') || 0);

    const empresasState = {
      items: [],
      selectedId: null,
      includeInactive: false,
    };

    let restoredToastShown = false;

    const $ = (id) => document.getElementById(id);

    function syncUi() {
      $('apiKey').value = state.apiKey;
      $('metricBase').textContent = state.baseUrl;
    }

    function applyBranding(branding) {
      state.branding = branding;
      const root = document.documentElement;
      root.style.setProperty('--brand-accent-1', branding.accent_1);
      root.style.setProperty('--brand-accent-2', branding.accent_2);
      const logo = $('sidebarBrandLogo');
      if (branding.logo_url) {
        logo.src = branding.logo_url;
        logo.style.display = 'block';
        $('sidebarBrandMark').style.display = 'none';
      } else {
        logo.removeAttribute('src');
        logo.style.display = 'none';
        $('sidebarBrandMark').style.display = 'grid';
        $('sidebarBrandMark').textContent = branding.initials;
      }
      $('sidebarBrandName').textContent = branding.display_name;
      $('sidebarBrandMeta').textContent = `${branding.tag} · ${branding.subtitle}`;
      $('heroTitle').textContent = `Gestiona ${branding.display_name} desde una interfaz moderna.`;
      $('heroLead').textContent = `Operaciones de ${branding.tag.toLowerCase()} con identidad visual de ${branding.display_name}. Aquí puedes cargar CAF, generar DTEs, revisar tracking y trabajar con la misma API que Swagger.`;
      $('metricEmpresa').textContent = branding.initials;
      document.title = `${branding.display_name} | Motor DTE`;
      $('brandingName').value = branding.display_name || '';
      $('brandingLogoUrl').value = branding.logo_url || '';
      $('brandingAccent1').value = branding.accent_1 || '';
      $('brandingAccent2').value = branding.accent_2 || '';
    }

    function setConsole(message, ok = true) {
      const el = $('result-console');
      el.className = ok ? 'result ok' : 'result err';
      el.textContent = typeof message === 'string' ? message : JSON.stringify(message, null, 2);
    }

    function setResult(target, payload, ok = true) {
      const el = $(target);
      el.className = ok ? 'result ok' : 'result err';
      el.textContent = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
    }

    function setResultLoading(target, message = 'Procesando...') {
      const el = $(target);
      if (!el) return;
      el.className = 'result loading';
      el.textContent = message;
    }

    function showToast(title, message, type = 'info', timeout = 4200) {
      const zone = $('toastZone');
      if (!zone) return;
      const toast = document.createElement('div');
      toast.className = `toast ${type}`;
      toast.innerHTML = `<div class="toast-title">${title}</div><div class="toast-message">${message}</div>`;
      zone.appendChild(toast);
      window.setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(-8px)';
        toast.style.transition = 'all 0.2s ease';
        window.setTimeout(() => toast.remove(), 220);
      }, timeout);
    }

    function setBusy(isBusy) {
      document.querySelectorAll('button').forEach((button) => {
        if (button.id === 'btnPanelLogin') return;
        if (isBusy) {
          button.dataset.prevDisabled = button.disabled ? '1' : '0';
          button.disabled = true;
        } else if (button.dataset.prevDisabled === '0') {
          button.disabled = false;
        }
      });
    }

    function saveKey() {
      state.apiKey = $('apiKey').value.trim();
      localStorage.setItem('dte_api_key', state.apiKey);
      syncUi();
      setConsole('API Key guardada localmente.');
    }

    function persistEmpresaSelection(empresa) {
      if (!empresa) return;
      empresasState.selectedId = empresa.id;
      localStorage.setItem('dte_empresa_id', String(empresa.id));
      if (empresa.api_key) {
        state.apiKey = empresa.api_key;
        localStorage.setItem('dte_api_key', state.apiKey);
        syncUi();
      }
    }

    function renderEmpresaEstado(empresa) {
      const badge = $('empresaEstadoBadge');
      const text = $('empresaEstadoText');
      if (!badge || !text) return;

      if (!empresa) {
        badge.className = 'badge';
        text.textContent = 'Sin empresa seleccionada';
        return;
      }

      const estado = empresa.estado_operativo || 'Pendiente';
      const ready = !!empresa.ready;
      badge.className = ready ? 'badge' : 'badge';
      const parts = [empresa.razon_social_emisor, estado];
      if (empresa.caf_count !== undefined) parts.push(`CAF: ${empresa.caf_count}`);
      if (empresa.has_cert !== undefined) parts.push(empresa.has_cert ? 'Cert: OK' : 'Cert: Falta');
      text.textContent = parts.join(' · ');
      const dot = badge.querySelector('.status-dot');
      if (dot) {
        dot.style.background = ready ? 'var(--success)' : (empresa.activo ? 'var(--warning)' : 'var(--danger)');
        dot.style.boxShadow = ready ? '0 0 0 4px rgba(52,211,153,0.12)' : (empresa.activo ? '0 0 0 4px rgba(251,191,36,0.12)' : '0 0 0 4px rgba(251,113,133,0.12)');
      }
    }

    function renderEmpresaRestaurada(empresa) {
      const badge = $('empresaRestoreBadge');
      const text = $('empresaRestoreText');
      const metric = $('metricEmpresaRestore');
      if (!badge || !text) return;

      if (!empresa) {
        badge.className = 'badge';
        text.textContent = 'Sin empresa restaurada';
        if (metric) metric.textContent = 'Sin selección';
        return;
      }

      const restored = empresa.id === persistedEmpresaId;
      badge.className = 'badge';
      text.textContent = restored ? `Restaurada: ${empresa.razon_social_emisor}` : `Activa: ${empresa.razon_social_emisor}`;
      if (metric) {
        metric.textContent = restored ? `Restaurada` : 'Activa';
      }
      const dot = badge.querySelector('.status-dot');
      if (dot) {
        dot.style.background = restored ? 'var(--success)' : 'var(--primary)';
        dot.style.boxShadow = restored ? '0 0 0 4px rgba(52,211,153,0.12)' : '0 0 0 4px rgba(101,214,255,0.12)';
      }
    }

    function getEmpresaActiva() {
      if (!empresasState.items.length) return null;
      const bySelected = empresasState.items.find((item) => item.id === empresasState.selectedId);
      if (bySelected) return bySelected;
      const byPersisted = empresasState.items.find((item) => item.id === persistedEmpresaId);
      if (byPersisted) return byPersisted;
      const byApiKey = empresasState.items.find((item) => item.api_key && item.api_key === state.apiKey);
      if (byApiKey) return byApiKey;
      return empresasState.items.find((item) => item.activo) || empresasState.items[0] || null;
    }

    function renderFlowChecklist() {
      const empresa = getEmpresaActiva();
      const cafStatus = $('flowCafStatus');
      const cafHint = $('flowCafHint');
      const certStatus = $('flowCertStatus');
      const certHint = $('flowCertHint');
      const readyStatus = $('flowReadyStatus');
      const readyHint = $('flowReadyHint');

      if (!empresa) {
        if (cafStatus) cafStatus.textContent = 'Pendiente';
        if (cafHint) cafHint.textContent = 'Selecciona una empresa para ver el estado.';
        if (certStatus) certStatus.textContent = 'Pendiente';
        if (certHint) certHint.textContent = 'Selecciona una empresa para ver el estado.';
        if (readyStatus) readyStatus.textContent = 'No';
        if (readyHint) readyHint.textContent = 'No hay empresa activa seleccionada.';
        return;
      }

      const cafOk = Number(empresa.caf_count || 0) > 0;
      const certOk = !!empresa.has_cert;
      const ready = !!empresa.ready;

      if (cafStatus) cafStatus.textContent = cafOk ? 'OK' : 'Falta';
      if (cafHint) cafHint.textContent = cafOk ? `${empresa.caf_count} CAF cargado(s)` : 'Debe cargar al menos un CAF.';
      if (certStatus) certStatus.textContent = certOk ? 'OK' : 'Falta';
      if (certHint) certHint.textContent = certOk ? 'Certificado asociado a la empresa.' : 'Debe subir el certificado digital.';
      if (readyStatus) readyStatus.textContent = ready ? 'Sí' : 'No';
      if (readyHint) readyHint.textContent = ready ? 'Esta empresa ya puede emitir.' : 'Completa CAF y certificado para emitir.';
    }

    function renderTopEmpresaSelector() {
      const selector = $('empresaActivaTop');
      if (!selector) return;
      const options = ['<option value="">Selecciona empresa activa</option>'];
      empresasState.items.forEach((empresa) => {
        const mark = empresa.activo ? '' : ' [inactiva]';
        const ready = empresa.ready ? ' · lista' : ' · pendiente';
        options.push(`<option value="${empresa.id}">${empresa.razon_social_emisor}${mark}${ready}</option>`);
      });
      selector.innerHTML = options.join('');
      const current = empresasState.items.find((item) => item.id === empresasState.selectedId)
        || empresasState.items.find((item) => item.id === persistedEmpresaId)
        || empresasState.items.find((item) => item.api_key && item.api_key === state.apiKey);
      if (current) {
        selector.value = String(current.id);
        renderEmpresaEstado(current);
        renderEmpresaRestaurada(current);
        // mostrar badge de ambiente
        let badge = document.getElementById('empresaAmbienteBadge');
        if (!badge) {
          badge = document.createElement('span');
          badge.id = 'empresaAmbienteBadge';
          badge.style.marginLeft = '12px';
          badge.style.padding = '6px 10px';
          badge.style.borderRadius = '12px';
          badge.style.fontSize = '12px';
          badge.style.background = 'rgba(0,0,0,0.16)';
          badge.style.color = 'var(--primary)';
          selector.parentElement && selector.parentElement.appendChild(badge);
        }
        badge.textContent = `Ambiente: ${current.sii_ambiente || 'certificacion'}`;
      } else if (empresasState.items.length) {
        renderEmpresaEstado(empresasState.items[0]);
        renderEmpresaRestaurada(empresasState.items[0]);
      }
    }

    function updateLegacyCertVisibility() {
      const legacyBtn = $('btnPfxLegacy');
      const modeBadge = $('certModeBadge');
      if (!legacyBtn) return;
      const multiempresaDetected = Array.isArray(empresasState.items) && empresasState.items.length > 0;
      legacyBtn.style.display = multiempresaDetected ? 'none' : 'inline-flex';
      if (modeBadge) {
        modeBadge.textContent = multiempresaDetected
          ? 'Modo multiempresa activo: certificado por empresa'
          : 'Modo legacy: Base64 global habilitado';
      }
    }

    async function setEmpresaActiva(empresa, persist = true) {
      if (!empresa) return;
      empresasState.selectedId = empresa.id;
      fillEmpresaForm(empresa);
      renderEmpresaEstado(empresa);
      if (persist) {
        persistEmpresaSelection(empresa);
      } else if (empresa.api_key) {
        state.apiKey = empresa.api_key;
        syncUi();
      }
      renderEmpresaRestaurada(empresa);
      await loadBranding().catch(() => {});
      await loadHistory(1).catch(() => {});
      await loadNextFolio().catch(() => {});
      renderFlowChecklist();
      showToast('Empresa activa', `${empresa.razon_social_emisor} quedó como empresa activa.`, 'success');
      setConsole(`Empresa activa: ${empresa.razon_social_emisor}`);
    }

    function jumpToSection(sectionId, message = '') {
      const section = document.getElementById(sectionId);
      if (section) {
        section.scrollIntoView({ behavior: 'smooth', block: 'start' });
        section.classList.remove('collapsed');
      }
      if (message) {
        setResult('result-flow', message, true);
        showToast('Flujo guiado', message, 'info');
      }
    }

    function focusSection(sectionId) {
      const section = document.getElementById(sectionId);
      if (!section) return;
      section.classList.remove('collapsed');
      section.classList.add('focused');
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });
      window.setTimeout(() => section.classList.remove('focused'), 1800);
    }

    function empresaPayloadFromForm() {
      return {
        rut_emisor: $('empresaRutEmisor').value.trim(),
        rut_envia: $('empresaRutEnvia').value.trim(),
        razon_social_emisor: $('empresaRazon').value.trim(),
        giro_emisor: $('empresaGiro').value.trim(),
        acteco_emisor: Number($('empresaActeco').value || 0),
        dir_origen: $('empresaDir').value.trim(),
        cmna_origen: $('empresaComuna').value.trim(),
        ciudad_origen: $('empresaCiudad').value.trim(),
        sii_ambiente: $('empresaAmbiente').value,
        sii_fecha_resolucion: $('empresaFechaRes').value.trim(),
        sii_numero_resolucion: Number($('empresaNumeroRes').value || 0),
        api_key: $('empresaApiKey').value.trim(),
      };
    }

    function clearEmpresaForm() {
      empresasState.selectedId = null;
      $('empresaSelector').value = '';
      const top = $('empresaActivaTop');
      if (top) top.value = '';
      $('empresaRutEmisor').value = '';
      $('empresaRutEnvia').value = '';
      $('empresaRazon').value = '';
      $('empresaGiro').value = '';
      $('empresaActeco').value = '';
      $('empresaApiKey').value = '';
      $('empresaDir').value = '';
      $('empresaComuna').value = '';
      $('empresaCiudad').value = '';
      $('empresaAmbiente').value = 'certificacion';
      $('empresaFechaRes').value = '';
      $('empresaNumeroRes').value = '';
    }

    function fillEmpresaForm(empresa) {
      empresasState.selectedId = empresa.id;
      localStorage.setItem('dte_empresa_id', String(empresa.id));
      $('empresaSelector').value = String(empresa.id);
      const top = $('empresaActivaTop');
      if (top) top.value = String(empresa.id);
      $('empresaRutEmisor').value = empresa.rut_emisor || '';
      $('empresaRutEnvia').value = empresa.rut_envia || '';
      $('empresaRazon').value = empresa.razon_social_emisor || '';
      $('empresaGiro').value = empresa.giro_emisor || '';
      $('empresaActeco').value = String(empresa.acteco_emisor || '');
      $('empresaApiKey').value = empresa.api_key || '';
      $('empresaDir').value = empresa.dir_origen || '';
      $('empresaComuna').value = empresa.cmna_origen || '';
      $('empresaCiudad').value = empresa.ciudad_origen || '';
      $('empresaAmbiente').value = empresa.sii_ambiente || 'certificacion';
      $('empresaFechaRes').value = empresa.sii_fecha_resolucion || '';
      $('empresaNumeroRes').value = String(empresa.sii_numero_resolucion || '');
    }

    function renderEmpresaSelector() {
      const selector = $('empresaSelector');
      const options = ['<option value="">Selecciona empresa</option>'];
      empresasState.items.forEach((empresa) => {
        const markDefault = empresa.es_default ? ' (default)' : '';
        const markInactive = empresa.activo ? '' : ' [inactiva]';
        options.push(`<option value="${empresa.id}">${empresa.razon_social_emisor}${markDefault}${markInactive}</option>`);
      });
      selector.innerHTML = options.join('');
      if (empresasState.selectedId) {
        selector.value = String(empresasState.selectedId);
      }
    }

    function renderEmpresasTable() {
      const body = $('empresasTableBody');
      if (!empresasState.items.length) {
        body.innerHTML = '<tr><td colspan="7" class="muted">No hay empresas para mostrar.</td></tr>';
        return;
      }

      body.innerHTML = empresasState.items.map((empresa) => {
        const estado = empresa.ready ? 'LISTA' : (empresa.activo ? 'PENDIENTE' : 'INACTIVA');
        const keyLabel = empresa.api_key ? `${empresa.api_key.slice(0, 6)}...${empresa.api_key.slice(-4)}` : '-';
        const badgeClass = empresa.ready ? 'pill' : (empresa.activo ? 'pill' : 'pill');
        return `
          <tr>
            <td>${empresa.id}</td>
            <td>${empresa.razon_social_emisor}${empresa.es_default ? ' (default)' : ''}</td>
            <td>${empresa.rut_emisor}</td>
            <td>${empresa.sii_ambiente}</td>
            <td><span class="${badgeClass}">${estado}</span></td>
            <td>${keyLabel}</td>
            <td>
              <button class="btn secondary" data-empresa-open="${empresa.id}">Seleccionar</button>
              <button class="btn" data-empresa-get-token="${empresa.id}">Obtener token</button>
            </td>
          </tr>
        `;
      }).join('');

      body.querySelectorAll('[data-empresa-open]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id = Number(btn.dataset.empresaOpen || 0);
          const empresa = empresasState.items.find((item) => item.id === id);
          if (empresa) {
            try {
              const useProd = window.confirm(`Abrir empresa "${empresa.razon_social_emisor}" en modo PRODUCCIÓN? (Cancelar = certificación)`);
              const ambiente = useProd ? 'produccion' : 'certificacion';
              // Persistir cambio de ambiente en la empresa via API
              const payload = {
                rut_emisor: empresa.rut_emisor,
                rut_envia: empresa.rut_envia,
                razon_social_emisor: empresa.razon_social_emisor,
                giro_emisor: empresa.giro_emisor,
                acteco_emisor: empresa.acteco_emisor || 0,
                dir_origen: empresa.dir_origen || '',
                cmna_origen: empresa.cmna_origen || '',
                ciudad_origen: empresa.ciudad_origen || '',
                sii_ambiente: ambiente,
                sii_fecha_resolucion: empresa.sii_fecha_resolucion || '',
                sii_numero_resolucion: empresa.sii_numero_resolucion || 0,
                api_key: empresa.api_key || null,
                brand_name: empresa.brand_name || null,
                brand_logo_url: empresa.brand_logo_url || null,
                brand_accent_1: empresa.brand_accent_1 || null,
                brand_accent_2: empresa.brand_accent_2 || null,
                cert_pfx_path: empresa.cert_pfx_path || null,
              };
              await fetchJson(`/api/v1/dashboard/empresas/${empresa.id}`, { method: 'PUT', json: payload });
              // actualizar en memoria y activar
              empresa.sii_ambiente = ambiente;
              await setEmpresaActiva(empresa).catch(handleEmpresasError);
            } catch (err) {
              handleEmpresasError(err);
            }
          }
        });
      });

      body.querySelectorAll('[data-empresa-get-token]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id = Number(btn.dataset.empresaGetToken || 0);
          try {
            setResultLoading('result-empresas', 'Obteniendo token...');
            const resp = await fetchJson(`/api/v1/dashboard/empresas/${encodeURIComponent(id)}/token`, { method: 'POST' });
            setResult('result-empresas', JSON.stringify(resp));
            showToast('Token', resp.token_preview ? `Token obtenido: ${resp.token_preview}` : 'Token renovado', 'success');
          } catch (err) {
            handleEmpresasError(err);
          }
        });
      });
    }

    async function loadEmpresas(selectId = null) {
      setResultLoading('result-empresas', 'Cargando empresas...');
      const query = empresasState.includeInactive ? '?include_inactive=true' : '';
      const data = await fetchJson(`/api/v1/dashboard/empresas${query}`);
      empresasState.items = Array.isArray(data) ? data : [];
      const targetId = selectId || empresasState.selectedId || persistedEmpresaId || null;
      if (targetId) {
        const empresa = empresasState.items.find((item) => item.id === targetId);
        if (empresa) {
          fillEmpresaForm(empresa);
          if (empresa.api_key) {
            state.apiKey = empresa.api_key;
            localStorage.setItem('dte_api_key', state.apiKey);
            syncUi();
          }
        }
      }
      if (!targetId && empresasState.items.length) {
        fillEmpresaForm(empresasState.items[0]);
        persistEmpresaSelection(empresasState.items[0]);
      }
      renderEmpresaSelector();
      renderTopEmpresaSelector();
      renderEmpresasTable();
      renderFlowChecklist();
      updateLegacyCertVisibility();
      if (targetId) {
        focusSection('section-empresas');
        if (!restoredToastShown) {
          const empresa = empresasState.items.find((item) => item.id === targetId);
          if (empresa) {
            const estadoTexto = empresa.ready ? 'lista para emitir' : (empresa.activo ? 'pendiente de completar' : 'inactiva');
            showToast('Empresa restaurada', `Se cargó ${empresa.razon_social_emisor} como empresa activa (${estadoTexto}).`, 'info');
            restoredToastShown = true;
          }
        }
      }
      setResult('result-empresas', data, true);
      setConsole(data, true);
      showToast('Empresas', 'Listado actualizado correctamente.', 'success');
    }

    async function createEmpresa() {
      setResultLoading('result-empresas', 'Creando empresa...');
      const payload = empresaPayloadFromForm();
      const data = await fetchJson('/api/v1/dashboard/empresas', { method: 'POST', json: payload });
      await loadEmpresas(data.id);
      setConsole('Empresa creada correctamente.', true);
      showToast('Empresa creada', `${data.razon_social_emisor} fue creada correctamente.`, 'success');
    }

    async function updateEmpresa() {
      setResultLoading('result-empresas', 'Guardando cambios...');
      const empresaId = empresasState.selectedId || Number($('empresaSelector').value);
      if (!empresaId) throw { status: 0, data: 'Selecciona una empresa para guardar cambios.' };
      const payload = empresaPayloadFromForm();
      const data = await fetchJson(`/api/v1/dashboard/empresas/${empresaId}`, { method: 'PUT', json: payload });
      await loadEmpresas(data.id);
      setConsole('Empresa actualizada correctamente.', true);
      showToast('Empresa actualizada', `${data.razon_social_emisor} se guardó correctamente.`, 'success');
    }

    async function deleteEmpresa() {
      setResultLoading('result-empresas', 'Desactivando empresa...');
      const empresaId = empresasState.selectedId || Number($('empresaSelector').value);
      if (!empresaId) throw { status: 0, data: 'Selecciona una empresa para eliminar.' };
      if (!window.confirm('Se desactivará la empresa seleccionada. ¿Deseas continuar?')) {
        return;
      }
      const data = await fetchJson(`/api/v1/dashboard/empresas/${empresaId}`, { method: 'DELETE' });
      clearEmpresaForm();
      await loadEmpresas();
      setResult('result-empresas', data, true);
      setConsole('Empresa desactivada correctamente.', true);
      showToast('Empresa desactivada', 'La empresa quedó inactiva.', 'info');
    }

    async function reactivateEmpresa() {
      setResultLoading('result-empresas', 'Reactivando empresa...');
      const empresaId = empresasState.selectedId || Number($('empresaSelector').value);
      if (!empresaId) throw { status: 0, data: 'Selecciona una empresa para reactivar.' };
      const data = await fetchJson(`/api/v1/dashboard/empresas/${empresaId}/reactivate`, { method: 'POST', json: {} });
      await loadEmpresas(data.id);
      setResult('result-empresas', data, true);
      setConsole('Empresa reactivada correctamente.', true);
      showToast('Empresa reactivada', 'La empresa volvió a estar activa.', 'success');
    }

    async function regenerateEmpresaKey() {
      setResultLoading('result-empresas', 'Regenerando API Key...');
      const empresaId = empresasState.selectedId || Number($('empresaSelector').value);
      if (!empresaId) throw { status: 0, data: 'Selecciona una empresa para regenerar API Key.' };
      const data = await fetchJson(`/api/v1/dashboard/empresas/${empresaId}/regenerate-key`, { method: 'POST', json: {} });
      await loadEmpresas(data.id);
      setResult('result-empresas', data, true);
      setConsole('API Key regenerada correctamente.', true);
      showToast('API Key regenerada', 'Se generó una nueva clave para la empresa.', 'info');
    }

    async function uploadEmpresaCaf() {
      setResultLoading('result-empresas', 'Subiendo CAF...');
      const empresaId = empresasState.selectedId || Number($('empresaSelector').value);
      if (!empresaId) throw { status: 0, data: 'Selecciona una empresa para subir CAF.' };
      const file = $('empresaCafFile').files[0];
      if (!file) throw { status: 0, data: 'Selecciona un archivo CAF XML.' };
      const form = new FormData();
      form.append('file', file);
      const data = await fetchJson(`/api/v1/dashboard/empresas/${empresaId}/caf`, { method: 'POST', body: form });
      await loadEmpresas(empresaId);
      setResult('result-empresas', data, true);
      setConsole('CAF cargado para empresa.', true);
      showToast('CAF cargado', 'El CAF se guardó para la empresa seleccionada.', 'success');
    }

    async function uploadEmpresaCert() {
      setResultLoading('result-empresas', 'Subiendo certificado...');
      const empresaId = empresasState.selectedId || Number($('empresaSelector').value);
      if (!empresaId) throw { status: 0, data: 'Selecciona una empresa para subir certificado.' };
      const file = $('empresaPfxFile').files[0];
      if (!file) throw { status: 0, data: 'Selecciona un archivo PFX.' };
      const password = $('empresaPfxPassword').value;
      if (!password) throw { status: 0, data: 'Ingresa la contraseña del PFX.' };
      const form = new FormData();
      form.append('file', file);
      form.append('password', password);
      const data = await fetchJson(`/api/v1/dashboard/empresas/${empresaId}/cert`, { method: 'POST', body: form });
      await loadEmpresas(empresaId);
      setResult('result-empresas', data, true);
      setConsole('Certificado guardado para empresa.', true);
      showToast('Certificado cargado', 'El certificado quedó asociado a la empresa.', 'success');
    }

    function handleEmpresasError(error) {
      const payload = error && error.data ? error.data : error;
      const message = typeof payload === 'string' ? payload : (payload?.detail || JSON.stringify(payload, null, 2));
      setResult('result-empresas', payload, false);
      setConsole(`Empresas: ${message}`, false);
      showToast('Error en empresas', message, 'error');
    }

    function wireSidebar() {
      document.querySelectorAll('[data-jump]').forEach((btn) => {
        btn.addEventListener('click', () => {
          document.querySelectorAll('.nav-link').forEach((link) => link.classList.remove('active'));
          btn.classList.add('active');
          const target = document.getElementById(btn.dataset.jump);
          if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
      });

      document.querySelectorAll('[data-collapse]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const section = document.getElementById(btn.dataset.collapse);
          if (!section) return;
          section.classList.toggle('collapsed');
          btn.textContent = section.classList.contains('collapsed') ? 'Mostrar' : 'Ocultar';
        });
      });
    }

    async function syncPanelLock() {
      const response = await fetch('/api/v1/dashboard/session');
      const data = await response.json();
      const lock = $('panelLock');
      if (!data.enabled || data.authenticated) {
        lock.classList.remove('visible');
        return;
      }
      lock.classList.add('visible');
    }

    async function loadBranding() {
      try {
        const branding = await fetchJson('/api/v1/dashboard/branding');
        applyBranding(branding);
      } catch (error) {
        setConsole('No se pudo cargar el branding de la empresa, usando identidad por defecto.', false);
      }
    }

    async function saveBranding() {
      const payload = {
        brand_name: $('brandingName').value.trim(),
        brand_logo_url: $('brandingLogoUrl').value.trim(),
        brand_accent_1: $('brandingAccent1').value.trim(),
        brand_accent_2: $('brandingAccent2').value.trim(),
      };
      const data = await fetchJson('/api/v1/dashboard/branding', { method: 'PUT', json: payload });
      applyBranding(data);
      setResult('result-branding', data, true);
      setConsole('Branding guardado correctamente.');
    }

    async function resetBranding() {
      const data = await fetchJson('/api/v1/dashboard/branding', {
        method: 'PUT',
        json: { brand_name: '', brand_logo_url: '', brand_accent_1: '', brand_accent_2: '' },
      });
      applyBranding(data);
      setResult('result-branding', data, true);
      setConsole('Branding restaurado al modo automático.');
    }

    const historyState = {
      page: 1,
      pageSize: 10,
      lastPage: 1,
    };

    function historyQueryParams() {
      const params = new URLSearchParams();
      params.set('page', String(historyState.page));
      params.set('page_size', String(historyState.pageSize));
      const q = $('historyQuery').value.trim();
      const estado = $('historyEstado').value.trim();
      const tipo = $('historyTipo').value.trim();
      if (q) params.set('q', q);
      if (estado) params.set('estado', estado);
      if (tipo) params.set('tipo_dte', tipo);
      return params.toString();
    }

    function renderHistoryTable(data) {
      historyState.lastPage = data.total_pages || 1;
      historyState.page = data.page || historyState.page;
      historyState.pageSize = data.page_size || historyState.pageSize;

      const rows = data.items || [];
      const body = $('historyTableBody');
      if (!rows.length) {
        body.innerHTML = '<tr><td colspan="9" class="muted">No se encontraron DTEs con esos filtros.</td></tr>';
      } else {
        body.innerHTML = rows.map((item) => `
          <tr>
            <td><span class="pill">#${item.id}</span></td>
            <td>${item.tipo_dte}</td>
            <td>${item.folio}</td>
            <td>${item.estado}</td>
            <td>$${Number(item.monto_total).toLocaleString('es-CL')}</td>
            <td>${item.fecha_emision}</td>
            <td>${item.rut_receptor || '-'}</td>
            <td>${item.track_id || '-'}</td>
            <td>
              <div class="history-actions">
                <button class="btn secondary" data-history-open="${item.id}">Abrir</button>
              </div>
            </td>
          </tr>
        `).join('');

        body.querySelectorAll('[data-history-open]').forEach((btn) => {
          btn.addEventListener('click', () => {
            $('boletaId').value = btn.dataset.historyOpen;
            $('boletaIdEnviar').value = btn.dataset.historyOpen;
            $('trackingDteId').value = btn.dataset.historyOpen;
            document.getElementById('section-boleta')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
          });
        });
      }

      const start = data.total_items === 0 ? 0 : ((data.page - 1) * data.page_size) + 1;
      const end = Math.min(data.page * data.page_size, data.total_items);
      $('historyMeta').innerHTML = `
        <span>Mostrando ${start} - ${end} de ${data.total_items} registros</span>
        <span>Página ${data.page} / ${data.total_pages}</span>
      `;

      $('btnHistoryPrev').disabled = !data.has_prev;
      $('btnHistoryNext').disabled = !data.has_next;
    }

    async function loadHistory(nextPage = null) {
      if (nextPage !== null) {
        historyState.page = nextPage;
      }
      historyState.pageSize = Number($('historyPageSize').value || 10);
      const query = historyQueryParams();
      const data = await fetchJson(`/api/v1/dashboard/dtes?${query}`);
      renderHistoryTable(data);
      setConsole(data, true);
      setResult('result-history', data, true);
    }

    async function loginPanel() {
      const password = $('panelPassword').value;
      try {
        const response = await fetch('/api/v1/dashboard/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password }),
        });
        const data = await response.json();
        if (!response.ok) throw data;
        $('result-panel-lock').className = 'result ok';
        $('result-panel-lock').textContent = 'Panel desbloqueado.';
        await syncPanelLock();
      } catch (error) {
        $('result-panel-lock').className = 'result err';
        $('result-panel-lock').textContent = typeof error === 'string' ? error : (error.detail || 'No se pudo desbloquear el panel.');
      }
    }

    async function fetchJson(path, options = {}) {
      const headers = new Headers(options.headers || {});
      if (state.apiKey) headers.set('X-API-Key', state.apiKey);
      // Enviar X-Empresa-Id cuando hay una empresa activa seleccionada en el dashboard.
      // Esto permite usar la API key global y especificar la empresa objetivo.
      try {
        const empresaId = (empresasState && empresasState.selectedId) ? empresasState.selectedId : (persistedEmpresaId || null);
        if (empresaId) headers.set('X-Empresa-Id', String(empresaId));
      } catch (e) {
        // seguridad: si empresasState no está definido, no hacemos nada
      }
      if (options.json !== undefined) {
        headers.set('Content-Type', 'application/json');
      }
      const response = await fetch(path, {
        method: options.method || 'GET',
        headers,
        body: options.json !== undefined ? JSON.stringify(options.json) : options.body,
      });
      const contentType = response.headers.get('content-type') || '';
      let data;
      if (contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }
      if (!response.ok) {
        throw { status: response.status, data };
      }
      return data;
    }

    function parseDetalles() {
      const value = $('detallesJson').value.trim();
      return JSON.parse(value);
    }

    function boletaPayload() {
      const tipo = Number($('boletaTipo').value);
      const receptorRut = $('receptorRut').value.trim();
      const receptorRazon = $('receptorRazon').value.trim();
      const detalles = parseDetalles();
      const payload = { tipo_dte: tipo, detalles };
      const fecha = $('boletaFecha').value;
      if (fecha) payload.fecha_emision = fecha;
      if (receptorRut) payload.receptor = { rut: receptorRut };
      if (receptorRazon) payload.receptor = { ...(payload.receptor || {}), razon_social: receptorRazon };
      return payload;
    }

    async function loadNextFolio() {
      const el = $('boletaFolioInfo');
      if (!el) return;
      const empresa = getEmpresaActiva();
      const tipo = Number($('boletaTipo').value || 0);
      if (!empresa) {
        el.textContent = 'Folio disponible: - (sin empresa)';
        return;
      }
      if (!tipo) {
        el.textContent = 'Folio disponible: - (tipo indefinido)';
        return;
      }
      el.textContent = 'Consultando folio...';
      try {
        const data = await fetchJson(`/api/v1/boleta/next-folio?tipo_dte=${encodeURIComponent(tipo)}`);
        el.textContent = `Folio disponible: ${data.folio_disponible}  (CAF ${data.caf_id} rango ${data.rango_desde}-${data.rango_hasta})`;
      } catch (err) {
        const raw = err && err.data ? (err.data.detail || err.data) : (err || 'error');
        const message = typeof raw === 'object' ? JSON.stringify(raw) : String(raw);
        el.textContent = `Folio: - (${message})`;
      }
    }

    function requireActiveEmpresaSelection() {
      const selector = $('empresaActivaTop');
      const selectedId = Number(selector?.value || 0);
      if (!selectedId) {
        jumpToSection('section-empresas', 'Selecciona una empresa activa antes de emitir boletas.');
        throw { status: 0, data: 'Selecciona una empresa activa en el selector superior antes de continuar.' };
      }
      const empresa = empresasState.items.find((item) => item.id === selectedId);
      if (!empresa || !empresa.activo) {
        jumpToSection('section-empresas', 'La empresa activa no está disponible. Selecciona otra empresa activa.');
        throw { status: 0, data: 'La empresa activa no está disponible o está inactiva.' };
      }
      return empresa;
    }

    async function run(op) {
      const target = op.startsWith('caf') ? 'result-caf' : op.startsWith('pfx') ? 'result-pfx' : op.startsWith('tracking') ? 'result-tracking' : op.startsWith('token') ? 'result-token' : 'result-boleta';
      setResultLoading(target, 'Ejecutando acción...');
      try {
        let data;
        let refreshHistory = false;
        switch (op) {
          case 'health':
            data = await fetchJson('/health');
            $('metricHealth').textContent = data.status || 'ok';
            break;
          case 'token-status':
            data = await fetchJson('/api/v1/token/status');
            break;
          case 'token-refresh':
            data = await fetchJson('/api/v1/token/refresh', { method: 'POST', json: {} });
            break;
          case 'token-validate':
            data = await fetchJson('/api/v1/token/validate', {
              method: 'POST',
              json: { path: $('certPath').value.trim(), password: $('certPassword').value },
            });
            break;
          case 'caf-upload': {
            const file = $('cafFile').files[0];
            if (!file) throw { status: 0, data: 'Selecciona un archivo CAF XML.' };
            const form = new FormData();
            form.append('file', file);
            data = await fetchJson('/api/v1/caf/upload', { method: 'POST', body: form });
            break;
          }
          case 'caf-status':
            data = await fetchJson(`/api/v1/caf/status?tipo_dte=${encodeURIComponent($('cafTipo').value)}`);
            break;
          case 'pfx-upload': {
            const file = $('pfxFile').files[0];
            if (!file) throw { status: 0, data: 'Selecciona un archivo PFX.' };
            const password = $('pfxPassword').value;
            if (!password) throw { status: 0, data: 'Ingresa la contraseña del .pfx.' };
            const form = new FormData();
            form.append('file', file);
            form.append('password', password);
            data = await fetchJson('/api/v1/cert/upload', { method: 'POST', body: form });
            break;
          }
          case 'pfx-upload-empresa': {
            const file = $('pfxFile').files[0];
            if (!file) throw { status: 0, data: 'Selecciona un archivo PFX.' };
            const password = $('pfxPassword').value;
            if (!password) throw { status: 0, data: 'Ingresa la contraseña del .pfx.' };
            const form = new FormData();
            form.append('file', file);
            form.append('password', password);
            data = await fetchJson('/api/v1/cert/upload/empresa', { method: 'POST', body: form });
            await loadEmpresas(empresasState.selectedId || null).catch(() => {});
            break;
          }
          case 'boleta-generar':
            requireActiveEmpresaSelection();
            // Verificar folio disponible antes de intentar generar (no reserva, solo validación)
            try {
              const tipo = Number($('boletaTipo').value || 0);
              await fetchJson(`/api/v1/boleta/next-folio?tipo_dte=${encodeURIComponent(tipo)}`);
            } catch (err) {
              const raw = err && err.data ? (err.data.detail || err.data) : 'No hay folios disponibles para el tipo/empresa seleccionados.';
              const msg = typeof raw === 'object' ? JSON.stringify(raw) : String(raw);
              throw { status: 0, data: `Fallo pre-validación folio: ${msg}` };
            }
            data = await fetchJson('/api/v1/boleta/generar', { method: 'POST', json: boletaPayload() });
            refreshHistory = true;
            break;
          case 'boleta-enviar':
            requireActiveEmpresaSelection();
            let dteIdEnviar = Number($('boletaIdEnviar').value);
            if (!Number.isInteger(dteIdEnviar) || dteIdEnviar <= 0) {
              const dteIdConsulta = Number($('boletaId').value);
              if (Number.isInteger(dteIdConsulta) && dteIdConsulta > 0) {
                dteIdEnviar = dteIdConsulta;
                $('boletaIdEnviar').value = String(dteIdEnviar);
              }
            }
            if (!Number.isInteger(dteIdEnviar) || dteIdEnviar <= 0) {
              throw { status: 0, data: 'Ingresa un ID DTE válido (> 0) en "ID DTE para enviar" o en "ID DTE".' };
            }
            data = await fetchJson('/api/v1/boleta/enviar', { method: 'POST', json: { dte_id: dteIdEnviar } });
            $('boletaId').value = String(dteIdEnviar);
            $('trackingDteId').value = String(dteIdEnviar);
            if (data && data.track_id) {
              try {
                const trackingData = await fetchJson(`/api/v1/tracking/${encodeURIComponent(dteIdEnviar)}/estado`);
                data = { ...data, tracking: trackingData };
              } catch (trackingError) {
                data = {
                  ...data,
                  tracking_warning: trackingError && trackingError.data ? trackingError.data : 'No fue posible consultar tracking inmediatamente.',
                };
              }
            }
            refreshHistory = true;
            break;
          case 'boleta-obtener':
            data = await fetchJson(`/api/v1/boleta/${encodeURIComponent($('boletaId').value)}`);
            break;
          case 'boleta-xml':
            data = await fetchJson(`/api/v1/boleta/${encodeURIComponent($('boletaId').value)}/xml`);
            break;
          case 'boleta-xml-raw':
            data = await fetchJson(`/api/v1/boleta/${encodeURIComponent($('boletaId').value)}/xml-raw`);
            break;
          case 'boleta-log':
            data = await fetchJson(`/api/v1/boleta/${encodeURIComponent($('boletaId').value)}/log`);
            break;
          case 'boleta-firma': {
            const comparar = $('boletaComparar').value.trim();
            const url = comparar ? `/api/v1/boleta/${encodeURIComponent($('boletaId').value)}/firma-diagnostico?comparar_con=${encodeURIComponent(comparar)}` : `/api/v1/boleta/${encodeURIComponent($('boletaId').value)}/firma-diagnostico`;
            data = await fetchJson(url);
            break;
          }
          case 'tracking-estado':
            data = await fetchJson(`/api/v1/tracking/${encodeURIComponent($('trackingDteId').value)}/estado`);
            refreshHistory = true;
            break;
          case 'history-load':
            data = await fetchJson(`/api/v1/dashboard/dtes?${historyQueryParams()}`);
            renderHistoryTable(data);
            break;
          default:
            throw { status: 0, data: `Operación no soportada: ${op}` };
        }
        setResult(target, data, true);
        setConsole(data, true);
        if (refreshHistory) {
          await loadHistory(historyState.page).catch(() => {});
        }
        showToast('Acción completada', 'La operación se ejecutó correctamente.', 'success');
      } catch (error) {
        const payload = error && error.data ? error.data : error;
        const message = error && error.status ? `Error ${error.status}` : 'Error';
        setConsole(`${message}\n${typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2)}`, false);
        setResult((error && error.opTarget) || target, payload, false);
        showToast('Error', typeof payload === 'string' ? payload : 'La operación falló.', 'error');
      }
    }

    document.querySelectorAll('[data-op]').forEach((btn) => btn.addEventListener('click', () => run(btn.dataset.op)));
    $('btnSaveKey').addEventListener('click', saveKey);
    $('btnClearKey').addEventListener('click', () => { state.apiKey = ''; localStorage.removeItem('dte_api_key'); syncUi(); setConsole('API Key eliminada.'); });
    $('btnPing').addEventListener('click', () => run('health'));
    $('btnHealth').addEventListener('click', () => run('health'));
    $('btnPanelLogin').addEventListener('click', loginPanel);
    $('panelPassword').addEventListener('keydown', (event) => { if (event.key === 'Enter') loginPanel(); });
    $('btnSaveBranding').addEventListener('click', saveBranding);
    $('btnResetBranding').addEventListener('click', resetBranding);
    $('btnHistorySearch').addEventListener('click', () => loadHistory(1));
    $('btnHistoryPrev').addEventListener('click', () => { if (historyState.page > 1) loadHistory(historyState.page - 1); });
    $('btnHistoryNext').addEventListener('click', () => { if (historyState.page < historyState.lastPage) loadHistory(historyState.page + 1); });
    $('btnHistoryRefresh').addEventListener('click', () => loadHistory(historyState.page));
    $('historyPageSize').addEventListener('change', () => loadHistory(1));
    $('boletaTipo').addEventListener('change', () => loadNextFolio());
    $('btnEmpresasLoad').addEventListener('click', () => loadEmpresas().catch(handleEmpresasError));
    $('btnEmpresaNuevo').addEventListener('click', clearEmpresaForm);
    $('btnEmpresaCrear').addEventListener('click', () => createEmpresa().catch(handleEmpresasError));
    $('btnEmpresaGuardar').addEventListener('click', () => updateEmpresa().catch(handleEmpresasError));
    $('btnEmpresaEliminar').addEventListener('click', () => deleteEmpresa().catch(handleEmpresasError));
    $('btnEmpresaReactivar').addEventListener('click', () => reactivateEmpresa().catch(handleEmpresasError));
    $('btnEmpresaRegenKey').addEventListener('click', () => regenerateEmpresaKey().catch(handleEmpresasError));
    $('btnEmpresaSubirCaf').addEventListener('click', () => uploadEmpresaCaf().catch(handleEmpresasError));
    $('btnEmpresaSubirCert').addEventListener('click', () => uploadEmpresaCert().catch(handleEmpresasError));
    $('empresaIncludeInactive').addEventListener('change', (event) => {
      empresasState.includeInactive = !!event.target.checked;
      loadEmpresas(empresasState.selectedId).catch(handleEmpresasError);
    });
    $('empresaSelector').addEventListener('change', async (event) => {
      const id = Number(event.target.value || 0);
      if (!id) {
        clearEmpresaForm();
        return;
      }
      const empresa = empresasState.items.find((item) => item.id === id);
      if (empresa) {
        await setEmpresaActiva(empresa).catch(handleEmpresasError);
      }
      renderFlowChecklist();
    });
    $('empresaActivaTop').addEventListener('change', async (event) => {
      const id = Number(event.target.value || 0);
      if (!id) return;
      const empresa = empresasState.items.find((item) => item.id === id);
      if (!empresa) return;
      await setEmpresaActiva(empresa).catch((error) => setResult('result-flow', error.data || error, false));
    });
    $('btnFlowNewEmpresa').addEventListener('click', () => jumpToSection('section-empresas', 'Completa el formulario y crea o selecciona una empresa.'));
    $('btnFlowCaf').addEventListener('click', () => jumpToSection('section-empresas', 'Selecciona la empresa y sube su CAF desde aquí.'));
    $('btnFlowCert').addEventListener('click', () => jumpToSection('section-empresas', 'Selecciona la empresa y sube su certificado digital.'));
    $('btnFlowEmitir').addEventListener('click', () => jumpToSection('section-boleta', 'Cuando la empresa tenga CAF y certificado, prueba la emisión desde boleta.'));
    $('btnFlowProbarEmpresa').addEventListener('click', () => {
      const empresa = getEmpresaActiva();
      if (!empresa) {
        setResult('result-flow', 'Selecciona una empresa primero.', false);
        showToast('Flujo guiado', 'No hay empresa activa seleccionada.', 'error');
        return;
      }

      const issues = [];
      if (!empresa.activo) issues.push('la empresa está inactiva');
      if (!empresa.caf_count) issues.push('falta CAF');
      if (!empresa.has_cert) issues.push('falta certificado');

      renderFlowChecklist();

      if (!issues.length) {
        const message = `${empresa.razon_social_emisor} está lista para emitir.`;
        setResult('result-flow', message, true);
        showToast('Empresa lista', message, 'success');
        jumpToSection('section-boleta', 'Empresa lista para emitir. Puedes probar la generación de boleta.');
        return;
      }

      const message = `A ${empresa.razon_social_emisor} le falta: ${issues.join(', ')}.`;
      setResult('result-flow', message, false);
      showToast('Empresa pendiente', message, 'error');
    });
    wireSidebar();
    syncUi();
    updateLegacyCertVisibility();
    run('health');
    loadHistory(1).catch(() => {});
    loadEmpresas().catch(() => {});
    loadBranding().catch(() => {});
    syncPanelLock();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html)
