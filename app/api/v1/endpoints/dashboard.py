"""
DTE Core Engine — Panel web administrativo.
"""

from __future__ import annotations

from math import ceil

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_api_key, get_current_empresa, get_db_session
from app.config import get_settings
from app.domain.models import Dte
from app.services.empresa_service import build_empresa_branding

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


def _dashboard_enabled() -> bool:
  return bool(settings.dashboard_password)


def _dashboard_authenticated(access_cookie: str | None) -> bool:
  if not _dashboard_enabled():
    return True
  return access_cookie == settings.dashboard_password


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
    .hero-grid { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 12px; margin-top: 18px; }
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
    .result.ok { border-color: rgba(52, 211, 153, 0.35); }
    .result.err { border-color: rgba(251, 113, 133, 0.35); }
    .badge { display: inline-flex; align-items: center; gap: 8px; border-radius: 999px; padding: 7px 10px; background: rgba(255,255,255,0.06); color: var(--muted); font-size: 12px; }
    .status-dot { width: 8px; height: 8px; border-radius: 999px; background: var(--warning); box-shadow: 0 0 0 4px rgba(251,191,36,0.12); }
    .topbar { display: flex; justify-content: space-between; gap: 16px; flex-wrap: wrap; margin-bottom: 18px; }
    .topbar .actions { align-items: center; }
    .muted { color: var(--muted); }
    .mini { font-size: 12px; }
    @media (max-width: 1200px) { .app-layout, .hero, .grid { grid-template-columns: 1fr; } .sidebar-nav { position: static; } .span-4, .span-6, .span-8, .span-12 { grid-column: span 12; } }
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

  <div class="shell">
    <div class="topbar">
      <div class="badge"><span class="status-dot"></span><span>Motor DTE · Panel de operaciones</span></div>
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
        <div class="sub card-body">Convierte un .pfx a base64 para Railway o úsalo como archivo local.</div>
        <input class="input card-body" type="file" id="pfxFile" accept=".pfx" />
        <div style="height:12px" class="card-body"></div>
        <input class="input card-body" id="pfxPassword" placeholder="Contraseña del .pfx" />
        <div class="actions card-body" style="margin-top:12px;">
          <button class="btn" data-op="pfx-upload">Generar Base64</button>
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

    function saveKey() {
      state.apiKey = $('apiKey').value.trim();
      localStorage.setItem('dte_api_key', state.apiKey);
      syncUi();
      setConsole('API Key guardada localmente.');
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

    async function run(op) {
      try {
        let data;
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
            const form = new FormData();
            form.append('file', file);
            form.append('password', $('pfxPassword').value);
            data = await fetchJson('/api/v1/cert/upload', { method: 'POST', body: form });
            break;
          }
          case 'boleta-generar':
            data = await fetchJson('/api/v1/boleta/generar', { method: 'POST', json: boletaPayload() });
            break;
          case 'boleta-enviar':
            data = await fetchJson('/api/v1/boleta/enviar', { method: 'POST', json: { dte_id: Number($('boletaIdEnviar').value) } });
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
            break;
          case 'history-load':
            data = await fetchJson(`/api/v1/dashboard/dtes?${historyQueryParams()}`);
            renderHistoryTable(data);
            break;
          default:
            throw { status: 0, data: `Operación no soportada: ${op}` };
        }
        const target = op.startsWith('caf') ? 'result-caf' : op.startsWith('pfx') ? 'result-pfx' : op.startsWith('tracking') ? 'result-tracking' : op.startsWith('token') ? 'result-token' : 'result-boleta';
        setResult(target, data, true);
        setConsole(data, true);
      } catch (error) {
        const payload = error && error.data ? error.data : error;
        const message = error && error.status ? `Error ${error.status}` : 'Error';
        setConsole(`${message}\n${typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2)}`, false);
        const target = (error && error.opTarget) || 'result-console';
        setResult(target, payload, false);
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
    wireSidebar();
    syncUi();
    run('health');
    loadHistory(1).catch(() => {});
    loadBranding().catch(() => {});
    syncPanelLock();
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html)
