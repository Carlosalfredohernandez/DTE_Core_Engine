"""
DTE Core Engine — Endpoint para estado del Token SII.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_api_key
from app.services.token_service import token_service

router = APIRouter()


class TokenStatusResponse(BaseModel):
    is_cached: bool
    expires_at: str | None


class CertTestRequest(BaseModel):
    path: str
    password: str


class CertTestResponse(BaseModel):
    ok: bool
    subject: str | None = None
    not_valid_after: str | None = None
    token_preview: str | None = None
    error: str | None = None
    respuesta_sii: str | None = None


@router.get("/status", response_model=TokenStatusResponse)
async def get_token_status(_: str = Depends(get_api_key)):
    """Retorna el estado de la caché del Token del SII."""
    # Accedemos a variables internas para solo lectura rápida
    is_cached = token_service._cached_token is not None
    expires_at = None
    if token_service._token_expires_at:
        expires_at = token_service._token_expires_at.isoformat()
        
    return TokenStatusResponse(
        is_cached=is_cached,
        expires_at=expires_at
    )


@router.post("/refresh")
async def refresh_token(_: str = Depends(get_api_key)):
    """Fuerza la renovación del Token en el SII."""
    token = await token_service.get_valid_token(force_refresh=True)
    return {"message": "Token renovado exitosamente"}


@router.post("/validate", response_model=CertTestResponse)
async def validate_cert(req: CertTestRequest, _: str = Depends(get_api_key)):
    """
    Prueba un certificado PFX específico.
    Útil para debugging de credenciales y conectividad.
    """
    result = await token_service.test_pfx(req.path, req.password)
    
    return CertTestResponse(
        ok=result["ok"],
        subject=result.get("subject"),
        not_valid_after=result.get("not_valid_after"),
        token_preview=result.get("token"),
        error=result.get("error_sii") or result.get("error_interno"),
        respuesta_sii=result.get("respuesta_raw")
    )
