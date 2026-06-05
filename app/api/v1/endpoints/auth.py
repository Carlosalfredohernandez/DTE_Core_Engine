"""
DTE Core Engine — Endpoint para estado del Token SII.
"""

from fastapi import APIRouter, Depends
from fastapi import HTTPException, status
from pydantic import BaseModel
import structlog

from app.api.deps import get_api_key, get_current_empresa
from app.domain.exceptions import DteEngineError
from app.services.token_service import token_service

router = APIRouter()
logger = structlog.get_logger(__name__)


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
async def get_token_status(empresa = Depends(get_current_empresa), _: str = Depends(get_api_key)):
    """Retorna el estado de la caché del Token del SII."""
    # Accedemos a variables internas para solo lectura rápida
    cache_key = token_service._cache_key(empresa)
    is_cached = cache_key in token_service._cached_tokens
    expires_at = None
    if cache_key in token_service._token_expires_at:
        expires_at = token_service._token_expires_at[cache_key].isoformat()
        
    return TokenStatusResponse(
        is_cached=is_cached,
        expires_at=expires_at
    )


@router.post("/refresh")
async def refresh_token(empresa = Depends(get_current_empresa), _: str = Depends(get_api_key)):
    """Fuerza la renovación del Token en el SII."""
    try:
        await token_service.get_valid_token(force_refresh=True, empresa=empresa)
        return {"message": "Token renovado exitosamente"}
    except DteEngineError as e:
        logger.warning("Error controlado renovando token", error=e.message, code=e.code)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )
    except Exception as e:
        logger.exception("Error inesperado renovando token", error_type=type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fallo renovando token SII: {str(e)}",
        )


@router.post("/validate", response_model=CertTestResponse)
async def validate_cert(req: CertTestRequest, _: str = Depends(get_api_key)):
    """
    Prueba un certificado PFX específico.
    Útil para debugging de credenciales y conectividad.
    """
    try:
        result = await token_service.test_pfx(req.path, req.password)
    except DteEngineError as e:
        logger.warning("Error controlado validando certificado", error=e.message, code=e.code)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )
    except Exception as e:
        logger.exception("Error inesperado validando certificado", error_type=type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Fallo validando certificado: {str(e)}",
        )
    
    return CertTestResponse(
        ok=result["ok"],
        subject=result.get("subject"),
        not_valid_after=result.get("not_valid_after"),
        token_preview=result.get("token"),
        error=result.get("error_sii") or result.get("error_interno"),
        respuesta_sii=result.get("respuesta_raw")
    )
