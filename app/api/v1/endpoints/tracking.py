"""
DTE Core Engine — Endpoint para Seguimiento (Tracking).
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_api_key, get_db_session
from app.domain.exceptions import DteEngineError
from app.services.track_service import TrackService

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/{dte_id}/estado")
async def consultar_estado_envio(
    dte_id: int,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """
    Consulta el estado de un envío de DTE en el SII y actualiza la base de datos local.
    """
    try:
        resultado = await TrackService.consultar_estado_envio(db, dte_id)
        return resultado
    except ValueError as e:
        logger.warning("Solicitud de tracking inválida", dte_id=dte_id, error=str(e))
        raise HTTPException(status_code=404, detail=str(e))
    except DteEngineError as e:
        logger.error("Error al consultar track id en SII", dte_id=dte_id, error=e.message)
        raise HTTPException(status_code=400, detail=e.message)
    except Exception as e:
        logger.error("Error inesperado en tracking", dte_id=dte_id, error=str(e))
        raise HTTPException(status_code=500, detail="Error interno al consultar el SII")
