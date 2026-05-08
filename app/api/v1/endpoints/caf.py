"""
DTE Core Engine — Endpoint para CAFs.
"""

import structlog
from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.deps import get_api_key, get_db_session
from app.domain.models import Caf
from app.services.caf_service import CafService

logger = structlog.get_logger(__name__)
router = APIRouter()


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_caf(
    file: UploadFile,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """
    Sube un archivo XML de CAF descargado desde el portal del SII.
    El sistema parseará el archivo y disponibilizará el rango de folios.
    """
    if not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="El archivo debe ser un XML")

    content = await file.read()
    try:
        xml_str = content.decode("latin-1")
        # Validar y parsear
        caf_info = CafService.parse_caf_xml(xml_str)
        
        # Guardar en DB
        nuevo_caf = Caf(
            tipo_dte=caf_info["tipo_dte"],
            rango_desde=caf_info["rango"]["desde"],
            rango_hasta=caf_info["rango"]["hasta"],
            folio_actual=caf_info["rango"]["desde"],
            caf_xml=xml_str,
            activo=True
        )
        db.add(nuevo_caf)
        await db.commit()
        await db.refresh(nuevo_caf)
        
        logger.info("CAF cargado exitosamente", tipo_dte=nuevo_caf.tipo_dte, rango=f"{nuevo_caf.rango_desde}-{nuevo_caf.rango_hasta}")

        return {
            "message": "CAF cargado exitosamente",
            "id": nuevo_caf.id,
            "tipo_dte": nuevo_caf.tipo_dte,
            "rango": f"{nuevo_caf.rango_desde} al {nuevo_caf.rango_hasta}",
            "folios_disponibles": (nuevo_caf.rango_hasta - nuevo_caf.rango_desde) + 1
        }
    except Exception as e:
        await db.rollback()
        logger.error("Error procesando CAF subido", error=str(e))
        raise HTTPException(status_code=400, detail=f"Error procesando CAF: {str(e)}")


@router.get("/status")
async def status_caf(
    tipo_dte: int = 39,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Verifica la cantidad de folios disponibles para un tipo de documento."""
    stmt = select(Caf).where(Caf.tipo_dte == tipo_dte, Caf.activo == True).order_by(Caf.id.asc())
    result = await db.execute(stmt)
    cafs = result.scalars().all()
    
    disponibles = 0
    rangos = []
    
    for c in cafs:
        restantes = (c.rango_hasta - c.folio_actual) + 1
        if restantes > 0:
            disponibles += restantes
            rangos.append({
                "id": c.id,
                "rango": f"{c.rango_desde}-{c.rango_hasta}",
                "actual": c.folio_actual,
                "restantes": restantes
            })
            
    return {
        "tipo_dte": tipo_dte,
        "total_folios_disponibles": disponibles,
        "detalles": rangos
    }
