"""
DTE Core Engine — Endpoint para Boletas (Generar y Enviar).
"""

import base64
import hashlib

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from lxml import etree
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_api_key, get_db_session
from app.api.v1.schemas.boleta import (
    BoletaCreateRequest,
    BoletaResponse,
    EnviarBoletaRequest,
    EnviarBoletaResponse,
)
from app.services.xml_signer import XmlSignerService
from app.services.caf_service import CafService
from app.domain.exceptions import DteEngineError
from app.services.dte_service import DteService

logger = structlog.get_logger(__name__)
router = APIRouter()


def _signature_summary(xml_text: str) -> dict:
    checks = XmlSignerService.verify_signatures(xml_text)
    return {
        "total_firmas": len(checks),
        "firmas_validas": sum(1 for c in checks if c.get("digest_ok") and c.get("signature_ok")),
        "detalles": checks,
    }


def _xml_diff_offset(a: str, b: str) -> int | None:
    max_common = min(len(a), len(b))
    for i in range(max_common):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return max_common
    return None


def _forensic_identity(xml_text: str) -> dict:
    ns = {
        "sii": "http://www.sii.cl/SiiDte",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }
    try:
        root = etree.fromstring(xml_text.encode("latin-1"))
    except Exception as e:
        return {"error": str(e)}

    certs = [
        (el.text or "").strip()
        for el in root.findall(".//ds:X509Certificate", namespaces=ns)
        if (el.text or "").strip()
    ]
    cert_sha1 = []
    for cert_b64 in certs:
        try:
            cert_sha1.append(hashlib.sha1(base64.b64decode(cert_b64)).hexdigest())
        except Exception:
            cert_sha1.append(None)

    return {
        "rut_envia": root.findtext(".//sii:RutEnvia", namespaces=ns),
        "rut_emisor_caratula": root.findtext(".//sii:RutEmisor", namespaces=ns),
        "rut_emisor_documento": root.findtext(".//sii:RUTEmisor", namespaces=ns),
        "caf": {
            "folio_dd": root.findtext(".//sii:TED/sii:DD/sii:F", namespaces=ns),
            "desde": root.findtext(".//sii:TED/sii:DD/sii:CAF/sii:DA/sii:RNG/sii:D", namespaces=ns),
            "hasta": root.findtext(".//sii:TED/sii:DD/sii:CAF/sii:DA/sii:RNG/sii:H", namespaces=ns),
            "fa": root.findtext(".//sii:TED/sii:DD/sii:CAF/sii:DA/sii:FA", namespaces=ns),
            "idk": root.findtext(".//sii:TED/sii:DD/sii:CAF/sii:DA/sii:IDK", namespaces=ns),
        },
        "certificados_sha1": cert_sha1,
    }


@router.post("/generar", response_model=BoletaResponse, status_code=status.HTTP_201_CREATED)
async def generar_boleta(
    request: BoletaCreateRequest,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Genera el XML firmado de una Boleta Electrónica usando un CAF válido."""
    try:
        receptor_dict = request.receptor.model_dump() if request.receptor else None
        detalles_list = [d.model_dump() for d in request.detalles]

        dte = await DteService.generar_boleta(
            session=db,
            tipo_dte=request.tipo_dte,
            receptor=receptor_dict,
            detalles=detalles_list,
            fecha_emision=request.fecha_emision,
        )

        xml_b64 = None
        if dte.xml_documento:
            xml_b64 = base64.b64encode(dte.xml_documento.encode("utf-8")).decode("utf-8")

        return BoletaResponse(
            id=dte.id,
            tipo_dte=dte.tipo_dte,
            folio=dte.folio,
            estado=dte.estado,
            monto_total=dte.monto_total,
            fecha_emision=dte.fecha_emision,
            xml_base64=xml_b64,
        )
    except DteEngineError as e:
        logger.warning("Error controlado generando boleta", error=e.message)
        raise HTTPException(status_code=400, detail=e.message)


@router.get("/{id}", response_model=BoletaResponse)
async def obtener_boleta(
    id: int,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Obtiene los detalles de una boleta por su ID, incluyendo el XML en Base64."""
    from app.domain.models import Dte
    dte = await db.get(Dte, id)
    if not dte:
        raise HTTPException(status_code=404, detail="Boleta no encontrada")

    xml_b64 = None
    if dte.xml_documento:
        xml_b64 = base64.b64encode(dte.xml_documento.encode("utf-8")).decode("utf-8")

    return BoletaResponse(
        id=dte.id,
        tipo_dte=dte.tipo_dte,
        folio=dte.folio,
        estado=dte.estado,
        monto_total=dte.monto_total,
        fecha_emision=dte.fecha_emision,
        xml_base64=xml_b64,
    )


@router.get("/{id}/xml", response_class=PlainTextResponse)
async def obtener_xml_boleta(
    id: int,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Devuelve el XML crudo del envío (o del documento) de una boleta para debugging."""
    from app.domain.models import Dte
    dte = await db.get(Dte, id)
    if not dte:
        raise HTTPException(status_code=404, detail="Boleta no encontrada")
    xml = dte.xml_envio or dte.xml_documento or ""
    return PlainTextResponse(content=xml, media_type="text/xml; charset=utf-8")


@router.get("/{id}/log", response_class=PlainTextResponse)
async def obtener_log_boleta(
    id: int,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Devuelve el último log de UPLOAD del SII (XML enviado + respuesta raw) para debugging."""
    from app.domain.models import SiiLog
    from sqlalchemy import select, desc
    stmt = select(SiiLog).where(
        SiiLog.dte_id == id,
        SiiLog.operacion == "UPLOAD"
    ).order_by(desc(SiiLog.id)).limit(1)
    result = await db.execute(stmt)
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="No hay logs de upload para esta boleta")
    content = (
        "=== REQUEST (XML enviado al SII) ===\n"
        f"{log.request_data}\n\n"
        "=== RESPONSE (respuesta raw del SII) ===\n"
        f"{log.response_data}"
    )
    return PlainTextResponse(content=content, media_type="text/plain; charset=utf-8")


@router.get("/{id}/firma-diagnostico")
async def diagnostico_firma_boleta(
    id: int,
    comparar_con: int | None = None,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Entrega diagnóstico de firma local del XML de envío y comparación opcional entre DTEs."""
    from app.domain.models import Dte

    dte = await db.get(Dte, id)
    if not dte:
        raise HTTPException(status_code=404, detail="Boleta no encontrada")

    xml_base = dte.xml_envio or dte.xml_documento
    if not xml_base:
        raise HTTPException(status_code=404, detail="La boleta no tiene XML disponible")

    base_diag = {
        "dte_id": dte.id,
        "track_id": dte.track_id,
        "estado": dte.estado,
        "sha1_xml": hashlib.sha1(xml_base.encode("latin-1")).hexdigest(),
        "largo_xml": len(xml_base),
        "firma_local": _signature_summary(xml_base),
        "ted_local": CafService.verify_ted_signature(xml_base),
        "ted_debug": CafService.ted_debug_payload(xml_base),
        "forense": _forensic_identity(xml_base),
    }

    try:
        root = etree.fromstring(xml_base.encode("latin-1"))
        base_diag["signature_nodes"] = len(list(root.iter("{http://www.w3.org/2000/09/xmldsig#}Signature")))
    except Exception as e:
        base_diag["parse_error"] = str(e)

    if comparar_con is None:
        return {"base": base_diag}

    other = await db.get(Dte, comparar_con)
    if not other:
        raise HTTPException(status_code=404, detail=f"Boleta de comparación no encontrada: {comparar_con}")

    xml_other = other.xml_envio or other.xml_documento
    if not xml_other:
        raise HTTPException(status_code=404, detail="La boleta de comparación no tiene XML disponible")

    other_diag = {
        "dte_id": other.id,
        "track_id": other.track_id,
        "estado": other.estado,
        "sha1_xml": hashlib.sha1(xml_other.encode("latin-1")).hexdigest(),
        "largo_xml": len(xml_other),
        "firma_local": _signature_summary(xml_other),
        "ted_local": CafService.verify_ted_signature(xml_other),
        "ted_debug": CafService.ted_debug_payload(xml_other),
        "forense": _forensic_identity(xml_other),
    }

    diff_offset = _xml_diff_offset(xml_base, xml_other)
    return {
        "base": base_diag,
        "comparado": other_diag,
        "diff": {
            "primer_offset_diferente": diff_offset,
            "iguales": diff_offset is None,
        },
    }


@router.get("/{id}/xml-raw")
async def obtener_xml_crudo(
    id: int,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Retorna el XML crudo (envio o documento) de una boleta en formato texto plano."""
    from app.domain.models import Dte
    dte = await db.get(Dte, id)
    if not dte:
        raise HTTPException(status_code=404, detail="Boleta no encontrada")

    xml_content = dte.xml_envio or dte.xml_documento
    if not xml_content:
        raise HTTPException(status_code=404, detail="La boleta no tiene XML disponible")

    return PlainTextResponse(content=xml_content, media_type="application/xml; charset=utf-8")


@router.post("/enviar", response_model=EnviarBoletaResponse)
async def enviar_boleta(
    request: EnviarBoletaRequest,
    db: AsyncSession = Depends(get_db_session),
    _: str = Depends(get_api_key),
):
    """Envía una boleta generada previamente al SII."""
    try:
        dte = await DteService.enviar_boleta(db, request.dte_id)
        
        return EnviarBoletaResponse(
            dte_id=dte.id,
            track_id=dte.track_id,
            estado=dte.estado,
            glosa_sii=dte.glosa_sii,
        )
    except DteEngineError as e:
        logger.error("Error al enviar boleta", error=e.message)
        raise HTTPException(status_code=400, detail=e.message)
    except Exception as e:
        logger.error("Error inesperado al enviar boleta", error=str(e))
        raise HTTPException(status_code=500, detail="Error interno al enviar al SII")
