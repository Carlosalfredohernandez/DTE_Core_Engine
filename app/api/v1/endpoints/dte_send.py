from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from pathlib import Path

from app.api.deps import get_api_key
from app.services.rebuild_and_upload_service import rebuild_and_upload

router = APIRouter()


class DteSendRequest(BaseModel):
    dte_id: int
    folio: int | None = None
    rut_emisor: str | None = None
    rut_company: str | None = None
    send: bool = False  # default dry-run


class DteSendResponse(BaseModel):
    rebuilt_path: str
    signed_path: str
    sha1: str
    respuesta_sii: str | None = None


@router.post('/send', response_model=DteSendResponse)
async def send_dte(req: DteSendRequest, _: str = Depends(get_api_key)):
    template = Path('tools/accepted_extracted.xml')
    if not template.exists():
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Template missing')

    try:
        result = await rebuild_and_upload(template, dte_id=req.dte_id, folio=req.folio, rut_emisor=req.rut_emisor, rut_company=req.rut_company, send=req.send)
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    return DteSendResponse(
        rebuilt_path=result['rebuilt_path'],
        signed_path=result['signed_path'],
        sha1=result['sha1'],
        respuesta_sii=result.get('respuesta_sii')
    )
