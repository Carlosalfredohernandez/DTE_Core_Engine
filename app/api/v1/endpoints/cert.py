from fastapi import APIRouter, Depends, UploadFile, Form, HTTPException, status
import base64
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_api_key, get_current_empresa, get_db_session
from app.config import get_settings
from app.infrastructure.secrets import encrypt_secret
import os

router = APIRouter()

@router.post("/cert/upload", summary="Subir .pfx y obtener base64")
async def upload_pfx(
    file: UploadFile,
    password: str = Form(..., description="Contraseña del certificado .pfx")
):
    """
    Sube un archivo .pfx, lo convierte a base64 y muestra el resultado junto a la clave ingresada.
    Copia ambos valores y agrégalos como variables CERT_PFX_BASE64 y CERT_PFX_PASSWORD en Railway.
    """
    if not file.filename.endswith(".pfx"):
        raise HTTPException(status_code=400, detail="El archivo debe ser .pfx")

    content = await file.read()
    b64 = base64.b64encode(content).decode()

    return {
        "CERT_PFX_BASE64": b64,
        "CERT_PFX_PASSWORD": password,
        "instrucciones": "Copia estos valores y agrégalos como variables de entorno en Railway."
    }


@router.post("/cert/upload/empresa", summary="Subir .pfx y guardarlo cifrado para la empresa activa")
async def upload_pfx_empresa(
    file: UploadFile,
    password: str = Form(..., description="Contrasena del certificado .pfx"),
    db: AsyncSession = Depends(get_db_session),
    empresa = Depends(get_current_empresa),
    _: str = Depends(get_api_key),
):
    """Guarda el certificado por empresa en BD. Requiere CERT_MASTER_KEY para cifrar."""
    settings = get_settings()
    # Preferir la variable de entorno si está presente (útil para dev/run-time)
    master_key = os.environ.get("CERT_MASTER_KEY") or settings.cert_master_key
    if not master_key:
        raise HTTPException(
            status_code=400,
            detail="Falta CERT_MASTER_KEY en variables de entorno para cifrar certificados multiempresa",
        )

    if not file.filename.endswith(".pfx"):
        raise HTTPException(status_code=400, detail="El archivo debe ser .pfx")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="El archivo .pfx esta vacio")

    try:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            content,
            password.encode("utf-8") if password else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Contrasena de certificado invalida") from exc

    if not private_key or not certificate:
        raise HTTPException(status_code=400, detail="No se pudo leer el certificado .pfx")

    pfx_b64 = base64.b64encode(content).decode("utf-8")
    empresa.cert_pfx_base64 = encrypt_secret(pfx_b64, master_key)
    empresa.cert_pfx_password = encrypt_secret(password, master_key)
    empresa.cert_pfx_path = None

    await db.commit()
    await db.refresh(empresa)

    return {
        "message": "Certificado guardado cifrado para la empresa activa",
        "empresa_id": empresa.id,
        "rut_emisor": empresa.rut_emisor,
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_valid_after": certificate.not_valid_after_utc.isoformat(),
    }


@router.post("/cert/passphrase", summary="Guardar/actualizar passphrase .pfx para la empresa activa")
async def set_passphrase(
    password: str = Form(..., description="Contraseña del certificado .pfx"),
    db: AsyncSession = Depends(get_db_session),
    empresa = Depends(get_current_empresa),
    _: str = Depends(get_api_key),
):
    """
    Guarda o actualiza la passphrase del .pfx para la empresa activa.
    Requiere `CERT_MASTER_KEY` configurada para cifrar el secreto.
    Uso esperado: onboarding one-time desde backend/mobile para evitar pedir passphrase en cada venta.
    """
    settings = get_settings()
    master_key = os.environ.get("CERT_MASTER_KEY") or settings.cert_master_key
    if not master_key:
        raise HTTPException(
            status_code=400,
            detail="Falta CERT_MASTER_KEY en variables de entorno para cifrar certificados multiempresa",
        )

    if empresa is None:
        raise HTTPException(status_code=400, detail="Empresa no encontrada")

    if not getattr(empresa, "cert_pfx_base64", None):
        raise HTTPException(
            status_code=400,
            detail="No hay certificado cargado para la empresa. Use /cert/upload/empresa primero",
        )

    empresa.cert_pfx_password = encrypt_secret(password, master_key)
    await db.commit()
    await db.refresh(empresa)

    return {
        "message": "Passphrase guardada para la empresa activa",
        "empresa_id": empresa.id,
        "rut_emisor": empresa.rut_emisor,
    }
