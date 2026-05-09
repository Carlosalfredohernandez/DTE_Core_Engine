from fastapi import APIRouter, UploadFile, Form, HTTPException, status
import base64

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
