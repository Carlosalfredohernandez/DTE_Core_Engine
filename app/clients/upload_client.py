"""
DTE Core Engine — Cliente para subida (Upload) de documentos al SII.
"""

from __future__ import annotations

import structlog
import httpx

from app.config import get_settings
from app.domain.exceptions import SiiUploadError
from app.infrastructure.retry import sii_retry

logger = structlog.get_logger(__name__)
settings = get_settings()


class UploadClient:
    """Cliente HTTP para subir el archivo DTE XML (multipart/form-data) al SII."""

    def __init__(self):
        self.upload_url = settings.sii_upload_url

    @sii_retry
    async def upload_dte(self, token: str, xml_content: str, rut_emisor: str, rut_empresa: str) -> str:
        """
        Sube un documento XML firmado al SII mediante POST multipart.
        
        Args:
            token: Token válido obtenido del SII.
            xml_content: Contenido XML del DTE o Sobre firmado.
            rut_emisor: RUT del certificado digital que realiza el envío.
            rut_empresa: RUT de la empresa emisora del documento.

        Returns:
            str: Respuesta XML cruda del SII indicando el TrackID o error.
        """
        logger.info("Iniciando upload de DTE al SII", url=self.upload_url)

        headers = {
            "Accept": "image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-powerpoint, application/ms-excel, application/msword, */*",
            "Accept-Language": "es-cl",
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "Mozilla/4.0 (compatible; PROG 1.0; Windows NT 5.0; YComp 5.0.2.4)",
            "Connection": "Keep-Alive",
            "Cache-Control": "no-cache",
            "Cookie": f"TOKEN={token}",
        }

        # Limpiar RUTs de puntos y guiones para asegurar formato numérico
        def clean_rut(r):
            return r.replace(".", "").replace("-", "").upper()

        clean_emisor = clean_rut(rut_emisor)
        clean_empresa = clean_rut(rut_empresa)

        # En el SII DTEUpload, se envían los primeros N-1 caracteres como RUT y el último como DV
        files = {
            "rutSender": (None, clean_emisor[:-1]),
            "dvSender": (None, clean_emisor[-1]),
            "rutCompany": (None, clean_empresa[:-1]),
            "dvCompany": (None, clean_empresa[-1]),
            "archivo": ("boleta.xml", xml_content.encode("latin-1"), "text/xml"),
        }

        try:
            async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
                response = await client.post(
                    self.upload_url,
                    headers=headers,
                    files=files
                )

                # El SII devuelve código HTTP 200 aunque el contenido sea un error XML
                if response.status_code != 200:
                    logger.error("Error HTTP al subir DTE", status=response.status_code, body=response.text)
                    raise SiiUploadError(
                        f"El servidor respondió con código {response.status_code}",
                        status=response.status_code
                    )

                logger.debug("Upload completado", response=response.text)
                return response.text

        except httpx.RequestError as e:
            logger.error("Error de conexión al subir DTE", error=str(e))
            raise SiiUploadError(f"Error de conexión con el SII: {str(e)}") from e
