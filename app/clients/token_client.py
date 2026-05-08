"""
DTE Core Engine — Cliente SOAP para GetTokenFromSeed.
"""

import structlog

from app.clients.base_soap import create_soap_client
from app.config import get_settings
from app.domain.exceptions import SiiTokenError
from app.infrastructure.retry import sii_retry

logger = structlog.get_logger(__name__)
settings = get_settings()


class TokenClient:
    """Cliente para el servicio GetTokenFromSeed.jws del SII."""

    def __init__(self):
        self.wsdl_url = settings.sii_wsdl_token
        self._client = None

    async def _get_client(self):
        if self._client is None:
            self._client = create_soap_client(self.wsdl_url)
        return self._client

    @sii_retry
    async def get_token(self, signed_seed_xml: str) -> str:
        """
        Envía la semilla firmada al SII para obtener el token.

        Args:
            signed_seed_xml: XML de la semilla firmado con el certificado digital.

        Returns:
            str: XML retornado por el SII que contiene el token.
        """
        client = await self._get_client()
        logger.info("Solicitando token al SII", wsdl=self.wsdl_url)

        try:
            logger.debug("Enviando XML firmado al SII", xml=signed_seed_xml)
            # El método SOAP se llama getToken
            response = await client.service.getToken(signed_seed_xml)

            if not response:
                raise SiiTokenError("Respuesta vacía desde GetTokenFromSeed")

            # El SII retorna un string que contiene un XML, por ejemplo:
            # <?xml version="1.0"?><SII:RESPUESTA xmlns:SII="http://www.sii.cl/XMLSchema"><SII:RESP_BODY><TOKEN>ASDQAWE...</TOKEN></SII:RESP_BODY><SII:RESP_HDR><ESTADO>00</ESTADO></SII:RESP_HDR></SII:RESPUESTA>
            logger.debug("Token response obtenida", length=len(response))
            return response

        except Exception as e:
            logger.error("Error al solicitar token", error=str(e))
            raise SiiTokenError(f"Falla de comunicación SOAP: {str(e)}") from e
