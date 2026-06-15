"""
DTE Core Engine — Cliente SOAP para CrSeed (Obtener Semilla).
"""

import structlog

from app.clients.base_soap import create_soap_client
from app.config import get_settings
from app.domain.exceptions import SiiSeedError
from app.domain.models import Empresa
from app.infrastructure.retry import sii_retry

logger = structlog.get_logger(__name__)
settings = get_settings()


class SeedClient:
    """Cliente para el servicio CrSeed.jws del SII."""

    def __init__(self):
        self._client = None
        self._client_wsdl_url: str | None = None

    async def _get_client(self, empresa: Empresa | None = None):
        ambiente = empresa.sii_ambiente if empresa is not None else None
        wsdl_url = settings.sii_wsdl_seed_for(ambiente)
        if self._client is None or self._client_wsdl_url != wsdl_url:
            self._client = create_soap_client(wsdl_url)
            self._client_wsdl_url = wsdl_url
        return self._client

    @sii_retry
    async def get_seed(self, empresa: Empresa | None = None) -> str:
        """
        Obtiene una semilla (seed) desde el SII.
        La semilla viene en un XML dentro de la respuesta SOAP.
        
        Returns:
            str: XML crudo retornado por el SII que contiene la semilla.
        """
        client = await self._get_client(empresa=empresa)
        logger.info("Solicitando semilla al SII", wsdl=self._client_wsdl_url)

        try:
            # El método en el WSDL se llama getSeed
            response = await client.service.getSeed()
            
            if not response:
                raise SiiSeedError("Respuesta vacía desde CrSeed")

            # El SII retorna un string que contiene un XML, por ejemplo:
            # <?xml version="1.0" encoding="UTF-8"?><SII:RESPUESTA xmlns:SII="http://www.sii.cl/XMLSchema"><SII:RESP_BODY><SEMILLA>0321321</SEMILLA></SII:RESP_BODY><SII:RESP_HDR><ESTADO>00</ESTADO></SII:RESP_HDR></SII:RESPUESTA>
            logger.debug("Semilla obtenida", xml_response=response)
            return response

        except Exception as e:
            logger.error("Error al obtener semilla", error=str(e))
            raise SiiSeedError(f"Falla de comunicación SOAP: {str(e)}") from e
