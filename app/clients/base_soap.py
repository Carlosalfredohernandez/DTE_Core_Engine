"""
DTE Core Engine — Cliente SOAP Base

Wrapper para la librería zeep con configuración de timeouts, transporte y
deshabilitación temporal de verificación estricta de SSL si es necesario
(el SII a veces tiene problemas de cadena de certificados en el ambiente Maullín).
"""

import httpx
import structlog
from zeep import AsyncClient, Settings
from zeep.transports import AsyncTransport

logger = structlog.get_logger(__name__)

def create_soap_client(wsdl_url: str) -> AsyncClient:
    """
    Crea un cliente SOAP asíncrono configurado para el SII.
    """
    # Configuramos httpx para ignorar la verificación SSL en caso de
    # certificados autofirmados del SII (frecuente en ambiente de certificación).
    # Para producción estricta, esto debe estar en True o con el bundle correcto.
    http_client = httpx.AsyncClient(verify=False, timeout=30.0)
    
    transport = AsyncTransport(client=http_client)
    
    # Settings para ser tolerantes con XML mal formado o namespaces raros
    settings = Settings(
        strict=False,
        xml_huge_tree=True,
    )
    
    client = AsyncClient(
        wsdl=wsdl_url,
        transport=transport,
        settings=settings
    )
    return client
