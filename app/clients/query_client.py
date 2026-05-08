"""
DTE Core Engine — Cliente SOAP para consulta de estado de envíos.
"""

from __future__ import annotations

import structlog

from app.clients.base_soap import create_soap_client
from app.config import get_settings
from app.domain.exceptions import SiiQueryError
from app.infrastructure.retry import sii_retry

logger = structlog.get_logger(__name__)
settings = get_settings()


class QueryClient:
    """Cliente para consultar estados de envíos (QueryEstUp.jws)."""

    def __init__(self):
        self.wsdl_url_up = settings.sii_wsdl_query_est_up
        self.wsdl_url_dte = settings.sii_wsdl_query_est_dte
        self._client_up = None
        self._client_dte = None

    async def _get_client_up(self):
        if self._client_up is None:
            self._client_up = create_soap_client(self.wsdl_url_up)
        return self._client_up

    async def _get_client_dte(self):
        if self._client_dte is None:
            self._client_dte = create_soap_client(self.wsdl_url_dte)
        return self._client_dte

    @sii_retry
    async def get_est_up(self, rut_empresa: str, dv_empresa: str, track_id: str, token: str) -> str:
        """
        Consulta el estado de un envío (sobre) a través del TrackID.

        Args:
            rut_empresa: RUT de la empresa sin dígito verificador.
            dv_empresa: Dígito verificador de la empresa.
            track_id: Identificador de envío devuelto por el SII.
            token: Token de autenticación del SII.

        Returns:
            str: Respuesta XML del estado del envío.
        """
        client = await self._get_client_up()
        logger.info("Consultando estado de TrackID", track_id=track_id)

        try:
            # El método SOAP se llama getEstUp
            response = await client.service.getEstUp(
                RutCompania=rut_empresa,
                DvCompania=dv_empresa,
                TrackId=track_id,
                Token=token
            )

            if not response:
                raise SiiQueryError("Respuesta vacía desde QueryEstUp")

            logger.debug("Respuesta estado obtenida", track_id=track_id, length=len(response))
            return response

        except Exception as e:
            logger.error("Error al consultar estado de envío", error=str(e), track_id=track_id)
            raise SiiQueryError(f"Falla de comunicación SOAP: {str(e)}") from e

    @sii_retry
    async def get_est_dte(
        self,
        rut_consultante: str,
        dv_consultante: str,
        rut_empresa: str,
        dv_empresa: str,
        rut_receptor: str,
        dv_receptor: str,
        tipo_dte: str,
        folio_dte: str,
        fecha_emision_dte: str,
        monto_dte: str,
        token: str,
    ) -> str:
        """Consulta estado detallado de un DTE individual vía QueryEstDte.jws."""
        client = await self._get_client_dte()
        logger.info("Consultando estado detallado DTE", tipo_dte=tipo_dte, folio_dte=folio_dte)

        try:
            response = await client.service.getEstDte(
                RutConsultante=rut_consultante,
                DvConsultante=dv_consultante,
                RutCompania=rut_empresa,
                DvCompania=dv_empresa,
                RutReceptor=rut_receptor,
                DvReceptor=dv_receptor,
                TipoDte=tipo_dte,
                FolioDte=folio_dte,
                FechaEmisionDte=fecha_emision_dte,
                MontoDte=monto_dte,
                Token=token,
            )

            if not response:
                raise SiiQueryError("Respuesta vacía desde QueryEstDte")

            return response
        except Exception as e:
            logger.error("Error al consultar estado detallado DTE", error=str(e), tipo_dte=tipo_dte, folio_dte=folio_dte)
            raise SiiQueryError(f"Falla de comunicación SOAP QueryEstDte: {str(e)}") from e
