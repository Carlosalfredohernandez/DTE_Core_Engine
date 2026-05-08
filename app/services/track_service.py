"""
DTE Core Engine — Servicio para consulta de estado de DTEs en el SII.
"""

from __future__ import annotations

import hashlib
import structlog
from lxml import etree
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.query_client import QueryClient
from app.config import get_settings
from app.domain.enums import EstadoDte, EstadoSii
from app.domain.exceptions import SiiQueryError
from app.domain.models import Dte, SiiLog
from app.services.caf_service import CafService
from app.services.token_service import token_service
from app.services.xml_signer import XmlSignerService

logger = structlog.get_logger(__name__)
settings = get_settings()

class TrackService:
    """Orquestador para consultar Track IDs y actualizar la DB."""

    @staticmethod
    def _signature_summary(xml_text: str) -> dict:
        checks = XmlSignerService.verify_signatures(xml_text)
        return {
            "total_firmas": len(checks),
            "firmas_validas": sum(1 for c in checks if c.get("digest_ok") and c.get("signature_ok")),
            "detalles": checks,
        }

    @staticmethod
    def _build_forensic_summary(dte: Dte) -> dict | None:
        xml = dte.xml_envio or dte.xml_documento
        if not xml:
            return None

        forensic: dict[str, object] = {
            "sha1_xml": hashlib.sha1(xml.encode("latin-1")).hexdigest(),
            "largo_xml": len(xml),
            "firma_local": TrackService._signature_summary(xml),
            "ted_local": CafService.verify_ted_signature(xml),
            "ted_debug": CafService.ted_debug_payload(xml),
            "analisis_xml_envio": TrackService._analyze_xml_envio(dte.xml_envio),
        }

        try:
            root = etree.fromstring(xml.encode("latin-1"))
            forensic["signature_nodes"] = len(list(root.iter("{http://www.w3.org/2000/09/xmldsig#}Signature")))
        except Exception as e:
            forensic["parse_error"] = str(e)

        return forensic

    @staticmethod
    def _analyze_xml_envio(xml_envio: str | None) -> dict | None:
        if not xml_envio:
            return None
        try:
            line_lengths = [len(line) for line in xml_envio.splitlines()] or [len(xml_envio)]
            max_line_length = max(line_lengths)

            root = etree.fromstring(xml_envio.encode("latin-1"))
            sii_ns = "http://www.sii.cl/SiiDte"
            ns = {"sii": sii_ns}

            fch_emis = root.findtext(".//sii:Documento/sii:Encabezado/sii:IdDoc/sii:FchEmis", namespaces=ns)
            fa_caf = root.findtext(".//sii:TED/sii:DD/sii:CAF/sii:DA/sii:FA", namespaces=ns)
            tipo_dte = root.findtext(".//sii:Documento/sii:Encabezado/sii:IdDoc/sii:TipoDTE", namespaces=ns)
            ind_mnt_neto = root.findtext(".//sii:Documento/sii:Encabezado/sii:IdDoc/sii:IndMntNeto", namespaces=ns)

            rut_envia_car = root.findtext(".//sii:SetDTE/sii:Caratula/sii:RutEnvia", namespaces=ns)
            fch_resol_car = root.findtext(".//sii:SetDTE/sii:Caratula/sii:FchResol", namespaces=ns)
            nro_resol_car = root.findtext(".//sii:SetDTE/sii:Caratula/sii:NroResol", namespaces=ns)

            mnt_neto_txt = root.findtext(".//sii:Documento/sii:Encabezado/sii:Totales/sii:MntNeto", namespaces=ns)
            iva_txt = root.findtext(".//sii:Documento/sii:Encabezado/sii:Totales/sii:IVA", namespaces=ns)
            mnt_total_txt = root.findtext(".//sii:Documento/sii:Encabezado/sii:Totales/sii:MntTotal", namespaces=ns)

            detalle_txt = [
                (el.text or "").strip()
                for el in root.findall(".//sii:Documento/sii:Detalle/sii:MontoItem", namespaces=ns)
            ]

            rut_recep = root.findtext(".//sii:Documento/sii:Encabezado/sii:Receptor/sii:RUTRecep", namespaces=ns)
            rr_ted = root.findtext(".//sii:TED/sii:DD/sii:RR", namespaces=ns)

            def _to_int(v: str | None) -> int | None:
                if v is None or v == "":
                    return None
                try:
                    return int(v)
                except ValueError:
                    return None

            mnt_neto = _to_int(mnt_neto_txt)
            iva = _to_int(iva_txt)
            mnt_total = _to_int(mnt_total_txt)
            detalle_vals = [_to_int(v) for v in detalle_txt]
            detalle_vals = [v for v in detalle_vals if v is not None]

            checks: dict[str, bool | None] = {}
            checks["fecha_emision_ge_fa_caf"] = (fch_emis >= fa_caf) if (fch_emis and fa_caf) else None
            checks["rut_receptor_matches_ted_rr"] = (rut_recep == rr_ted) if (rut_recep and rr_ted) else None
            checks["sum_detalle_equals_mnttotal"] = (
                sum(detalle_vals) == mnt_total if (detalle_vals and mnt_total is not None) else None
            )
            checks["max_line_length_le_4090"] = max_line_length <= 4090
            checks["caratula_rutenvia_matches_settings"] = (
                rut_envia_car == settings.rut_envia.replace(".", "") if rut_envia_car else None
            )
            checks["caratula_fchresol_matches_settings"] = (
                fch_resol_car == settings.sii_fecha_resolucion if fch_resol_car else None
            )
            checks["caratula_nroresol_matches_settings"] = (
                str(nro_resol_car) == str(settings.sii_numero_resolucion) if nro_resol_car else None
            )

            if ind_mnt_neto == "2":
                checks["sum_detalle_equals_mntneto"] = (
                    sum(detalle_vals) == mnt_neto if (detalle_vals and mnt_neto is not None) else None
                )
                checks["mntneto_plus_iva_equals_mnttotal"] = (
                    (mnt_neto + iva) == mnt_total
                    if (mnt_neto is not None and iva is not None and mnt_total is not None)
                    else None
                )

            return {
                "tipo_dte": tipo_dte,
                "fch_emis": fch_emis,
                "fa_caf": fa_caf,
                "ind_mnt_neto": ind_mnt_neto,
                "rut_envia_caratula": rut_envia_car,
                "fch_resol_caratula": fch_resol_car,
                "nro_resol_caratula": nro_resol_car,
                "rut_recep": rut_recep,
                "rr_ted": rr_ted,
                "max_line_length": max_line_length,
                "mnt_neto": mnt_neto,
                "iva": iva,
                "mnt_total": mnt_total,
                "detalle_montos": detalle_vals,
                "checks": checks,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _split_rut(rut: str) -> tuple[str, str]:
        limpio = (rut or "").replace(".", "").strip()
        if "-" in limpio:
            r, dv = limpio.split("-", 1)
            return r, dv.upper()
        return limpio, ""

    @staticmethod
    def _find_text_by_localname(root: etree._Element, tag: str) -> str | None:
        for el in root.iter():
            if etree.QName(el).localname == tag:
                return (el.text or "").strip() or None
        return None

    @staticmethod
    async def consultar_estado_envio(session: AsyncSession, dte_id: int) -> dict:
        """
        Consulta el TrackID de un DTE enviado usando QueryEstUp.
        """
        dte = await session.get(Dte, dte_id)
        if not dte or not dte.track_id:
            raise ValueError("DTE no encontrado o no tiene TrackID asignado")

        token = await token_service.get_valid_token()
        client = QueryClient()
        debug_enabled = settings.sii_debug_tracking

        rut_sin_dv = settings.rut_emisor.split("-")[0]
        dv = settings.rut_emisor.split("-")[1]

        try:
            response_xml = await client.get_est_up(
                rut_empresa=rut_sin_dv,
                dv_empresa=dv,
                track_id=dte.track_id,
                token=token
            )

            logger.info("Respuesta raw QueryEstUp", track_id=dte.track_id, response=response_xml[:500])

            # El SII devuelve elementos con prefijo SII: (namespace http://www.sii.cl/XMLSchema).
            # Usamos un parser con recover=True y buscamos por localname para ser
            # independientes del namespace.
            parser = etree.XMLParser(recover=True)
            root = etree.fromstring(response_xml.encode("utf-8"), parser)

            # La respuesta real del SII usa <ESTADO> y <GLOSA> dentro de RESP_HDR
            estado_envio = TrackService._find_text_by_localname(root, "ESTADO")
            desc_estado = TrackService._find_text_by_localname(root, "GLOSA")

            # Extraer todas las claves del RESP_HDR para diagnóstico completo
            resp_hdr_data: dict[str, str] = {}
            for el in root.iter():
                if etree.QName(el).localname == "RESP_HDR":
                    for child in el:
                        key = etree.QName(child).localname
                        value = (child.text or "").strip()
                        if key and value:
                            resp_hdr_data[key] = value
                    break

            detalle_dte: dict | None = None
            if estado_envio in (EstadoSii.RECHAZADO_SCHEMA, EstadoSii.RECHAZADO, "RFR"):
                # Si el sobre fue rechazado, pedimos detalle por documento para
                # obtener código/glosa específica (schema, firma, datos, etc.).
                rut_cons_envia, dv_cons_envia = TrackService._split_rut(settings.rut_envia)
                rut_cons_emisor, dv_cons_emisor = TrackService._split_rut(settings.rut_emisor)
                rut_rec, dv_rec = TrackService._split_rut(dte.rut_receptor or "66666666-6")
                monto = str(int(float(dte.monto_total)))
                fecha = dte.fecha_emision.strftime("%Y-%m-%d")

                try:
                    async def _query_est_dte(rut_consultante: str, dv_consultante: str) -> tuple[str, str | None, str | None, str | None]:
                        raw = await client.get_est_dte(
                            rut_consultante=rut_consultante,
                            dv_consultante=dv_consultante,
                            rut_empresa=rut_sin_dv,
                            dv_empresa=dv,
                            rut_receptor=rut_rec,
                            dv_receptor=dv_rec,
                            tipo_dte=str(dte.tipo_dte),
                            folio_dte=str(dte.folio),
                            fecha_emision_dte=fecha,
                            monto_dte=monto,
                            token=token,
                        )
                        parsed = etree.fromstring(raw.encode("utf-8"), parser)
                        estado = TrackService._find_text_by_localname(parsed, "ESTADO")
                        glosa = TrackService._find_text_by_localname(parsed, "GLOSA")
                        codigo = TrackService._find_text_by_localname(parsed, "CODIGO") or TrackService._find_text_by_localname(parsed, "CODIGO_RESPUESTA")
                        return raw, estado, glosa, codigo

                    raw_1, est_1, glo_1, cod_1 = await _query_est_dte(rut_cons_envia, dv_cons_envia)

                    # Fallback: algunos contribuyentes requieren RutConsultante=RutEmisor
                    raw_2 = est_2 = glo_2 = cod_2 = None
                    if est_1 == "2":
                        raw_2, est_2, glo_2, cod_2 = await _query_est_dte(rut_cons_emisor, dv_cons_emisor)

                    # Elegir mejor respuesta disponible (distinta de ERROR INTERNO)
                    best_raw, best_est, best_glo, best_cod = raw_1, est_1, glo_1, cod_1
                    if est_2 and est_2 != "2":
                        best_raw, best_est, best_glo, best_cod = raw_2, est_2, glo_2, cod_2

                    detalle_dte = {
                        "estado_dte": best_est,
                        "glosa_dte": best_glo,
                        "cod_resp_dte": best_cod,
                    }
                    if debug_enabled:
                        detalle_dte["respuesta_raw_dte"] = best_raw
                        detalle_dte["debug_query_est_dte"] = {
                            "consulta_con_rut_envia": {
                                "rut_consultante": f"{rut_cons_envia}-{dv_cons_envia}",
                                "estado": est_1,
                                "glosa": glo_1,
                            },
                            "consulta_con_rut_emisor": {
                                "rut_consultante": f"{rut_cons_emisor}-{dv_cons_emisor}",
                                "estado": est_2,
                                "glosa": glo_2,
                            },
                        }

                    session.add(
                        SiiLog(
                            dte_id=dte.id,
                            operacion="QUERY_EST_DTE",
                            request_data=(
                                f"TipoDte: {dte.tipo_dte}, Folio: {dte.folio}, Fecha: {fecha}, "
                                f"Monto: {monto}, RutReceptor: {dte.rut_receptor}"
                            ),
                            response_data=best_raw,
                            status_code=200,
                        )
                    )
                except Exception as e:
                    logger.warning("No se pudo obtener detalle QueryEstDte", dte_id=dte.id, error=str(e))

            logger.info("Estado QueryEstUp parseado", estado_envio=estado_envio, desc_estado=desc_estado)

            log = SiiLog(
                dte_id=dte.id,
                operacion="QUERY_EST_UP",
                request_data=f"TrackID: {dte.track_id}",
                response_data=response_xml,
                status_code=200
            )
            session.add(log)

            # Mapear estado
            if estado_envio == EstadoSii.ACEPTADO:
                dte.estado = EstadoDte.ACEPTADO
            elif estado_envio in (EstadoSii.RECHAZADO_SCHEMA, EstadoSii.RECHAZADO, "RFR"):
                dte.estado = EstadoDte.RECHAZADO
            elif estado_envio == EstadoSii.ACEPTADO_CON_REPAROS:
                dte.estado = EstadoDte.REPARO
            
            dte.glosa_sii = desc_estado
            
            await session.commit()
            
            result = {
                "track_id": dte.track_id,
                "estado_sii": estado_envio,
                "glosa": desc_estado,
                "estado_interno": dte.estado,
                "detalle_estup": {
                    "resp_hdr": resp_hdr_data,
                },
                "detalle_dte": detalle_dte,
            }

            if estado_envio in (EstadoSii.RECHAZADO_SCHEMA, EstadoSii.RECHAZADO, "RFR"):
                result["diagnostico_local"] = TrackService._build_forensic_summary(dte)

            if debug_enabled:
                result["detalle_estup"]["respuesta_raw_estup"] = response_xml
                result["debug_xml_envio"] = TrackService._analyze_xml_envio(dte.xml_envio)
            return result

        except Exception as e:
            await session.rollback()
            raise SiiQueryError(f"Error consultando estado: {str(e)}") from e
