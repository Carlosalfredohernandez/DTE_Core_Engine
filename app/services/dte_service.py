"""
DTE Core Engine — Orquestador de Generación de DTE.
"""

import datetime
import re
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from lxml import etree
from cryptography.x509.oid import NameOID

from app.domain.enums import EstadoDte, TipoDte
from app.domain.exceptions import (
    BusinessValidationError,
    CafFoliosAgotadosError,
    CafNotFoundError,
    SiiEnvioError,
)
from app.domain.models import Caf, Dte, SiiLog
from app.infrastructure.certificate import load_pfx_from_settings
from app.config import get_settings
from app.services.caf_service import CafService
from app.services.schema_validator import validate_envio_schema
from app.services.token_service import token_service
from app.clients.upload_client import UploadClient
from app.services.xml_builder import XmlBuilderService
from app.services.xml_signer import XmlSignerService

settings = get_settings()
logger = structlog.get_logger(__name__)

class DteService:
    """Orquestador para generar y registrar DTEs."""

    @staticmethod
    def _normalize_rut(rut: str) -> str:
        return re.sub(r"[^0-9kK]", "", rut or "").upper()

    @staticmethod
    def _extract_rut_candidates_from_certificate(cert_data: Any) -> list[str]:
        """Obtiene posibles RUTs del subject del certificado X.509."""
        candidates: set[str] = set()
        rut_with_hyphen = re.compile(r"\b\d{7,8}-[0-9Kk]\b")
        rut_compact = re.compile(r"\b\d{8}[0-9Kk]\b")

        for attr in cert_data.certificate.subject:
            value = str(attr.value or "")
            for match in rut_with_hyphen.findall(value):
                norm = DteService._normalize_rut(match)
                if norm:
                    candidates.add(norm)
            for match in rut_compact.findall(value):
                norm = DteService._normalize_rut(match)
                if norm:
                    candidates.add(norm)

        return sorted(candidates)

    @staticmethod
    def _assert_sender_rut_matches_certificate(cert_data: Any) -> None:
        """Valida que RUT_ENVIA coincida con el titular del certificado digital."""
        attrs = cert_data.certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        rut_candidates = DteService._extract_rut_candidates_from_certificate(cert_data)
        rut_envia_norm = DteService._normalize_rut(settings.rut_envia)

        if not attrs and not rut_candidates:
            logger.warning(
                "El certificado no expone RUT en SERIALNUMBER/subject; se omite validación RUT_ENVIA vs certificado"
            )
            return

        # Mantener SERIALNUMBER explícito como pista principal en mensaje.
        cert_serial = attrs[0].value if attrs else ""

        if rut_envia_norm and rut_candidates and rut_envia_norm not in rut_candidates:
            raise BusinessValidationError(
                (
                    "RUT_ENVIA no coincide con el titular del certificado digital. "
                    f"RUT_ENVIA={settings.rut_envia} vs CERT_CANDIDATOS={rut_candidates} "
                    f"(SERIALNUMBER={cert_serial or 'N/A'})."
                ),
                field="rut_envia",
            )

    @staticmethod
    async def generar_boleta(
        session: AsyncSession,
        tipo_dte: TipoDte,
        receptor: dict[str, Any] | None,
        detalles: list[dict[str, Any]],
        fecha_emision: datetime.date | None = None
    ) -> Dte:
        """
        Orquesta la generación completa de una Boleta.
        """
        if not fecha_emision:
            fecha_emision = datetime.date.today()

        # 1. Obtener y reservar folio del CAF
        stmt = select(Caf).where(
            Caf.tipo_dte == tipo_dte.value,
            Caf.activo == True
        ).order_by(Caf.id.asc()).limit(1)
        
        result = await session.execute(stmt)
        caf_db = result.scalar_one_or_none()

        if not caf_db:
            raise CafNotFoundError(tipo_dte.value)

        folio = caf_db.folio_actual
        if folio > caf_db.rango_hasta:
            caf_db.activo = False
            await session.commit()
            raise CafFoliosAgotadosError(tipo_dte.value, f"{caf_db.rango_desde}-{caf_db.rango_hasta}")

        # Avanzar el folio
        caf_db.folio_actual += 1

        # 2. Parsear el XML del CAF
        caf_info = CafService.parse_caf_xml(caf_db.caf_xml)

        # Guardrail de negocio/SII: no emitir con fecha anterior a la fecha
        # de autorización del CAF (FA), porque suele terminar en rechazos
        # post-upload (RSC) sin detalle claro en QueryEstDte.
        fecha_aut = caf_info.get("fecha_autorizacion")
        if fecha_aut:
            try:
                fecha_aut_caf = datetime.date.fromisoformat(fecha_aut)
                if fecha_emision < fecha_aut_caf:
                    raise BusinessValidationError(
                        (
                            "La fecha de emisión no puede ser anterior a la fecha "
                            f"de autorización del CAF (FA={fecha_aut_caf.isoformat()})."
                        ),
                        field="fecha_emision",
                    )
            except ValueError:
                logger.warning(
                    "FA del CAF no tiene formato ISO válido; se omite validación de fecha",
                    fecha_autorizacion=fecha_aut,
                )

        # 3. Construir el XML de la Boleta (sin firma XMLDSIG)
        xml_sin_firma = XmlBuilderService.build_boleta_xml(
            folio=folio,
            fecha_emision=fecha_emision,
            tipo_dte=tipo_dte,
            receptor=receptor,
            detalles=detalles,
            caf_info=caf_info
        )

        # 4. Firmar el documento XML con el Certificado Digital (.pfx)
        cert_data = load_pfx_from_settings()
        uri_referencia = f"#T{tipo_dte.value}F{folio}"
        xml_firmado = XmlSignerService.sign_document(xml_sin_firma, cert_data, uri_referencia)

        # 5. Guardar en Base de Datos
        monto_total = sum(d["monto_item"] for d in detalles)

        # Guardar el RUT receptor efectivo del XML para mantener consistencia
        # en consultas posteriores (QueryEstDte).
        rut_receptor_xml = receptor.get("rut", "66666666-6") if receptor else "66666666-6"
        
        dte_db = Dte(
            tipo_dte=tipo_dte.value,
            folio=folio,
            rut_receptor=rut_receptor_xml,
            monto_total=monto_total,
            xml_documento=xml_firmado,
            estado=EstadoDte.GENERADO,
            fecha_emision=fecha_emision
        )
        
        # Log de generación
        log = SiiLog(
            operacion="GENERACION",
            request_data=f"Folio: {folio}, Monto: {monto_total}",
            status_code=200
        )
        dte_db.logs.append(log)

        session.add(dte_db)
        await session.commit()
        await session.refresh(dte_db)

        return dte_db

    @staticmethod
    async def enviar_boleta(session: AsyncSession, dte_id: int) -> Dte:
        """
        Toma un DTE generado, lo envuelve en un EnvioDTE, lo firma y lo envía al SII.
        """
        dte = await session.get(Dte, dte_id)
        if not dte:
            raise ValueError(f"DTE con ID {dte_id} no encontrado")
        
        if not dte.xml_documento:
            raise ValueError("El DTE no tiene XML documento generado")

        # Guardrail suave: no bloquear por una combinación específica de
        # resolución, ya que en certificación SII puede ser válida.
        if not settings.sii_fecha_resolucion:
            raise BusinessValidationError(
                "SII_FECHA_RESOLUCION es obligatoria para construir la carátula del envío.",
                field="sii_fecha_resolucion",
            )

        # 1. Construir EnvioDTE (Sobre)
        envio_xml_sin_firma = XmlBuilderService.build_envio_dte([dte.xml_documento])

        # 2. Firmar el EnvioDTE
        cert_data = load_pfx_from_settings()
        DteService._assert_sender_rut_matches_certificate(cert_data)
        envio_xml_firmado = XmlSignerService.sign_document(
            envio_xml_sin_firma, 
            cert_data, 
            reference_uri="#SetDoc" # Firma el SetDTE específicamente
        )

        # Guardrail: nunca enviar una firma suelta al SII.
        if "<EnvioBOLETA" not in envio_xml_firmado:
            raise SiiEnvioError("XML de envío inválido: no contiene EnvioBOLETA (solo Signature)")

        # Verificación local de firmas XMLDSIG antes del upload
        verificaciones = XmlSignerService.verify_signatures(envio_xml_firmado)
        for v in verificaciones:
            if not v["digest_ok"] or not v["signature_ok"]:
                logger.error(
                    "Verificación local XMLDSIG FALLÓ — no se enviará al SII",
                    reference_uri=v["reference_uri"],
                    digest_ok=v["digest_ok"],
                    digest_calculado=v["computed_digest"],
                    digest_almacenado=v["stored_digest"],
                    firma_ok=v["signature_ok"],
                    error=v.get("error"),
                    si_c14n=v.get("si_c14n_hex"),
                )
                raise SiiEnvioError(
                    f"Firma XMLDSIG inválida localmente en '{v['reference_uri']}': "
                    f"digest_ok={v['digest_ok']} firma_ok={v['signature_ok']} error={v.get('error')}"
                )
            else:
                logger.info(
                    "Verificación local XMLDSIG OK",
                    reference_uri=v["reference_uri"],
                )

        # Validación local XSD (estructura tributaria) para cortar RSC antes del SII.
        schema_errors = validate_envio_schema(envio_xml_firmado)
        if schema_errors:
            resumen = " | ".join(schema_errors[:5])
            logger.error(
                "Validación local XSD FALLÓ — no se enviará al SII",
                errores=schema_errors[:20],
            )
            raise SiiEnvioError(f"XML inválido contra XSD local: {resumen}")
        logger.info("Validación local XSD OK")

        dte.xml_envio = envio_xml_firmado

        # 3. Autenticación y Upload
        token = await token_service.get_valid_token()
        uploader = UploadClient()

        # Una respuesta típica: <RECEPCIONDTE><STATUS>0</STATUS><TRACKID>123456</TRACKID></RECEPCIONDTE>
        try:
            response_xml = await uploader.upload_dte(
                token=token,
                xml_content=envio_xml_firmado,
                rut_emisor=settings.rut_envia,
                rut_empresa=settings.rut_emisor
            )

            root = etree.fromstring(response_xml.encode("utf-8"))
            status = root.findtext(".//STATUS")

            if status == "0":
                track_id = root.findtext(".//TRACKID")
                dte.track_id = track_id
                dte.estado = EstadoDte.ENVIADO
                log = SiiLog(
                    dte_id=dte.id,
                    operacion="UPLOAD",
                    request_data=envio_xml_firmado,
                    response_data=response_xml,
                    status_code=200
                )
                session.add(log)
                await session.commit()
                return dte
            else:
                # Extraer la mejor descripción posible desde la respuesta XML
                # para no devolver solo "Status N" en errores de upload.
                detalle = None
                for tag in (
                    "GLOSA",
                    "DETAIL",
                    "DESCRIPCION",
                    "ERROR",
                    "ERRORTOKEN",
                    "RUTSENDER",
                    "RUTCOMPANY",
                ):
                    val = root.findtext(f".//{tag}")
                    if val and val.strip():
                        detalle = f"{tag}={val.strip()}"
                        break

                if not detalle:
                    # Fallback tolerante a namespaces/prefijos desconocidos.
                    for node in root.iter():
                        local = etree.QName(node).localname.upper()
                        if local in {
                            "GLOSA",
                            "DETAIL",
                            "DESCRIPCION",
                            "ERROR",
                            "ERRORTOKEN",
                            "RUTSENDER",
                            "RUTCOMPANY",
                        }:
                            text = (node.text or "").strip()
                            if text:
                                detalle = f"{local}={text}"
                                break

                # Commit ANTES de lanzar: así xml_envio y el log quedan persistidos
                # y son inspeccionables aunque la operación haya fallado.
                dte.estado = EstadoDte.ERROR_ENVIO
                dte.glosa_sii = (
                    f"Rechazo en Upload. Status: {status}. {detalle}"
                    if detalle
                    else f"Rechazo en Upload. Status: {status}"
                )
                log = SiiLog(
                    dte_id=dte.id,
                    operacion="UPLOAD",
                    request_data=envio_xml_firmado,
                    response_data=response_xml,
                    status_code=400
                )
                session.add(log)
                await session.commit()
                mensaje = (
                    f"SII rechazó el upload. Status {status}. {detalle}"
                    if detalle
                    else f"SII rechazó el upload. Status {status}"
                )
                raise SiiEnvioError(mensaje)

        except SiiEnvioError:
            raise
        except Exception as e:
            await session.rollback()
            raise e
