"""
Sube al SII el EnvioBOLETA resignado en `tools/resigned_envio_dte128.xml`.
Registra un `SiiLog` y actualiza el DTE según la respuesta.
"""
import asyncio
from lxml import etree
import hashlib
from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa, SiiLog
from app.services.xml_signer import XmlSignerService
from app.clients.upload_client import UploadClient
from app.services.token_service import token_service
from app.domain.enums import EstadoDte


async def main():
    dte_id = 128
    path = "tools/resigned_envio_dte128.xml"
    with open(path, "r", encoding="latin-1") as fh:
        xml_content = fh.read()

    async with async_session_factory() as session:
        dte = await session.get(Dte, dte_id)
        if not dte:
            print(f"DTE {dte_id} no encontrado")
            return
        empresa = await session.get(Empresa, dte.empresa_id) if dte.empresa_id else None

        # Obtener token SII
        token = await token_service.get_valid_token(empresa=empresa)
        uploader = UploadClient()

        try:
            response_xml = await uploader.upload_dte(
                token=token,
                xml_content=xml_content,
                rut_emisor=(empresa.rut_envia if empresa is not None else None),
                rut_empresa=(empresa.rut_emisor if empresa is not None else None),
                empresa=empresa,
            )
        except Exception as e:
            print(f"Upload falló: {e}")
            return

        # Parse response
        try:
            root = etree.fromstring(response_xml.encode("utf-8"))
        except Exception:
            raw_preview = (response_xml or "")[:2000]
            log = SiiLog(
                empresa_id=empresa.id if empresa and empresa.id is not None else None,
                dte_id=dte.id,
                operacion="UPLOAD",
                request_data=xml_content,
                response_data=raw_preview,
                status_code=502,
            )
            session.add(log)
            await session.commit()
            print("SII devolvió respuesta no-XML. Ver log en DB.")
            return

        status = root.findtext('.//STATUS')
        if status == "0":
            track_id = root.findtext('.//TRACKID')
            dte.track_id = track_id
            dte.estado = EstadoDte.ENVIADO
            log = SiiLog(
                empresa_id=empresa.id if empresa and empresa.id is not None else None,
                dte_id=dte.id,
                operacion="UPLOAD",
                request_data=xml_content,
                response_data=response_xml,
                status_code=200,
            )
            session.add(log)
            await session.commit()
            print(f"Upload OK. TRACKID={track_id}")
            return
        else:
            detalle = None
            for tag in ("GLOSA", "DETAIL", "DESCRIPCION", "ERROR"):
                val = root.findtext(f".//{tag}")
                if val and val.strip():
                    detalle = f"{tag}={val.strip()}"
                    break

            upload_diag = {
                "xml_sha1": hashlib.sha1(xml_content.encode("latin-1")).hexdigest(),
            }
            request_data = xml_content
            if status == "7":
                request_data = (
                    "=== DIAGNOSTICO_UPLOAD ===\n"
                    f"XML_SHA1={upload_diag['xml_sha1']}\n\n"
                    f"{xml_content}"
                )

            dte.estado = EstadoDte.ERROR_ENVIO
            dte.glosa_sii = (
                f"Rechazo en Upload. Status: {status}. {detalle}"
                if detalle
                else f"Rechazo en Upload. Status: {status}"
            )
            log = SiiLog(
                empresa_id=empresa.id if empresa and empresa.id is not None else None,
                dte_id=dte.id,
                operacion="UPLOAD",
                request_data=request_data,
                response_data=response_xml,
                status_code=400,
            )
            session.add(log)
            await session.commit()
            print(f"SII rechazó upload. Status={status}. Ver SiiLog id={log.id}")


if __name__ == "__main__":
    asyncio.run(main())
