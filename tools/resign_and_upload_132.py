"""
Resigna y sube el EnvioBOLETA para DTE id=132 usando la variante de
SignedInfo canonizada en contexto de documento.

Uso: python tools/resign_and_upload_132.py
"""
import asyncio
import hashlib
from lxml import etree

from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa
from app.services.xml_builder import XmlBuilderService
from app.infrastructure.certificate import load_pfx_from_empresa
from app.services.xml_signer import XmlSignerService
from app.clients.upload_client import UploadClient
from app.services.token_service import token_service


async def main():
    dte_id = 132
    async with async_session_factory() as session:
        dte = await session.get(Dte, dte_id)
        if not dte:
            print(f"DTE {dte_id} no encontrado")
            return
        empresa = await session.get(Empresa, dte.empresa_id) if dte.empresa_id else None

        envio_xml_sin_firma = XmlBuilderService.build_envio_dte([dte.xml_documento], empresa=empresa)

        cert_data = None
        try:
            cert_data = load_pfx_from_empresa(empresa) if empresa else load_pfx_from_empresa(None)
        except Exception as e:
            print("No pude cargar .pfx de la empresa:", e)
            return

        # Intentar firmar apuntando al ID del <Documento> en vez de al SetDTE
        try:
            root = etree.fromstring(envio_xml_sin_firma.encode("latin-1"))
            # namespace local de SiiDte
            sii_ns = "{http://www.sii.cl/SiiDte}"
            doc_elem = root.find(f".//{sii_ns}Documento")
            doc_id = doc_elem.get("ID") if doc_elem is not None else None
            reference_uri = f"#{doc_id}" if doc_id else "#SetDoc"
        except Exception:
            reference_uri = "#SetDoc"

        # Primera firma: apuntar al Documento (si existe) o al SetDoc
        envio_intermedio = XmlSignerService.sign_document(
            envio_xml_sin_firma,
            cert_data,
            reference_uri=reference_uri,
            exclusive=None,
            empresa=empresa,
            si_c14n_doc_context=True,
        )

        # Segunda firma (opcional): firmar también el SetDTE para cubrir ambos casos
        try:
            envio_resignado = XmlSignerService.sign_document(
                envio_intermedio,
                cert_data,
                reference_uri="#SetDoc",
                exclusive=None,
                empresa=empresa,
                si_c14n_doc_context=True,
            )
        except Exception:
            # Si falla la segunda firma, conservar la primera
            envio_resignado = envio_intermedio

        out_path = "tools/resigned_envio_dte132.xml"
        with open(out_path, "w", encoding="latin-1") as fh:
            fh.write(envio_resignado)

        print("Resignado guardado en:", out_path)
        print("SHA1:", hashlib.sha1(envio_resignado.encode('latin-1')).hexdigest())

        # Subir
        token = await token_service.get_valid_token(empresa=empresa)
        uploader = UploadClient()
        try:
            response_xml = await uploader.upload_dte(
                token=token,
                xml_content=envio_resignado,
                rut_emisor=(empresa.rut_envia if empresa is not None else None),
                rut_empresa=(empresa.rut_emisor if empresa is not None else None),
                empresa=empresa,
            )
        except Exception as e:
            print("Upload falló:", e)
            return

        print("Respuesta SII:\n", response_xml[:2000])


if __name__ == "__main__":
    asyncio.run(main())
