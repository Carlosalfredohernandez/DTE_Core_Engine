"""
Prueba varias variantes de `xsi:schemaLocation` y sube el EnvioBOLETA para DTE 132.

Genera para cada variante el XML, lo resigna y lo sube registrando la respuesta.
"""
import asyncio
import hashlib
import os
from lxml import etree

from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa
from app.services.xml_builder import XmlBuilderService
from app.infrastructure.certificate import load_pfx_from_empresa
from app.services.xml_signer import XmlSignerService
from app.clients.upload_client import UploadClient
from app.services.token_service import token_service


VARIANTS = [
    # Exact tokens tried as a single-line with space
    "http://www.sii.cl/SiiDte http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd",
    "http://www.sii.cl/SiiDte https://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd",
    # No space (invalid but test)
    "http://www.sii.cl/SiiDtehttp://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd",
    # Newline between tokens (observed problematic form)
    "http://www.sii.cl/SiiDte\nhttp://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd",
    # Carriage return + newline
    "http://www.sii.cl/SiiDte\r\nhttp://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd",
    # Add ds namespace XSD as a third token
    "http://www.sii.cl/SiiDte http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd http://www.w3.org/2000/09/xmldsig# xmldsignature_v10.xsd",
    # Include ds namespace explicitly in schemaLocation mapping
    "http://www.sii.cl/SiiDte http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd http://www.w3.org/2000/09/xmldsig# http://www.w3.org/2000/09/xmldsig#",
]


async def test_variants(dte_id: int = 132):
    results = []

    async with async_session_factory() as session:
        dte = await session.get(Dte, dte_id)
        if not dte:
            print(f"DTE {dte_id} no encontrado")
            return
        empresa = await session.get(Empresa, dte.empresa_id) if dte.empresa_id else None

        # Construir envio usando builder, luego reemplazar atributo en memoria
        envio_base = XmlBuilderService.build_envio_dte([dte.xml_documento], empresa=empresa)

        for idx, variant in enumerate(VARIANTS, start=1):
            try:
                parser = etree.XMLParser(recover=True)
                root = etree.fromstring(envio_base.encode('latin-1'), parser=parser)

                xsi_ns = "http://www.w3.org/2001/XMLSchema-instance"
                # Establecer exactamente el atributo deseado
                root.set(f"{{{xsi_ns}}}schemaLocation", variant)

                envio_str = etree.tostring(root, encoding="ISO-8859-1", xml_declaration=True).decode('latin-1')

                # Firmar
                cert_data = load_pfx_from_empresa(empresa) if empresa else load_pfx_from_empresa(None)
                envio_signed = XmlSignerService.sign_document(
                    envio_str,
                    cert_data,
                    reference_uri="#SetDoc",
                    si_c14n_doc_context=True,
                    empresa=empresa,
                )

                filename = f"tools/variant_{idx}.xml"
                with open(filename, "w", encoding="latin-1") as fh:
                    fh.write(envio_signed)

                sha1 = hashlib.sha1(envio_signed.encode('latin-1')).hexdigest()

                # Upload
                token = await token_service.get_valid_token(empresa=empresa)
                uploader = UploadClient()
                response = await uploader.upload_dte(
                    token=token,
                    xml_content=envio_signed,
                    rut_emisor=(empresa.rut_envia if empresa is not None else None),
                    rut_empresa=(empresa.rut_emisor if empresa is not None else None),
                    empresa=empresa,
                )

                results.append({
                    "variant_index": idx,
                    "variant": variant,
                    "file": filename,
                    "sha1": sha1,
                    "response": response,
                })
                print(f"[{idx}] variante probada, SHA1={sha1}, respuesta corta: {response[:200]}")

            except Exception as e:
                results.append({
                    "variant_index": idx,
                    "variant": variant,
                    "error": str(e),
                })
                print(f"[{idx}] error: {e}")

    # Guardar resumen
    import json
    with open("tools/schema_variants_results.json", "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=2)

    print("Pruebas completadas. Resumen guardado en tools/schema_variants_results.json")


if __name__ == "__main__":
    asyncio.run(test_variants())
