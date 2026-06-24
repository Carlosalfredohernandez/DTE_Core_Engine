"""Reconstruye un envío usando un template aceptado por el SII, reemplaza el <Documento>
por nuestro Documento generado y realiza resign+upload.

Uso:
  python tools/rebuild_from_template_and_upload.py --template tools\accepted_extracted.xml

Requisitos:
  Ejecutar desde la raíz del repo con PYTHONPATH, y variable CERT_MASTER_KEY definida.
"""
from __future__ import annotations
import argparse
import hashlib
from lxml import etree
from pathlib import Path
import asyncio

from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa
from app.infrastructure.certificate import load_pfx_from_empresa
from app.services.xml_signer import XmlSignerService
from app.clients.upload_client import UploadClient
from app.services.token_service import token_service


def replace_document_in_template(template_xml: str, source_envio_xml: str) -> str:
    # parse as XML fragments (template may contain multiple top-level nodes)
    parser = etree.XMLParser(recover=True, encoding='ISO-8859-1')
    # wrap in a dummy root so sibling top-level elements (e.g., DatosAdjuntos)
    # are preserved when parsing
    wrapped_tmpl = f"<root>{template_xml}</root>"
    tmpl_root = etree.fromstring(wrapped_tmpl.encode('latin-1'), parser=parser)
    src_root = etree.fromstring(f"<root>{source_envio_xml}</root>".encode('latin-1'), parser=parser)

    NS = {'sii': 'http://www.sii.cl/SiiDte'}

    # localizar el Documento en el source (EnvioBOLETA -> SetDTE -> DTE -> Documento)
    src_doc = src_root.find('.//{http://www.sii.cl/SiiDte}Documento')
    if src_doc is None:
        # intentar encontrar Documento sin prefijo
        src_doc = src_root.find('.//Documento')
    if src_doc is None:
        raise RuntimeError('No se encontró <Documento> en el envío fuente')

    # en template localizar primer elemento Documento
    tmpl_doc = tmpl_root.find('.//{http://www.sii.cl/SiiDte}Documento')
    if tmpl_doc is None:
        tmpl_doc = tmpl_root.find('.//Documento')
    if tmpl_doc is None:
        raise RuntimeError('No se encontró <Documento> en el template')

    # importar nodo: reemplazar el Documento en el árbol del template
    parent = tmpl_doc.getparent()
    index = parent.index(tmpl_doc)
    # crear una copia independiente del src_doc
    new_doc = etree.fromstring(etree.tostring(src_doc))

    # Asegurar que todos los hijos del Documento/DTE tengan el namespace
    # por defecto del SII (http://www.sii.cl/SiiDte). Si algún subelemento
    # fue creado sin namespace, el SII lo rechazará; por eso reasignamos
    # el namespace recursivamente cuando falte.
    def ensure_namespace(elem, ns_uri):
        # Cambiar tag si no tiene namespace
        if isinstance(elem.tag, str):
            q = etree.QName(elem.tag)
            if not q.namespace:
                elem.tag = f"{{{ns_uri}}}{q.localname}"
        for ch in list(elem):
            ensure_namespace(ch, ns_uri)

    SII_NS = 'http://www.sii.cl/SiiDte'
    ensure_namespace(new_doc, SII_NS)
    parent.remove(tmpl_doc)
    parent.insert(index, new_doc)

    # eliminar firmas existentes en todo el fragmento (xmldsig), las volveremos a crear
    for sig in tmpl_root.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature'):
        sig.getparent().remove(sig)

    # Forzar xsi:schemaLocation exacto en cualquier EnvioBOLETA del template
    try:
        xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance'
        sii_ns = 'http://www.sii.cl/SiiDte'
        desired = f"{sii_ns} http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd"
        for envio in tmpl_root.findall('.//{http://www.sii.cl/SiiDte}EnvioBOLETA') or tmpl_root.findall('.//EnvioBOLETA'):
            envio.set(f'{{{xsi_ns}}}schemaLocation', desired)
    except Exception:
        pass

    # serializar todos los hijos de <root> para mantener el mismo orden y
    # conservar nodos que estuvieran fuera del <DTE> (como DatosAdjuntos)
    parts = []
    for child in tmpl_root:
        # tostring may include XML declaration in some parsed fragments; remove it
        s = etree.tostring(child, encoding='ISO-8859-1').decode('latin-1')
        s = s.replace("<?xml version='1.0' encoding='ISO-8859-1'?>", '')
        s = s.replace('<?xml version="1.0" encoding="ISO-8859-1"?>', '')
        parts.append(s)

    # unir sin declaración XML (mantener formato similar al template)
    return ''.join(parts)


async def main_async(template_path: Path, dte_id: int = 132, folio: int | None = None, use_dte_id_from: Path | None = None, rut_emisor_arg: str | None = None, rut_company_arg: str | None = None):
    # cargar template
    template_xml = template_path.read_text(encoding='latin-1')

    # obtener nuestro Documento desde tools/resigned_envio_dte{dte_id}.xml si existe
    source_path = Path(f'tools/resigned_envio_dte{dte_id}.xml')
    if use_dte_id_from is not None:
        source_path = use_dte_id_from
    if not source_path.exists():
        raise SystemExit(f'No se encontró el archivo fuente: {source_path}')
    source_xml = source_path.read_text(encoding='latin-1')

    # si se solicita, actualizar folio y Documento@ID en el XML fuente antes de reemplazar
    if folio is not None:
        parser = etree.XMLParser(recover=True, encoding='ISO-8859-1')
        # parsear el fragmento fuente (puede contener múltiples nodos)
        src_body = source_xml
        if '<?xml' in src_body:
            src_body = src_body.split('?>', 1)[-1]
        wrapped_src = f"<root>{src_body}</root>"
        src_root = etree.fromstring(wrapped_src.encode('latin-1'), parser=parser)
        # buscar Documento y TipoDTE
        doc = src_root.find('.//{http://www.sii.cl/SiiDte}Documento') or src_root.find('.//Documento')
        tipo = src_root.find('.//{http://www.sii.cl/SiiDte}TipoDTE') or src_root.find('.//TipoDTE')
        tipo_val = tipo.text if tipo is not None else None
        if doc is not None and tipo_val is not None:
            doc.set('ID', f'T{tipo_val}F{folio}')
        # actualizar <Folio>
        folio_node = src_root.find('.//{http://www.sii.cl/SiiDte}Folio') or src_root.find('.//Folio')
        if folio_node is not None:
            folio_node.text = str(folio)
        # serializar de vuelta
        parts = []
        for child in src_root:
            parts.append(etree.tostring(child, encoding='ISO-8859-1').decode('latin-1'))
        source_xml = ''.join(parts)

    rebuilt = replace_document_in_template(template_xml, source_xml)

    out_rebuilt = Path('tools/rebuilt_envio_from_template.xml')
    out_rebuilt.write_text(rebuilt, encoding='latin-1')
    print('Reconstruido guardado en:', out_rebuilt)
    print('SHA1:', hashlib.sha1(rebuilt.encode('latin-1')).hexdigest())

    # cargar empresa y certificado como en resign_and_upload_132.py
    async with async_session_factory() as session:
        # intentar obtener DTE solicitado solo para obtener empresa
        dte = await session.get(Dte, dte_id)
        empresa = await session.get(Empresa, dte.empresa_id) if dte and dte.empresa_id else None

        cert_data = None
        try:
            cert_data = load_pfx_from_empresa(empresa) if empresa else load_pfx_from_empresa(None)
        except Exception as e:
            print('No pude cargar .pfx de la empresa:', e)
            raise

        # firmar solo el nodo <DTE> (o el <Documento> dentro) y reinsertarlo
        parser = etree.XMLParser(recover=True, encoding='ISO-8859-1')
        wrapped = f"<root>{rebuilt}</root>"
        root = etree.fromstring(wrapped.encode('latin-1'), parser=parser)

        # localizar el elemento Documento para obtener ID y decidir referencia
        doc_elem = root.find('.//{http://www.sii.cl/SiiDte}Documento') or root.find('.//Documento')
        doc_id = doc_elem.get('ID') if doc_elem is not None else None
        reference_uri = f'#{doc_id}' if doc_id else '#SetDoc'

        # localizar el elemento DTE a firmar (puede ser el propio DTE o solo el Documento)
        dte_elem = root.find('.//{http://www.sii.cl/SiiDte}DTE') or root.find('.//DTE')
        elem_to_sign = dte_elem if dte_elem is not None else (doc_elem if doc_elem is not None else None)
        if elem_to_sign is None:
            raise RuntimeError('No se encontró elemento DTE ni Documento para firmar')

        # serializar el elemento a firmar
        elem_str = etree.tostring(elem_to_sign, encoding='ISO-8859-1').decode('latin-1')

        # firmar el fragmento (XmlSignerService espera un documento XML válido)
        signed_fragment = XmlSignerService.sign_document(elem_str, cert_data, reference_uri=reference_uri, empresa=empresa, si_c14n_doc_context=True)

        # signed_fragment contiene una declaración XML seguida del contenido canónico;
        # quitar la declaración si existe y parsear el fragmento firmado
        if signed_fragment.startswith('<?xml'):
            signed_body = signed_fragment.split('?>', 1)[1]
        else:
            signed_body = signed_fragment
        signed_node = etree.fromstring(signed_body.encode('latin-1'))

        # reemplazar el elemento original por el firmado en el árbol
        parent = elem_to_sign.getparent()
        if parent is None:
            # elem_to_sign es root; crear nuevo root con el firmado
            new_root = signed_node
        else:
            parent_index = parent.index(elem_to_sign)
            parent.remove(elem_to_sign)
            parent.insert(parent_index, signed_node)

        # serializar todos los hijos de <root> para obtener el documento final
        final_parts = []
        for child in root:
            final_parts.append(etree.tostring(child, encoding='ISO-8859-1'))
        final_doc = b"".join(final_parts).decode('latin-1')

        # Normalizar: eliminar declaraciones XML internas y dejar una sola al inicio
        cleaned = final_doc.replace("<?xml version='1.0' encoding='ISO-8859-1'?>", '')
        cleaned = cleaned.replace('<?xml version="1.0" encoding="ISO-8859-1"?>', '')
        cleaned = cleaned.strip()
        cleaned = '<?xml version="1.0" encoding="ISO-8859-1"?>\n' + cleaned

        out_signed = Path('tools/rebuilt_resigned_envio.xml')
        out_signed.write_text(cleaned, encoding='latin-1')
        print('Reconstruido resignado guardado en:', out_signed)

        # Asegurar que el contenido a subir sea un EnvioBOLETA con schemaLocation exacto
        # Buscar la etiqueta real '<EnvioBOLETA' o con prefijo 'sii:EnvioBOLETA' para evitar falsos positivos
        if ('<EnvioBOLETA' not in cleaned) and ('<sii:EnvioBOLETA' not in cleaned):
            xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance'
            sii_ns = 'http://www.sii.cl/SiiDte'
            desired = f'{sii_ns} http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd'
            wrapped = '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
            wrapped += f'<EnvioBOLETA xmlns="{sii_ns}" xmlns:xsi="{xsi_ns}" xsi:schemaLocation="{desired}">\n'
            wrapped += cleaned.split('?>',1)[-1]
            wrapped += '\n</EnvioBOLETA>'
            signed = wrapped
        else:
            signed = cleaned

        # subir
        token = await token_service.get_valid_token(empresa=empresa)
        uploader = UploadClient()

        # Preparar valores rut_emisor/rut_empresa (pueden venir de BD o de args/fallback)
        rut_emisor_val = None
        rut_empresa_val = None
        # si se pasaron por CLI, priorizarlos
        if rut_emisor_arg:
            rut_emisor_val = rut_emisor_arg
        if rut_company_arg:
            rut_empresa_val = rut_company_arg

        # Si no se proporcionaron y no hay empresa, extraer del XML
        if empresa is None and (not rut_emisor_val or not rut_empresa_val):
            try:
                parser2 = etree.XMLParser(recover=True, encoding='ISO-8859-1')
                doc_root = etree.fromstring(signed.encode('latin-1'), parser=parser2)
                rut_node = doc_root.find('.//{http://www.sii.cl/SiiDte}RUTEmisor') or doc_root.find('.//RUTEmisor')
                if rut_node is not None and (rut_node.text or '').strip():
                    if not rut_emisor_val:
                        rut_emisor_val = rut_node.text.strip()
                    if not rut_empresa_val:
                        rut_empresa_val = rut_node.text.strip()
            except Exception:
                pass
            # fallback: intentar extraer del source_xml original
            if not rut_emisor_val or not rut_empresa_val:
                try:
                    parser3 = etree.XMLParser(recover=True, encoding='ISO-8859-1')
                    src_body2 = source_xml
                    if '<?xml' in src_body2:
                        src_body2 = src_body2.split('?>',1)[-1]
                    wrapped2 = f"<root>{src_body2}</root>"
                    src_root2 = etree.fromstring(wrapped2.encode('latin-1'), parser=parser3)
                    rut_node2 = src_root2.find('.//{http://www.sii.cl/SiiDte}RUTEmisor') or src_root2.find('.//RUTEmisor')
                    if rut_node2 is not None and (rut_node2.text or '').strip():
                        if not rut_emisor_val:
                            rut_emisor_val = rut_node2.text.strip()
                        if not rut_empresa_val:
                            rut_empresa_val = rut_node2.text.strip()
                except Exception:
                    pass

        response_xml = await uploader.upload_dte(
            token=token,
            xml_content=signed,
            rut_emisor=(empresa.rut_envia if empresa else rut_emisor_val),
            rut_empresa=(empresa.rut_emisor if empresa else rut_empresa_val),
            empresa=empresa,
        )
        print('Respuesta SII:\n', response_xml)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--template', default='tools/accepted_extracted.xml', help='Ruta al XML template extraído del envío aceptado')
    p.add_argument('--dte-id', type=int, default=132, help='ID local del DTE para obtener empresa y .pfx')
    p.add_argument('--folio', type=int, help='Folio a usar en el Documento reemplazado')
    p.add_argument('--rut-emisor', type=str, help='RUTEmisor a usar en upload cuando no haya Empresa en BD')
    p.add_argument('--rut-company', type=str, help='RUTCompany a usar en upload cuando no haya Empresa en BD')
    args = p.parse_args()
    template = Path(args.template)
    if not template.exists():
        print('Template no existe:', template)
        raise SystemExit(2)
    asyncio.run(main_async(template, dte_id=args.dte_id, folio=args.folio, rut_emisor_arg=args.rut_emisor, rut_company_arg=args.rut_company))


if __name__ == '__main__':
    main()
