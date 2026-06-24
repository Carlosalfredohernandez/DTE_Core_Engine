from __future__ import annotations
import hashlib
import os
from lxml import etree
from sqlalchemy import select
from pathlib import Path
from app.infrastructure.certificate import load_pfx_from_empresa
from app.services.xml_signer import XmlSignerService
from app.clients.upload_client import UploadClient
from app.services.token_service import token_service
from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa, SiiLog


def _ensure_namespace(elem, ns_uri: str):
    if isinstance(elem.tag, str):
        q = etree.QName(elem.tag)
        if not q.namespace:
            elem.tag = f"{{{ns_uri}}}{q.localname}"
    for ch in list(elem):
        _ensure_namespace(ch, ns_uri)


def replace_document_in_template(template_xml: str, source_envio_xml: str) -> str:
    parser = etree.XMLParser(recover=True, encoding='ISO-8859-1')
    wrapped_tmpl = f"<root>{template_xml}</root>"
    tmpl_root = etree.fromstring(wrapped_tmpl.encode('latin-1'), parser=parser)
    src_wr = f"<root>{source_envio_xml}</root>"
    src_root = etree.fromstring(src_wr.encode('latin-1'), parser=parser)

    tmpl_doc = tmpl_root.find('.//{http://www.sii.cl/SiiDte}Documento') or tmpl_root.find('.//Documento')
    if tmpl_doc is None:
        raise RuntimeError('No se encontró <Documento> en el template')

    src_doc = src_root.find('.//{http://www.sii.cl/SiiDte}Documento') or src_root.find('.//Documento')
    if src_doc is None:
        raise RuntimeError('No se encontró <Documento> en el envío fuente')

    parent = tmpl_doc.getparent()
    index = parent.index(tmpl_doc)
    new_doc = etree.fromstring(etree.tostring(src_doc))
    SII_NS = 'http://www.sii.cl/SiiDte'
    _ensure_namespace(new_doc, SII_NS)
    parent.remove(tmpl_doc)
    parent.insert(index, new_doc)

    # remove existing xmldsig signatures
    for sig in tmpl_root.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature'):
        sig.getparent().remove(sig)

    # force xsi:schemaLocation on EnvioBOLETA nodes
    try:
        xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance'
        sii_ns = 'http://www.sii.cl/SiiDte'
        desired = f"{sii_ns} http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd"
        for envio in tmpl_root.findall('.//{http://www.sii.cl/SiiDte}EnvioBOLETA') or tmpl_root.findall('.//EnvioBOLETA'):
            envio.set(f'{{{xsi_ns}}}schemaLocation', desired)
    except Exception:
        pass

    parts = []
    for child in tmpl_root:
        s = etree.tostring(child, encoding='ISO-8859-1').decode('latin-1')
        s = s.replace("<?xml version='1.0' encoding='ISO-8859-1'?>", '')
        s = s.replace('<?xml version="1.0" encoding="ISO-8859-1"?>', '')
        parts.append(s)
    return ''.join(parts)


async def rebuild_and_upload(template_path: Path, dte_id: int = 132, folio: int | None = None, rut_emisor: str | None = None, rut_company: str | None = None, send: bool = False) -> dict:
    template_xml = template_path.read_text(encoding='latin-1')
    source_path = Path(f'tools/resigned_envio_dte{dte_id}.xml')
    if not source_path.exists():
        raise FileNotFoundError(f'No se encontró el archivo fuente: {source_path}')
    source_xml = source_path.read_text(encoding='latin-1')

    # optionally update folio and Documento@ID
    if folio is not None:
        parser = etree.XMLParser(recover=True, encoding='ISO-8859-1')
        src_body = source_xml
        if '<?xml' in src_body:
            src_body = src_body.split('?>', 1)[-1]
        wrapped_src = f"<root>{src_body}</root>"
        src_root = etree.fromstring(wrapped_src.encode('latin-1'), parser=parser)
        doc = src_root.find('.//{http://www.sii.cl/SiiDte}Documento') or src_root.find('.//Documento')
        tipo = src_root.find('.//{http://www.sii.cl/SiiDte}TipoDTE') or src_root.find('.//TipoDTE')
        tipo_val = tipo.text if tipo is not None else None
        if doc is not None and tipo_val is not None:
            doc.set('ID', f'T{tipo_val}F{folio}')
        folio_node = src_root.find('.//{http://www.sii.cl/SiiDte}Folio') or src_root.find('.//Folio')
        if folio_node is not None:
            folio_node.text = str(folio)
        parts = [etree.tostring(child, encoding='ISO-8859-1').decode('latin-1') for child in src_root]
        source_xml = ''.join(parts)

    rebuilt = replace_document_in_template(template_xml, source_xml)
    out_rebuilt = Path('tools/rebuilt_envio_from_template.xml')
    out_rebuilt.write_text(rebuilt, encoding='latin-1')

    # sign fragment (can be skipped in test mode)
    parser = etree.XMLParser(recover=True, encoding='ISO-8859-1')
    wrapped = f"<root>{rebuilt}</root>"
    root = etree.fromstring(wrapped.encode('latin-1'), parser=parser)
    doc_elem = root.find('.//{http://www.sii.cl/SiiDte}Documento') or root.find('.//Documento')
    doc_id = doc_elem.get('ID') if doc_elem is not None else None
    reference_uri = f'#{doc_id}' if doc_id else '#SetDoc'

    dte_elem = root.find('.//{http://www.sii.cl/SiiDte}DTE') or root.find('.//DTE')
    elem_to_sign = dte_elem if dte_elem is not None else (doc_elem if doc_elem is not None else None)
    if elem_to_sign is None:
        raise RuntimeError('No se encontró elemento DTE ni Documento para firmar')

    elem_str = etree.tostring(elem_to_sign, encoding='ISO-8859-1').decode('latin-1')

    # If running tests and DTE_TEST_NO_SIGN is set, skip actual signing to speed tests
    skip_signing = os.environ.get('DTE_TEST_NO_SIGN') == '1' and not send

    # load empresa and cert
    async with async_session_factory() as session:
        dte = await session.get(Dte, dte_id)
        empresa = await session.get(Empresa, dte.empresa_id) if dte and dte.empresa_id else None
        cert_data = None
        # Cargar certificado sólo si realmente vamos a firmar (no en modo test skip_signing)
        if not skip_signing:
            try:
                cert_data = load_pfx_from_empresa(empresa) if empresa else load_pfx_from_empresa(None)
            except Exception as e:
                raise

        # Prevent accidental re-sends: check if another DTE with same tipo/folio already sent
        try:
            check_tipo = None
            check_folio = folio if folio is not None else (dte.folio if dte is not None else None)
            if dte is not None:
                check_tipo = dte.tipo_dte
            # If we have empresa and both tipo+folio, query for existing
            if empresa and check_tipo is not None and check_folio is not None:
                stmt = select(Dte).where(
                    Dte.empresa_id == empresa.id,
                    Dte.tipo_dte == check_tipo,
                    Dte.folio == check_folio,
                )
                existing = (await session.execute(stmt)).scalars().first()
                if existing and existing.id != dte_id:
                    already = bool(existing.track_id) or (existing.estado in ('ENVIADO', 'ACEPTADO'))
                    if already:
                        if send:
                            raise RuntimeError(f'Folio {check_folio} para tipo {check_tipo} ya fue enviado (DTE id {existing.id}).')
                        else:
                            return {
                                'rebuilt_path': str(out_rebuilt),
                                'signed_path': None,
                                'sha1': hashlib.sha1(rebuilt.encode('latin-1')).hexdigest(),
                                'duplicate': True,
                                'duplicate_dte_id': existing.id,
                                'duplicate_track_id': existing.track_id,
                            }
        except Exception:
            # no bloquear el flujo por errores en la comprobación; preferimos permitir continuar
            pass

        if skip_signing:
            # write rebuilt content as 'signed' (no signature) for tests
            final_parts = [etree.tostring(child, encoding='ISO-8859-1') for child in root]
            final_doc = b"".join(final_parts).decode('latin-1')
        else:
            signed_fragment = XmlSignerService.sign_document(elem_str, cert_data, reference_uri=reference_uri, empresa=empresa, si_c14n_doc_context=True)
            signed_body = signed_fragment.split('?>', 1)[1] if signed_fragment.startswith('<?xml') else signed_fragment
            signed_node = etree.fromstring(signed_body.encode('latin-1'))

            parent = elem_to_sign.getparent()
            if parent is None:
                new_root = signed_node
            else:
                parent_index = parent.index(elem_to_sign)
                parent.remove(elem_to_sign)
                parent.insert(parent_index, signed_node)

            final_parts = [etree.tostring(child, encoding='ISO-8859-1') for child in root]
            final_doc = b"".join(final_parts).decode('latin-1')
        cleaned = final_doc.replace("<?xml version='1.0' encoding='ISO-8859-1'?>", '')
        cleaned = cleaned.replace('<?xml version="1.0" encoding="ISO-8859-1"?>', '')
        cleaned = cleaned.strip()
        cleaned = '<?xml version="1.0" encoding="ISO-8859-1"?>\n' + cleaned

        out_signed = Path('tools/rebuilt_resigned_envio.xml')
        out_signed.write_text(cleaned, encoding='latin-1')

        # ensure EnvioBOLETA wrapper
        if ('<EnvioBOLETA' not in cleaned) and ('<sii:EnvioBOLETA' not in cleaned):
            xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance'
            sii_ns = 'http://www.sii.cl/SiiDte'
            desired = f'{sii_ns} http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd'
            wrapped_env = '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
            wrapped_env += f'<EnvioBOLETA xmlns="{sii_ns}" xmlns:xsi="{xsi_ns}" xsi:schemaLocation="{desired}">\n'
            wrapped_env += cleaned.split('?>', 1)[-1]
            wrapped_env += '\n</EnvioBOLETA>'
            signed = wrapped_env
        else:
            signed = cleaned

        # Persistir/actualizar DTE en BD para auditoría (creado desde panel)
        try:
            # extraer documento interno para guardar como xml_documento
            parser2 = etree.XMLParser(recover=True, encoding='ISO-8859-1')
            root_signed = etree.fromstring(signed.encode('latin-1'), parser=parser2)
            doc_node = root_signed.find('.//{http://www.sii.cl/SiiDte}Documento') or root_signed.find('.//Documento')
            doc_xml = None
            if doc_node is not None:
                doc_xml = etree.tostring(doc_node, encoding='ISO-8859-1').decode('latin-1')

            # determinar tipo y folio
            tipo_node = root_signed.find('.//{http://www.sii.cl/SiiDte}TipoDTE') or root_signed.find('.//TipoDTE')
            folio_node2 = root_signed.find('.//{http://www.sii.cl/SiiDte}Folio') or root_signed.find('.//Folio')
            tipo_val2 = int(tipo_node.text) if tipo_node is not None and tipo_node.text and tipo_node.text.isdigit() else None
            folio_val2 = int(folio_node2.text) if folio_node2 is not None and folio_node2.text and folio_node2.text.isdigit() else (folio if folio is not None else None)

            if dte is None:
                # crear nuevo registro mínimo (monto_total requiere no nulo)
                new_dte = Dte(
                    empresa_id=empresa.id if empresa and getattr(empresa, 'id', None) is not None else None,
                    tipo_dte=tipo_val2 or 39,
                    folio=folio_val2 or 0,
                    monto_total=0,
                    xml_documento=doc_xml,
                    xml_envio=signed,
                )
                session.add(new_dte)
                await session.flush()
                dte = new_dte
            else:
                # actualizar campos útiles
                if tipo_val2 is not None:
                    dte.tipo_dte = tipo_val2
                if folio_val2 is not None:
                    dte.folio = folio_val2
                dte.xml_documento = doc_xml
                dte.xml_envio = signed
                session.add(dte)

            # registrar log local del rebuilt (dry-run) para auditoría
            session.add(
                SiiLog(
                    empresa_id=empresa.id if empresa and getattr(empresa, 'id', None) is not None else None,
                    dte_id=dte.id,
                    operacion='REBUILD',
                    request_data=None,
                    response_data='rebuilt_and_signed_saved',
                    status_code=200,
                )
            )
            await session.commit()
        except Exception:
            await session.rollback()

        result = {
            'rebuilt_path': str(out_rebuilt),
            'signed_path': str(out_signed),
            'sha1': hashlib.sha1(signed.encode('latin-1')).hexdigest(),
        }

        if send:
            token = await token_service.get_valid_token(empresa=empresa)
            uploader = UploadClient()
            rut_em = rut_emisor or (empresa.rut_envia if empresa else None)
            rut_co = rut_company or (empresa.rut_emisor if empresa else None)
            response_xml = await uploader.upload_dte(token=token, xml_content=signed, rut_emisor=rut_em, rut_empresa=rut_co, empresa=empresa)
            result['respuesta_sii'] = response_xml

            # Registrar respuesta SII en logs y actualizar DTE con track_id si viene
            try:
                parser3 = etree.XMLParser(recover=True)
                root_resp = etree.fromstring(response_xml.encode('utf-8'), parser=parser3)
                # buscar TRACKID por local-name
                track_elems = root_resp.xpath("//*[local-name()='TRACKID']")
                track_val = track_elems[0].text.strip() if track_elems and track_elems[0].text else None

                # Guardar log de UPLOAD
                session.add(
                    SiiLog(
                        empresa_id=empresa.id if empresa and getattr(empresa, 'id', None) is not None else None,
                        dte_id=dte.id if dte is not None else None,
                        operacion='UPLOAD',
                        request_data=signed,
                        response_data=response_xml,
                        status_code=200,
                    )
                )

                if track_val:
                    if dte is None:
                        # crear DTE si no existía
                        new_dte2 = Dte(
                            empresa_id=empresa.id if empresa and getattr(empresa, 'id', None) is not None else None,
                            tipo_dte=tipo_val2 or 39,
                            folio=folio_val2 or 0,
                            monto_total=0,
                            xml_documento=doc_xml,
                            xml_envio=signed,
                            track_id=track_val,
                            estado='ENVIADO',
                        )
                        session.add(new_dte2)
                    else:
                        dte.track_id = track_val
                        dte.estado = 'ENVIADO'
                        session.add(dte)

                await session.commit()
            except Exception:
                try:
                    await session.rollback()
                except Exception:
                    pass

        return result
