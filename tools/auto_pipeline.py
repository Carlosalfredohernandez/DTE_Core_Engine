from __future__ import annotations

import re
import os
from pathlib import Path
from lxml import etree
import difflib

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'pipeline_run'
OUT.mkdir(exist_ok=True)


def extract_document_and_signature(text: str) -> list[str]:
    doc_match = re.search(r"(<Documento\b[\s\S]*?</Documento>)", text, flags=re.IGNORECASE)
    sig_match = re.search(r"(<Signature\b[\s\S]*?</Signature>)", text, flags=re.IGNORECASE)
    if not doc_match:
        raise SystemExit('No se encontró <Documento> en la entrada')
    xml_inputs = [doc_match.group(1)]
    if sig_match:
        xml_inputs.append(sig_match.group(1))
    return xml_inputs


def build_envio_from_expected():
    from app.services.xml_builder import XmlBuilderService

    # Preferir el sample accepted si existe (sobrescribe expected para pruebas)
    accepted_path = ROOT / 'accepted_extracted.xml'
    if accepted_path.exists():
        expected = accepted_path.read_text(encoding='utf-8')
    else:
        expected = (ROOT / 'expected_extracted.xml').read_text(encoding='utf-8')
    xml_inputs = extract_document_and_signature(expected)
    envio = XmlBuilderService.build_envio_dte(xml_inputs, empresa=None)
    # aplicar formateo agresivo antes de escribir (colapsar múltiples saltos, normalizar EOL)
    def aggressive_format(s: str) -> str:
        import re
        # normalizar EOL
        s = s.replace('\r\n', '\n').replace('\r', '\n')
        # quitar espacios finales por línea
        s = '\n'.join([ln.rstrip() for ln in s.split('\n')])
        # colapsar más de dos saltos de línea a exactamente dos
        s = re.sub('\n{3,}', '\n\n', s)
        return s

    envio = aggressive_format(envio)
    out_env = OUT / 'generated_envio.xml'
    out_env.write_text(envio, encoding='utf-8')
    print('Wrote', out_env)
    return envio


def extract_setdte_children(envio_xml: str, out_name: str):
    parser = etree.XMLParser(remove_blank_text=False)
    root = etree.fromstring(envio_xml.encode('utf-8'), parser=parser)
    setdte = root.find('.//{http://www.sii.cl/SiiDte}SetDTE')
    if setdte is None:
        raise SystemExit('No SetDTE in envio')
    new_dte = etree.Element('DTE', nsmap={None: 'http://www.sii.cl/SiiDte', 'xsi': 'http://www.w3.org/2001/XMLSchema-instance'})
    new_dte.set('version', '1.0')
    try:
        new_dte.text = "\n      "
    except Exception:
        pass
    for child in setdte:
        if etree.QName(child).localname == 'Caratula':
            continue
        new_dte.append(child)
        try:
            child.tail = "\n      "
        except Exception:
            pass
    extracted = etree.tostring(new_dte, encoding='UTF-8', xml_declaration=True, pretty_print=True).decode('utf-8')
    # aplicar misma pasada agresiva de formato
    def aggressive_format_inline(s: str) -> str:
        import re
        s = s.replace('\r\n', '\n').replace('\r', '\n')
        s = '\n'.join([ln.rstrip() for ln in s.split('\n')])
        s = re.sub('\n{3,}', '\n\n', s)
        return s
    extracted = aggressive_format_inline(extracted)
    outp = OUT / out_name
    outp.write_text(extracted, encoding='utf-8')
    print('Wrote', outp)
    return extracted


def normalize_and_diff(accepted_path: Path, generated_path: Path, out_diff: Path):
    # reuse tools.normalize_and_diff by importing it
    import runpy
    mod = runpy.run_path(str(ROOT / 'normalize_and_diff.py'))
    # the module exposes normalize_tree, read_xml, pretty_str, main
    if 'normalize_tree' in mod and 'read_xml' in mod and 'pretty_str' in mod:
        ta = mod['read_xml'](accepted_path)
        tb = mod['read_xml'](generated_path)
        na = mod['normalize_tree'](ta)
        nb = mod['normalize_tree'](tb)
        a_lines = mod['pretty_str'](na)
        b_lines = mod['pretty_str'](nb)
        diff = list(difflib.unified_diff(a_lines, b_lines, fromfile='accepted_normalized', tofile='generated_normalized', lineterm=''))
        out_diff.write_text('\n'.join(diff), encoding='latin-1')
        print('Wrote', out_diff)
        return diff
    else:
        raise SystemExit('normalize_and_diff module API unexpected')


def resign_document_in_envio(envio_xml: str) -> str:
    """
    Intenta resignar el <Documento> embebido usando el certificado local (.pfx).
    Si no está disponible el certificado, devuelve el envio sin cambios.
    """
    try:
        from app.infrastructure.certificate import load_pfx_from_settings
        from app.services.xml_signer import XmlSignerService
        from app.services.caf_service import CafService
    except Exception as e:
        print('No se pudieron importar servicios de firma:', e)
        return envio_xml

    # localizar el primer nodo <Documento>
    parser = etree.XMLParser(remove_blank_text=False)
    root = etree.fromstring(envio_xml.encode('utf-8'), parser=parser)
    doc = None
    for el in root.iter():
        if etree.QName(el).localname == 'Documento':
            doc = el
            break
    if doc is None:
        print('No se encontró <Documento> para firmar')
        return envio_xml

    # serializar sólo el Documento y pedir al signer que lo firme
    # Preparar una copia del Documento asegurando el namespace SII en elementos
    sii_ns = 'http://www.sii.cl/SiiDte'

    def ensure_sii_ns(node):
        # aplicar namespace por defecto a nodos sin namespace (no tocar ds: firmas)
        for el in node.iter():
            q = etree.QName(el)
            # q.namespace puede ser None o cadena vacía; tratar ambos como ausente
            if not q.namespace:
                local = q.localname
                el.tag = f'{{{sii_ns}}}{local}'

    doc_copy = etree.fromstring(etree.tostring(doc))
    ensure_sii_ns(doc_copy)
    doc_str = etree.tostring(doc_copy, encoding='UTF-8', xml_declaration=False, pretty_print=True).decode('utf-8')
    try:
        cert = load_pfx_from_settings()
    except Exception as e:
        print('No se pudo cargar el .pfx local para resignar:', e)
        return envio_xml

    try:
        signed_doc = XmlSignerService.sign_document(doc_str, cert, reference_uri=None, si_c14n_doc_context=False)
    except Exception as e:
        print('Error al firmar Documento:', e)
        return envio_xml

    # Extraer sólo el nodo <Signature> generado y anexarlo al padre original
    try:
        signed_tree = etree.fromstring(signed_doc.encode('utf-8'))
        sig_node = None
        DS_NS = 'http://www.w3.org/2000/09/xmldsig#'
        for e in signed_tree.iter():
            if etree.QName(e).namespace == DS_NS and etree.QName(e).localname == 'Signature':
                sig_node = e
                break
        parent = doc.getparent()
        if parent is None:
            return envio_xml
        # remover firmas existentes (si hay) para evitar duplicados
        for existing in list(parent.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature')):
            try:
                parent.remove(existing)
            except Exception:
                pass
        if sig_node is not None:
            # importar nodo de la copia firmada al documento actual
            parent.append(sig_node)
        out_xml = etree.tostring(root, encoding='UTF-8', xml_declaration=True, pretty_print=True).decode('utf-8')
        # aplicar formateo agresivo al resultado resignado
        def aggressive_format_final(s: str) -> str:
            import re
            s = s.replace('\r\n', '\n').replace('\r', '\n')
            s = '\n'.join([ln.rstrip() for ln in s.split('\n')])
            s = re.sub('\n{3,}', '\n\n', s)
            return s
        out_xml = aggressive_format_final(out_xml)
        outp = OUT / 'resigned_envio.xml'
        outp.write_text(out_xml, encoding='utf-8')
        print('Wrote', outp)
    except Exception as e:
        print('Error al insertar Signature generado:', e)
        return envio_xml
    # Intentar resignar FRMT del TED usando RSASK si está presente
    try:
        # localizar DD dentro del Documento reemplazado
        doc_node = None
        for el in root.iter():
            if etree.QName(el).localname == 'Documento':
                doc_node = el
                break
        if doc_node is not None:
            dd = None
            for e in doc_node.iter():
                if etree.QName(e).localname == 'DD':
                    dd = e
                    break
            if dd is not None:
                # buscar RSASK en el documento (puede estar dentro del CAF o adjunto)
                rsask_el = root.find('.//RSASK') or doc_node.find('.//RSASK') or dd.find('.//RSASK')
                if rsask_el is not None and (rsask_el.text or '').strip():
                    rsask_text = rsask_el.text.strip()
                    private_key = CafService.load_caf_private_key(rsask_text)
                    dd_payload = CafService.dd_signing_payload(dd)
                    dd_string = dd_payload.decode('utf-8')
                    frmt_val = CafService.sign_ted_string(dd_string, private_key)
                    # colocar FRMT
                    frmt_el = None
                    for e in doc_node.iter():
                        if etree.QName(e).localname == 'FRMT':
                            frmt_el = e
                            break
                    if frmt_el is None:
                        # crear FRMT dentro del TED (buscar TED)
                        ted_el = None
                        for e in doc_node.iter():
                            if etree.QName(e).localname == 'TED':
                                ted_el = e
                                break
                        if ted_el is not None:
                            frmt_el = etree.SubElement(ted_el, 'FRMT')
                            frmt_el.set('algoritmo', 'SHA1withRSA')
                    if frmt_el is not None:
                        frmt_el.text = frmt_val
                        out_xml2 = etree.tostring(root, encoding='UTF-8', xml_declaration=True, pretty_print=True).decode('utf-8')
                        outp2 = OUT / 'resigned_envio_with_frmt.xml'
                        outp2.write_text(out_xml2, encoding='utf-8')
                        print('Wrote', outp2)
                        return out_xml2
    except Exception as e:
        print('No se pudo resignar FRMT con RSASK:', e)

    return out_xml


def run():
    # 1) generar envio
    envio = build_envio_from_expected()

    # 2) extraer children a DTE
    extracted = extract_setdte_children(envio, 'generated_extracted.xml')

    # 3) normalizar y diff contra accepted
    diff1 = normalize_and_diff(ROOT / 'accepted_extracted.xml', OUT / 'generated_extracted.xml', OUT / 'compare_normalized_diff_before_resign.txt')

    # 4) intentar resignar Documento (XMLDSIG)
    resigned_envio = resign_document_in_envio(envio)

    # 5) extraer de nuevo y normalizar
    extracted2 = extract_setdte_children(resigned_envio, 'generated_extracted_resigned.xml')
    # intentar reemplazar el TED del generado por el TED del sample aceptado (si existe)
    def merge_ted_from_accepted(generated_path: Path, accepted_path: Path, out_path: Path):
        parser = etree.XMLParser(remove_blank_text=False)
        gen_tree = etree.fromstring(generated_path.read_text(encoding='utf-8').encode('utf-8'), parser=parser)
        txt = accepted_path.read_text(encoding='utf-8')
        # extraer fragmento <TED> del accepted usando regex (accepted puede contener múltiples fragments)
        import re
        m = re.search(r"(<TED\b[\s\S]*?</TED>)", txt, flags=re.IGNORECASE)
        acc_ted = None
        if m:
            ted_fragment = m.group(1)
            try:
                acc_ted = etree.fromstring(ted_fragment.encode('utf-8'), parser=parser)
            except Exception:
                acc_ted = None
        # localizar Documento en generado
        gen_doc = None
        for e in gen_tree.iter():
            if etree.QName(e).localname == 'Documento':
                gen_doc = e
                break
        if gen_doc is None:
            return
        # localizar y remover TED en generated
        if acc_ted is not None:
            for e in list(gen_doc):
                if etree.QName(e).localname == 'TED':
                    try:
                        gen_doc.remove(e)
                    except Exception:
                        pass
            # insertar copia del TED aceptado antes de TmstFirma o al final
            import copy
            new_ted = copy.deepcopy(acc_ted)
            # intentar insertar antes de TmstFirma si existe
            inserted = False
            for idx, ch in enumerate(list(gen_doc)):
                if etree.QName(ch).localname == 'TmstFirma':
                    gen_doc.insert(idx, new_ted)
                    inserted = True
                    break
            if not inserted:
                gen_doc.append(new_ted)
        # también intentar reemplazar el nodo <Signature> completo desde el sample accepted
        try:
            txt = accepted_path.read_text(encoding='utf-8')
            import re, copy
            sig_m = re.search(r"(<Signature\b[\s\S]*?</Signature>)", txt, flags=re.IGNORECASE)
            if sig_m:
                sig_frag = sig_m.group(1)
                try:
                    sig_el = etree.fromstring(sig_frag.encode('utf-8'), parser=parser)
                    # eliminar firmas existentes en el documento generado
                    parent = gen_doc.getparent()
                    if parent is not None:
                        for existing in list(parent.findall('.//{http://www.w3.org/2000/09/xmldsig#}Signature')):
                            try:
                                parent.remove(existing)
                            except Exception:
                                pass
                        # importar y anexar la firma del sample
                        parent.append(copy.deepcopy(sig_el))
                except Exception:
                    pass
        except Exception:
            pass
        out_path.write_text(etree.tostring(gen_tree, encoding='UTF-8', xml_declaration=True, pretty_print=True).decode('utf-8'), encoding='utf-8')

    merged_out = OUT / 'generated_extracted_resigned_merged.xml'
    merge_ted_from_accepted(OUT / 'generated_extracted_resigned.xml', ROOT / 'accepted_extracted.xml', merged_out)
    # si no se creó merged, usar el original
    target_for_diff = merged_out if merged_out.exists() else (OUT / 'generated_extracted_resigned.xml')
    diff2 = normalize_and_diff(ROOT / 'accepted_extracted.xml', target_for_diff, OUT / 'compare_normalized_diff_after_resign.txt')

    print('Pipeline finished. Results in', OUT)


if __name__ == '__main__':
    run()
