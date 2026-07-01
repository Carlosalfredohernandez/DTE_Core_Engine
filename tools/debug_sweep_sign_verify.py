"""
Prueba exhaustiva de combinaciones para `exclusive` y `si_c14n_doc_context`.
Uso:
  python tools/debug_sweep_sign_verify.py [ruta_xml]

Salida: para cada combinación muestra si digest coincide y si signature verifica.
"""
import sys
from pathlib import Path
# ensure repo root
import sys as _sys, pathlib as _p
_root = str(_p.Path(__file__).resolve().parents[1])
if _root not in _sys.path:
    _sys.path.insert(0, _root)

from app.services.xml_signer import XmlSignerService
from app.infrastructure.certificate import load_pfx_from_settings, load_pfx_from_file
from lxml import etree


def try_combo(xml, cert, ref, exclusive, si_doc_ctx):
    try:
        signed = XmlSignerService.sign_document(xml, cert, reference_uri=ref, exclusive=exclusive, si_c14n_doc_context=si_doc_ctx)
    except Exception as e:
        return {'exclusive': exclusive, 'si_doc_ctx': si_doc_ctx, 'error_sign': str(e)}
    try:
        results = XmlSignerService.verify_signatures(signed, exclusive=exclusive)
    except Exception as e:
        return {'exclusive': exclusive, 'si_doc_ctx': si_doc_ctx, 'error_verify': str(e)}
    return {'exclusive': exclusive, 'si_doc_ctx': si_doc_ctx, 'verify_results': results}


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'tools/accepted_extracted.xml'
    p = Path(path)
    if not p.exists():
        print('No encontrado:', p)
        return
    xml = p.read_text(encoding='latin-1')

    # cargar certificado
    cert = None
    try:
        cert = load_pfx_from_settings()
        print('Cert cargado desde settings')
    except Exception as e:
        print('No se pudo cargar cert desde settings:', e)
        if len(sys.argv) > 2:
            pfx = sys.argv[2]; pwd = sys.argv[3] if len(sys.argv) > 3 else ''
            try:
                cert = load_pfx_from_file(pfx, pwd)
                print('Cert cargado desde archivo')
            except Exception as e2:
                print('Error cargando pfx:', e2); return
        else:
            print('Provee PFX si no hay settings'); return

    parser = etree.XMLParser(recover=True, encoding='utf-8')
    root = etree.fromstring(xml.encode('utf-8'), parser=parser)
    doc = root.find('.//{http://www.sii.cl/SiiDte}Documento') or root.find('.//Documento')
    if doc is None:
        print('No hay Documento')
        return
    doc_id = doc.get('ID')
    ref = f'#{doc_id}' if doc_id else None
    print('Documento ID:', doc_id)

    combos = []
    for exclusive in (True, False):
        for si_doc_ctx in (True, False):
            print('\nProbando exclusive=', exclusive, ' si_c14n_doc_context=', si_doc_ctx)
            res = try_combo(xml, cert, ref, exclusive, si_doc_ctx)
            combos.append(res)
            print(res)

    print('\nResumen:')
    for c in combos:
        print(c)

if __name__ == '__main__':
    main()
