"""
Herramienta de debugging: firma un documento con el certificado configurado
y verifica inmediatamente las firmas para volcar C14N/digest usados.

Uso:
  python tools/debug_roundtrip_sign_verify.py [ruta_xml]

Si no se provee ruta, intenta usar 'tools/accepted_extracted.xml' o
herramienta generadora 'tools/generate_test_boleta.py' si existe.
"""

import sys
from pathlib import Path
# Ensure repo root is on sys.path so `import app` works when running as script
import pathlib as _p
_root = str(_p.Path(__file__).resolve().parents[1])
if _root not in sys.path:
    sys.path.insert(0, _root)

from app.services.xml_signer import XmlSignerService
from app.infrastructure.certificate import load_pfx_from_settings, load_pfx_from_file

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'tools/accepted_extracted.xml'
    p = Path(path)
    if not p.exists():
        print('Archivo no encontrado:', p)
        return
    xml = p.read_text(encoding='latin-1')

    # intentar cargar certificado desde settings (env o .env)
    cert = None
    try:
        cert = load_pfx_from_settings()
        print('Certificado cargado desde settings')
    except Exception as e:
        print('No se pudo cargar certificado desde settings:', e)
        # solicitar pfx local
        if len(sys.argv) > 2:
            pfx_path = sys.argv[2]
            pfx_pass = sys.argv[3] if len(sys.argv) > 3 else ''
            try:
                cert = load_pfx_from_file(pfx_path, pfx_pass)
                print('Certificado cargado desde archivo:', pfx_path)
            except Exception as e2:
                print('Error cargando pfx desde archivo:', e2)
                return
        else:
            print('Provee ruta a PFX y contraseña como segundo y tercer argumento.')
            return

    # determinar ID de Documento o usar root
    from lxml import etree
    parser = etree.XMLParser(recover=True, encoding='utf-8')
    try:
        root = etree.fromstring(xml.encode('utf-8'), parser=parser)
    except Exception:
        print('Error parseando XML de entrada')
        return

    doc = root.find('.//{http://www.sii.cl/SiiDte}Documento') or root.find('.//Documento')
    if doc is None:
        print('No se encontró <Documento> en el XML de entrada')
        return
    doc_id = doc.get('ID') or doc.get('Id') or doc.get('id')
    ref = f'#{doc_id}' if doc_id else None

    print('ID documento:', doc_id)

    # firmar y verificar
    try:
        signed = XmlSignerService.sign_document(xml, cert, reference_uri=ref, si_c14n_doc_context=True)
        print('Documento firmado (preview 1000 chars):')
        print(signed[:1000])
    except Exception as e:
        print('Error firmando:', e)
        return

    print('\nVerificando firmas...')
    res = XmlSignerService.verify_signatures(signed)
    print('Resultados verificación:')
    for r in res:
        print(r)

if __name__ == '__main__':
    main()
