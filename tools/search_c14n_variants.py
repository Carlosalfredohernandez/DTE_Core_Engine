"""
Buscar automáticamente variantes de canonicalización que reproduzcan el Digest
almacenado en la firma de un sample (e.g. tools/accepted_extracted.xml).

Prueba combinaciones de:
 - contexto: element standalone, parent, parent.parent, root
 - exclusive: True/False
 - include_xsi: mantener/ quitar xmlns:xsi en el contexto serializado

Imprime cualquier combinación que reproduzca el DigestValue almacenado.
"""
import sys
from pathlib import Path
import base64, hashlib

# ensure repo root
import sys as _sys, pathlib as _p
_root = str(_p.Path(__file__).resolve().parents[1])
if _root not in _sys.path:
    _sys.path.insert(0, _root)

from lxml import etree


def load_sample(path):
    txt = Path(path).read_text(encoding='latin-1')
    import re
    txt = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", txt)
    parser = etree.XMLParser(recover=True, encoding='utf-8')
    root = etree.fromstring(txt.encode('utf-8'), parser=parser)
    return root


def get_reference_digest(root):
    sig = root.find('.//{http://www.w3.org/2000/09/xmldsig#}Signature')
    if sig is None:
        raise RuntimeError('No Signature found')
    ref = sig.find('.//{http://www.w3.org/2000/09/xmldsig#}Reference')
    dv = ref.find('.//{http://www.w3.org/2000/09/xmldsig#}DigestValue')
    uri = ref.get('URI')
    return (uri or ''), (dv.text or '').strip()


def compute_digest(elem, exclusive):
    c14n = etree.tostring(elem, method='c14n', exclusive=exclusive)
    return base64.b64encode(hashlib.sha1(c14n).digest()).decode(), c14n


def try_variants(root, uri, stored_digest):
    results = []
    # find target element id
    target_id = uri.lstrip('#') if uri else None

    # candidate elements
    candidates = []
    if target_id:
        # search element with ID in whole document
        for e in root.iter():
            if e.get('ID') == target_id or e.get('Id') == target_id or e.get('id') == target_id:
                candidates.append(e)
    else:
        candidates.append(root)

    contexts = [
        ('element_standalone', lambda e: etree.fromstring(etree.tostring(e))),
        ('parent', lambda e: etree.fromstring(etree.tostring(e.getparent())) if e.getparent() is not None else etree.fromstring(etree.tostring(e))),
        ('parent_parent', lambda e: etree.fromstring(etree.tostring(e.getparent().getparent())) if e.getparent() is not None and e.getparent().getparent() is not None else etree.fromstring(etree.tostring(e))),
        ('root', lambda e: etree.fromstring(etree.tostring(root))),
    ]

    for cand in candidates:
        for ctx_name, ctx_fn in contexts:
            try:
                ctx_elem = ctx_fn(cand)
            except Exception:
                continue
            for exclusive in (False, True):
                # variant A: compute digest for the element located inside ctx_elem (find by ID)
                # locate element by id inside ctx_elem
                if target_id:
                    found = None
                    for el in ctx_elem.iter():
                        if el.get('ID') == target_id or el.get('Id') == target_id or el.get('id') == target_id:
                            found = el
                            break
                    elem_for_digest = found or cand
                else:
                    elem_for_digest = ctx_elem

                # Option: try with xmlns:xsi preserved and with xmlns:xsi removed from ctx_elem
                for include_xsi in (True, False):
                    work_ctx = etree.fromstring(etree.tostring(ctx_elem))
                    if not include_xsi:
                        # remove xsi namespace declarations from all elements in work_ctx
                        for el in work_ctx.iter():
                            # remove attributes starting with '{http://www.w3.org/2001/XMLSchema-instance}'
                            attrs = list(el.attrib.items())
                            for k, v in attrs:
                                if isinstance(k, str) and k.startswith('{http://www.w3.org/2001/XMLSchema-instance}'):
                                    del el.attrib[k]
                    # re-find element inside work_ctx
                    if target_id:
                        found2 = None
                        for el in work_ctx.iter():
                            if el.get('ID') == target_id or el.get('Id') == target_id or el.get('id') == target_id:
                                found2 = el
                                break
                        elem_to_c14n = found2 if found2 is not None else work_ctx
                    else:
                        elem_to_c14n = work_ctx

                    computed, c14n_bytes = compute_digest(elem_to_c14n, exclusive)
                    ok = (computed == stored_digest)
                    results.append({
                        'context': ctx_name,
                        'exclusive': exclusive,
                        'include_xsi': include_xsi,
                        'computed': computed,
                        'match': ok,
                        'c14n_preview': c14n_bytes[:400],
                    })
                    if ok:
                        return results, {'context': ctx_name, 'exclusive': exclusive, 'include_xsi': include_xsi, 'computed': computed}
    return results, None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'tools/accepted_extracted.xml'
    p = Path(path)
    if not p.exists():
        print('File not found:', p); return
    root = load_sample(p)
    uri, stored = get_reference_digest(root)
    print('Reference URI:', uri)
    print('Stored Digest:', stored)
    results, match = try_variants(root, uri, stored)
    if match:
        print('FOUND MATCH:', match)
    else:
        print('No match found among tested variants.')
    # print summary of first 10 results
    for r in results[:40]:
        print(r['context'], r['exclusive'], 'include_xsi=', r['include_xsi'], 'computed=', r['computed'], 'match=', r['match'])

if __name__ == '__main__':
    main()
