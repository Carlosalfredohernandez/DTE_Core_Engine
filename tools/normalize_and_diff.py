from lxml import etree
from pathlib import Path
import difflib

ROOT = Path(__file__).resolve().parent

TAGS_TO_ZERO = {
    'Folio', 'FchEmis', 'FchVenc', 'TmstFirma', 'TSTED', 'FE', 'F',
    'FRMA', 'FRMT', 'DigestValue', 'SignatureValue'
}

# Ignorar también elementos dentro de KeyInfo/X509 que varían por certificado
TAGS_TO_ZERO.update({'X509Certificate', 'Modulus', 'Exponent', 'RSAKeyValue', 'KeyValue'})

ATTRS_TO_REMOVE = {
    ('Documento', 'ID'),
}


def normalize_tree(tree):
    ns = {'s': 'http://www.sii.cl/SiiDte', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
    for elem in tree.iter():
        tag = etree.QName(elem).localname
        # remove dynamic text
        if tag in TAGS_TO_ZERO:
            elem.text = ''
        # blank out numeric-like nodes that are dynamic
        if tag in ('CAF', 'FRMA'):
            elem.text = ''
        # remove signature-related children content
        if tag in ('DigestValue', 'SignatureValue'):
            elem.text = ''
        # normalize whitespace
        if elem.text is not None:
            elem.text = elem.text.strip()
        if elem.tail is not None:
            elem.tail = elem.tail.strip()
    # remove attributes that contain dynamic identifiers
    for tag, attr in ATTRS_TO_REMOVE:
        for e in tree.findall('.//{http://www.sii.cl/SiiDte}%s' % tag):
            if attr in e.attrib:
                e.attrib[attr] = ''
    return tree


def read_xml(path):
    parser = etree.XMLParser(remove_blank_text=False, encoding='utf-8', recover=True)
    data = path.read_bytes()
    return etree.fromstring(data, parser=parser)


def pretty_str(elem):
    return etree.tostring(elem, pretty_print=True, encoding='UTF-8').decode('utf-8').splitlines()


def main():
    a = ROOT / 'accepted_extracted.xml'
    b = ROOT / 'generated_extracted_from_builder.xml'
    if not a.exists() or not b.exists():
        print('Missing required files in tools/:', a, b)
        return 2
    ta = read_xml(a)
    tb = read_xml(b)
    na = normalize_tree(ta)
    nb = normalize_tree(tb)
    a_lines = pretty_str(na)
    b_lines = pretty_str(nb)
    diff = list(difflib.unified_diff(a_lines, b_lines, fromfile='accepted_normalized', tofile='generated_normalized', lineterm=''))
    out_diff = ROOT / 'compare_normalized_diff.txt'
    out_diff.write_text('\n'.join(diff), encoding='utf-8')
    print('Wrote', out_diff)
    print('\n'.join(diff[:200]))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
