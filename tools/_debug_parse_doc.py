from pathlib import Path
import re
from lxml import etree

p = Path(__file__).resolve().parent / 'accepted_extracted.xml'
s = p.read_text(encoding='utf-8')
d = re.search(r'(<Documento\b[\s\S]*?</Documento>)', s, flags=re.IGNORECASE)
if not d:
    print('No Documento found')
    raise SystemExit(1)
frag = d.group(1)
print('Len fragment:', len(frag))
parser = etree.XMLParser(remove_blank_text=False)
try:
    node = etree.fromstring(frag.encode('latin-1'), parser=parser)
    print('Parsed tag:', etree.QName(node).localname)
except Exception as e:
    print('Parse error:', e)
    try:
        node2 = etree.fromstring(frag.encode('utf-8'), parser=parser)
        print('Parsed with utf-8 tag:', etree.QName(node2).localname)
    except Exception as e2:
        print('Also failed utf-8:', e2)
