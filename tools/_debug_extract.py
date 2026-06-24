import re
from pathlib import Path

p = Path(__file__).resolve().parent / 'accepted_extracted.xml'
s = p.read_text(encoding='utf-8')
d = re.search(r'(<Documento\b[\s\S]*?</Documento>)', s, flags=re.IGNORECASE)
sig = re.search(r'(<Signature\b[\s\S]*?</Signature>)', s, flags=re.IGNORECASE)
print('Documento found:', bool(d))
print('Signature found:', bool(sig))
if d:
    print('Documento starts:', d.group(1)[:200].replace('\n','\\n'))
if sig:
    print('Signature starts:', sig.group(1)[:200].replace('\n','\\n'))
