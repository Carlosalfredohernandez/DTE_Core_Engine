from pathlib import Path
import re
import sys
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent))
from app.services.xml_builder import XmlBuilderService

p = Path(__file__).resolve().parent
s = (p / 'accepted_extracted.xml').read_text(encoding='utf-8')
doc = re.search(r'(<Documento\b[\s\S]*?</Documento>)', s, flags=re.IGNORECASE)
sig = re.search(r'(<Signature\b[\s\S]*?</Signature>)', s, flags=re.IGNORECASE)
xml_inputs = []
if doc:
    xml_inputs.append(doc.group(1))
if sig:
    xml_inputs.append(sig.group(1))
print('xml_inputs count:', len(xml_inputs))
envio = XmlBuilderService.build_envio_dte(xml_inputs, empresa=None)
print('Envio contains Documento?', '<Documento' in envio)
open(p / 'dbg_envio_output.xml', 'w', encoding='utf-8').write(envio)
print('Wrote dbg_envio_output.xml')
