import sys
from app.services.xml_signer import XmlSignerService

path = sys.argv[1] if len(sys.argv)>1 else 'tools/rebuilt_resigned_envio.xml'
print('Reading', path)
with open(path, 'rb') as f:
    data = f.read()
try:
    res = XmlSignerService.verify_signatures(data)
    import json
    print(json.dumps(res, indent=2, ensure_ascii=False))
except Exception as e:
    print('Error:', e)
