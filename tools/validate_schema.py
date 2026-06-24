from lxml import etree
from pathlib import Path

xsd_path = Path('scratch/EnvioBOLETA_v11.xsd')
xml_path = Path('tools/pipeline_run/generated_envio.xml')
if not xsd_path.exists():
    print('XSD not found:', xsd_path)
    raise SystemExit(2)
if not xml_path.exists():
    print('XML not found:', xml_path)
    raise SystemExit(2)

xmlschema_doc = etree.parse(str(xsd_path))
xmlschema = etree.XMLSchema(xmlschema_doc)

parser = etree.XMLParser(remove_blank_text=True)
doc = etree.parse(str(xml_path), parser=parser)
valid = xmlschema.validate(doc)
print('Valid:', valid)
if not valid:
    for error in xmlschema.error_log:
        print(error.message)
    raise SystemExit(1)
