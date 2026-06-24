from app.services.schema_validator import validate_envio_schema
import sys
p = sys.argv[1] if len(sys.argv)>1 else 'tools/generated_envio_from_builder.xml'
print('Validando', p)
xml = open(p, 'r', encoding='latin-1').read()
errs = validate_envio_schema(xml)
if not errs:
    print('XML válido según XSD adaptado')
else:
    print('Errores encontrados:')
    for e in errs:
        print('-', e)
