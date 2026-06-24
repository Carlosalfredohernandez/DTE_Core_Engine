"""
Valida `tools/resigned_envio_dte132.xml` contra el XSD local adaptado.
"""
from app.services.schema_validator import validate_envio_schema


def main():
    path = "tools/resigned_envio_dte132.xml"
    with open(path, "r", encoding="latin-1") as fh:
        xml = fh.read()

    errors = validate_envio_schema(xml)
    if not errors:
        print("XML válido según XSD adaptado")
        return
    print("Errores XSD:")
    for e in errors:
        print("-", e)


if __name__ == "__main__":
    main()
