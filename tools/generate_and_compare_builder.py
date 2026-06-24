from lxml import etree
from app.services.xml_builder import XmlBuilderService
import difflib
import re

# Leer el Documento firmado desde tools/expected_extracted.xml
with open('tools/expected_extracted.xml', 'r', encoding='latin-1') as f:
    s = f.read()

# Extraer el bloque <Documento>...</Documento> usando regex para evitar
# problemas con declaraciones XML múltiples embebidas en el archivo.
doc_match = re.search(r"(<Documento\b[\s\S]*?</Documento>)", s, flags=re.IGNORECASE)
sig_match = re.search(r"(<Signature\b[\s\S]*?</Signature>)", s, flags=re.IGNORECASE)

if not doc_match:
    raise SystemExit('No se encontró <Documento> en tools/expected_extracted.xml')

# Obtener XML de Documento y Signature
doc_xml = doc_match.group(1)
sig_xml = sig_match.group(1) if sig_match else None
# Construir Envio usando el builder: pasar Documento y Signature como entradas separadas
xml_inputs = [doc_xml]
if sig_xml:
    xml_inputs.append(sig_xml)
envio = XmlBuilderService.build_envio_dte(xml_inputs, empresa=None)
with open('tools/generated_envio_from_builder.xml', 'w', encoding='latin-1') as f:
    f.write(envio)

# Comparar contra accepted
with open('tools/accepted_extracted.xml', 'r', encoding='latin-1') as f:
    accepted = f.read()

gen = envio

diff = difflib.unified_diff(accepted.splitlines(True), gen.splitlines(True), fromfile='accepted_extracted.xml', tofile='generated_envio_from_builder.xml')
with open('tools/compare_generated_vs_accepted.txt', 'w', encoding='latin-1') as f:
    f.writelines(diff)

# También extraer los nodos dentro de SetDTE (excluyendo Caratula), envolverlos
# en un elemento DTE para comparar con el accepted_extracted.xml que contiene
# el cuerpo esperado.
parser = etree.XMLParser(remove_blank_text=False)
env_root = etree.fromstring(envio.encode('latin-1'), parser=parser)
setdte = env_root.find('.//{http://www.sii.cl/SiiDte}SetDTE')
if setdte is not None:
    # Crear nuevo DTE root con namespaces
    sii_ns = 'http://www.sii.cl/SiiDte'
    xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance'
    nsmap = {None: sii_ns, 'xsi': xsi_ns}
    new_dte = etree.Element('DTE', nsmap=nsmap)
    new_dte.set('version', '1.0')
    # Preparar texto para que pretty_print incluya salto de línea antes del primer hijo
    try:
        new_dte.text = "\n      "
    except Exception:
        pass

    for child in setdte:
        if child.tag == '{http://www.sii.cl/SiiDte}Caratula':
            continue
        # importar nodo al nuevo documento
        new_dte.append(child)
        try:
            child.tail = "\n      "
        except Exception:
            pass

    extracted = etree.tostring(new_dte, encoding='ISO-8859-1', xml_declaration=True, pretty_print=True).decode('latin-1')
    with open('tools/generated_extracted_from_builder.xml', 'w', encoding='latin-1') as f:
        f.write(extracted)

    # Comparar extracted vs accepted
    diff2 = difflib.unified_diff(accepted.splitlines(True), extracted.splitlines(True), fromfile='accepted_extracted.xml', tofile='generated_extracted_from_builder.xml')
    with open('tools/compare_extracted_vs_accepted.txt', 'w', encoding='latin-1') as f:
        f.writelines(diff2)

print('Generado: tools/generated_envio_from_builder.xml')
print('Diff: tools/compare_generated_vs_accepted.txt')

# --- Generar Envío usando el Documento exacto del accepted y comparar ---
acc_doc_match = re.search(r"(<Documento\b[\s\S]*?</Documento>)", accepted, flags=re.IGNORECASE)
acc_sig_match = re.search(r"(<Signature\b[\s\S]*?</Signature>)", accepted, flags=re.IGNORECASE)
if acc_doc_match:
    acc_doc_xml = acc_doc_match.group(1)
    acc_sig_xml = acc_sig_match.group(1) if acc_sig_match else None
    xml_inputs2 = [acc_doc_xml]
    if acc_sig_xml:
        xml_inputs2.append(acc_sig_xml)
    envio2 = XmlBuilderService.build_envio_dte(xml_inputs2, empresa=None)
    with open('tools/generated_envio_from_accepted_doc.xml', 'w', encoding='latin-1') as f:
        f.write(envio2)

    # Extraer DTE children (excluyendo Caratula)
    root2 = etree.fromstring(envio2.encode('latin-1'), parser=parser)
    setdte2 = root2.find('.//{http://www.sii.cl/SiiDte}SetDTE')
    if setdte2 is not None:
        new_dte2 = etree.Element('DTE', nsmap={None: 'http://www.sii.cl/SiiDte', 'xsi': 'http://www.w3.org/2001/XMLSchema-instance'})
        new_dte2.set('version', '1.0')
        try:
            new_dte2.text = "\n      "
        except Exception:
            pass
        for child in setdte2:
            if child.tag == '{http://www.sii.cl/SiiDte}Caratula':
                continue
            new_dte2.append(child)
            try:
                child.tail = "\n      "
            except Exception:
                pass
        extracted2 = etree.tostring(new_dte2, encoding='ISO-8859-1', xml_declaration=True, pretty_print=True).decode('latin-1')
        with open('tools/generated_extracted_from_accepted_doc.xml', 'w', encoding='latin-1') as f:
            f.write(extracted2)

        diff3 = difflib.unified_diff(accepted.splitlines(True), extracted2.splitlines(True), fromfile='accepted_extracted.xml', tofile='generated_extracted_from_accepted_doc.xml')
        with open('tools/compare_accepted_doc_extracted_diff.txt', 'w', encoding='latin-1') as f:
            f.writelines(diff3)
        print('Generado desde accepted: tools/generated_envio_from_accepted_doc.xml')
        print('Extracted: tools/generated_extracted_from_accepted_doc.xml')
        print('Diff: tools/compare_accepted_doc_extracted_diff.txt')
