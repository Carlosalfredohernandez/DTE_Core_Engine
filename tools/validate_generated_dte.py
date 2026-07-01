import asyncio
import sys
sys.path.insert(0, '.')
from app.infrastructure.database import async_session_factory
from sqlalchemy import select
from app.domain.models import Dte
from app.services.schema_validator import validate_envio_schema
from app.services.xml_builder import XmlBuilderService
from app.domain.models import Empresa

async def main(dte_id: int | None = None):
    async with async_session_factory() as session:
        if dte_id is None:
            # obtener último DTE
            res = await session.execute(select(Dte).order_by(Dte.id.desc()).limit(1))
            dte = res.scalar_one_or_none()
        else:
            dte = await session.get(Dte, dte_id)
        if not dte:
            print('DTE no encontrado')
            return
        xml = dte.xml_envio or ''
        # Si no hay Envio (sobre) construido, construirlo a partir del Documento
        if not xml and dte.xml_documento:
            # resolver empresa si está asociada
            empresa = None
            if dte.empresa_id:
                empresa = await session.get(Empresa, dte.empresa_id)
            xml = XmlBuilderService.build_envio_dte([dte.xml_documento], empresa=empresa)
        if not xml:
            print('No hay XML para validar')
            return
        # Asegurar que SetDTE contenga un elemento DTE (algunos docs vienen con Documento suelto)
        from lxml import etree
        try:
            parser = etree.XMLParser(remove_blank_text=False, recover=True)
            root = etree.fromstring(xml.encode('utf-8'), parser=parser)
            print('Root tag:', etree.QName(root).localname)
            print('Children of root:', [etree.QName(ch).localname for ch in list(root)])
            ns = {'sii': 'http://www.sii.cl/SiiDte'}
            setdte = root.find('.//{http://www.sii.cl/SiiDte}SetDTE') or root.find('.//SetDTE')
            print('SetDTE found:', setdte is not None)
            if setdte is not None:
                    print('Children of SetDTE:', [etree.QName(ch).localname for ch in list(setdte)])
                    # Wrap any loose <Documento> (+ adjacent <Signature>) nodes into a <DTE> element
                    children = list(setdte)
                    i = 0
                    modified = False
                    while i < len(children):
                        ch = children[i]
                        ln = etree.QName(ch).localname
                        if ln == 'Documento':
                            dte_el = etree.Element('{http://www.sii.cl/SiiDte}DTE', version='1.0')
                            # move Documento
                            setdte.remove(ch)
                            dte_el.append(ch)
                            # if following sibling is Signature, move it too
                            # recalc children list
                            children = list(setdte)
                            # find position of insertion (first index where child had been)
                            insert_pos = i
                            # check next element at insert_pos (if exists) for Signature
                            if insert_pos < len(children):
                                nxt = children[insert_pos]
                                if etree.QName(nxt).localname == 'Signature':
                                    setdte.remove(nxt)
                                    dte_el.append(nxt)
                            # insert DTE at original position (after Caratula etc.)
                            # find current children list and insert
                            current_children = list(setdte)
                            # if insert_pos is within bounds, insert at that index
                            if insert_pos <= len(current_children):
                                # convert to list and reinsert
                                for idx, _ in enumerate(current_children):
                                    pass
                                # append at end of current_children to preserve order
                                setdte.append(dte_el)
                            else:
                                setdte.append(dte_el)
                            modified = True
                            # refresh children list and continue
                            children = list(setdte)
                            i += 1
                        else:
                            i += 1
                    if modified:
                        xml = etree.tostring(root, encoding='utf-8', xml_declaration=True, pretty_print=True).decode('utf-8')
                        print('Se envolvieron Documentos sueltos en DTE para validar')
            if setdte is not None:
                first_child = next(iter(list(setdte)), None)
                if first_child is not None and etree.QName(first_child).localname == 'Documento':
                    # envolver todos los hijos actuales en un nuevo <DTE>
                    dte_el = etree.Element('{http://www.sii.cl/SiiDte}DTE', version='1.0')
                    # mover hijos
                    for ch in list(setdte):
                        setdte.remove(ch)
                        dte_el.append(ch)
                    setdte.append(dte_el)
                    xml = etree.tostring(root, encoding='utf-8', xml_declaration=True, pretty_print=True).decode('utf-8')
                    print('Se envolvieron Documentos en DTE para validar')
        except Exception:
            # si parsing falla, seguir con el xml original
            pass

        errors = validate_envio_schema(xml)
        if not errors:
            print('XML válido contra XSD local (sin firmas)')
        else:
            print('Errores XSD encontrados:')
            for e in errors:
                print(e)

if __name__ == '__main__':
    import sys
    dte_id = int(sys.argv[1]) if len(sys.argv)>1 else None
    asyncio.run(main(dte_id))
