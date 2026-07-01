import asyncio
import sys
from datetime import date
from lxml import etree

sys.path.insert(0, '.')

from app.infrastructure.database import async_session_factory
from sqlalchemy import select
from app.domain.models import Empresa
from app.services.dte_service import DteService
from app.domain.enums import TipoDte
from app.services.xml_builder import XmlBuilderService

async def main():
    async with async_session_factory() as session:
        # intentar obtener la empresa por defecto (primera activa)
        result = await session.execute(select(Empresa).limit(1))
        empresa = result.scalar_one_or_none()
        if not empresa:
            print('No hay Empresas en la BD; generando XML sin empresa (modo local)')
        receptor = {
            'rut': '11111111-1',
            'razon_social': 'CLIENTE PRUEBA',
            'dir_recep': 'CALLE FALSA 123',
            'cmna_recep': 'SANTIAGO',
            'ciudad_recep': 'SANTIAGO'
        }
        detalles = [
            {'nombre': 'Servicio de prueba', 'monto_item': 100}
        ]
        try:
            dte = await DteService.generar_boleta(
                session=session,
                tipo_dte=TipoDte.BOLETA_ELECTRONICA,
                receptor=receptor,
                detalles=detalles,
                fecha_emision=date.today(),
                empresa=empresa,
            )
            print('DTE generado con ID:', dte.id)
            if dte.xml_documento:
                print(dte.xml_documento)
            else:
                print('DTE sin xml_documento')
        except Exception as e:
            print('Error generando boleta (probablemente falta certificado):', e)
            # fallback: construir XML sin firmar
            from app.services.caf_service import CafService
            # obtener caf del primer activo en DB
            try:
                # intentar parsear un CAF de prueba desde DB si existe
                from app.domain.models import Caf
                res = await session.execute(select(Caf).limit(1))
                caf_db = res.scalar_one_or_none()
                if caf_db:
                    caf_info = CafService.parse_caf_xml(caf_db.caf_xml)
                else:
                    # crear un caf_info mínimo
                    caf_info = {'caf_xml_element': etree.Element('CAF')}
            except Exception:
                caf_info = {'caf_xml_element': etree.Element('CAF')}
            xml = XmlBuilderService.build_boleta_xml(
                folio=171,
                fecha_emision=date.today(),
                tipo_dte=TipoDte.BOLETA_ELECTRONICA,
                receptor=receptor,
                detalles=detalles,
                caf_info=caf_info,
                empresa=empresa,
            )
            print(xml)

if __name__ == '__main__':
    asyncio.run(main())
