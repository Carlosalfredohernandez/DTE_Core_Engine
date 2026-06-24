import asyncio
from sqlalchemy import select
from app.infrastructure.database import async_session_factory
from app.domain.models import Empresa
from app.services.dte_service import DteService
from app.domain import TipoDte
import datetime

async def main():
    async with async_session_factory() as session:
        # listar empresas activas
        stmt = select(Empresa).where(Empresa.activo == True)
        result = await session.execute(stmt)
        empresas = result.scalars().all()
        print(f'Encontradas {len(empresas)} empresa(s) activas')
        for empresa in empresas:
            print('---')
            print(f'Empresa id={empresa.id} rut={empresa.rut_emisor} ambiente={empresa.sii_ambiente}')
            try:
                dte = await DteService.generar_boleta(
                    session=session,
                    tipo_dte=TipoDte.BOLETA_ELECTRONICA,
                    receptor={'rut': '66666666-6', 'razon_social': 'Cliente Prueba'},
                    detalles=[{'nombre': 'Prueba', 'cantidad': 1, 'precio': 1000, 'monto_item': 1000}],
                    fecha_emision=datetime.date.today(),
                    empresa=empresa,
                )
                print('Generado DTE id=', dte.id, 'folio=', dte.folio, 'tipo=', dte.tipo_dte)
                if dte.xml_documento:
                    # extraer info CAF simple
                    from lxml import etree
                    ns={'sii': 'http://www.sii.cl/SiiDte'}
                    root = etree.fromstring(dte.xml_documento.encode('latin-1'))
                    folio_dd = root.findtext('.//sii:TED/sii:DD/sii:F', namespaces=ns)
                    rng_d = root.findtext('.//sii:TED/sii:DD/sii:CAF/sii:DA/sii:RNG/sii:D', namespaces=ns)
                    rng_h = root.findtext('.//sii:TED/sii:DD/sii:CAF/sii:DA/sii:RNG/sii:H', namespaces=ns)
                    print('CAF used folio_dd=', folio_dd, 'range=', rng_d, '-', rng_h)
            except Exception as e:
                print('Error generando para empresa', empresa.id, str(e))

if __name__ == '__main__':
    asyncio.run(main())
