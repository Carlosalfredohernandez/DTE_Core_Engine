import asyncio
from sqlalchemy import select
from app.infrastructure.database import async_session_factory
from app.domain.models import Caf

async def main():
    async with async_session_factory() as session:
        stmt = select(Caf).order_by(Caf.id.asc())
        result = await session.execute(stmt)
        cafs = result.scalars().all()
        print(f'Found {len(cafs)} caf(s)')
        for c in cafs:
            print(f'id={c.id} empresa_id={c.empresa_id} rango={c.rango_desde}-{c.rango_hasta} folio_actual={c.folio_actual} ambiente={c.ambiente} activo={c.activo}')

if __name__ == '__main__':
    asyncio.run(main())
