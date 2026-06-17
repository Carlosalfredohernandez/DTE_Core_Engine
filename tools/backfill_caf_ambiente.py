import asyncio
from sqlalchemy import select, update
from app.infrastructure.database import async_session_factory
from app.domain.models import Caf, Empresa

async def main():
    async with async_session_factory() as session:
        # Seleccionar CAFs sin ambiente y con empresa_id
        stmt = select(Caf).where(Caf.ambiente.is_(None), Caf.empresa_id.is_not(None))
        result = await session.execute(stmt)
        cafs = result.scalars().all()
        print(f'Found {len(cafs)} caf(s) to backfill')
        updated = 0
        for caf in cafs:
            empresa = None
            if caf.empresa_id:
                empresa = await session.get(Empresa, caf.empresa_id)
            if empresa and empresa.sii_ambiente:
                caf.ambiente = empresa.sii_ambiente
                updated += 1
        if updated > 0:
            await session.commit()
        print(f'Backfilled {updated} caf(s)')

if __name__ == '__main__':
    asyncio.run(main())
