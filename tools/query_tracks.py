import asyncio
from sqlalchemy import select
from app.infrastructure.database import async_session_factory
from app.domain.models import Dte

async def main():
    async with async_session_factory() as session:
        stmt = select(Dte).where(Dte.track_id != None).order_by(Dte.id.desc()).limit(20)
        res = await session.execute(stmt)
        dtes = res.scalars().all()
        if not dtes:
            print('NO_TRACKS_FOUND')
            return
        for d in dtes:
            print(f'id={d.id} empresa_id={d.empresa_id} tipo={d.tipo_dte} folio={d.folio} estado={d.estado} track_id={d.track_id}')

if __name__ == '__main__':
    asyncio.run(main())
