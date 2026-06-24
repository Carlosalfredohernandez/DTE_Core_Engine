import asyncio
from app.infrastructure.database import async_session_factory
from app.domain.models import Dte

async def main(dte_id:int):
    async with async_session_factory() as session:
        d = await session.get(Dte, dte_id)
        if not d:
            print('DTE_NOT_FOUND')
            return
        print(f'id={d.id} empresa_id={d.empresa_id} tipo={d.tipo_dte} folio={d.folio} estado={d.estado} track_id={d.track_id}')

if __name__ == '__main__':
    import sys
    id = int(sys.argv[1]) if len(sys.argv)>1 else 133
    asyncio.run(main(id))
