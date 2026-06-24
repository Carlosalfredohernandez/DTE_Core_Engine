"""
Reenvía un DTE por su ID y muestra SHA1 del `xml_envio` y los últimos SiiLog.

Uso: ejecutar desde la raíz del repo: `python tools/reenvio_dte.py`
"""
import asyncio
import hashlib
from sqlalchemy import select

from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa, SiiLog
from app.services.dte_service import DteService


async def main():
    dte_id = 132

    async with async_session_factory() as session:
        dte = await session.get(Dte, dte_id)
        if not dte:
            print(f"DTE {dte_id} no encontrado")
            return

        empresa = None
        if dte.empresa_id:
            empresa = await session.get(Empresa, dte.empresa_id)

        print("DTE encontrado:", dte_id, "folio=", getattr(dte, 'folio', None))

        if dte.xml_envio:
            sha_before = hashlib.sha1(dte.xml_envio.encode('latin-1')).hexdigest()
            print("SHA1 xml_envio (DB, antes):", sha_before)
        else:
            print("No hay xml_envio persistido en DB antes del reenvío.")

        try:
            result = await DteService.enviar_boleta(session, dte_id, empresa=empresa)
            print("Enviar resultado: estado=", getattr(result, 'estado', None), "track_id=", getattr(result, 'track_id', None))
        except Exception as e:
            print("Enviar falló:", type(e).__name__, str(e))

        # Consultar últimos SiiLog para este DTE
        stmt = select(SiiLog).where(SiiLog.dte_id == dte_id).order_by(SiiLog.id.desc()).limit(10)
        res = await session.execute(stmt)
        logs = res.scalars().all()
        print(f"Encontrados {len(logs)} SiiLog(s) para DTE {dte_id}")
        for l in logs:
            print("---")
            print("Log id:", l.id, "operacion:", l.operacion, "status:", l.status_code)
            rd = (l.request_data or "")
            rd_head = rd[:1000]
            # buscar XML_SHA1 en request_data si existe
            xml_sha1 = None
            for line in rd_head.splitlines():
                if 'XML_SHA1=' in line:
                    xml_sha1 = line.strip()
                    break
            print("XML_SHA1 en request_data:", xml_sha1)
            print("Request head (primeros 300 chars):", rd_head[:300])
            print("Response head (primeros 300 chars):", (l.response_data or "")[:300])


if __name__ == '__main__':
    asyncio.run(main())
