import asyncio
from app.services.token_service import token_service
from app.clients.query_client import QueryClient

async def main(track_id, rut_compania, dv_compania):
    # Obtener token
    token = await token_service.get_valid_token()
    client = QueryClient()
    resp = await client.get_est_up(rut_empresa=rut_compania, dv_empresa=dv_compania, track_id=track_id, token=token)
    print(resp)

if __name__ == '__main__':
    import sys
    track = sys.argv[1] if len(sys.argv)>1 else '252170856'
    rut = sys.argv[2] if len(sys.argv)>2 else '77710916'
    dv = sys.argv[3] if len(sys.argv)>3 else '2'
    asyncio.run(main(track, rut, dv))
