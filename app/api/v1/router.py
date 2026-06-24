"""
DTE Core Engine — Router Principal V1.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, boleta, caf, cert, dashboard, tracking
from app.api.v1.endpoints import dte_send

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/token", tags=["Auth SII"])
api_router.include_router(caf.router, prefix="/caf", tags=["CAF y Folios"])
api_router.include_router(boleta.router, prefix="/boleta", tags=["Boleta Electrónica"])
api_router.include_router(cert.router, prefix="", tags=["Certificado Digital"])
api_router.include_router(dashboard.router, prefix="", tags=["Dashboard"])
api_router.include_router(tracking.router, prefix="/tracking", tags=["Tracking SII"])
api_router.include_router(dte_send.router, prefix="/dte", tags=["DTE Send"])
