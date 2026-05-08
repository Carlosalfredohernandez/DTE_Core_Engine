"""
DTE Core Engine — Router Principal V1.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, boleta, caf, tracking

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/token", tags=["Auth SII"])
api_router.include_router(caf.router, prefix="/caf", tags=["CAF y Folios"])
api_router.include_router(boleta.router, prefix="/boleta", tags=["Boleta Electrónica"])
api_router.include_router(tracking.router, prefix="/tracking", tags=["Tracking SII"])
