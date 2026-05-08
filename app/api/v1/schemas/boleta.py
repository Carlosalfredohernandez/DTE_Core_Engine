"""
DTE Core Engine — Schemas Pydantic para Boletas.
"""

from datetime import date
from typing import List, Optional

from pydantic import BaseModel, Field

from app.domain.enums import EstadoDte, TipoDte


class DetalleItem(BaseModel):
    nombre: str = Field(..., max_length=80)
    cantidad: float = Field(..., gt=0)
    precio: float = Field(..., gt=0)
    monto_item: int = Field(..., gt=0)


class Receptor(BaseModel):
    rut: str = Field(..., max_length=12, description="RUT con guión")
    razon_social: Optional[str] = Field(None, max_length=100)


class BoletaCreateRequest(BaseModel):
    tipo_dte: TipoDte = Field(default=TipoDte.BOLETA_ELECTRONICA)
    receptor: Optional[Receptor] = None
    detalles: List[DetalleItem] = Field(..., min_length=1)
    fecha_emision: Optional[date] = None


class BoletaResponse(BaseModel):
    id: int
    tipo_dte: int
    folio: int
    estado: EstadoDte
    monto_total: float
    fecha_emision: date
    xml_base64: Optional[str] = None

    model_config = {"from_attributes": True}


class EnviarBoletaRequest(BaseModel):
    dte_id: int


class EnviarBoletaResponse(BaseModel):
    dte_id: int
    track_id: Optional[str]
    estado: EstadoDte
    glosa_sii: Optional[str]

    model_config = {"from_attributes": True}
