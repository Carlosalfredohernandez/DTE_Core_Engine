"""
DTE Core Engine — Modelos SQLAlchemy (Single-Tenant, SQL Server)
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Integer,
    Numeric,
    String,
    Text,
    ForeignKey,
    func,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Caf(Base):
    """Código de Autorización de Folios (CAF)."""

    __tablename__ = "cafs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tipo_dte = Column(Integer, nullable=False)
    rango_desde = Column(Integer, nullable=False)
    rango_hasta = Column(Integer, nullable=False)
    folio_actual = Column(Integer, nullable=False)
    caf_xml = Column(Text, nullable=False)
    fecha_carga = Column(DateTime, default=func.now())
    activo = Column(Boolean, default=True)


class Dte(Base):
    """Documento Tributario Electrónico (Boleta, Factura, etc)."""

    __tablename__ = "dtes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tipo_dte = Column(Integer, nullable=False, default=39)
    folio = Column(Integer, nullable=False)
    rut_receptor = Column(String(12), nullable=True)  # Boletas pueden no tener receptor
    monto_total = Column(Numeric(15, 2), nullable=False)
    xml_documento = Column(Text, nullable=True)  # DTE firmado
    xml_envio = Column(Text, nullable=True)      # SetDTE (Sobre)
    track_id = Column(String(50), nullable=True)
    estado = Column(String(30), nullable=False, default="GENERADO")
    glosa_sii = Column(Text, nullable=True)
    fecha_emision = Column(Date, nullable=False, default=date.today)
    created_at = Column(DateTime, default=func.now())

    # Relación a logs
    logs = relationship("SiiLog", back_populates="dte", cascade="all, delete-orphan")


class SiiLog(Base):
    """Registro de interacciones SOAP/HTTP con el SII."""

    __tablename__ = "sii_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    dte_id = Column(Integer, ForeignKey("dtes.id"), nullable=True)
    operacion = Column(String(50), nullable=False)  # ej: TOKEN, UPLOAD, QUERY
    request_data = Column(Text, nullable=True)
    response_data = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())

    dte = relationship("Dte", back_populates="logs")
