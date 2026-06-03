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


class Empresa(Base):
    """Configuración multiempresa para un emisor de DTE."""

    __tablename__ = "empresas"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rut_emisor = Column(String(12), nullable=False)
    rut_envia = Column(String(12), nullable=False)
    razon_social_emisor = Column(String(150), nullable=False)
    giro_emisor = Column(String(150), nullable=False)
    acteco_emisor = Column(Integer, nullable=False)
    dir_origen = Column(String(200), nullable=False)
    cmna_origen = Column(String(100), nullable=False)
    ciudad_origen = Column(String(100), nullable=False)
    sii_ambiente = Column(String(20), nullable=False, default="certificacion")
    sii_fecha_resolucion = Column(String(10), nullable=False)
    sii_numero_resolucion = Column(Integer, nullable=False)
    brand_name = Column(String(150), nullable=True)
    brand_logo_url = Column(String(500), nullable=True)
    brand_accent_1 = Column(String(20), nullable=True)
    brand_accent_2 = Column(String(20), nullable=True)
    api_key = Column(String(120), nullable=True, unique=True)
    cert_pfx_path = Column(String(255), nullable=True)
    cert_pfx_base64 = Column(Text, nullable=True)
    cert_pfx_password = Column(String(255), nullable=True)
    es_default = Column(Boolean, default=False, nullable=False)
    activo = Column(Boolean, default=True, nullable=False)
    fecha_creacion = Column(DateTime, default=func.now())
    fecha_actualizacion = Column(DateTime, default=func.now(), onupdate=func.now())


class Caf(Base):
    """Código de Autorización de Folios (CAF)."""

    __tablename__ = "cafs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    empresa_id = Column(Integer, ForeignKey("empresas.id"), nullable=True)
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
    empresa_id = Column(Integer, ForeignKey("empresas.id"), nullable=True)
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
    empresa_id = Column(Integer, ForeignKey("empresas.id"), nullable=True)
    dte_id = Column(Integer, ForeignKey("dtes.id"), nullable=True)
    operacion = Column(String(50), nullable=False)  # ej: TOKEN, UPLOAD, QUERY
    request_data = Column(Text, nullable=True)
    response_data = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=func.now())

    dte = relationship("Dte", back_populates="logs")
