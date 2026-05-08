"""
DTE Core Engine — Enumeraciones del dominio.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class TipoDte(IntEnum):
    """Tipos de Documento Tributario Electrónico soportados."""

    FACTURA_ELECTRONICA = 33
    FACTURA_EXENTA = 34
    BOLETA_ELECTRONICA = 39
    BOLETA_EXENTA = 41
    NOTA_CREDITO = 61
    NOTA_DEBITO = 56
    GUIA_DESPACHO = 52

    @property
    def nombre(self) -> str:
        _nombres = {
            33: "Factura Electrónica",
            34: "Factura Electrónica Exenta",
            39: "Boleta Electrónica",
            41: "Boleta Electrónica Exenta",
            61: "Nota de Crédito Electrónica",
            56: "Nota de Débito Electrónica",
            52: "Guía de Despacho Electrónica",
        }
        return _nombres.get(self.value, f"Tipo {self.value}")


class EstadoDte(StrEnum):
    """Estados internos del ciclo de vida de un DTE."""

    GENERADO = "GENERADO"
    FIRMADO = "FIRMADO"
    ENVIADO = "ENVIADO"
    ACEPTADO = "ACEPTADO"
    RECHAZADO = "RECHAZADO"
    REPARO = "REPARO"
    ERROR_ENVIO = "ERROR_ENVIO"
    ERROR_FIRMA = "ERROR_FIRMA"


class EstadoSii(StrEnum):
    """Códigos de estado del SII tras consulta (QueryEstUp RESP_HDR.ESTADO)."""

    # Estados del sobre/envío
    RECIBIDO = "EPR"           # Envío Procesado (recibido, aún no validado)
    ACEPTADO = "SOK"           # Schema OK, todo bien
    ACEPTADO_CON_REPAROS = "RPR"  # Aceptado con reparos
    RECHAZADO_SCHEMA = "RSC"   # Rechazado por Error en Schema
    RECHAZADO = "RCH"          # Rechazado

    # QueryEstDte — Estados del documento individual
    DOC_ACEPTADO = "DOK"
    DOC_RECHAZADO = "DNK"
    DOC_REPARO = "DRP"


class AmbienteSii(StrEnum):
    """Ambiente de operación del SII."""

    CERTIFICACION = "certificacion"
    PRODUCCION = "produccion"


class IndicadorServicio(IntEnum):
    """Indicador de tipo de servicio/transacción en el DTE."""

    FACTURA_BIENES = 1
    FACTURA_SERVICIOS = 3
    FACTURA_BIENES_Y_SERVICIOS = 4


class TipoImpuesto(IntEnum):
    """Tipos de impuesto."""

    IVA = 1


# Tasa IVA vigente en Chile
TASA_IVA = 0.19
