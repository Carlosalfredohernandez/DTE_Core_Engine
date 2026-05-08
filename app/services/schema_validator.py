"""
Validación local de EnvioBOLETA contra XSD (enfocada en estructura tributaria).

Nota: el XSD oficial importa xmldsignature_v10.xsd. Para validar rápidamente
el contenido tributario del documento, se eliminan nodos ds:Signature del XML
y se adapta el XSD en memoria para no requerir esa importación.
"""

from __future__ import annotations

from pathlib import Path

import structlog
from lxml import etree


DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_XSD_REL_PATH = Path("scratch") / "EnvioBOLETA_v11.xsd"
logger = structlog.get_logger(__name__)


def _candidate_xsd_paths() -> list[Path]:
    current = Path(__file__).resolve()
    return [
        current.parents[2] / _XSD_REL_PATH,  # repo root local (/.../DTE_Core_Engine/scratch)
        current.parents[1] / _XSD_REL_PATH,  # fallback when layout differs
        Path.cwd() / _XSD_REL_PATH,          # runtime cwd (/app/scratch)
        Path("/app") / _XSD_REL_PATH,       # explicit Railway/Docker path
    ]


def _normalize_legacy_xsd(xsd_text: str) -> str:
    """
    Ajustes mínimos para compilar el XSD legacy con lxml sin tocar el archivo fuente.

    El XSD oficial contiene algunos facets inconsistentes para validadores modernos,
    por ejemplo `minInclusive="0.00"` sobre tipos de porcentaje cuyo mínimo base
    termina siendo `0.01`.
    """
    normalized = xsd_text
    normalized = normalized.replace(
        '<xs:import namespace="http://www.w3.org/2000/09/xmldsig#" schemaLocation="xmldsignature_v10.xsd"/>',
        "",
    )
    normalized = normalized.replace(
        '<xs:element ref="ds:Signature"/>',
        '<xs:any namespace="##other" processContents="skip" minOccurs="0" maxOccurs="1"/>',
    )
    normalized = normalized.replace(
        '<xs:minInclusive value="0.00"/>',
        '<xs:minInclusive value="0.01"/>',
    )
    return normalized


def validate_envio_schema(xml_content: str) -> list[str]:
    """Retorna lista de errores XSD; vacía si el XML es estructuralmente válido."""
    xsd_path = next((p for p in _candidate_xsd_paths() if p.exists()), None)

    if xsd_path is None:
        logger.warning(
            "XSD local no disponible; se omite validación de schema previa al upload",
            searched_paths=[str(p) for p in _candidate_xsd_paths()],
        )
        return []

    # 1) Parse XML y remover firmas ds:Signature
    parser = etree.XMLParser(remove_blank_text=False, recover=False)
    xml_root = etree.fromstring(xml_content.encode("latin-1"), parser=parser)
    for sig in xml_root.xpath("//*[local-name()='Signature' and namespace-uri()=$ns]", ns=DS_NS):
        parent = sig.getparent()
        if parent is not None:
            parent.remove(sig)

    # 2) Cargar XSD y adaptar en memoria para no depender de import dsig
    xsd_text = _normalize_legacy_xsd(xsd_path.read_text(encoding="latin-1"))

    try:
        xsd_doc = etree.fromstring(xsd_text.encode("latin-1"), parser=parser)
        schema = etree.XMLSchema(xsd_doc)
    except Exception as e:
        logger.warning(
            "No se pudo compilar XSD local adaptado; se omite validación previa",
            error=str(e),
            xsd_path=str(xsd_path),
        )
        return []

    # 3) Validar XML sin firmas
    is_valid = schema.validate(xml_root)
    if is_valid:
        return []

    errors: list[str] = []
    for err in schema.error_log:
        errors.append(f"line {err.line}: {err.message}")
    return errors
