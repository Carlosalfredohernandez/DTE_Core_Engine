"""
DTE Core Engine — Servicio para manejo de CAF y folios.
"""

from __future__ import annotations

import base64
import hashlib
from typing import TypedDict

import structlog
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import load_der_private_key
from lxml import etree

from app.domain.exceptions import CafError

logger = structlog.get_logger(__name__)


class RangoCaf(TypedDict):
    desde: int
    hasta: int


class CafInfo(TypedDict):
    tipo_dte: int
    rango: RangoCaf
    fecha_autorizacion: str
    private_key_pem: str
    caf_xml_element: etree._Element


class CafService:
    """Servicio para parsear XMLs de CAF y firmar el TED."""

    @staticmethod
    def _find_by_localname(node: etree._Element, name: str) -> etree._Element | None:
        for el in node.iter():
            if etree.QName(el).localname == name:
                return el
        return None

    @staticmethod
    def _clone_localname_only(node: etree._Element) -> etree._Element:
        cloned = etree.Element(etree.QName(node).localname)
        for key, value in node.attrib.items():
            attr_name = etree.QName(key).localname if key.startswith("{") else key
            cloned.set(attr_name, value)
        cloned.text = node.text
        cloned.tail = node.tail
        for child in node:
            cloned.append(CafService._clone_localname_only(child))
        return cloned

    @staticmethod
    def dd_signing_payload(dd: etree._Element) -> bytes:
        """Retorna el payload exacto usado para firmar/verificar FRMT."""
        payload_root = CafService._clone_localname_only(dd)
        for element in payload_root.iter():
            if element.text is not None and element.text.strip() == "":
                element.text = None
            if element.tail is not None and element.tail.strip() == "":
                element.tail = None

        payload = etree.tostring(payload_root, encoding="ISO-8859-1")
        if payload.startswith(b"<?xml") and b"?>" in payload:
            payload = payload.split(b"?>", 1)[1].strip()
        return payload.replace(b"\n", b"").replace(b"\r", b"").strip()

    @staticmethod
    def parse_caf_xml(xml_content: str) -> CafInfo:
        """
        Parsea un archivo CAF XML y extrae la información relevante.
        """
        try:
            # Parsear el XML
            root = etree.fromstring(xml_content.encode("latin-1"))
            
            # Buscar el elemento <DA> que contiene los datos de autorización
            da = root.find(".//DA")
            if da is None:
                raise CafError("Archivo CAF no contiene elemento <DA>")

            tipo_dte = int(da.findtext("TD") or "0")
            rango = da.find("RNG")
            if rango is None:
                raise CafError("Archivo CAF no contiene elemento <RNG>")
                
            desde = int(rango.findtext("D") or "0")
            hasta = int(rango.findtext("H") or "0")
            fecha_aut = da.findtext("FA") or ""
            
            # Buscar llave privada RSA (RSASK está al mismo nivel que CAF)
            rsask = root.findtext(".//RSASK")
            if not rsask:
                raise CafError("Archivo CAF no contiene llave privada <RSASK>")

            # Guardar el nodo <CAF> para embeberlo en el TED
            caf_element = root.find(".//CAF")
            if caf_element is None:
                raise CafError("Archivo CAF no contiene elemento <CAF>")

            return CafInfo(
                tipo_dte=tipo_dte,
                rango=RangoCaf(desde=desde, hasta=hasta),
                fecha_autorizacion=fecha_aut,
                private_key_pem=rsask,
                caf_xml_element=caf_element
            )
        except etree.XMLSyntaxError as e:
            raise CafError(f"Error parseando CAF XML: {str(e)}") from e
        except Exception as e:
            raise CafError(f"Error procesando CAF: {str(e)}") from e

    @staticmethod
    def load_caf_private_key(rsask_str: str) -> rsa.RSAPrivateKey:
        """
        Carga la llave privada RSA del CAF.
        Soporta formato PEM (con cabeceras) y formato DER/Base64 puro (PKCS#1 o PKCS#8).
        """
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key
        
        try:
            # Limpiar espacios y saltos de línea
            clean_str = rsask_str.strip()
            
            # Caso 1: Es formato PEM (tiene cabeceras)
            if "-----BEGIN" in clean_str:
                private_key = load_pem_private_key(
                    clean_str.encode("utf-8"),
                    password=None
                )
            else:
                # Caso 2: Es Base64 puro (DER)
                # Eliminamos posibles espacios internos
                clean_b64 = clean_str.replace("\n", "").replace("\r", "").replace(" ", "")
                der_data = base64.b64decode(clean_b64)
                
                # Intentamos cargar como PKCS#8 (estándar de load_der_private_key)
                # Si falla, el error ASN.1 suele indicar que es PKCS#1
                try:
                    private_key = load_der_private_key(der_data, password=None)
                except Exception:
                    # Fallback para PKCS#1 DER (común en CAFs antiguos o procesados)
                    # Re-empaquetamos como PEM para usar load_pem_private_key que es más flexible
                    pem_data = (
                        b"-----BEGIN RSA PRIVATE KEY-----\n" +
                        base64.b64encode(der_data) +
                        b"\n-----END RSA PRIVATE KEY-----"
                    )
                    private_key = load_pem_private_key(pem_data, password=None)
            
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("La llave cargada no es RSA")
                
            return private_key
        except Exception as e:
            logger.error("Error crítico cargando llave CAF", error=str(e), content_preview=rsask_str[:50])
            raise CafError(f"Error cargando llave privada del CAF: {str(e)}") from e

    @staticmethod
    def sign_ted_string(datos_dd: str, private_key: rsa.RSAPrivateKey) -> str:
        """
        Firma el string de los datos del timbre (DD) con la llave RSA del CAF.
        Utiliza RSA con SHA1 según normativa del SII.
        """
        try:
            signature = private_key.sign(
                datos_dd.encode("latin-1"),
                padding.PKCS1v15(),
                hashes.SHA1()
            )
            return base64.b64encode(signature).decode("ascii")
        except Exception as e:
            raise CafError(f"Error firmando el timbre electrónico: {str(e)}") from e

    @staticmethod
    def verify_ted_signature(xml_content: str) -> dict[str, object]:
        """Verifica FRMT del TED con la llave pública contenida en CAF/RSAPK."""
        result: dict[str, object] = {
            "has_ted": False,
            "frmt_present": False,
            "caf_public_key_present": False,
            "valid": False,
            "matched_strategy": None,
            "error": None,
        }
        try:
            root = etree.fromstring(xml_content.encode("latin-1"))

            ted = CafService._find_by_localname(root, "TED")
            if ted is None:
                return result
            result["has_ted"] = True

            dd = CafService._find_by_localname(ted, "DD")
            frmt = CafService._find_by_localname(ted, "FRMT")
            if dd is None or frmt is None or not (frmt.text or "").strip():
                return result
            result["frmt_present"] = True

            rsapk = CafService._find_by_localname(dd, "RSAPK")
            if rsapk is None:
                return result
            m_el = CafService._find_by_localname(rsapk, "M")
            e_el = CafService._find_by_localname(rsapk, "E")
            if m_el is None or e_el is None or not m_el.text or not e_el.text:
                return result
            result["caf_public_key_present"] = True

            n = int.from_bytes(base64.b64decode(m_el.text.strip()), "big")
            e = int.from_bytes(base64.b64decode(e_el.text.strip()), "big")
            pub = RSAPublicNumbers(e, n).public_key()
            sig = base64.b64decode((frmt.text or "").strip())

            strategies = [
                ("raw-iso", CafService.dd_signing_payload(dd)),
                ("raw-utf8", etree.tostring(dd, encoding="utf-8")),
                ("c14n", etree.tostring(dd, method="c14n")),
            ]

            for name, payload in strategies:
                if payload.startswith(b"<?xml") and b"?>" in payload:
                    payload = payload.split(b"?>", 1)[1].strip()
                payload = payload.replace(b"\n", b"").replace(b"\r", b"").strip()
                try:
                    pub.verify(sig, payload, padding.PKCS1v15(), hashes.SHA1())
                    result["valid"] = True
                    result["matched_strategy"] = name
                    return result
                except Exception:
                    continue

            return result
        except Exception as e:
            result["error"] = str(e)
            return result

    @staticmethod
    def ted_debug_payload(xml_content: str) -> dict[str, object]:
        """Entrega huellas del DD/FRMT para comparar envíos aceptados/rechazados."""
        debug: dict[str, object] = {
            "has_ted": False,
            "dd_present": False,
            "frmt_present": False,
            "dd_payload_len": None,
            "dd_payload_sha1": None,
            "dd_payload_prefix": None,
            "frmt_len": None,
            "frmt_sha1": None,
            "error": None,
        }
        try:
            root = etree.fromstring(xml_content.encode("latin-1"))
            ted = CafService._find_by_localname(root, "TED")
            if ted is None:
                return debug
            debug["has_ted"] = True

            dd = CafService._find_by_localname(ted, "DD")
            frmt = CafService._find_by_localname(ted, "FRMT")
            if dd is not None:
                debug["dd_present"] = True
                payload = CafService.dd_signing_payload(dd)
                debug["dd_payload_len"] = len(payload)
                debug["dd_payload_sha1"] = hashlib.sha1(payload).hexdigest()
                debug["dd_payload_prefix"] = payload[:140].decode("latin-1", errors="replace")

            frmt_text = (frmt.text or "").strip() if frmt is not None else ""
            if frmt_text:
                debug["frmt_present"] = True
                debug["frmt_len"] = len(frmt_text)
                debug["frmt_sha1"] = hashlib.sha1(frmt_text.encode("ascii", errors="ignore")).hexdigest()

            return debug
        except Exception as e:
            debug["error"] = str(e)
            return debug
