"""
DTE Core Engine — Servicio para firmas XML.

Firma XMLDSIG manual compatible con el schema restrictivo xmldsignature_v10.xsd del SII:
  - Sin <Transforms> en <Reference>  (el schema no permite ese nodo)
  - <KeyInfo> con <KeyValue><RSAKeyValue> seguido de <X509Data><X509Certificate>
    (el schema exige ambos, en ese orden)
  - C14N inclusivo (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)
  - RSA-SHA1
"""

from __future__ import annotations

import base64
import hashlib

import structlog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509 import load_der_x509_certificate
from lxml import etree

from app.domain.exceptions import XmlSignError
from app.infrastructure.certificate import CertificateData

logger = structlog.get_logger(__name__)

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
C14N_ALG = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"


class XmlSignerService:
    """Servicio para firmar documentos DTE (XMLDSIG)."""

    @staticmethod
    def sign_document(xml_content: str, cert_data: CertificateData, reference_uri: str | None = None) -> str:
        """
        Firma un documento XML (Boleta, EnvioBOLETA) con XMLDSIG.

        Estructura de Signature generada:
          <Signature xmlns="...xmldsig#">
            <SignedInfo>
              <CanonicalizationMethod Algorithm="c14n"/>
              <SignatureMethod Algorithm="rsa-sha1"/>
              <Reference URI="#ID">          ← sin <Transforms>
                <DigestMethod Algorithm="sha1"/>
                <DigestValue>...</DigestValue>
              </Reference>
            </SignedInfo>
            <SignatureValue>...</SignatureValue>
            <KeyInfo>
              <KeyValue><RSAKeyValue>
                <Modulus>...</Modulus>
                <Exponent>...</Exponent>
              </RSAKeyValue></KeyValue>
            </KeyInfo>
          </Signature>
        """
        try:
            root = etree.fromstring(xml_content.encode("latin-1"))

            # 1. Localizar el elemento a firmar por su ID
            if reference_uri:
                uri_id = reference_uri.lstrip("#")
                elem_to_sign = None
                for elem in root.iter():
                    if elem.get("ID") == uri_id or elem.get("id") == uri_id:
                        elem_to_sign = elem
                        break
                if elem_to_sign is None:
                    raise XmlSignError(f"No se encontró el elemento con ID='{uri_id}'")
                ref_attr = f"#{uri_id}"
            else:
                elem_to_sign = root
                ref_attr = ""

            # 2. C14N del elemento referenciado → digest SHA1
            #    (sin declarar Transform; el verificador aplica C14N por defecto)
            elem_c14n = etree.tostring(elem_to_sign, method="c14n")
            digest_b64 = base64.b64encode(hashlib.sha1(elem_c14n).digest()).decode()

            # 3. Componentes RSA para KeyValue + DER del certificado para X509Data
            private_key = cert_data.private_key
            pub_nums = private_key.public_key().public_numbers()
            n_bytes = pub_nums.n.to_bytes((pub_nums.n.bit_length() + 7) // 8, "big")
            e_bytes = pub_nums.e.to_bytes((pub_nums.e.bit_length() + 7) // 8, "big")
            modulus_b64 = base64.b64encode(n_bytes).decode()
            exponent_b64 = base64.b64encode(e_bytes).decode()
            cert_der = cert_data.certificate.public_bytes(serialization.Encoding.DER)
            cert_der_b64 = base64.b64encode(cert_der).decode()

            # 4. Construir Signature con SignatureValue vacío (se rellena luego)
            signature_xml = (
                f'<Signature xmlns="{DS_NS}">'
                f'<SignedInfo>'
                f'<CanonicalizationMethod Algorithm="{C14N_ALG}"></CanonicalizationMethod>'
                f'<SignatureMethod Algorithm="{DS_NS}rsa-sha1"></SignatureMethod>'
                f'<Reference URI="{ref_attr}">'
                f'<DigestMethod Algorithm="{DS_NS}sha1"></DigestMethod>'
                f'<DigestValue>{digest_b64}</DigestValue>'
                f'</Reference>'
                f'</SignedInfo>'
                f'<SignatureValue/>'
                f'<KeyInfo>'
                f'<KeyValue>'
                f'<RSAKeyValue>'
                f'<Modulus>{modulus_b64}</Modulus>'
                f'<Exponent>{exponent_b64}</Exponent>'
                f'</RSAKeyValue>'
                f'</KeyValue>'
                f'<X509Data>'
                f'<X509Certificate>{cert_der_b64}</X509Certificate>'
                f'</X509Data>'
                f'</KeyInfo>'
                f'</Signature>'
            )
            sig_tree = etree.fromstring(signature_xml.encode())

            # 5. Anexar Signature primero y firmar SignedInfo en el contexto final.
            #    Esto evita diferencias de canonicalización por namespaces en scope
            #    entre firmado y verificación.
            if elem_to_sign is not None:
              # Salto de línea entre nodo firmado y Signature (no afecta digest
              # del nodo referenciado por URI).
              elem_to_sign.tail = "\n"
            root.append(sig_tree)
            si_elem = sig_tree.find(f"{{{DS_NS}}}SignedInfo")
            si_c14n = etree.tostring(si_elem, method="c14n")
            sig_bytes = private_key.sign(si_c14n, asym_padding.PKCS1v15(), hashes.SHA1())
            sig_b64 = base64.b64encode(sig_bytes).decode()

            # 6. Insertar SignatureValue
            sig_tree.find(f"{{{DS_NS}}}SignatureValue").text = sig_b64

            # Serialización final en C14N (como texto canonizado) para mantener
            # estabilidad byte-a-byte respecto a la variante que ya fue aceptada
            # por el SII en este proyecto.
            c14n_content = etree.tostring(root, method="c14n").decode("latin-1")
            return '<?xml version="1.0" encoding="ISO-8859-1"?>\n' + c14n_content

        except XmlSignError:
            raise
        except Exception as e:
            logger.error("Error firmando documento XML", error=str(e))
            raise XmlSignError(f"Error firmando documento: {str(e)}") from e

    @staticmethod
    def verify_signatures(xml_content: str) -> list[dict]:
        """
        Verifica localmente todas las firmas XMLDSIG presentes en el documento.

        Criterios de contexto (para replicar exactamente cómo se firmó):
          - DigestValue: C14N del elemento referenciado en el contexto del padre
            de <Signature> serializado standalone (sin heredar xmlns del contenedor
            exterior, e.g. sin xmlns:xsi de EnvioBOLETA cuando se verifica un DTE
            firmado dentro de ella).
          - SignatureValue: C14N de <SignedInfo> usando <Signature> serializado
            standalone (sin heredar xmlns del contenedor).

        Retorna lista de dicts por cada Signature:
          {
            "reference_uri": str,
            "digest_ok": bool,
            "computed_digest": str,
            "stored_digest": str,
            "signature_ok": bool,
            "error": str | None,
            "si_c14n_hex": str,
          }
        """
        root = etree.fromstring(xml_content.encode("latin-1"))
        results: list[dict] = []

        for sig in root.iter(f"{{{DS_NS}}}Signature"):
            result: dict = {
                "reference_uri": None,
                "digest_ok": False,
                "computed_digest": None,
                "stored_digest": None,
                "signature_ok": False,
                "error": None,
                "si_c14n_hex": None,
            }
            try:
                # ── Contexto: padre de <Signature> serializado standalone ─────
                # Esto elimina namespaces heredados del contenedor superior
                # (e.g. xmlns:xsi de EnvioBOLETA) para replicar el contexto
                # exacto en que se firmó el elemento referenciado.
                sig_parent = sig.getparent()
                if sig_parent is not None:
                    parent_standalone = etree.fromstring(etree.tostring(sig_parent))
                else:
                    parent_standalone = etree.fromstring(etree.tostring(root))

                # ── 1. Digest ──────────────────────────────────────────────────
                ref = sig.find(f".//{{{DS_NS}}}Reference")
                uri = ref.get("URI", "") if ref is not None else ""
                result["reference_uri"] = uri

                uri_id = uri.lstrip("#")
                if uri_id:
                    elem_to_verify = None
                    for elem in parent_standalone.iter():
                        if elem.get("ID") == uri_id or elem.get("id") == uri_id:
                            elem_to_verify = elem
                            break
                    if elem_to_verify is None:
                        result["error"] = f"Elemento con ID='{uri_id}' no encontrado en contexto standalone"
                        results.append(result)
                        continue
                else:
                    elem_to_verify = parent_standalone

                computed = base64.b64encode(
                    hashlib.sha1(etree.tostring(elem_to_verify, method="c14n")).digest()
                ).decode()
                result["computed_digest"] = computed

                dv_elem = ref.find(f"{{{DS_NS}}}DigestValue") if ref is not None else None
                stored = (dv_elem.text or "").strip() if dv_elem is not None else ""
                result["stored_digest"] = stored
                result["digest_ok"] = (computed == stored)

                # ── 2. SignatureValue sobre nodo original ──────────────────────
                # Para evitar drift por reserialización/prefijos (ns0), usamos
                # el SignedInfo del nodo Signature ya parseado en el XML real.
                sv_elem = sig.find(f"{{{DS_NS}}}SignatureValue")
                sig_bytes_val = base64.b64decode(
                    (sv_elem.text or "").strip()
                ) if sv_elem is not None else b""

                x509_elem = sig.find(f".//{{{DS_NS}}}X509Certificate")
                if x509_elem is None or not x509_elem.text:
                    result["error"] = "X509Certificate ausente en KeyInfo"
                    results.append(result)
                    continue

                cert_der = base64.b64decode((x509_elem.text or "").strip())
                pub_key = load_der_x509_certificate(cert_der).public_key()

                si_elem = sig.find(f"{{{DS_NS}}}SignedInfo")
                si_c14n = etree.tostring(si_elem, method="c14n")
                result["si_c14n_hex"] = si_c14n[:200].decode("latin-1")

                try:
                    pub_key.verify(sig_bytes_val, si_c14n, asym_padding.PKCS1v15(), hashes.SHA1())
                    result["signature_ok"] = True
                except Exception as ve:
                    result["error"] = f"Firma RSA inválida: {ve}"

            except Exception as e:
                result["error"] = f"Error de verificación: {e}"

            results.append(result)

        return results
