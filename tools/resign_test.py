"""
Script de prueba: re-firma DTEs seleccionados usando Exclusive C14N y verifica localmente.
Guardar salida en `tools/resigned_dtes/`.
"""

import asyncio
import base64
import hashlib
import os
from pathlib import Path
from lxml import etree
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa
from app.infrastructure.certificate import load_pfx_from_empresa

EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

OUT_DIR = Path(__file__).parent / "resigned_dtes"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def canonicalize(elem, exclusive: bool = True) -> bytes:
    # lxml supports exclusive via exclusive=True
    return etree.tostring(elem, method="c14n", exclusive=exclusive)


async def resign_and_verify(dte_id: int):
    async with async_session_factory() as session:
        d = await session.get(Dte, dte_id)
        if not d:
            print(f"DTE {dte_id} no encontrado")
            return
        empresa = None
        if d.empresa_id:
            empresa = await session.get(Empresa, d.empresa_id)
        xml = d.xml_envio or d.xml_documento
        if not xml:
            print(f"DTE {dte_id} no tiene xml")
            return

        # Intentar cargar certificado desde la configuracion de la empresa;
        # si falla (p.ej. falta CERT_MASTER_KEY), hacer fallback a archivo local.
        try:
            cert_data = load_pfx_from_empresa(empresa)
        except Exception as e:
            from app.config import get_settings
            settings = get_settings()
            cert_path = settings.cert_pfx_path
            cert_pass = settings.cert_pfx_password
            print(f"load_pfx_from_empresa falló: {e}; usando cert path {cert_path}")
            from app.infrastructure.certificate import load_pfx_from_file
            cert_data = load_pfx_from_file(cert_path, cert_pass)
        private_key = cert_data.private_key

        root = etree.fromstring(xml.encode('latin-1'))

        # Forzar xsi:schemaLocation exacto en la raíz EnvioBOLETA (evita variantes mal formadas)
        try:
            xsi_ns = 'http://www.w3.org/2001/XMLSchema-instance'
            sii_ns = 'http://www.sii.cl/SiiDte'
            desired = f"{sii_ns} http://www.sii.cl/SiiDte/EnvioBOLETA_v11.xsd"
            # root puede ser EnvioBOLETA o contenerlo como hijo
            if (etree.QName(root).localname == 'EnvioBOLETA'):
                root.set(f'{{{xsi_ns}}}schemaLocation', desired)
            else:
                for envio in root.findall('.//{http://www.sii.cl/SiiDte}EnvioBOLETA') or root.findall('.//EnvioBOLETA'):
                    envio.set(f'{{{xsi_ns}}}schemaLocation', desired)
        except Exception:
            pass

        # localizar elemento a firmar (el Documento dentro del EnvioBOLETA)
        # asumimos el ID del documento (por ejemplo T39F368)
        # buscaremos la primera firma existente para tomar su Reference URI
        sigs = list(root.iter(f"{{{DS_NS}}}Signature"))
        ref_uri = None
        if sigs:
            ref = sigs[0].find(f".//{{{DS_NS}}}Reference")
            if ref is not None:
                ref_uri = (ref.get('URI') or '').lstrip('#')

        if ref_uri:
            elem_to_sign = None
            for elem in root.iter():
                if elem.get('ID') == ref_uri or elem.get('id') == ref_uri:
                    elem_to_sign = elem
                    break
            if elem_to_sign is None:
                print(f"Elemento a firmar con ID={ref_uri} no encontrado; firmando root")
                elem_to_sign = root
        else:
            elem_to_sign = root

        # compute digest using exclusive c14n
        elem_c14n = canonicalize(elem_to_sign, exclusive=True)
        digest_b64 = base64.b64encode(hashlib.sha1(elem_c14n).digest()).decode()

        # build Signature XML using exclusive c14n algorithm URI
        pub_nums = private_key.public_key().public_numbers()
        n_bytes = pub_nums.n.to_bytes((pub_nums.n.bit_length() + 7) // 8, "big")
        e_bytes = pub_nums.e.to_bytes((pub_nums.e.bit_length() + 7) // 8, "big")
        modulus_b64 = base64.b64encode(n_bytes).decode()
        exponent_b64 = base64.b64encode(e_bytes).decode()
        cert_der = cert_data.certificate.public_bytes(serialization.Encoding.DER)
        cert_der_b64 = base64.b64encode(cert_der).decode()

        ref_attr = f"#{ref_uri}" if ref_uri else ""

        signature_xml = (
            f'<Signature xmlns="{DS_NS}">'
            f'<SignedInfo>'
            f'<CanonicalizationMethod Algorithm="{EXCLUSIVE_C14N}"></CanonicalizationMethod>'
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

        # append signature
        elem_to_sign.tail = "\n"
        root.append(sig_tree)

        # sign SignedInfo using exclusive c14n
        si_elem = sig_tree.find(f"{{{DS_NS}}}SignedInfo")
        si_c14n = etree.tostring(si_elem, method='c14n', exclusive=True)
        sig_bytes = private_key.sign(si_c14n, asym_padding.PKCS1v15(), hashes.SHA1())
        sig_b64 = base64.b64encode(sig_bytes).decode()
        sig_tree.find(f"{{{DS_NS}}}SignatureValue").text = sig_b64

        # produce final XML
        final_xml = '<?xml version="1.0" encoding="ISO-8859-1"?>\n' + etree.tostring(root, method='c14n', exclusive=True).decode('latin-1')

        out_path = OUT_DIR / f"dte_{dte_id}_exclusive.xml"
        out_path.write_text(final_xml, encoding='latin-1')
        print(f"Generated {out_path} sha1={hashlib.sha1(final_xml.encode('latin-1')).hexdigest()}")

        # verify locally using exclusive c14n
        verify_results = []
        # parse fresh
        r2 = etree.fromstring(final_xml.encode('latin-1'))
        for sig in r2.iter(f"{{{DS_NS}}}Signature"):
            res = {'reference_uri': None, 'digest_ok': False, 'signature_ok': False, 'error': None}
            try:
                ref = sig.find(f".//{{{DS_NS}}}Reference")
                uri = (ref.get('URI') or '') if ref is not None else ''
                res['reference_uri'] = uri
                uri_id = uri.lstrip('#')
                if uri_id:
                    elem_to_verify = None
                    # find in parent standalone
                    parent = sig.getparent()
                    parent_standalone = etree.fromstring(etree.tostring(parent))
                    for elem in parent_standalone.iter():
                        if elem.get('ID') == uri_id or elem.get('id') == uri_id:
                            elem_to_verify = elem
                            break
                    if elem_to_verify is None:
                        raise Exception(f"ID {uri_id} not found")
                else:
                    parent = sig.getparent()
                    parent_standalone = etree.fromstring(etree.tostring(parent))
                    elem_to_verify = parent_standalone

                computed = base64.b64encode(hashlib.sha1(etree.tostring(elem_to_verify, method='c14n', exclusive=True)).digest()).decode()
                dv = ref.find(f"{{{DS_NS}}}DigestValue") if ref is not None else None
                stored = (dv.text or '').strip() if dv is not None else ''
                res['computed_digest'] = computed
                res['stored_digest'] = stored
                res['digest_ok'] = (computed == stored)

                # signature verify
                sv = sig.find(f"{{{DS_NS}}}SignatureValue")
                sv_bytes = base64.b64decode((sv.text or '').strip()) if sv is not None else b''
                x509_elem = sig.find(f".//{{{DS_NS}}}X509Certificate")
                cert_der_b64 = (x509_elem.text or '').strip() if x509_elem is not None else ''
                pub_key = None
                if cert_der_b64:
                    from cryptography.x509 import load_der_x509_certificate
                    cert_der = base64.b64decode(cert_der_b64)
                    pub_key = load_der_x509_certificate(cert_der).public_key()
                si_elem2 = sig.find(f"{{{DS_NS}}}SignedInfo")
                si_c14n2 = etree.tostring(si_elem2, method='c14n', exclusive=True)
                try:
                    pub_key.verify(sv_bytes, si_c14n2, asym_padding.PKCS1v15(), hashes.SHA1())
                    res['signature_ok'] = True
                except Exception as ve:
                    res['error'] = f"Signature verify failed: {ve}"

            except Exception as e:
                res['error'] = str(e)
            verify_results.append(res)

        print('verify_results:', verify_results)


async def main():
    await resign_and_verify(125)
    await resign_and_verify(126)

if __name__ == '__main__':
    asyncio.run(main())
