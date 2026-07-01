"""
Verifica el certificado configurado (PFX) y realiza pruebas básicas:
 - carga desde settings (CERT_PFX_BASE64 / path) o desde archivo provisto
 - muestra subject, issuer, serial, validez
 - comprueba key usage (Digital Signature)
 - prueba firma/verificación con SHA1+PKCS1v15
 - comprueba tamaño de clave RSA

Uso:
  python tools/check_certificate.py [pfx_path] [password]

Si no se provee pfx_path, se intenta cargar desde settings/env.
"""
import sys
from pathlib import Path
# ensure repo root
import sys as _sys, pathlib as _p
_root = str(_p.Path(__file__).resolve().parents[1])
if _root not in _sys.path:
    _sys.path.insert(0, _root)

from app.infrastructure.certificate import load_pfx_from_settings, load_pfx_from_file
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64


def main():
    pfx_path = sys.argv[1] if len(sys.argv) > 1 else None
    password = sys.argv[2] if len(sys.argv) > 2 else None

    cert_data = None
    try:
        if pfx_path:
            cert_data = load_pfx_from_file(pfx_path, password or '')
            print('Cargado PFX desde archivo:', pfx_path)
        else:
            cert_data = load_pfx_from_settings()
            print('Cargado PFX desde settings/env')
    except Exception as e:
        print('Error cargando certificado:', e)
        return

    cert = cert_data.certificate
    priv = cert_data.private_key

    print('\n--- Certificado ---')
    print('Subject:', cert.subject.rfc4514_string())
    print('Issuer :', cert.issuer.rfc4514_string())
    print('Serial :', cert.serial_number)
    print('Not valid before:', cert.not_valid_before)
    print('Not valid after :', cert.not_valid_after)
    from datetime import datetime
    now = datetime.utcnow()
    print('Now UTC        :', now)
    print('Expired?       :', now > cert.not_valid_after)

    # key info
    pub = cert.public_key()
    try:
        key_size = pub.key_size
    except Exception:
        key_size = 'unknown'
    print('\n--- Key Info ---')
    print('Public key type:', type(pub))
    print('Key size (bits) :', key_size)

    # Key Usage extension (if present)
    try:
        ku = cert.extensions.get_extension_for_class(__import__('cryptography.x509').x509.KeyUsage).value
        print('\nKeyUsage:')
        print('  digital_signature:', ku.digital_signature)
        print('  content_commitment:', ku.content_commitment)
        print('  key_encipherment:', ku.key_encipherment)
        print('  data_encipherment:', ku.data_encipherment)
        print('  key_agreement:', ku.key_agreement)
        print('  key_cert_sign:', ku.key_cert_sign)
        print('  crl_sign:', ku.crl_sign)
        print('  encipher_only:', ku.encipher_only)
        print('  decipher_only:', ku.decipher_only)
    except Exception:
        print('\nKeyUsage: no presente o no legible')

    # Test sign/verify
    try:
        msg = b'Test message for certificate verification'
        signer = priv
        sig = signer.sign(msg, padding.PKCS1v15(), hashes.SHA1())
        # verify with public key
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA1())
        print('\nSign/verify test with SHA1+PKCS1v15: OK')
    except Exception as e:
        print('\nSign/verify test: FAILED', e)

    # Check whether certificate subject contains RUT-like string (e.g., digits-D)
    subj = cert.subject.rfc4514_string()
    import re
    rut_match = re.search(r"(\d{7,8}-[0-9Kk])", subj)
    if rut_match:
        print('\nDetected RUT in subject:', rut_match.group(1))
    else:
        print('\nNo RUT-like pattern found in subject')

    print('\n--- End ---')

if __name__ == '__main__':
    main()
