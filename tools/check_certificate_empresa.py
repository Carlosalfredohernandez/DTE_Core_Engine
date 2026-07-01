"""
Carga el certificado asociado a una Empresa (por id) y realiza comprobaciones:
 - carga empresa desde DB
 - usa `load_pfx_from_empresa` para extraer PFX
 - muestra subject, issuer, serial, validez, key usage y prueba sign/verify

Uso:
  python tools/check_certificate_empresa.py <empresa_id>

"""
import sys
import asyncio
from pathlib import Path
# ensure repo root
import sys as _sys, pathlib as _p
_root = str(_p.Path(__file__).resolve().parents[1])
if _root not in _sys.path:
    _sys.path.insert(0, _root)

from app.infrastructure.certificate import load_pfx_from_empresa
from app.infrastructure.database import async_session_factory
from app.domain.models import Empresa
from sqlalchemy import select

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def _print_cert_info(cert, priv):
    from datetime import datetime
    print('\n--- Certificado ---')
    print('Subject:', cert.subject.rfc4514_string())
    print('Issuer :', cert.issuer.rfc4514_string())
    print('Serial :', cert.serial_number)
    try:
        print('Not valid before:', cert.not_valid_before)
        print('Not valid after :', cert.not_valid_after)
    except Exception:
        print('Validez: (no disponible)')
    now = datetime.utcnow()
    print('Now UTC        :', now)
    try:
        print('Expired?       :', now > cert.not_valid_after)
    except Exception:
        pass

    pub = cert.public_key()
    try:
        key_size = pub.key_size
    except Exception:
        key_size = 'unknown'
    print('\n--- Key Info ---')
    print('Public key type:', type(pub))
    print('Key size (bits) :', key_size)

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

    try:
        msg = b'Test message for certificate verification'
        sig = priv.sign(msg, padding.PKCS1v15(), hashes.SHA1())
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA1())
        print('\nSign/verify test with SHA1+PKCS1v15: OK')
    except Exception as e:
        print('\nSign/verify test: FAILED', e)

    subj = cert.subject.rfc4514_string()
    import re
    rut_match = re.search(r"(\d{7,8}-[0-9Kk])", subj)
    if rut_match:
        print('\nDetected RUT in subject:', rut_match.group(1))
    else:
        print('\nNo RUT-like pattern found in subject')


async def main():
    if len(sys.argv) < 2:
        print('Uso: python tools/check_certificate_empresa.py <empresa_id>')
        return
    try:
        empresa_id = int(sys.argv[1])
    except Exception:
        print('empresa_id debe ser un entero')
        return

    async with async_session_factory() as session:
        stmt = select(Empresa).where(Empresa.id == empresa_id)
        res = await session.execute(stmt)
        empresa = res.scalar_one_or_none()
        if empresa is None:
            print('Empresa con id', empresa_id, 'no encontrada')
            return
        print('Empresa encontrada: id=', empresa.id, 'razon_social=', empresa.razon_social_emisor)
        try:
            cert_data = load_pfx_from_empresa(empresa)
        except Exception as e:
            print('Error cargando PFX para la empresa:', e)
            return

        _print_cert_info(cert_data.certificate, cert_data.private_key)

if __name__ == '__main__':
    asyncio.run(main())
