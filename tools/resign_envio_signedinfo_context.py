"""
Script de prueba: genera un EnvioBOLETA resignado usando la variante
que canonicaliza <SignedInfo> en el contexto del documento.

Uso: ejecutar localmente desde la raíz del repo.
"""
import asyncio
import hashlib
from app.infrastructure.database import async_session_factory
from app.domain.models import Dte, Empresa
from app.services.xml_builder import XmlBuilderService
from app.infrastructure.certificate import load_pfx_from_empresa
from app.services.xml_signer import XmlSignerService


async def main():
    dte_id = 128
    async with async_session_factory() as session:
        dte = await session.get(Dte, dte_id)
        if not dte:
            print(f"DTE {dte_id} no encontrado")
            return
        empresa = await session.get(Empresa, dte.empresa_id) if dte.empresa_id else None

        envio_xml_sin_firma = XmlBuilderService.build_envio_dte([dte.xml_documento], empresa=empresa)
        # Prefer loading .pfx desde archivo con la contraseña conocida
        import os
        from app.config import get_settings
        from app.infrastructure.certificate import load_pfx_from_file

        settings = get_settings()
        tried = []
        cert_data = None
        # Try empresa pfx path
        pfx_path = getattr(empresa, 'cert_pfx_path', None) or None
        candidates = [pfx_path, getattr(settings, 'cert_pfx_path', None)]
        for cand in candidates:
            if not cand:
                continue
            full = os.path.abspath(cand)
            tried.append(full)
            if os.path.exists(full):
                try:
                    cert_data = load_pfx_from_file(full, 'vikingo80')
                    break
                except Exception as e:
                    tried.append(f"error_loading:{e}")
        if cert_data is None:
            # fallback: attempt load_pfx_from_empresa which may use base64 (requires master key)
            try:
                cert_data = load_pfx_from_empresa(empresa) if empresa else load_pfx_from_empresa(None)
            except Exception as e:
                raise RuntimeError(f"No pude cargar .pfx desde {tried} y load_pfx_from_empresa falló: {e}")

        # Generar resignado con SignedInfo canonizado en contexto de documento
        envio_resignado = XmlSignerService.sign_document(
            envio_xml_sin_firma,
            cert_data,
            reference_uri="#SetDoc",
            exclusive=None,
            empresa=empresa,
            si_c14n_doc_context=True,
        )

        sha1 = hashlib.sha1(envio_resignado.encode('latin-1')).hexdigest()
        out_path = "tools/resigned_envio_dte128.xml"
        with open(out_path, "w", encoding="latin-1") as fh:
            fh.write(envio_resignado)

        print("Resignado guardado en:", out_path)
        print("SHA1:", sha1)


if __name__ == "__main__":
    asyncio.run(main())
