"""
DTE Core Engine — Servicio de Autenticación con el SII (Token).

Orquesta el proceso completo:
1. Obtener Semilla (CrSeed)
2. Firmar Semilla (XMLDSIG)
3. Obtener Token (GetTokenFromSeed)
4. Cachear Token en memoria
"""

import asyncio
from datetime import datetime, timedelta, timezone

import structlog
from lxml import etree
import signxml
from signxml import XMLSigner

from app.clients.seed_client import SeedClient
from app.clients.token_client import TokenClient
from app.config import get_settings
from app.domain.exceptions import SiiAuthError
from app.infrastructure.certificate import (
    CertificateData, 
    load_pfx_from_settings,
    load_pfx_from_file
)

logger = structlog.get_logger(__name__)
settings = get_settings()


class LegacyXMLSigner(XMLSigner):
    """
    Clase para saltarse la restricción de seguridad de signxml.
    El SII de Chile requiere obligatoriamente SHA1, que está obsoleto 
    y bloqueado por defecto en librerías modernas.
    """
    def check_deprecated_methods(self):
        pass


class TokenService:
    """Servicio para obtención y cacheo de Token del SII."""

    def __init__(self):
        self.seed_client = SeedClient()
        self.token_client = TokenClient()
        self._lock = asyncio.Lock()
        
        self._cached_token: str | None = None
        self._token_expires_at: datetime | None = None
        
        self._cert_data: CertificateData | None = None

    def _get_cert(self) -> CertificateData:
        """Carga el certificado bajo demanda."""
        if self._cert_data is None:
            self._cert_data = load_pfx_from_settings()
        return self._cert_data

    def _parse_xml_value(self, xml_string: str, tag_name: str, default: str | None = None) -> str:
        """Extrae un valor de texto de un tag específico en el XML del SII."""
        try:
            if not xml_string:
                if default is not None: return default
                raise SiiAuthError("Respuesta del SII vacía")

            # Parseamos usando lxml, ignorando namespaces por simplicidad
            root = etree.fromstring(xml_string.encode("utf-8"))
            # Buscar el tag sin importar el namespace usando XPath completo
            elements = root.xpath(f"//*[local-name()='{tag_name}']")
            
            if elements and elements[0].text is not None:
                return elements[0].text
                
            if default is not None:
                return default

            raise SiiAuthError(f"No se encontró el tag <{tag_name}> en la respuesta")
        except etree.XMLSyntaxError as e:
            raise SiiAuthError(f"Error parseando respuesta XML del SII: {str(e)}") from e

    def _sign_seed(self, seed_xml_str: str, cert_data: CertificateData | None = None) -> str:
        """Firma el XML de la semilla con el certificado usando XMLDSIG."""
        if cert_data is None:
            cert_data = self._get_cert()
        
        try:
            # Recreamos la estructura que el SII espera que firmemos.
            # Estructura: <getToken><item><Semilla>...
            getToken_element = etree.Element("getToken")
            item_element = etree.SubElement(getToken_element, "item")
            semilla_element = etree.SubElement(item_element, "Semilla")
            semilla_element.text = self._parse_xml_value(seed_xml_str, "SEMILLA")

            # Firmamos el elemento getToken.
            # El SII requiere SHA1 y C14N inclusivo.
            signer = LegacyXMLSigner(
                method=signxml.methods.enveloped,
                signature_algorithm="rsa-sha1",
                digest_algorithm="sha1",
                c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            )
            
            # IMPORTANTE: Forzamos que el namespace de la firma no tenga prefijo (ds:)
            # El SII es muy sensible a esto en el servicio de Token.
            signer.namespaces = {None: "http://www.w3.org/2000/09/xmldsig#"}
            
            # Firmar el elemento raíz.
            signed_element = signer.sign(
                getToken_element,
                key=cert_data.private_key_pem,
                cert=cert_data.certificate_pem
            )
            
            # El SII a veces requiere el RSAKeyValue (Modulus y Exponent) además del X509Data.
            # Lo añadimos manualmente al KeyInfo. Como es una firma enveloped, 
            # el KeyInfo no forma parte del digest y podemos alterarlo tras firmar.
            try:
                from cryptography.hazmat.primitives.asymmetric import rsa
                import base64

                public_key = cert_data.certificate.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    # Localizar KeyInfo (sin prefijo gracias a signer.namespaces)
                    key_info_list = signed_element.xpath("//*[local-name()='KeyInfo']")
                    if key_info_list:
                        key_info = key_info_list[0]
                        ds_ns = "http://www.w3.org/2000/09/xmldsig#"
                        
                        # Crear KeyValue
                        key_value = etree.Element(f"{{{ds_ns}}}KeyValue")
                        rsa_key_value = etree.SubElement(key_value, f"{{{ds_ns}}}RSAKeyValue")
                        
                        numbers = public_key.public_numbers()
                        def b64_n(n):
                            return base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, 'big')).decode()
                        
                        mod = etree.SubElement(rsa_key_value, f"{{{ds_ns}}}Modulus")
                        mod.text = b64_n(numbers.n)
                        exp = etree.SubElement(rsa_key_value, f"{{{ds_ns}}}Exponent")
                        exp.text = b64_n(numbers.e)
                        
                        # Insertar al principio de KeyInfo
                        key_info.insert(0, key_value)
            except Exception as e:
                logger.warning("No se pudo añadir RSAKeyValue a la firma", error=str(e))

            # El SII es extremadamente sensible al formato.
            # Forzamos Canonicalización (C14N) sobre el resultado final.
            c14n_xml = etree.tostring(signed_element, method="c14n")
            
            return c14n_xml.decode("utf-8")
            
        except Exception as e:
            raise SiiAuthError(f"Error al firmar la semilla: {str(e)}") from e

    async def get_valid_token(self, force_refresh: bool = False) -> str:
        """
        Obtiene un token válido. Retorna el cacheado si aún está vigente.
        """
        async with self._lock:
            now = datetime.now(timezone.utc)
            
            # Si hay token y no expiró (y no forzamos), lo retornamos
            if not force_refresh and self._cached_token and self._token_expires_at:
                if now < self._token_expires_at:
                    logger.debug("Usando token SII en cache")
                    return self._cached_token

            logger.info("Obteniendo nuevo token SII")
            
            # 1. Obtener Semilla
            seed_xml_response = await self.seed_client.get_seed()
            
            # 2. Extraer y Firmar Semilla
            import signxml # local import para prevenir problemas si falla global
            signed_seed_xml = self._sign_seed(seed_xml_response)
            
            # 3. Obtener Token
            token_xml_response = await self.token_client.get_token(signed_seed_xml)
            
            # 4. Extraer valor del Token
            try:
                token_value = self._parse_xml_value(token_xml_response, "TOKEN")
            except SiiAuthError as e:
                logger.error(
                    "El SII rechazó el documento firmado o la respuesta no tiene TOKEN", 
                    error=str(e),
                    respuesta_raw=token_xml_response
                )
                
                # Intentamos extraer información de error detallada
                estado = "Desconocido"
                glosa = "Error Desconocido"
                
                try:
                    # Intentamos buscar tags de error comunes en el SII
                    root = etree.fromstring(token_xml_response.encode("utf-8"))
                    
                    def find_tag(tag):
                        els = root.xpath(f"//*[local-name()='{tag}']")
                        return els[0].text if els and els[0].text else None

                    estado = find_tag("ESTADO") or find_tag("RETORNO") or "Desconocido"
                    glosa = find_tag("GLOSA") or find_tag("DESC_RETORNO") or "Error Desconocido"
                except Exception as parse_err:
                    logger.warning("No se pudo parsear detalles de error adicionales", error=str(parse_err))
                
                raise SiiAuthError(f"Rechazo del SII. Estado: {estado} - Glosa: {glosa}. Verifica tu clave y certificado.")
            
            # 5. Guardar en cache
            self._cached_token = token_value
            self._token_expires_at = now + timedelta(minutes=settings.sii_token_ttl_minutes)
            
            logger.info(
                "Token SII obtenido exitosamente",
                expires_at=self._token_expires_at.isoformat()
            )
            
            return token_value

    async def test_pfx(self, pfx_path: str, password: str) -> dict:
        """
        Prueba un certificado PFX obteniendo una semilla y un token.
        No usa ni afecta la caché.
        """
        try:
            # 1. Cargar certificado
            cert_data = load_pfx_from_file(pfx_path, password)
            
            # 2. Obtener Semilla
            seed_xml = await self.seed_client.get_seed()
            
            # 3. Firmar con el cert específico
            signed_seed = self._sign_seed(seed_xml, cert_data=cert_data)
            
            # 4. Pedir token
            token_xml = await self.token_client.get_token(signed_seed)
            
            # 5. Parsear respuesta
            try:
                token = self._parse_xml_value(token_xml, "TOKEN")
                return {
                    "ok": True,
                    "subject": cert_data.subject,
                    "not_valid_after": cert_data.not_valid_after.isoformat(),
                    "token": token[:10] + "...",
                }
            except SiiAuthError:
                estado = self._parse_xml_value(token_xml, "ESTADO", "Desconocido")
                glosa = self._parse_xml_value(token_xml, "GLOSA", "Error Desconocido")
                return {
                    "ok": False,
                    "subject": cert_data.subject,
                    "not_valid_after": cert_data.not_valid_after.isoformat(),
                    "error_sii": f"Estado: {estado} - Glosa: {glosa}",
                    "respuesta_raw": token_xml
                }

        except Exception as e:
            return {
                "ok": False,
                "error_interno": str(e)
            }

# Singleton
token_service = TokenService()
