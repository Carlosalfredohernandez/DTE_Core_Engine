# Motor DTE SII Chile (Boleta Electrónica)

API REST en Python (FastAPI) para emisión, firma y envío de Documentos Tributarios Electrónicos (DTE) al Servicio de Impuestos Internos (SII) de Chile.

## Características
* **Prioridad Boletas**: Soporte nativo para Boletas Electrónicas (Tipo 39) y Exentas (Tipo 41).
* **Firma Digital**: Implementación robusta de XMLDSIG (`rsa-sha1`) según estándar SII usando certificados `.pfx` y llave privada de CAFs.
* **Orquestación SII**: Autenticación automática (`CrSeed` -> `GetTokenFromSeed`), cacheo de Token, envío HTTP `multipart/form-data`, y consulta SOAP de TrackIDs.
* **SQL Server**: Base de datos para guardar CAFs, correlativos de folios y estados de DTEs.

## Estructura de Endpoints
* `POST /api/v1/boleta/generar`: Construye el XML de la boleta, asigna un folio del CAF y aplica firma doble.
* `POST /api/v1/boleta/enviar`: Empaqueta la boleta en el sobre `EnvioDTE`, lo firma y sube al SII.
* `GET /api/v1/tracking/{dte_id}/estado`: Consulta el TrackID devuelto por el envío en el SII.
* `POST /api/v1/caf/upload`: Endpoint para cargar archivos XML CAF descargados desde el portal del SII.
* `GET /api/v1/token/status`: Revisa si tienes un Token SII vigente en cache.

## Puesta en Marcha

1. Copiar `.env.example` a `.env` y configurar variables globales (RUT emisor, string de BD, etc).
2. Poner tu certificado digital en `certs/certificado.pfx` y especificar la clave en `.env` (`CERT_PFX_PASSWORD`).
3. Levantar servicios con Docker Compose:
   ```bash
   docker-compose up -d --build
   ```
4. Acceder a Swagger UI: `http://localhost:8000/docs`

> **Atención**: La API requiere el header `X-API-Key` (configurado en `.env` bajo `API_KEY`) para permitir peticiones.

## Variables Clave de Configuración (.env)
* `RUT_EMISOR`: RUT de la empresa emisora (ej: `77710916-2`).
* `RUT_ENVIA`: RUT del titular del certificado digital que firma y envía.
* `SII_FECHA_RESOLUCION`: Fecha de resolución SII (formato `YYYY-MM-DD`).
* `SII_NUMERO_RESOLUCION`: Número de resolución SII (entero, p.ej. `0`).
* `CERT_PFX_BASE64` o `CERT_PFX_PATH`: certificado digital.
* `CERT_PFX_PASSWORD`: contraseña del certificado.
* `SII_DEBUG_TRACKING`: `true/false` para incluir payloads raw y `debug_xml_envio` en `GET /tracking/{id}/estado`.

> Desde esta versión, el envío falla de forma explícita si:
> - falta `SII_FECHA_RESOLUCION`.
> - `RUT_ENVIA` no coincide con el `SERIALNUMBER` del certificado digital cargado.

## Notas de Hardcode
* Los únicos valores fijos esperados por normativa SII son:
* `RutReceptor` de carátula: `60803000-K`.
* Nombre de archivo multipart en upload: `boleta.xml`.
* Receptor genérico para boleta 39 en este flujo: `66666666-6`.
