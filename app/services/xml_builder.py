"""
DTE Core Engine — Constructor de XML para Boleta Electrónica (Tipo 39 y 41).
"""

from __future__ import annotations

import datetime
import hashlib
from typing import Any

import structlog
from lxml import etree

from app.config import get_settings
from app.domain.enums import TipoDte
from app.services.caf_service import CafInfo, CafService

settings = get_settings()
logger = structlog.get_logger(__name__)


class XmlBuilderService:
    """Constructor del XML del DTE respetando schemas del SII."""

    @staticmethod
    def build_boleta_xml(
        folio: int,
        fecha_emision: datetime.date,
        tipo_dte: TipoDte,
        receptor: dict[str, Any] | None,
        detalles: list[dict[str, Any]],
        caf_info: CafInfo
    ) -> str:
        """
        Construye el XML para una Boleta Electrónica (39 o 41).
        """
        # Calcular totales
        monto_total = sum(d["monto_item"] for d in detalles)
        monto_exento = monto_total if tipo_dte == TipoDte.BOLETA_EXENTA else 0

        # Para boleta afecta (39), usar detalle en bruto (sin IndMntNeto).
        # En certificación SII algunos validadores internos esperan que la suma
        # de Detalle/MontoItem coincida con MntTotal.
        detalle_montos_xml = [int(d["monto_item"]) for d in detalles]
        mnt_neto = None
        mnt_iva = None
        if tipo_dte == TipoDte.BOLETA_ELECTRONICA:
            mnt_neto = round(monto_total / 1.19)
            mnt_iva = monto_total - mnt_neto

        # Usar receptor informado por el cliente en ambos tipos de boleta.
        # Si no viene receptor, se mantiene fallback genérico para compatibilidad.
        rut_receptor_dte = receptor.get("rut", "66666666-6") if receptor else "66666666-6"
        rzn_receptor_enc = receptor.get("razon_social", "Persona") if receptor else "Persona"
        rzn_receptor_ted = (rzn_receptor_enc or "N/A")
        
        # 1. Definir namespaces
        # Declarar xsi en el DTE evita que cambie el contexto de C14N cuando el
        # documento se incrusta dentro de EnvioBOLETA (que también declara xsi).
        nsmap = {
            None: "http://www.sii.cl/SiiDte",
            "xsi": "http://www.w3.org/2001/XMLSchema-instance",
        }
        dte_id = f"T{tipo_dte.value}F{folio}"
        
        # Elemento Raíz
        root = etree.Element("DTE", version="1.0", nsmap=nsmap)
        
        # Elemento Documento
        documento = etree.SubElement(root, "Documento", ID=dte_id)
        
        # Encabezado
        encabezado = etree.SubElement(documento, "Encabezado")
        
        # IdDoc
        iddoc = etree.SubElement(encabezado, "IdDoc")
        etree.SubElement(iddoc, "TipoDTE").text = str(tipo_dte.value)
        etree.SubElement(iddoc, "Folio").text = str(folio)
        etree.SubElement(iddoc, "FchEmis").text = fecha_emision.strftime("%Y-%m-%d")
        etree.SubElement(iddoc, "IndServicio").text = "3" # Por defecto servicios (3)
        
        # Emisor
        emisor = etree.SubElement(encabezado, "Emisor")
        etree.SubElement(emisor, "RUTEmisor").text = settings.rut_emisor
        etree.SubElement(emisor, "RznSocEmisor").text = settings.razon_social_emisor
        etree.SubElement(emisor, "GiroEmisor").text = settings.giro_emisor
        etree.SubElement(emisor, "DirOrigen").text = settings.dir_origen
        etree.SubElement(emisor, "CmnaOrigen").text = settings.cmna_origen
        
        # Receptor (Opcional en boletas, pero recomendado)
        receptor_el = etree.SubElement(encabezado, "Receptor")
        etree.SubElement(receptor_el, "RUTRecep").text = rut_receptor_dte
        if rzn_receptor_enc:
            etree.SubElement(receptor_el, "RznSocRecep").text = rzn_receptor_enc[:100]
        
        # Totales
        totales = etree.SubElement(encabezado, "Totales")
        if tipo_dte == TipoDte.BOLETA_EXENTA:
            # Tipo 41: sin IVA, solo monto exento
            etree.SubElement(totales, "MntExe").text = str(monto_exento)
            etree.SubElement(totales, "MntTotal").text = str(monto_total)
        else:
            # Tipo 39 en modo bruto: para máxima compatibilidad SII enviar
            # solo MntTotal (sin IndMntNeto, MntNeto ni IVA).
            etree.SubElement(totales, "MntTotal").text = str(monto_total)
        
        # Detalles
        for i, det in enumerate(detalles, 1):
            detalle_el = etree.SubElement(documento, "Detalle")
            etree.SubElement(detalle_el, "NroLinDet").text = str(i)
            if tipo_dte == TipoDte.BOLETA_EXENTA:
                etree.SubElement(detalle_el, "IndExe").text = "1"
            etree.SubElement(detalle_el, "NmbItem").text = str(det["nombre"])
            # Agregar cantidad y precio unitario si están presentes
            etree.SubElement(detalle_el, "QtyItem").text = str(det.get("cantidad", 1))
            etree.SubElement(detalle_el, "PrcItem").text = str(det.get("precio", 0))
            etree.SubElement(detalle_el, "MontoItem").text = str(detalle_montos_xml[i - 1])

        # TED (Timbre Electrónico DTE)
        # El payload FRMT se deriva desde una copia del DD sin namespaces
        # ni whitespace-only text nodes, por lo que aquí solo construimos
        # el árbol tributario normal y delegamos la serialización exacta.
        dd = etree.Element("DD")
        etree.SubElement(dd, "RE").text = settings.rut_emisor
        etree.SubElement(dd, "TD").text = str(tipo_dte.value)
        etree.SubElement(dd, "F").text = str(folio)
        etree.SubElement(dd, "FE").text = fecha_emision.strftime("%Y-%m-%d")
        etree.SubElement(dd, "RR").text = rut_receptor_dte
        etree.SubElement(dd, "RSR").text = rzn_receptor_ted[:40]
        etree.SubElement(dd, "MNT").text = str(monto_total)
        etree.SubElement(dd, "IT1").text = detalles[0]["nombre"][:40]

        # Añadir el nodo CAF original extraído
        dd.append(caf_info["caf_xml_element"])

        # TSTED es elemento obligatorio (sin minOccurs="0" en el XSD)
        tsted_valor = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        etree.SubElement(dd, "TSTED").text = tsted_valor

        # Crear TED y agregar DD al árbol antes de firmar.
        ted = etree.SubElement(documento, "TED", version="1.0")
        ted.append(dd)
        
        # Firmar usando la serialización exacta requerida por FRMT.
        dd_payload = CafService.dd_signing_payload(dd)
        dd_string = dd_payload.decode("latin-1")
        
        private_key = CafService.load_caf_private_key(caf_info["private_key_pem"])
        firma_dd = CafService.sign_ted_string(dd_string, private_key)
        logger.info(
            "TED DD payload firmado",
            folio=folio,
            dte_id=dte_id,
            dd_payload_len=len(dd_payload),
            dd_payload_sha1=hashlib.sha1(dd_payload).hexdigest(),
            frmt_sha1=hashlib.sha1(firma_dd.encode("ascii")).hexdigest(),
        )
        
        etree.SubElement(ted, "FRMT", algoritmo="SHA1withRSA").text = firma_dd
        
        # Agregamos TmstFirma
        tmst_firma = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        etree.SubElement(documento, "TmstFirma").text = tmst_firma

        # Convertir a XML
        xml_string = etree.tostring(
            root, 
            encoding="ISO-8859-1", 
            xml_declaration=True,
            pretty_print=False # Importante: el SII es sensible a los espacios en la firma
        ).decode("latin-1")
        
        return xml_string

    @staticmethod
    def build_envio_dte(xml_documentos_firmados: list[str]) -> str:
        """
        Construye el Sobre (EnvioBOLETA) definitivo con carátula completa.
        """
        sii_ns = "http://www.sii.cl/SiiDte"
        xsi_ns = "http://www.w3.org/2001/XMLSchema-instance"
        nsmap = {
            None: sii_ns,
            "xsi": xsi_ns,
        }
        root = etree.Element("EnvioBOLETA", nsmap=nsmap)
        root.set("version", "1.0")
        # xsi:schemaLocation es obligatorio: sin él el SII devuelve SCH-00001: Invalid Schema Name
        root.set(f"{{{xsi_ns}}}schemaLocation", f"{sii_ns} EnvioBOLETA_v11.xsd")
        
        rut_limpio = settings.rut_emisor.replace(".", "")
        
        set_dte = etree.SubElement(root, "SetDTE", ID="SetDoc")
        caratula = etree.SubElement(set_dte, "Caratula", version="1.0")
        
        etree.SubElement(caratula, "RutEmisor").text = rut_limpio
        etree.SubElement(caratula, "RutEnvia").text = settings.rut_envia.replace(".", "")
        etree.SubElement(caratula, "RutReceptor").text = "60803000-K"
        etree.SubElement(caratula, "FchResol").text = settings.sii_fecha_resolucion
        etree.SubElement(caratula, "NroResol").text = str(settings.sii_numero_resolucion)
        etree.SubElement(caratula, "TmstFirmaEnv").text = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        
        # El SubTotDTE es obligatorio en muchos validadores de boletas
        for xml_doc in xml_documentos_firmados:
            try:
                clean_xml = xml_doc.strip()
                if "<?xml" in clean_xml:
                    clean_xml = clean_xml.split("?>", 1)[1].strip()
                    
                doc_node = etree.fromstring(clean_xml.encode("latin-1"))
                
                # Extraemos el tipo para el resumen obligatorio
                tipo_node = doc_node.find(".//{http://www.sii.cl/SiiDte}TipoDTE")
                if tipo_node is not None:
                    sub_tot = etree.SubElement(caratula, "SubTotDTE")
                    etree.SubElement(sub_tot, "TpoDTE").text = tipo_node.text
                    etree.SubElement(sub_tot, "NroDTE").text = "1"

                # NO llamar cleanup_namespaces: eliminaría el namespace xmldsig#
                # y rompería la firma XMLDSIG del DTE embebido
                set_dte.append(doc_node)
            except Exception:
                pass

        return etree.tostring(
            root, 
            encoding="ISO-8859-1", 
            xml_declaration=True
        ).decode("latin-1")
