#!/usr/bin/env python3
"""Comparar multipart enviado con un ejemplo SII-aceptado.

Uso:
  python tools/compare_multipart_with_accepted.py --accepted path/to/accepted.bin

Salida:
  - tools/compare_diff.txt : diff de texto entre los multiparts (latin-1)
  - tools/compare_summary.txt : resumen binario y hashes
"""
from __future__ import annotations
import argparse
import hashlib
import difflib
from pathlib import Path


def read_bytes(p: Path) -> bytes:
    return p.read_bytes()


def extract_xml_from_bytes(b: bytes) -> str | None:
    try:
        txt = b.decode("latin-1", errors="replace")
    except Exception:
        return None
    # Buscar prolog XML o marcas comunes de EnvioBOLETA/DTE
    candidates = ["<?xml", "<EnvioBOLETA", "<DTE ", "<DTE>", "<SetDTE", "<Documento"]
    idx = -1
    for c in candidates:
        idx = txt.find(c)
        if idx != -1:
            break
    if idx == -1:
        # fallback: buscar primer '<' que parezca inicio de XML
        idx = txt.find('<')
        if idx == -1:
            return None
    return txt[idx:]


def sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--accepted", required=True, help="Ruta al multipart SII-aceptado (bin) o al envio xml aceptado")
    p.add_argument("--expected", default="tools/last_multipart.bin", help="Ruta al multipart generado (por defecto tools/last_multipart.bin)")
    args = p.parse_args()

    accepted = Path(args.accepted)
    expected = Path(args.expected)
    out_diff = Path("tools/compare_diff.txt")
    out_summary = Path("tools/compare_summary.txt")

    if not accepted.exists():
        print(f"Archivo aceptado no existe: {accepted}")
        raise SystemExit(2)
    if not expected.exists():
        print(f"Archivo generado no existe: {expected}")
        raise SystemExit(2)

    a_bytes = read_bytes(accepted)
    e_bytes = read_bytes(expected)

    # resumen
    lines = []
    lines.append(f"accepted: {accepted} size={len(a_bytes)} sha1={sha1(a_bytes)}")
    lines.append(f"expected: {expected} size={len(e_bytes)} sha1={sha1(e_bytes)}")
    # primer byte distinto
    minlen = min(len(a_bytes), len(e_bytes))
    diffs = []
    for i in range(minlen):
        if a_bytes[i] != e_bytes[i]:
            diffs.append(i)
            if len(diffs) >= 10:
                break
    if len(diffs) == 0 and len(a_bytes) != len(e_bytes):
        diffs.append(minlen)
    if diffs:
        lines.append("Primeras posiciones con diferencia (offset): " + ",".join(str(x) for x in diffs))
    else:
        lines.append("No se detectaron diferencias en los primeros {} bytes".format(minlen))

    out_summary.write_text("\n".join(lines), encoding="utf-8")
    print(out_summary)

    # diff textual (latin-1)
    a_txt = a_bytes.decode("latin-1", errors="replace")
    e_txt = e_bytes.decode("latin-1", errors="replace")
    a_lines = a_txt.splitlines(keepends=True)
    e_lines = e_txt.splitlines(keepends=True)

    diff = difflib.unified_diff(a_lines, e_lines, fromfile=str(accepted), tofile=str(expected), lineterm="")
    diff_text = "".join(diff)
    out_diff.write_text(diff_text, encoding="latin-1")
    print(out_diff)

    # Extraer XMLs y guardar
    a_xml = extract_xml_from_bytes(a_bytes)
    e_xml = extract_xml_from_bytes(e_bytes)
    if a_xml:
        Path("tools/accepted_extracted.xml").write_text(a_xml, encoding="latin-1")
        print("tools/accepted_extracted.xml")
    if e_xml:
        Path("tools/expected_extracted.xml").write_text(e_xml, encoding="latin-1")
        print("tools/expected_extracted.xml")

    if a_xml and e_xml:
        a_lines = a_xml.splitlines(keepends=True)
        e_lines = e_xml.splitlines(keepends=True)
        xml_diff = difflib.unified_diff(a_lines, e_lines, fromfile="accepted_extracted.xml", tofile="expected_extracted.xml", lineterm="")
        Path("tools/compare_xml_diff.txt").write_text("".join(xml_diff), encoding="latin-1")
        print("tools/compare_xml_diff.txt")

    print("Comparación completada. Revisa los archivos en tools/.")


if __name__ == "__main__":
    main()
