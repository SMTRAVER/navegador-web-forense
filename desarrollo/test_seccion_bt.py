# -*- coding: utf-8 -*-
"""Renderiza la seccion de Binary Transparency con datos de muestra."""
import types
import unicodedata

from fpdf.enums import XPos, YPos

FUENTE = r"C:\navegadorforense\navegador_forense_pro_v1_0.py"
src = open(FUENTE, encoding="utf-8").read()

PRE = '''
import os, datetime, unicodedata
from pathlib import Path
from typing import Dict, List, Optional, Any
from fpdf import FPDF
from fpdf.enums import XPos, YPos
SOFTWARE_INFO = {"software": "Traverso Forensics - Navegador Web Forense",
                 "version": "v1.0", "norma": "ISO/IEC 27037:2012"}
LOGO_PATH = r"C:\\navegadorforense\\traverso_logo.png"
def sanitize_text(t):
    n = unicodedata.normalize("NFKD", str(t))
    return "".join(c for c in n if not unicodedata.combining(c)).encode("latin-1", "ignore").decode("latin-1")
def get_self_hash():
    return "a" * 64
'''

ini = src.index("class DictamenForense")
fin = src.index("\nclass ", ini + 10)
mod = types.ModuleType("m")
exec(PRE + src[ini:fin], mod.__dict__)
DictamenForense = mod.DictamenForense
sanitize_text = mod.sanitize_text

pdf = DictamenForense()
pdf.add_page()
pdf.section_title("V", "VERIFICACION DE INTEGRIDAD DEL CODIGO (BINARY TRANSPARENCY)")
pdf.cuerpo_texto(
    "Los portales de Meta publican en la propia pagina un manifiesto que contiene el "
    "hash SHA-256 de cada script autorizado de esa version del sitio, junto con un "
    "hash combinado que resume la totalidad del conjunto. De forma independiente, "
    "Cloudflare publica el hash raiz de esa misma version en su servicio de "
    "auditabilidad (api.privacy-auditability.cloudflare.com), actuando como tercero "
    "de confianza ajeno a Meta. Es el mismo mecanismo de transparencia de codigo que "
    "emplea la herramienta oficial Code Verify (Meta, licencia MIT)."
)
pdf.cuerpo_texto(
    "ALCANCE DE LA VERIFICACION REALIZADA: durante la presente diligencia se "
    "contrasto el hash combinado declarado por cada portal contra el hash raiz "
    "publicado por dicho tercero independiente. Un resultado VERIFICADO acredita que "
    "el inventario de codigo declarado por el sitio es autentico y corresponde a una "
    "version efectivamente publicada por Meta. Se deja constancia de que la presente "
    "comprobacion opera a nivel del manifiesto y no comprende la verificacion "
    "individual de cada script."
)
pdf.ln(2)

ver = {"dominio": "instagram.com", "version": "1044521783", "cant_scripts": 5417,
       "hash_pagina": "fe0bc5ff8841e011b301b473e3b67e9e6401dee21689b339a1c2d3e4f5a6b7c8",
       "hash_cloudflare": "fe0bc5ff8841e011b301b473e3b67e9e6401dee21689b339a1c2d3e4f5a6b7c8",
       "fuente_externa": "https://api.privacy-auditability.cloudflare.com/v1/hash/instagram.com/1044521783",
       "resultado": "VERIFICADO", "ts_legible": "06/08/2026 19:24:43"}
pdf.set_fill_color(46, 125, 50)
pdf.set_text_color(255, 255, 255)
pdf.set_font("helvetica", "B", 9)
pdf.cell(0, 7, sanitize_text("  Verificacion 1  |  instagram.com  |  VERIFICADO"),
         fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
pdf.set_text_color(0, 0, 0)
filas = [
    ("Portal verificado", ver["dominio"]),
    ("Version del codigo", ver["version"]),
    ("Scripts declarados", f"{ver['cant_scripts']:,}"),
    ("Hash segun el portal", ver["hash_pagina"]),
    ("Hash segun Cloudflare", ver["hash_cloudflare"]),
    ("Fuente independiente", ver["fuente_externa"]),
    ("Resultado", "VERIFICADO"),
    ("Momento de la verificacion", ver["ts_legible"]),
]
for fi, (k, v) in enumerate(filas):
    pdf.tabla_fila(k, sanitize_text(str(v)), fi, w_label=52)
pdf.ln(3)

# --- Bloque nuevo: fuentes de la metodologia ---
pdf.ln(2)
pdf.set_fill_color(13, 71, 161)
pdf.set_text_color(255, 255, 255)
pdf.set_font("helvetica", "B", 9)
pdf.cell(0, 7, sanitize_text("  ORIGEN DE LA METODOLOGIA APLICADA"),
         fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
pdf.set_text_color(0, 0, 0)
pdf.ln(1)
pdf.cuerpo_texto(
    "El procedimiento de verificacion empleado no es de elaboracion propia: reproduce "
    "el mecanismo de transparencia de codigo que Meta Platforms implemento para sus "
    "portales web y documento publicamente, y que la propia empresa distribuye como "
    "software libre. Se consignan las fuentes para que cualquier tercero pueda "
    "constatar su existencia y reproducir la verificacion de manera independiente."
)
fuentes = [
    ("Metodologia",            "Transparencia de codigo (binary transparency) de Meta Platforms"),
    ("Publicacion original",   "Meta Engineering, 10 de marzo de 2022"),
    ("Documentacion tecnica",  "engineering.fb.com/2022/03/10/security/code-verify/"),
    ("Codigo fuente oficial",  "github.com/facebookincubator/meta-code-verify (licencia MIT)"),
    ("Verificador de terceros", "Cloudflare - api.privacy-auditability.cloudflare.com"),
    ("Algoritmo de hash",      "SHA-256 (NIST FIPS 180-4)"),
]
for fi, (k, v) in enumerate(fuentes):
    pdf.tabla_fila(k, sanitize_text(v), fi, w_label=52)

import os
OUT = os.path.join(os.environ.get("TEMP", "."), "bt_con_fuentes.pdf")
pdf.output(OUT)
print("PDF:", OUT)

import fitz
doc = fitz.open(OUT)
png = OUT.replace(".pdf", ".png")
doc[0].get_pixmap(dpi=105).save(png)
print("PNG:", png)
