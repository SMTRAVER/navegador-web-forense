# -*- coding: utf-8 -*-
"""
El dictamen transcribe lo adquirido en cualquier alfabeto.

Hasta esta version el informe usaba las fuentes base del PDF, que solo cubren
latin-1, y antes de escribir pasaba todo por sanitize_text, que descartaba el
resto. Medido: "Muñoz" salia "Munoz", y un comentario en arabe, persa, ruso,
hebreo, chino o japones quedaba en un renglon vacio. En el caso real de
referencia se capturaron comentarios de cuentas persas, asi que no es hipotesis.

El original nunca se perdia (el listado .txt va en UTF-8 y la captura PNG
muestra la pantalla), pero el dictamen es lo que lee el juzgado.

Esta prueba genera un dictamen REAL con un listado de comentarios en nueve
alfabetos y despues lee el PDF para comprobar que cada uno esta. Es la
afirmacion CDX-CA-06 de la especificacion del NIST para herramientas de
extraccion en la nube: "the tool renders non-English text correctly", que pide
cubrir acentos, alfabetos no latinos, kanji, kana y escritura de derecha a
izquierda.

  python test_texto_multilingue.py [ruta al .py a probar]
"""
import importlib.util
import os
import shutil
import sys
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_texto_multilingue"
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

if not hasattr(app, "cargar_fuentes_unicode"):
    print("El informe no incrusta fuentes Unicode: es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

fallas = 0

IDIOMAS = [
    ("castellano con tildes", "Se\u00f1or Mu\u00f1oz: \u00bfcu\u00e1ndo lleg\u00f3?"),
    ("aleman", "Stra\u00dfe M\u00fcnchen"),
    ("griego", "\u0393\u03b5\u03b9\u03ac \u03c3\u03bf\u03c5"),
    ("ruso", "\u041f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440"),
    ("persa", "\u0633\u0644\u0627\u0645 \u0639\u0644\u06cc\u06a9\u0645"),
    ("arabe", "\u0645\u0631\u062d\u0628\u0627"),
    ("hebreo", "\u05e9\u05dc\u05d5\u05dd"),
    ("chino", "\u4f60\u597d\u4e16\u754c"),
    ("japones kana", "\u3053\u3093\u306b\u3061\u306f"),
    ("emoji", "Gracias \U0001f64f"),
]


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


def _escribible(fn, ruta, _exc):
    os.chmod(ruta, 0o666)
    fn(ruta)


print("archivo probado: %s\n" % os.path.basename(RUTA))
print("1. Antes de escribir: el texto no se altera")
for nombre, texto in IDIOMAS:
    debe(app.sanitize_text(texto) == texto, "%s: intacto" % nombre)

print("\n2. En el dictamen generado")
if TMP.exists():
    shutil.rmtree(TMP, onerror=_escribible)
TMP.mkdir(parents=True)

caso = app.ForensicCase(
    {"base_dir": str(TMP), "caratula": "PRUEBA MULTILINGUE", "expediente": "S/N",
     "juzgado": "-", "objeto": "transcripcion de texto"}, dict(app.AUTOR_SISTEMA))

listado = ["COMENTARIOS DE PUBLICACION - Instagram",
           "Caso        : %s" % caso.case_id,
           "Publicacion : https://www.instagram.com/p/EJEMPLO00003/",
           "Comentarios : %d" % len(IDIOMAS), "=" * 70, "", "COMENTARIOS", ""]
for i, (nombre, texto) in enumerate(IDIOMAS, 1):
    listado.append("    %d. @usuario_%02d | 2026-10-02T12:00:00.000Z | 1 me gusta" % (i, i))
    listado.append("       %s" % texto)
archivo = caso.dirs["evidence_raw"] / "Comentarios_Instagram_multilingue.txt"
archivo.write_text("\n".join(listado), encoding="utf-8")
caso.register_evidence("COMENTARIOS", str(archivo),
                       source_url="https://www.instagram.com/p/EJEMPLO00003/")


class Ventana:
    def __init__(self):
        self.case = caso
        self.perito_data = dict(app.AUTOR_SISTEMA)
        self.setup_data = {}
        self.status = type("S", (), {"showMessage": lambda *a, **k: None})()
        self.lineas = []

    def append_console(self, t):
        self.lineas.append(str(t))

    def __getattr__(self, nombre):
        return None


pdf = app.TraversoWebForensicsPro.generate_report(Ventana(), zip_info={"nombre": "prueba.zip"})
if not pdf or not os.path.exists(str(pdf)):
    cand = sorted(caso.dirs["report"].glob("*.pdf"), key=lambda p: p.stat().st_mtime)
    pdf = str(cand[-1]) if cand else ""
debe(bool(pdf), "se genero el dictamen (%.0f KB)" % (os.path.getsize(pdf) / 1024 if pdf else 0))

try:
    try:
        import pymupdf
    except ImportError:
        import fitz as pymupdf
    doc = pymupdf.open(pdf)
    texto = "".join(p.get_text() for p in doc)
    for nombre, muestra in IDIOMAS:
        # Las lenguas de derecha a izquierda se componen con ligaduras, asi que
        # se comprueba caracter por caracter y no la cadena entera.
        presentes = sum(1 for c in set(muestra) if c.strip() and c in texto)
        total = len([c for c in set(muestra) if c.strip()])
        debe(presentes == total, "%s: %d de %d caracteres en el PDF"
             % (nombre, presentes, total))
    debe("Transcripcion de texto" in " ".join(texto.split()),
         "el dictamen declara como transcribe")
    debe("CDX-CA-06" in " ".join(texto.split()),
         "y cita la afirmacion del NIST que lo exige")
except ImportError:
    print("  (sin PyMuPDF en este entorno: no se pudo leer el texto del PDF)")

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
