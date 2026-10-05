# -*- coding: utf-8 -*-
"""
El dictamen declara que el navegador no puede reproducir el video de WhatsApp
ni el de Instagram, y transcribe lo que el motor contesto.

El motor que se distribuye no trae los codecs H.264/AAC: no vienen compilados
en la version abierta de Qt WebEngine, y no hay forma de agregarlos desde
afuera (se probo con los wheels de Riverbank y con los de la propia Qt Company:
ninguno los trae). En esas publicaciones el recuadro del video queda en negro,
tambien en la grabacion de la sesion. El contenido igual se adquiere —el
archivo original, con su hash— pero si el dictamen no lo dice, ese negro parece
prueba perdida.

La prueba comprueba, ejecutando el codigo del programa:

  1. que el guion que interroga al motor devuelve los formatos, y cuales
  2. que el dictamen transcribe esa respuesta y explica la limitacion
  3. que si alguna vez el motor SI trae H.264, la prueba falla: en ese caso el
     texto del dictamen quedaria diciendo algo falso y hay que reescribirlo

  python test_codecs_en_dictamen.py [ruta al .py a probar]
"""
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_codecs_dictamen"
os.environ["QT_QPA_PLATFORM"] = "offscreen"

_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

if not hasattr(app, "resumen_codecs"):
    print("El programa no consulta los codecs del motor: es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

from PyQt6.QtCore import QTimer, QUrl                       # noqa: E402
from PyQt6.QtWidgets import QApplication                    # noqa: E402
from PyQt6.QtWebEngineWidgets import QWebEngineView         # noqa: E402

fallas = 0


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


def _escribible(fn, ruta, _exc):
    os.chmod(ruta, 0o666)
    fn(ruta)


print("archivo probado: %s\n" % os.path.basename(RUTA))

# ------------------------------------------------- 1. lo que contesta el motor
print("1. Lo que el motor contesta, con el guion del programa")
qt = QApplication.instance() or QApplication(sys.argv)
vista = QWebEngineView()
vista.resize(400, 300)
vista.show()
leido = {}
vista.loadFinished.connect(lambda _ok: vista.page().runJavaScript(
    app._RENDER_JS, lambda r: (leido.update(r=r), qt.quit())))
vista.setHtml("<html></html>", QUrl("https://local.test/"))
QTimer.singleShot(20000, qt.quit)
qt.exec()
datos = json.loads(leido.get("r") or "{}")
codecs = datos.get("codecs")
debe(bool(codecs), "el guion devuelve los formatos: %s" % (list(codecs) if codecs else "NADA"))
for nombre, valor in (codecs or {}).items():
    print("        %-16s %s" % (nombre, valor if valor not in ("", False) else "no"))
debe(app.sin_codecs_propietarios(codecs),
     "el motor NO reproduce H.264/AAC (si esto cambia hay que reescribir el texto del dictamen)")
debe((codecs or {}).get("VP9") in ("probably", "maybe"),
     "el motor si reproduce VP9, que es lo que usa YouTube")

# ------------------------------------------------- 2. el dictamen lo declara
print("\n2. El dictamen lo declara")
if TMP.exists():
    shutil.rmtree(TMP, onerror=_escribible)
TMP.mkdir(parents=True)
caso = app.ForensicCase(
    {"base_dir": str(TMP), "caratula": "PRUEBA DE CODECS", "expediente": "S/N",
     "juzgado": "-", "objeto": "declaracion de codecs"}, dict(app.AUTOR_SISTEMA))


class Ventana:
    def __init__(self):
        self.case = caso
        self.perito_data = dict(app.AUTOR_SISTEMA)
        self.setup_data = {}
        self.status = type("S", (), {"showMessage": lambda *a, **k: None})()
        self._render_info = datos            # lo que contesto el motor recien
        self.lineas = []

    def append_console(self, t):
        self.lineas.append(str(t))

    def __getattr__(self, nombre):
        return None


pdf = app.TraversoWebForensicsPro.generate_report(Ventana(), zip_info={"nombre": "prueba.zip"})
if not pdf or not os.path.exists(str(pdf)):
    cand = sorted(caso.dirs["report"].glob("*.pdf"), key=lambda p: p.stat().st_mtime)
    pdf = str(cand[-1]) if cand else ""
debe(bool(pdf), "se genero el dictamen")

try:
    try:
        import pymupdf
    except ImportError:
        import fitz as pymupdf
    # Los rotulos entran partidos en varios renglones dentro de la celda, asi
    # que se busca sobre el texto con los espacios normalizados.
    plano = " ".join("".join(p.get_text() for p in pymupdf.open(pdf)).split())
    debe("Reproduccion de video" in plano and "H.264 y AAC" in plano,
         "explica por que el video puede verse en negro")
    debe("Formatos que el motor declaro soportar" in plano,
         "transcribe la consulta hecha al motor")
    for pieza in ("H.264+AAC: no", "VP9: probably", "canPlayType"):
        debe(pieza in plano, "figura lo medido: %s" % pieza)
    debe("archivo original" in plano and "SHA-256" in plano,
         "aclara que el video se adquiere como archivo con su hash")
except ImportError:
    print("  (sin PyMuPDF en este entorno: no se pudo leer el texto del PDF)")

# ------------------------------------------------- 3. queda en el log del caso
print("\n3. Queda en el registro del caso")
import sqlite3                                              # noqa: E402
with sqlite3.connect(str(caso.db_path)) as con:
    filas = [m for (m,) in con.execute(
        "SELECT message FROM audit_log WHERE category='ENTORNO'").fetchall()]
print("  (el aviso se escribe cuando el navegador informa su entorno, al abrir la sesion)")
debe(app.resumen_codecs(codecs).startswith("H.264+AAC"),
     "el texto del log se arma con lo medido: %s" % app.resumen_codecs(codecs)[:70])

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
