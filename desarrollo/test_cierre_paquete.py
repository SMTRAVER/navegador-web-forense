# -*- coding: utf-8 -*-
"""
Ejecuta el bloque de empaquetado TAL COMO ESTA ESCRITO en el programa —se
extrae del archivo, no se copia— sobre un caso de prueba, y comprueba lo que
importa:

  1. el dictamen queda DENTRO del paquete
  2. el hash del sidecar coincide con el del ZIP entregado
  3. el dictamen NO lleva impreso el hash del paquete
  4. no quedan archivos temporales del informe dentro del ZIP
  5. junto al ZIP quedan su sello de tiempo (.tsr) y la cadena de la
     autoridad (.tsa.pem), y el acta los consigna
"""
import hashlib
import io
import os
import shutil
import sys
import textwrap
import zipfile
from pathlib import Path

BASE = Path(os.environ.get("TEMP", ".")) / "prueba_cierre_paquete"
RUTA = r"C:\navegadorforense\navegador_forense_pro_v1_0.py"
sys.path.insert(0, r"C:\navegadorforense")
os.environ["QT_QPA_PLATFORM"] = "offscreen"
import navegador_forense_pro_v1_0 as app        # noqa: E402
from PyQt6.QtWidgets import QApplication        # noqa: E402

qt = QApplication.instance() or QApplication(sys.argv)

def _forzar_borrado(fn, ruta, _exc):
    """El cierre deja la evidencia en solo lectura; para volver a correr la
    prueba hay que devolverle permiso de escritura antes de borrar."""
    os.chmod(ruta, 0o666)
    fn(ruta)


if BASE.exists():
    shutil.rmtree(BASE, onerror=_forzar_borrado)
BASE.mkdir(parents=True)

# --- caso real del programa, en una carpeta de prueba
caso = app.ForensicCase(
    {"base_dir": str(BASE), "caratula": "PRUEBA DE CIERRE", "expediente": "S/N",
     "juzgado": "-", "objeto": "verificacion del empaquetado"},
    dict(app.AUTOR_SISTEMA))
print("caso: %s" % caso.case_id)

# Capturas como evidencia. Si hay casos reales en el equipo se usan los
# primeros; si no, se fabrican. La prueba no puede quedar sin evidencias
# porque alguien limpio la carpeta de casos: un paquete vacio no prueba nada,
# y asi tambien corre en un equipo recien clonado.
import glob
from PIL import Image, ImageDraw                              # noqa: E402

reales = [p for p in sorted(set(glob.glob(os.path.join(
    r"C:\navegadorforense", "NAV_FORENSE", "*", "evidence", "**", "*.png"), recursive=True)))
    if os.path.getsize(p) > 100 * 1024][:6]
if reales:
    for p in reales:
        d = caso.dirs["evidence_img"] / os.path.basename(p)
        shutil.copy2(p, d)
        caso.register_evidence("CAPTURA_COMENTARIOS", str(d),
                               source_url="https://www.instagram.com/p/EJEMPLO00002/")
else:
    for k in range(4):
        im = Image.new("RGB", (1200, 800), (255, 255, 255))
        d = ImageDraw.Draw(im)
        for i in range(16):
            d.rounded_rectangle([40, 30 + i * 46, 900, 60 + i * 46], radius=8,
                                fill=(240, 242, 245))
            d.text((60, 38 + i * 46), "comentario de ejemplo %d-%d" % (k + 1, i + 1),
                   fill=(20, 20, 20))
        ruta = caso.dirs["evidence_img"] / ("Comentarios_%03d.png" % (k + 1))
        im.save(ruta, "PNG", compress_level=1)
        caso.register_evidence("CAPTURA_COMENTARIOS", str(ruta),
                               source_url="https://www.instagram.com/p/EJEMPLO00002/")
print("evidencias registradas: %d  (%s)"
      % (len(caso.evidences), "capturas del equipo" if reales else "fabricadas"))

# Se planta un temporal huerfano, como el que quedaria si la generacion del
# informe se cortara antes de la limpieza.
_huerfano = caso.dirs["thumbs"] / "inf_sobrante_de_una_corrida_cortada.jpg"
_huerfano.write_bytes(bytes([255, 216, 255]) + b"x" * 500)
print("temporal huerfano plantado: %s" % _huerfano.name)


class Ventana:
    """Lo minimo que el bloque de empaquetado necesita de la ventana."""
    def __init__(self):
        self.case = caso
        self.perito_data = dict(app.AUTOR_SISTEMA)
        self.setup_data = {}
        self.status = type("S", (), {"showMessage": lambda *a, **k: None})()
        self.lineas = []

    def append_console(self, t):
        self.lineas.append(str(t))

    def generate_report(self, zip_info=None):
        """Se usa el generador real del programa."""
        return app.TraversoWebForensicsPro.generate_report(self, zip_info=zip_info)

    def __getattr__(self, nombre):
        # Lo que el generador consulte y no sea parte del empaquetado —estado
        # de grabacion, widgets— se responde vacio. Lo que importa medir aca es
        # el orden del cierre, no la interfaz.
        return None


# El generador real necesita algunos atributos mas de la ventana
V = Ventana()
for attr, val in (("browser", None), ("_perfil_dir", None), ("firma_path", None)):
    setattr(V, attr, val)

fuente = io.open(RUTA, encoding="utf-8").read()
ini = fuente.index("        # 4. Dictamen primero, paquete despues.")
fin = fuente.index("            if _sello_ok:\n                self.append_console(", ini)
bloque = textwrap.dedent(fuente[ini:fin])
# El bloque abre un try cuyo except queda mas abajo, fuera del recorte: se
# cierra sin alterar el camino normal.
bloque += chr(10) + "except Exception:" + chr(10) + "    raise" + chr(10)

entorno = {
    "self": V, "os": os, "Path": Path, "_zf": zipfile,
    "sha256_file": app.sha256_file,
    "write_custody_sidecar": app.write_custody_sidecar,
    "escribir_sello_aparte": app.escribir_sello_aparte,
    "registrar_fallo_critico": app.registrar_fallo_critico,
    "QApplication": QApplication,
    "datetime": app.datetime,
}
try:
    exec(bloque, entorno)
except Exception as e:
    print("\nEl bloque fallo: %s: %s" % (type(e).__name__, e))
    import traceback
    traceback.print_exc()
    sys.exit(1)

print()
for L in V.lineas:
    print("   %s" % L.encode("ascii", "replace").decode())

# ------------------------------------------------------------- controles
print()
zips = list(BASE.rglob("*.zip"))
if not zips:
    print("NO SE GENERO EL ZIP")
    sys.exit(1)
z = zips[0]
ok = True

with zipfile.ZipFile(z) as zf:
    nombres = zf.namelist()
    dic = [n for n in nombres if "DICTAMEN" in n.upper() and n.upper().endswith(".PDF")]
    print("1) dictamen dentro del paquete : %s" % ("SI" if dic else "NO"))
    ok &= bool(dic)
    tmp = [n for n in nombres if "/inf_" in n or n.startswith("inf_")]
    print("2) temporales del informe dentro: %s" % (tmp[:3] if tmp else "ninguno (correcto)"))
    ok &= not tmp

real = hashlib.sha256(z.read_bytes()).hexdigest()
sc = Path(str(z) + ".sha256")
if sc.exists():
    declarado = sc.read_text(encoding="utf-8").split()[0]
    print("3) hash del sidecar coincide   : %s" % ("SI" if declarado == real else "NO"))
    ok &= (declarado == real)
else:
    print("3) sidecar del ZIP             : NO SE ESCRIBIO")
    ok = False

if dic:
    with zipfile.ZipFile(z) as zf:
        pdf_bytes = zf.read(dic[0])
    txt = pdf_bytes.decode("latin-1", "ignore")
    print("4) el dictamen imprime el hash del paquete: %s"
          % ("SI (mal)" if real in txt else "NO (correcto)"))
    ok &= real not in txt
    print("   tamaño del dictamen: %.2f MB" % (len(pdf_bytes) / 1048576.0))

tsr, pem = Path(str(z) + ".tsr"), Path(str(z) + ".tsa.pem")
acta = Path(str(z) + ".custodia.txt")
junto = tsr.exists() and pem.exists()
print("5) sello y cadena junto al ZIP : %s" % ("SI" if junto else "NO"))
ok &= junto
consigna = acta.exists() and "firma verificada" in acta.read_text(encoding="utf-8")
print("   el acta consigna el sello   : %s" % ("SI" if consigna else "NO"))
ok &= consigna

print()
print("RESULTADO: %s" % ("correcto" if ok else "HAY UN PROBLEMA"))
