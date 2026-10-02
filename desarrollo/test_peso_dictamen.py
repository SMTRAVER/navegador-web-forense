# -*- coding: utf-8 -*-
"""
Cuanto pesa el dictamen y de que esta hecho ese peso.

Ejecuta el anexo de vistas tal como esta escrito en el programa —se extrae la
seccion del archivo y se corre— y arma la portada con la portada de verdad, de
modo que lo que se mide es el codigo que se distribuye y no una copia de su
logica.

Tres cosas se comprueban:

  1. Las vistas del anexo pasan por el conversor. Sin el, un dictamen real
     medido dio 110,6 MB en 417 hojas, de los cuales 109,9 MB eran imagenes
     embebidas enteras.
  2. Las copias salen sin submuestreo de color (4:4:4). Con el submuestreo que
     trae JPEG por defecto los enlaces azules y el texto gris chico se ensucian,
     que es justamente lo que hay que poder leer en una captura de comentarios.
  3. El membrete de la portada va reducido. fpdf2 embebe los PNG sin perdida:
     el logo original ponia 737 KB en cada dictamen, mas que todo el texto de un
     informe de 417 hojas.

Usa las capturas del caso si hay; si no, fabrica capturas equivalentes (2560 px
de ancho, texto de 15 px como el de un navegador).

  python test_peso_dictamen.py [ruta al .py a probar]
"""
import glob
import hashlib
import importlib.util
import io
import os
import sys
import textwrap
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_peso_dictamen"
TMP.mkdir(exist_ok=True)

sys.path.insert(0, r"C:\navegadorforense")
os.environ["QT_QPA_PLATFORM"] = "offscreen"
_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

from PIL import Image, ImageDraw, ImageFont          # noqa: E402
from PIL.JpegImagePlugin import get_sampling         # noqa: E402

ok = True


# ---------------------------------------------------------------- capturas
def capturas_de_prueba(n=12):
    """Capturas como las que toma el programa: 2560 px y texto de 15 px."""
    try:
        f15 = ImageFont.truetype(r"C:\Windows\Fonts\segoeui.ttf", 15)
        f13 = ImageFont.truetype(r"C:\Windows\Fonts\segoeui.ttf", 13)
    except OSError:
        f15 = f13 = ImageFont.load_default()
    rutas = []
    for k in range(n):
        im = Image.new("RGB", (2560, 1440), (255, 255, 255))
        d = ImageDraw.Draw(im)
        y = 40
        for i in range(28):
            d.rounded_rectangle([80, y, 1500, y + 42], radius=10,
                                fill=(240, 242, 245))
            d.text((100, y + 6), "usuario_%02d" % i, font=f15, fill=(0, 55, 107))
            d.text((240, y + 6), "texto del comentario numero %d" % (i + k * 28),
                   font=f15, fill=(15, 15, 15))
            d.text((640, y + 6), "instagram.com/p/abc", font=f15, fill=(0, 110, 230))
            d.text((100, y + 24), "hace 3 h   Responder   12 Me gusta",
                   font=f13, fill=(120, 120, 120))
            y += 50
        p = str(TMP / ("cap_%03d.png" % k))
        im.save(p, "PNG", compress_level=1)
        rutas.append(p)
    return rutas


reales = [p for p in sorted(set(glob.glob(os.path.join(
    r"C:\navegadorforense", "NAV_FORENSE", "*", "evidence", "**", "*.png"),
    recursive=True))) if os.path.getsize(p) > 100 * 1024][:24]
caps = reales or capturas_de_prueba()
print("capturas: %d %s  (%.1f MB de originales)"
      % (len(caps), "del caso" if reales else "fabricadas",
         sum(os.path.getsize(p) for p in caps) / 1048576.0))
print()

evid = [{"tipo": "CAPTURA_COMENTARIOS", "filename": os.path.basename(p), "path": p,
         "ts": "2026-09-02T21:36:53", "size_bytes": os.path.getsize(p),
         "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()} for p in caps]


# ------------------------------------------- 1. el anexo, ejecutado de verdad
fuente = io.open(RUTA, encoding="utf-8").read()
ini = fuente.index("        # Vale para la conversacion y para los comentarios")
fin = fuente.index("        # ANEXO: VERIFICACION INDEPENDIENTE")
seccion = textwrap.dedent(fuente[ini:fin])


class Caso:
    evidences = evid
    dirs = {"thumbs": TMP}


class Yo:
    case = Caso()


def anexo(conversor):
    """Corre la seccion del anexo con el conversor que se le pase."""
    pdf = app.DictamenForense()
    pdf.add_page()
    temporales = []
    exec(seccion, {"self": Yo(), "pdf": pdf, "os": os, "Image": Image,
                   "sanitize_text": app.sanitize_text,
                   "XPos": app.XPos, "YPos": app.YPos,
                   "FUENTE_INFORME": app.FUENTE_INFORME,
                   "FUENTE_MONO": app.FUENTE_MONO,
                   "imagen_para_informe": conversor,
                   "dir_temp": TMP, "temp_thumbs": temporales})
    destino = TMP / "anexo.pdf"
    pdf.output(str(destino))
    peso = destino.stat().st_size / 1048576.0
    muestras = list(temporales)
    for t in temporales:
        try:
            os.remove(t)
        except OSError:
            pass
    return peso, pdf.page, muestras


def calidad_92(origen, ancho_mm, carpeta, **kw):
    """La calidad que se usaba antes, sobre la misma reduccion de tamano."""
    return app.imagen_para_informe(origen, ancho_mm, carpeta, calidad=92)


sin_conv, pag, _ = anexo(lambda o, a, t, **k: o)
antes, _, _ = anexo(calidad_92)
ahora, _, muestras = anexo(app.imagen_para_informe)

print("anexo de %d vistas en %d hojas:" % (len(caps), pag))
print("  sin conversor        %7.2f MB" % sin_conv)
print("  solo redimensionada  %7.2f MB   -%2.0f%%   (calidad 92)"
      % (antes, 100 * (1 - antes / sin_conv)))
print("  ahora                %7.2f MB   -%2.0f%%   (calidad 80, %.0f%% menos)"
      % (ahora, 100 * (1 - ahora / sin_conv), 100 * (1 - ahora / antes)))
if ahora >= antes:
    print("     FALLA: la calidad no bajo; pesa igual que a 92")
    ok = False
print()


# ----------------------------------------- 2. sin submuestreo de color
copia = app.imagen_para_informe(caps[0], 135.0, TMP)
if copia == caps[0]:
    print("  FALLA: el conversor devolvio el original")
    ok = False
else:
    with Image.open(copia) as im:
        muestreo = get_sampling(im)
    print("submuestreo de color : %s"
          % {0: "4:4:4 (ninguno)", 1: "4:2:2", 2: "4:2:0"}.get(muestreo, muestreo))
    if muestreo != 0:
        print("     FALLA: con submuestreo el texto chico y los enlaces se ensucian")
        ok = False
    os.remove(copia)
print()


# ------------------------------------------------- 3. el logo de la portada
from fpdf import FPDF                                # noqa: E402

vacio = TMP / "vacio.pdf"
FPDF().output(str(vacio))
base = vacio.stat().st_size


def con_imagen(ruta, nombre):
    p = FPDF()
    p.add_page()
    p.image(ruta, 14, 28, 42)
    d = TMP / nombre
    p.output(str(d))
    return d.stat().st_size - base


if not hasattr(app, "logo_para_portada"):
    print("membrete: esta version embebe el logo original, sin reducir")
    print("     FALLA: son 737 KB en cada dictamen (version anterior a la correccion)")
    ok = False
elif app.LOGO_PATH and os.path.exists(app.LOGO_PATH):
    crudo = con_imagen(app.LOGO_PATH, "logo_crudo.pdf")
    usado = con_imagen(app.logo_para_portada(), "logo_usado.pdf")
    print("membrete de la portada:")
    print("  archivo original     %7.0f KB embebidos" % (crudo / 1024.0))
    print("  el que se usa        %7.0f KB embebidos   -%2.0f%%"
          % (usado / 1024.0, 100 * (1 - usado / float(crudo))))
    if usado > crudo / 4:
        print("     FALLA: el membrete sigue pesando; va sin reducir")
        ok = False
else:
    print("membrete: no hay logo en esta instalacion, no se evalua")

print()


# --------------------------- 4. la misma imagen no va dos veces en el informe
#
# Las vistas del anexo aparecen ademas en el registro de evidencias. Mientras el
# registro las mostraba a media hoja, cada captura quedaba embebida dos veces.
if not hasattr(app, "TIPOS_CON_ANEXO_DE_VISTAS"):
    print("registro de evidencias: esta version repite la imagen a media hoja")
    print("     FALLA: cada vista queda embebida dos veces en el mismo dictamen")
    ok = False
else:
    declarados = set(app.TIPOS_CON_ANEXO_DE_VISTAS)
    en_anexo = set()
    for linea in seccion.splitlines():
        t = linea.strip()
        if t.startswith('("CAPTURA_'):
            en_anexo.add(t.split('"')[1])
    print("tipos reproducidos en el anexo : %s" % ", ".join(sorted(en_anexo)))
    print("tipos declarados en el programa: %s" % ", ".join(sorted(declarados)))
    if declarados != en_anexo:
        print("     FALLA: la lista quedo desfasada del anexo")
        ok = False

    def registro(ancho, alto, nombre):
        """
        Lo que pesa una miniatura del registro, corriendo pdf.miniatura de
        verdad.

        Se descuenta lo que pesa el documento vacio. Desde que el informe
        incrusta fuentes Unicode, cada PDF arrastra unos 60 KB de subconjunto
        tipografico, y comparando documentos enteros ese peso fijo tapaba la
        diferencia entre una miniatura y otra, que es lo que aca se mide.
        """
        pdf = app.DictamenForense()
        pdf.add_page()
        temporales = []
        if ancho:
            pdf.miniatura(caps[0], "miniatura", max_w_mm=ancho, max_h_mm=alto,
                          temp_dir=TMP, temporales=temporales)
        d = TMP / nombre
        pdf.output(str(d))
        for t in temporales:
            try:
                os.remove(t)
            except OSError:
                pass
        return d.stat().st_size / 1024.0

    vacio = registro(None, None, "reg_vacia.pdf")
    media_hoja = registro(140, 80, "reg_grande.pdf") - vacio
    chica = registro(45, 32, "reg_chica.pdf") - vacio
    print("  miniatura a media hoja %7.0f KB" % media_hoja)
    print("  miniatura chica        %7.0f KB   -%2.0f%%"
          % (chica, 100 * (1 - chica / media_hoja)))
    print("  por %d vistas se ahorran %.2f MB"
          % (len(caps), (media_hoja - chica) * len(caps) / 1024.0))
    if chica > media_hoja / 2:
        print("     FALLA: la miniatura chica no achica")
        ok = False

print()
print("RESULTADO: %s" % ("correcto" if ok else "HAY UN PROBLEMA"))
sys.exit(0 if ok else 1)
