# -*- coding: utf-8 -*-
"""
Las capturas salen sin marca visible y con los datos de la diligencia grabados
dentro del PNG.

El sello paso por tres etapas. Primero se dibujaba sobre la imagen y tapaba
contenido: en la pagina completa unida se comia los ultimos 126 pixeles, y en
el recorte de una columna de comentarios, los comentarios. Despues paso a una
franja negra agregada abajo, que no tapaba nada pero ensuciaba una imagen que
se acompana como prueba de como se veia la pagina. Ahora no se ve.

Lo que se comprueba:
  1. la imagen guardada mide exactamente lo capturado, sin un pixel agregado
  2. los datos de la diligencia estan adentro y se pueden leer
  3. ninguno de los datos que importan se perdio en el camino
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, r"C:\navegadorforense")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import navegador_forense_pro_v1_0 as app          # noqa: E402
from PIL import Image, ImageDraw                  # noqa: E402

TMP = Path(os.environ.get("TEMP", ".")) / "prueba_sello"
TMP.mkdir(exist_ok=True)

LINEAS = [
    "Traverso Forensics - Navegador Web Forense v1.0",
    "Case: TFWF_20260830_215422_9a381d3c",
    "Timestamp: 2026-08-30T21:58:00.301069",
    "Comentarios de la publicacion, vista 2",
    "Tool Hash: 11fd545d1aa53780...",
    "Perito: dFDSFDSF",
]

# Una captura con texto hasta el ultimo renglon, como una columna de comentarios
original = Image.new("RGB", (700, 400), (255, 255, 255))
d = ImageDraw.Draw(original)
for k in range(10):
    d.text((15, 20 + k * 38), "comentario %d: no se debe tapar ni recortar" % (k + 1),
           fill=(0, 0, 0))

ruta = TMP / "captura.png"
original.save(str(ruta), "PNG", compress_level=1,
              pnginfo=app.datos_del_sello(LINEAS))

ok = True
with Image.open(ruta) as guardada:
    print("  original : %dx%d" % original.size)
    print("  guardada : %dx%d" % guardada.size)
    if guardada.size != original.size:
        print("     FALLA: la imagen cambio de tamano; hay pixeles agregados")
        ok = False
    iguales = list(guardada.convert("RGB").getdata()) == list(original.getdata())
    print("  identica pixel por pixel : %s" % ("si" if iguales else "NO"))
    ok &= iguales

    meta = dict(guardada.text)

print()
print("  datos grabados dentro del PNG:")
for k, v in meta.items():
    print("     %-22s %s" % (k, v[:60]))

# Nada de lo que identifica la prueba puede haberse perdido
esperados = {
    "Case": "TFWF_20260830_215422_9a381d3c",
    "Perito": "dFDSFDSF",
}
print()
for clave, valor in esperados.items():
    hay = meta.get(clave) == valor
    print("  %-10s conservado : %s" % (clave, "si" if hay else "NO"))
    ok &= hay

# El hash de la herramienta y el momento tambien tienen que estar
for clave in ("Tool Hash", "Timestamp"):
    hay = clave in meta and meta[clave]
    print("  %-10s conservado : %s" % (clave, "si" if hay else "NO"))
    ok &= bool(hay)

print()
print("RESULTADO: %s" % ("correcto" if ok else "HAY UN PROBLEMA"))
sys.exit(0 if ok else 1)
