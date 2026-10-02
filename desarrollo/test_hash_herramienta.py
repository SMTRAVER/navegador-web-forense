# -*- coding: utf-8 -*-
"""
El hash de la herramienta cubre todos sus archivos, no solo el .exe.

El dictamen declaraba el SHA-256 del ejecutable. En una compilacion onedir ese
.exe es un lanzador de 16 MB, y el programa real —codigo, motor Chromium,
bibliotecas— esta en _internal, unos 345 archivos que el hash no cubria:
reemplazar una DLL cambiaba el comportamiento y el dictamen declaraba el mismo
hash de siempre.

Esta prueba EJECUTA manifiesto_de_la_herramienta() del programa sobre una
instalacion de prueba y comprueba:

  1. que cubre el .exe y todo _internal, y deja afuera el desinstalador y las
     carpetas de trabajo (casos, perfiles)
  2. que el hash del conjunto es el SHA-256 del manifiesto, y que certutil
     —lo que tiene cualquier Windows— da el mismo valor
  3. que cambiar un byte de una DLL de _internal deja igual el hash del .exe
     pero cambia el del conjunto, y el manifiesto senala esa DLL
  4. si ya hay una compilacion, que el calculo sobre dist coincide con el
     manifiesto oficial que escribio la compilacion

  python test_hash_herramienta.py [ruta al .py a probar]
"""
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_hash_herramienta"

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

if not hasattr(app, "manifiesto_de_la_herramienta"):
    print("El archivo solo calcula el hash del .exe: es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

fallas = 0


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


if TMP.exists():
    shutil.rmtree(TMP)
inst = TMP / "Navegador Web Forense"
(inst / "_internal" / "PyQt6" / "Qt6" / "bin").mkdir(parents=True)
(inst / "NAV_FORENSE" / "TFWF_caso").mkdir(parents=True)
(inst / "perfiles_navegador").mkdir()
(inst / "TraversoWebForensics.exe").write_bytes(b"MZ lanzador " + os.urandom(2000))
dll = inst / "_internal" / "PyQt6" / "Qt6" / "bin" / "Qt6WebEngineCore.dll"
dll.write_bytes(b"MZ motor " + os.urandom(50000))
(inst / "_internal" / "base_library.zip").write_bytes(os.urandom(3000))
(inst / "unins000.exe").write_bytes(b"MZ desinstalador")
(inst / "NAV_FORENSE" / "TFWF_caso" / "manifest.json").write_text("{}")
(inst / "perfiles_navegador" / "Cookies").write_bytes(b"sesion")

print("archivo probado: %s\n" % os.path.basename(RUTA))
print("1. Que archivos cubre")
r = app.manifiesto_de_la_herramienta(str(inst))
rutas = [linea.split("  ", 1)[1] for linea in r["manifiesto"].splitlines()]
debe(rutas == ["TraversoWebForensics.exe", "_internal/PyQt6/Qt6/bin/Qt6WebEngineCore.dll",
               "_internal/base_library.zip"],
     "el .exe y todo _internal, ordenados: %s" % rutas)
debe(not any("unins" in x or "NAV_FORENSE" in x or "perfiles" in x for x in rutas),
     "afuera el desinstalador, los casos y los perfiles")

print("\n2. El hash del conjunto es el del manifiesto")
debe(r["conjunto"] == hashlib.sha256(r["manifiesto"].encode("utf-8")).hexdigest(),
     "conjunto = SHA-256 del texto del manifiesto")
archivo = TMP / "herramienta_archivos.sha256"
archivo.write_text(r["manifiesto"], encoding="utf-8", newline="\n")
salida = subprocess.run(["certutil", "-hashfile", str(archivo), "SHA256"],
                        capture_output=True, text=True).stdout
debe(r["conjunto"] in salida.replace(" ", "").lower(),
     "certutil -hashfile sobre el manifiesto da el mismo valor")

print("\n3. Una DLL reemplazada")
exe_antes = app.sha256_file(str(inst / "TraversoWebForensics.exe"))
datos = bytearray(dll.read_bytes())
datos[100] ^= 1
dll.write_bytes(bytes(datos))
r2 = app.manifiesto_de_la_herramienta(str(inst))
exe_despues = app.sha256_file(str(inst / "TraversoWebForensics.exe"))
debe(exe_antes == exe_despues, "el hash del .exe NO cambia (por eso no alcanzaba)")
debe(r2["conjunto"] != r["conjunto"], "el hash del conjunto SI cambia")
distintas = [b.split("  ", 1)[1] for a, b in zip(r["manifiesto"].splitlines(),
                                                 r2["manifiesto"].splitlines()) if a != b]
debe(distintas == ["_internal/PyQt6/Qt6/bin/Qt6WebEngineCore.dll"],
     "comparar los manifiestos senala el archivo cambiado: %s" % distintas)

print("\n4. La compilacion real")
dist = Path(r"C:\navegadorforense\dist\TraversoWebForensics")
oficial = Path(r"C:\navegadorforense\instalador") / (
    "NavegadorWebForense_%s_archivos.sha256" % app.SOFTWARE_INFO["version"])
if dist.exists() and oficial.exists() and oficial.stat().st_mtime >= dist.stat().st_mtime - 3600:
    r3 = app.manifiesto_de_la_herramienta(str(dist))
    debe(r3["manifiesto"] == oficial.read_text(encoding="utf-8"),
         "dist coincide con el manifiesto oficial (%d archivos, conjunto %s...)"
         % (r3["archivos"], r3["conjunto"][:16]))
else:
    print("  (todavia no hay manifiesto oficial de esta compilacion)")

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
