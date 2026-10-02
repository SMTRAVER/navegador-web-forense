# -*- coding: utf-8 -*-
"""
Escribe el manifiesto oficial de archivos de la version recien compilada.

Es la referencia contra la que se comparan los dictamenes: cada uno declara el
hash del conjunto de archivos con que se adquirio la prueba, y lleva adentro su
propio manifiesto. Si el hash no coincide con el oficial, comparar los dos
manifiestos muestra que archivo cambio.

Lo llama compilar_onedir.bat despues de limpiar dist. Usa la misma funcion que
el programa, para que los dos calculos no puedan diferir.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
import navegador_forense_pro_v1_0 as app      # noqa: E402

r = app.manifiesto_de_la_herramienta(str(RAIZ / "dist" / "TraversoWebForensics"))
if r.get("conjunto") in (None, "N/A"):
    print("      ERROR: %s" % r.get("error"))
    sys.exit(1)

destino = RAIZ / "instalador" / ("NavegadorWebForense_%s_archivos.sha256"
                                 % app.SOFTWARE_INFO["version"])
destino.parent.mkdir(exist_ok=True)
destino.write_text(r["manifiesto"], encoding="utf-8", newline="\n")
print("      %d archivos, %.1f MB" % (r["archivos"], r["bytes"] / 1048576.0))
print("      conjunto : %s" % r["conjunto"])
print("      manifiesto: %s" % destino)
