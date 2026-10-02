# -*- coding: utf-8 -*-
"""
Falla si hay nombres usados y no definidos.

Por que existe: al mover la marca de agua a una funcion compartida quedo un
`alto_banda` huerfano dentro del guardado de capturas. El archivo compilaba
—py_compile no mira eso— y el error aparecio recien en uso real, con un
relevamiento entero sin una sola imagen y un mensaje que no explicaba nada:
"No se pudo guardar la captura: name 'alto_banda' is not defined".

Es un riesgo propio de este programa: buena parte del trabajo ocurre dentro de
funciones anidadas que corren en segundo plano y con su propio try/except. Ahi
un nombre equivocado no rompe nada visible; simplemente deja de guardarse la
prueba, que es la peor forma de fallar que puede tener una herramienta pericial.

Al ponerlo por primera vez aparecieron otros dos, que ya estaban desde antes:
  - `_verify_probe`, en el reintento del sondeo de media: cuando el servidor no
    informaba el tamano, el reintento reventaba y el peso quedaba sin conocer.
  - `plataforma`, al guardar la ficha visual del perfil: la ficha no se
    generaba nunca y solo quedaba el aviso en el log.

Usa pyflakes, que hace el analisis de alcances de verdad. Se instala solo en el
entorno de compilacion y no viaja en el instalador.

  python test_nombres_indefinidos.py [ruta al .py]
"""
import os
import subprocess
import sys

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")

try:
    import pyflakes  # noqa: F401
except ImportError:
    print("Falta pyflakes en el entorno de compilacion:")
    print("  .venv-forense\\Scripts\\python.exe -m pip install pyflakes")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

salida = subprocess.run([sys.executable, "-m", "pyflakes", RUTA],
                        capture_output=True, text=True).stdout
indefinidos = [L for L in salida.splitlines() if "undefined name" in L]

print("archivo: %s" % os.path.basename(RUTA))
print()
if indefinidos:
    print("nombres que se usan y no estan definidos:")
    for L in indefinidos:
        print("  %s" % L.split(os.sep)[-1])
    print()
    print("RESULTADO: %d nombre(s) sin definir" % len(indefinidos))
    sys.exit(1)

print("RESULTADO: correcto - ningun nombre sin definir")
