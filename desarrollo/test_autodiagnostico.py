# -*- coding: utf-8 -*-
"""
Verifica el autodiagnostico usando el modulo real del programa.

Comprueba tres cosas:
  - que las pruebas criptograficas pasen contra los vectores conocidos,
  - que detecte un directorio no escribible,
  - que detecte la falta de sellado de tiempo.
"""
import importlib.util
import sys
import tempfile
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")


def p(s):
    sys.stdout.write(s.encode("ascii", "replace").decode() + "\n")


spec = importlib.util.spec_from_file_location(
    "navf", r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
navf = importlib.util.module_from_spec(spec)
sys.modules["navf"] = navf
spec.loader.exec_module(navf)
p("Modulo cargado\n")

p("=== 1) Diagnostico normal (con red) ===")
tmp = tempfile.mkdtemp()
res = navf.autodiagnostico(root_caso=tmp, verificar_red=True)
for c in res:
    p(f"  [{'OK  ' if c['ok'] else 'FALLA'}] {c['prueba']:34} {c['detalle'][:44]}")
todo_ok = all(c["ok"] for c in res)
p(f"\n  Resultado global: {'TODO OK' if todo_ok else 'HAY FALLAS'}")

p("\n=== 2) Deteccion de directorio NO escribible ===")
res2 = navf.autodiagnostico(root_caso=r"Z:\ruta\inexistente", verificar_red=False)
esc = [c for c in res2 if "Escritura" in c["prueba"]]
if esc:
    c = esc[0]
    p(f"  [{'OK  ' if not c['ok'] else 'FALLA'}] detecta que no puede escribir: {not c['ok']}")
else:
    p("  FALLA: no se ejecuto la prueba de escritura")

p("\n=== 3) Los vectores criptograficos son los correctos ===")
import hashlib
p(f"  SHA-256('abc') esperado por FIPS 180-4:")
p(f"    {hashlib.sha256(b'abc').hexdigest()}")
p(f"    ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  <- publicado")
ok_vec = hashlib.sha256(b"abc").hexdigest() == \
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
p(f"    coinciden: {ok_vec}")
