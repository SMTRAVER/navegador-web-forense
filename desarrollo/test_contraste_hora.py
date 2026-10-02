# -*- coding: utf-8 -*-
"""
El reloj del equipo se contrasta contra una hora que no se puede falsear.

El dictamen consignaba el desfase del reloj segun una consulta NTP. NTP viaja
por UDP sin autenticar: quien controle la red puede responder con la hora que
quiera, y el dictamen lo habria declarado como "reloj sincronizado". Ahora el
programa aprovecha el sello RFC 3161 del autodiagnostico, cuya hora esta
firmada por la autoridad, para medir el reloj.

La prueba ejecuta el autodiagnostico y la apertura de caso REALES y comprueba:

  1. que con el reloj en hora el contraste da un desfase chico y pasa
  2. que con el reloj del equipo atrasado dos minutos el contraste lo detecta
  3. que si la consulta NTP miente —dice "en hora" mientras la hora firmada
     marca dos minutos— el caso lo registra como fallo y manda la firmada

Necesita red.

  python test_contraste_hora.py [ruta al .py a probar]
"""
import importlib.util
import os
import shutil
import sqlite3
import sys
import time as _time
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_contraste_hora"
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

fallas = 0


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


class RelojCorrido:
    """Reemplaza al modulo time del programa con un reloj corrido."""
    def __init__(self, segundos):
        self.segundos = segundos

    def time(self):
        return _time.time() + self.segundos

    def __getattr__(self, nombre):
        return getattr(_time, nombre)


def contraste(checks):
    return next((c for c in checks if c["prueba"].startswith("Reloj del equipo")), None)


shutil.rmtree(TMP, ignore_errors=True)
TMP.mkdir(parents=True)
print("archivo probado: %s\n" % os.path.basename(RUTA))

print("1. Reloj en hora")
c = contraste(app.autodiagnostico(root_caso=TMP, verificar_red=True))
if c is None:
    print("  El autodiagnostico no contrasta el reloj: version anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)
d = c["contraste_hora"]
debe(c["ok"] and abs(d["desfase_s"]) < 5,
     "desfase %+.2f s (margen %.2f s) segun %s" % (d["desfase_s"], d["margen_s"], d["autoridad"]))

print("\n2. Reloj del equipo atrasado 120 segundos")
original = app.time
app.time = RelojCorrido(-120)
try:
    c = contraste(app.autodiagnostico(root_caso=TMP, verificar_red=True))
finally:
    app.time = original
d = c["contraste_hora"]
debe(not c["ok"] and 110 < d["desfase_s"] < 130,
     "lo detecta: %s" % c["detalle"])

print("\n3. La consulta NTP miente")
ntp_real = app.get_ntp_info
app.get_ntp_info = lambda: {"servidor": "pool.ntp.org", "offset_segundos": 0.0,
                            "offset_legible": "+0.000 s", "sincronizado": True}
app.time = RelojCorrido(-120)
try:
    caso = app.ForensicCase({"base_dir": str(TMP), "caratula": "PRUEBA DEL RELOJ",
                             "expediente": "S/N", "juzgado": "-", "objeto": "reloj"},
                            dict(app.AUTOR_SISTEMA))
finally:
    app.time = original
    app.get_ntp_info = ntp_real
caso.flush_network_log()
with sqlite3.connect(str(caso.db_path)) as con:
    avisos = [m for (m,) in con.execute(
        "SELECT message FROM audit_log WHERE category='TIEMPO'").fetchall()]
debe(bool(avisos) and "no coinciden" in avisos[0],
     "el caso lo registra: %s" % (avisos[0][:110] + "..." if avisos else "NADA"))

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
