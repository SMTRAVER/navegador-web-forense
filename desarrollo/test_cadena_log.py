# -*- coding: utf-8 -*-
"""
El log de auditoria no se puede reescribir sin que se note, ni siquiera
teniendo el paquete completo.

Hasta la version anterior cada entrada llevaba un HMAC, y la clave del HMAC
viajaba dentro del ZIP, al lado del log que protegia: quien recibia el paquete
podia reescribir el log y volver a calcular todos los HMAC, y el verificador
lo daba por integro. Tampoco estaban encadenadas, aunque el dictamen lo
afirmaba: suprimir una linea no se detectaba.

Ahora cada entrada se encadena a la anterior con SHA-256 y el extremo de la
cadena se firma con una clave Ed25519 que vive solo en memoria. Esta prueba
arma un caso REAL del programa y comprueba:

  1. que no queda ninguna clave en disco: ni hmac.key ni la privada en ningun
     archivo del caso
  2. que el programa y verificar_caso.py dan el log por integro
  3. que se detecta una linea alterada, una suprimida, y una alteracion con
     toda la cadena rehecha (esta ultima, solo por la firma)
  4. que la verificacion de firmas de verificar_caso.py —escrita sin
     dependencias— coincide con la de cryptography, incluidos los vectores
     del RFC 8032
  5. que verificar_caso.py sigue leyendo los paquetes de versiones anteriores

  python test_cadena_log.py [ruta al .py a probar]
"""
import glob
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
VERIFICADOR = r"C:\navegadorforense\verificar_caso.py"
BASE = Path(os.environ.get("TEMP", ".")) / "prueba_cadena_log"
PY = sys.executable

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, r"C:\navegadorforense")
_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

if not hasattr(app.ForensicCase, "firmar_cabeza"):
    print("El archivo no firma el log: es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

import verificar_caso as vc                                          # noqa: E402
from cryptography.hazmat.primitives import serialization             # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

fallas = 0


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


def _escribible(fn, ruta, _exc):
    os.chmod(ruta, 0o666)
    fn(ruta)


def verificador(carpeta):
    r = subprocess.run([PY, VERIFICADOR, str(carpeta)], capture_output=True, text=True)
    return r.returncode, r.stdout


if BASE.exists():
    shutil.rmtree(BASE, onerror=_escribible)
BASE.mkdir(parents=True)

print("archivo probado: %s\n" % os.path.basename(RUTA))

# ------------------------------------------------------------ caso real
caso = app.ForensicCase(
    {"base_dir": str(BASE), "caratula": "PRUEBA DEL LOG", "expediente": "S/N",
     "juzgado": "-", "objeto": "cadena y firma del log"}, dict(app.AUTOR_SISTEMA))
for k in range(300):
    caso.log("INFO", "PRUEBA", "entrada de prueba %d" % k)
for k in range(250):
    caso.log_network("GET https://www.instagram.com/recurso/%d 200" % k)
caso.flush_network_log()
cierre = caso.firmar_cabeza("fin de la prueba")
raiz = caso.root
db = caso.db_path
print("caso: %s   (%d entradas en el log)" % (caso.case_id, cierre["entradas"]))

# ------------------------------------------------------------ 1
print("\n1. Ninguna clave en disco")
debe(not (raiz / "hmac.key").exists(), "no hay hmac.key en la carpeta del caso")
privada = caso._clave_log.private_bytes(serialization.Encoding.Raw,
                                        serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
encontrada = [f.name for f in raiz.rglob("*") if f.is_file()
              and (privada in f.read_bytes() or privada.hex().encode() in f.read_bytes())]
debe(not encontrada, "la clave privada no aparece en ningun archivo del caso%s"
     % (": " + ", ".join(encontrada) if encontrada else ""))
m = json.loads((raiz / "manifest.json").read_text(encoding="utf-8"))
debe(m.get("firma_log", {}).get("clave_publica") == caso.clave_publica_log,
     "la clave publica figura en manifest.json")

# ------------------------------------------------------------ 2
print("\n2. El log intacto verifica")
v = app.verificar_log(db, caso.clave_publica_log, caso.case_id)
debe(v["integro"] and v["firmadas"] == v["entradas"],
     "programa: %d entradas, %d cierres firmados, %d cubiertas por la firma"
     % (v["entradas"], v["cierres"], v["firmadas"]))
debe(v["cierres"] >= 3, "hubo cierres periodicos ademas del final (%d)" % v["cierres"])
rc, salida = verificador(raiz)
debe(rc == 0 and "INTEGRIDAD CONFIRMADA" in salida,
     "verificar_caso.py: %s" % ("integridad confirmada" if rc == 0 else "FALLA"))


# ------------------------------------------------------------ 3
def copia(nombre):
    d = BASE / nombre
    shutil.copytree(raiz, d)
    return d, d / "db" / "audit.db"


print("\n3. Alteraciones")
c1, db1 = copia("alterada")
with sqlite3.connect(str(db1)) as con:
    con.execute("UPDATE audit_log SET message='entrada cambiada' WHERE id=150")
v = app.verificar_log(db1, caso.clave_publica_log, caso.case_id)
rc, salida = verificador(c1)
debe(v["rotas"] == [150] and rc == 1,
     "una linea alterada: la cadena se rompe en la entrada %s y el verificador falla" % v["rotas"])

c2, db2 = copia("suprimida")
with sqlite3.connect(str(db2)) as con:
    con.execute("DELETE FROM audit_log WHERE id=200")
v = app.verificar_log(db2, caso.clave_publica_log, caso.case_id)
rc, salida = verificador(c2)
debe(v["rotas"] == [201] and rc == 1,
     "una linea suprimida: se rompe en la siguiente (%s) y el verificador falla" % v["rotas"])

c3, db3 = copia("rehecha")
with sqlite3.connect(str(db3)) as con:
    con.execute("UPDATE audit_log SET message='entrada cambiada' WHERE id=150")
    filas = con.execute("SELECT id, ts, level, category, message FROM audit_log ORDER BY id").fetchall()
    previa = ""
    for id_, ts, lvl, cat, msg in filas:
        previa = vc.encadenar_log(previa, ts, lvl, cat, msg)
        con.execute("UPDATE audit_log SET cadena=? WHERE id=?", (previa, id_))
    # y ademas hace coincidir los extremos guardados con su cadena nueva
    for hasta_id, in con.execute("SELECT hasta_id FROM firmas_log").fetchall():
        nueva = con.execute("SELECT cadena FROM audit_log WHERE id=?", (hasta_id,)).fetchone()[0]
        con.execute("UPDATE firmas_log SET cabeza=? WHERE hasta_id=?", (nueva, hasta_id))
v = app.verificar_log(db3, caso.clave_publica_log, caso.case_id)
rc, salida = verificador(c3)
debe(not v["rotas"] and v["cierres_invalidos"] and rc == 1,
     "alterada y con la cadena entera rehecha: el encadenamiento pasa, pero %d cierres "
     "no verifican y el verificador falla" % len(v["cierres_invalidos"]))

# ------------------------------------------------------------ 4
print("\n4. Ed25519 de verificar_caso.py contra cryptography")
vectores = [   # RFC 8032, seccion 7.1, pruebas 1 y 2
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", b""),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", b"\x72"),
]
for secreta, msg in vectores:
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(secreta))
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    debe(vc.ed25519_verifica(pub, msg, k.sign(msg)),
         "vector RFC 8032 con clave %s... verifica" % secreta[:8])
aciertos = 0
for _ in range(25):
    k = Ed25519PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    msg = os.urandom(40)
    firma = k.sign(msg)
    mala = bytearray(firma)
    mala[5] ^= 1
    aciertos += (vc.ed25519_verifica(pub, msg, firma)
                 and not vc.ed25519_verifica(pub, msg + b"x", firma)
                 and not vc.ed25519_verifica(pub, msg, bytes(mala)))
debe(aciertos == 25, "25 claves al azar: acepta la firma buena y rechaza mensaje y firma alterados")

# ------------------------------------------------------------ 5
print("\n5. Paquetes de versiones anteriores")
viejos = sorted(glob.glob(r"C:\navegadorforense\NAV_FORENSE\*.zip"))
if viejos:
    destino = BASE / "paquete_viejo"
    with zipfile.ZipFile(viejos[0]) as z:
        z.extractall(destino)
    carpeta = next(p for p in destino.iterdir() if p.is_dir())
    rc, salida = verificador(carpeta)
    debe("version anterior" in salida and "Integridad de" in salida,
         "%s: se verifica por la via HMAC y avisa su alcance" % Path(viejos[0]).name)
else:
    print("  (no hay paquetes viejos en disco para probar)")

# ------------------------------------------------------------ autodiagnostico
ed = [c for c in caso.diagnostico if "Ed25519" in c["prueba"]]
debe(bool(ed) and ed[0]["ok"], "el autodiagnostico contrasta Ed25519 contra el RFC 8032")

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
