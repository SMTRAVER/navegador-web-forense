# -*- coding: utf-8 -*-
"""
VALIDACION DE LA HERRAMIENTA - Traverso Forensics, Navegador Web Forense

Comprueba que las funciones de las que depende la prueba produzcan resultados
conocidos y esperados. Sigue el criterio del NIST para validacion de software
forense (CFTT): cada funcion se contrasta contra vectores publicados o casos
con resultado previsible, y se documenta el resultado.

El objetivo no es solo detectar errores: es poder afirmar en el dictamen que la
herramienta fue validada, indicando contra que y con que resultado.

USO:   python validacion_forense.py
       python validacion_forense.py --sin-red     (omite las pruebas de red)
"""
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

PROGRAMA = r"C:\navegadorforense\navegador_forense_pro_v1_0.py"
CON_RED = "--sin-red" not in sys.argv

resultados = []


def p(s=""):
    sys.stdout.write(s.encode("ascii", "replace").decode() + "\n")


def prueba(nombre, esperado, obtenido, detalle=""):
    ok = esperado == obtenido
    resultados.append({"prueba": nombre, "ok": ok, "esperado": str(esperado)[:70],
                       "obtenido": str(obtenido)[:70], "detalle": detalle})
    p(f"  [{'OK  ' if ok else 'FALLA'}] {nombre}")
    if not ok:
        p(f"          esperado: {str(esperado)[:64]}")
        p(f"          obtenido: {str(obtenido)[:64]}")
    return ok


spec = importlib.util.spec_from_file_location("navf", PROGRAMA)
navf = importlib.util.module_from_spec(spec)
sys.modules["navf"] = navf
spec.loader.exec_module(navf)

p("=" * 70)
p("  VALIDACION DE LA HERRAMIENTA FORENSE")
p("=" * 70)
p(f"  Programa : {os.path.basename(PROGRAMA)}")
p(f"  Hash     : {navf.get_self_hash()}")
p(f"  Pruebas de red: {'si' if CON_RED else 'no'}")
p()

# ---------------------------------------------------------------- criptografia
p("1. FUNCIONES CRIPTOGRAFICAS (vectores publicados)")
prueba("SHA-256 de 'abc' segun FIPS 180-4",
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
       hashlib.sha256(b"abc").hexdigest())
prueba("SHA-256 de cadena vacia segun FIPS 180-4",
       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
       hashlib.sha256(b"").hexdigest())
# Ed25519 firma el log de auditoria desde que dejo de usarse HMAC.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed
prueba("Ed25519 prueba 1 del RFC 8032",
       "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
       "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
       _Ed.from_private_bytes(bytes.fromhex(
           "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).sign(b"").hex())
prueba("Ed25519 prueba 2 del RFC 8032",
       "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
       "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
       _Ed.from_private_bytes(bytes.fromhex(
           "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")).sign(b"\x72").hex())
p()

# ------------------------------------------------------------ hash de archivos
p("2. CALCULO DE HASH SOBRE ARCHIVOS")
tmp = tempfile.mkdtemp()
f_ok = os.path.join(tmp, "conocido.txt")
with open(f_ok, "wb") as f:
    f.write(b"abc")
prueba("Hash de un archivo con contenido conocido",
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
       navf.sha256_file(f_ok))

n_antes = len(navf.FALLOS_CRITICOS)
r_falla = navf.sha256_file(os.path.join(tmp, "no_existe.bin"))
prueba("Archivo inexistente devuelve marca de fallo",
       navf.HASH_FALLIDO, r_falla)
prueba("El fallo de hash queda registrado",
       True, len(navf.FALLOS_CRITICOS) > n_antes,
       "no debe fallar en silencio")

grande = os.path.join(tmp, "grande.bin")
with open(grande, "wb") as f:
    f.write(b"A" * (5 * 1024 * 1024))
prueba("Hash de archivo de 5 MB (lectura por bloques)",
       hashlib.sha256(b"A" * (5 * 1024 * 1024)).hexdigest(),
       navf.sha256_file(grande))
p()

# ------------------------------------------------------------ autodiagnostico
p("3. AUTODIAGNOSTICO")
diag = navf.autodiagnostico(root_caso=tmp, verificar_red=False)
prueba("Ejecuta las comprobaciones criptograficas", True,
       any("SHA-256" in c["prueba"] for c in diag))
prueba("Todas las comprobaciones locales pasan", True,
       all(c["ok"] for c in diag))
diag_malo = navf.autodiagnostico(root_caso=r"Z:\inexistente", verificar_red=False)
prueba("Detecta un directorio no escribible", True,
       any((not c["ok"]) and "Escritura" in c["prueba"] for c in diag_malo))
p()

# ------------------------------------------------------- clasificador de media
p("4. CLASIFICADOR DE CONTENIDO")
cm = navf.ForensicNetworkInterceptor._classify_media
prueba("Detecta video mp4", "VIDEO", cm("https://cdn.ejemplo.com/v/clip.mp4?x=1"))
prueba("Detecta stream HLS", "STREAM", cm("https://cdn.ejemplo.com/master.m3u8"))
prueba("Detecta audio", "AUDIO", cm("https://cdn.ejemplo.com/a/voz.mp3"))
prueba("Descarta imagenes estaticas", None, cm("https://cdn.ejemplo.com/foto.jpg"))
prueba("Descarta el manifiesto de transparencia", None,
       cm("https://static.cdninstagram.com/btmanifest/123/instagram/main"))
p()

# ----------------------------------------------------------------- permisos
p("5. PROTECCION DE ARCHIVOS SENSIBLES")
f_sec = os.path.join(tmp, "credenciales.json")
with open(f_sec, "w") as f:
    f.write("{}")
ok_perm = navf.restringir_a_usuario_actual(f_sec)
prueba("Restringe el archivo al usuario actual", True, ok_perm)
try:
    open(f_sec).read()
    lectura = True
except Exception:
    lectura = False
prueba("El programa sigue pudiendo leerlo", True, lectura)
p()

# --------------------------------------------------------------------- WARC
p("6. EXPORTACION WARC (ISO 28500)")


class _Caso:
    pass


c = _Caso()
c.case_id = "VALIDACION_001"
c.case_data = {"exp": "validacion"}
c.perito_data = {"nombre": "Validacion automatica"}
c.dirs = {"network": Path(tmp)}
c.evidences = [{
    "path": f_ok, "tipo": "PRUEBA", "filename": "conocido.txt",
    "sha256": navf.sha256_file(f_ok), "size_bytes": 3,
    "ts": "2026-08-06T20:00:00", "source_url": "https://ejemplo.com/x",
    "integridad_ok": True, "tsa": {},
}]
w = navf.exportar_warc(c)
prueba("Genera el archivo WARC", True, w is not None)
if w:
    prueba("Contiene los registros esperados", 3, w["registros"],
           "warcinfo + resource + metadata")
    from warcio.archiveiterator import ArchiveIterator
    tipos, contenido = [], None
    with open(w["path"], "rb") as fh:
        for rec in ArchiveIterator(fh):
            tipos.append(rec.rec_type)
            if rec.rec_type == "resource":
                contenido = rec.content_stream().read()
    prueba("Se lee con una herramienta independiente",
           ["warcinfo", "resource", "metadata"], tipos)
    prueba("El contenido conserva los bytes originales", b"abc", contenido)
p()

# ------------------------------------------------------------- sellado y red
if CON_RED:
    p("7. SELLADO DE TIEMPO RFC 3161")
    r = navf.TimestampAuthority.stamp(hashlib.sha256(b"validacion").hexdigest())
    tiene = isinstance(r, dict) and bool(r.get("token_b64"))
    prueba("Obtiene sello de alguna autoridad", True, tiene,
           f"autoridad: {r.get('tsa_nombre','-')}" if tiene else "ninguna respondio")
    if tiene:
        prueba("El sello incluye la fecha", True, bool(r.get("timestamp_iso")))
        prueba("Consta que autoridad lo emitio", True, bool(r.get("tsa_nombre")))
    p()

# --------------------------------------------------------------------- cierre
total = len(resultados)
ok = sum(1 for r in resultados if r["ok"])
p("=" * 70)
p(f"  RESULTADO: {ok} de {total} pruebas superadas")
if ok < total:
    p("  PRUEBAS FALLIDAS:")
    for r in resultados:
        if not r["ok"]:
            p(f"    - {r['prueba']}")
p("=" * 70)

salida = Path(tempfile.gettempdir()) / "validacion_forense.json"
with open(salida, "w", encoding="utf-8") as f:
    json.dump({
        "programa": os.path.basename(PROGRAMA),
        "hash_programa": navf.get_self_hash(),
        "fecha": navf.datetime.datetime.now().isoformat(),
        "total": total, "superadas": ok,
        "pruebas": resultados,
    }, f, indent=2, ensure_ascii=False)
p(f"\n  Constancia: {salida}")

sys.exit(0 if ok == total else 1)
