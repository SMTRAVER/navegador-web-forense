# -*- coding: utf-8 -*-
"""
Un sello de tiempo solo cuenta si su firma verifica.

Hasta la version anterior el programa pedia el sello y lo guardaba sin
comprobar nada. Cuatro de las cinco autoridades responden por http, asi que
cualquiera en el camino de red podia devolver un token inventado —o uno
autentico de otro archivo— y el dictamen lo consignaba como "✓ Sello de tiempo
RFC 3161". Ademas, la instruccion de openssl que daba el dictamen fallaba tal
como estaba escrita.

Esta prueba EJECUTA el codigo del programa —verificar_sello, stamp y
escribir_sello_aparte— y comprueba:

  1. que los sellos reales de cada autoridad verifican
  2. que un tercero los verifica con openssl usando solo los archivos que
     deja el programa junto al paquete
  3. que se rechaza lo que no corresponde: firma con SHA-1, respuesta
     reutilizada para otro archivo, respuesta a otro pedido, firma alterada,
     fecha alterada, respuesta sin certificado
  4. que se rechaza un sello fabricado con una clave propia, y que el rechazo
     se debe a su raiz (el mismo sello pasa si esa raiz se reconociera)

Necesita red. Contra un respaldo anterior a la correccion no puede evaluarse:
esa version no tiene verificar_sello.

  python test_sello_verificado.py [ruta al .py a probar]
"""
import datetime
import hashlib
import importlib.util
import os
import secrets
import subprocess
import sys
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_sello_verificado"
TMP.mkdir(exist_ok=True)
OPENSSL = r"C:\Program Files\Git\mingw64\bin\openssl.exe"

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

if not hasattr(app, "verificar_sello"):
    print("El archivo no tiene verificar_sello(): es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

import requests                                          # noqa: E402
from asn1crypto import cms, tsp, x509 as ax              # noqa: E402
from cryptography import x509                            # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization     # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID      # noqa: E402

fallas = 0


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


def motivo(fn):
    """Corre fn y devuelve el motivo del rechazo, o 'ACEPTADO'."""
    try:
        fn()
        return "ACEPTADO"
    except app.SelloNoVerificado as e:
        return str(e)


def pedir(url, digest, nonce, cert_req=True):
    req = tsp.TimeStampReq({"version": 1, "message_imprint": {
        "hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
        "nonce": nonce, "cert_req": cert_req})
    return requests.post(url, data=req.dump(), timeout=10,
                         headers={"Content-Type": "application/timestamp-query"}).content


try:
    requests.head("http://timestamp.digicert.com", timeout=6)
except Exception:
    print("Sin acceso a las autoridades de sellado.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

print("archivo probado: %s\n" % os.path.basename(RUTA))

# ---------------------------------------------------------------- 1 y 2
print("1. Sello real de cada autoridad de la lista, y verificacion con openssl")
paquete = TMP / "paquete_de_prueba.zip"
paquete.write_bytes(b"contenido del paquete de prueba " + os.urandom(16))
h = hashlib.sha256(paquete.read_bytes()).hexdigest()
for nombre, url in app.TSA_URLS:
    r = app.TimestampAuthority.stamp(h, tsa_url=url)
    ok = bool(r and r.get("verificado"))
    debe(ok, "%-8s %s" % (nombre, ("verifica hasta %s, reloj %+.2f s (+-%.2f)"
                                   % (r["raiz"], r["desfase_reloj_s"], r["incertidumbre_s"]))
                          if ok else (r or {}).get("tsa_intentos")))
print()
s = app.escribir_sello_aparte(str(paquete), h)
debe(bool(s and s.get("token_b64")), "escribir_sello_aparte deja %s y %s"
     % (Path((s or {}).get("tsr_path", "?")).name, Path((s or {}).get("pem_path", "?")).name))
if os.path.exists(OPENSSL) and s and s.get("tsr_path"):
    p = subprocess.run([OPENSSL, "ts", "-verify", "-data", str(paquete),
                        "-in", s["tsr_path"], "-CAfile", s["pem_path"]],
                       capture_output=True, text=True)
    debe("Verification: OK" in p.stdout,
         "openssl ts -verify, tal como lo indica el dictamen -> %s"
         % ("Verification: OK" if "Verification: OK" in p.stdout
            else (p.stdout + p.stderr).strip().splitlines()[-1]))
    otro = TMP / "otro_archivo.zip"
    otro.write_bytes(b"no es el paquete")
    p = subprocess.run([OPENSSL, "ts", "-verify", "-data", str(otro),
                        "-in", s["tsr_path"], "-CAfile", s["pem_path"]],
                       capture_output=True, text=True)
    debe("Verification: OK" not in p.stdout, "openssl rechaza el sello contra otro archivo")
else:
    print("  (openssl no disponible en este equipo: se omite la verificacion externa)")

# ---------------------------------------------------------------- 3
print("\n2. Respuestas que tienen que rechazarse")
debe(motivo(lambda: app.TimestampAuthority._sellar_en("http://timestamp.apple.com/ts01", h))
     .startswith("firmado con sha1"),
     "Apple, que firma con SHA-1 -> %s"
     % motivo(lambda: app.TimestampAuthority._sellar_en("http://timestamp.apple.com/ts01", h)))
d = hashlib.sha256(b"original").digest()
n = secrets.randbits(62) + 1
crudo = pedir(app.TSA_URLS[0][1], d, n)
debe(app.verificar_sello(crudo, d, n)["raiz"] in app.RAICES_TSA.values(),
     "la respuesta intacta verifica")
m = motivo(lambda: app.verificar_sello(crudo, hashlib.sha256(b"otro").digest(), n))
debe(m == "el hash sellado no es el del archivo", "reutilizada para otro archivo -> %s" % m)
m = motivo(lambda: app.verificar_sello(crudo, d, n + 1))
debe(m.startswith("el numero de control no coincide"), "respuesta a otro pedido -> %s" % m)
firma = tsp.TimeStampResp.load(crudo)["time_stamp_token"]["content"]["signer_infos"][0]["signature"].native
i = crudo.find(firma) + 40
m = motivo(lambda: app.verificar_sello(crudo[:i] + bytes([crudo[i] ^ 1]) + crudo[i + 1:], d, n))
debe(m == "la firma de la autoridad no es valida", "un bit de la firma cambiado -> %s" % m)
gt = (tsp.TimeStampResp.load(crudo)["time_stamp_token"]["content"]["encap_content_info"]
      ["content"].parsed["gen_time"].dump())
k = crudo.find(gt) + len(gt) - 2
nuevo = b"1" if crudo[k:k + 1] != b"1" else b"2"
m = motivo(lambda: app.verificar_sello(crudo[:k] + nuevo + crudo[k + 1:], d, n))
debe(m == "el contenido del sello fue alterado", "la fecha del sello cambiada -> %s" % m)
m = motivo(lambda: app.verificar_sello(pedir(app.TSA_URLS[0][1], d, n, cert_req=False), d, n))
debe(m.startswith("la respuesta no trae el certificado"), "sin el certificado firmante -> %s" % m)

# ---------------------------------------------------------------- 4
print("\n3. Sello fabricado con una clave propia")
clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Autoridad Falsa")])
ahora = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre)
        .public_key(clave.public_key()).serial_number(4242)
        .not_valid_before(ahora - datetime.timedelta(days=1))
        .not_valid_after(ahora + datetime.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(clave, hashes.SHA256()))
der = cert.public_bytes(serialization.Encoding.DER)
cert_asn = ax.Certificate.load(der)
tst = tsp.TSTInfo({"version": 1, "policy": "1.2.3.4",
                   "message_imprint": {"hash_algorithm": {"algorithm": "sha256"},
                                       "hashed_message": d},
                   "serial_number": 1, "gen_time": ahora.replace(microsecond=0), "nonce": n})
atributos = cms.CMSAttributes([
    cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
    cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(tst.dump()).digest()]}),
    cms.CMSAttribute({"type": "signing_certificate_v2",
                      "values": [{"certs": [{"cert_hash": hashlib.sha256(der).digest()}]}]}),
])
firma_propia = clave.sign(atributos.dump(), padding.PKCS1v15(), hashes.SHA256())
firmante = cms.SignerInfo({
    "version": "v1",
    "sid": cms.SignerIdentifier({"issuer_and_serial_number": {
        "issuer": cert_asn.issuer, "serial_number": cert_asn.serial_number}}),
    "digest_algorithm": {"algorithm": "sha256"},
    "signed_attrs": atributos,
    "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
    "signature": firma_propia,
})
sd = cms.SignedData({"version": "v3", "digest_algorithms": [{"algorithm": "sha256"}],
                     "encap_content_info": {"content_type": "tst_info", "content": tst},
                     "certificates": [cert_asn], "signer_infos": [firmante]})
fabricado = tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": {
    "content_type": "signed_data", "content": sd}}).dump()
m = motivo(lambda: app.verificar_sello(fabricado, d, n))
debe("no es una raiz reconocida" in m, "firmado con clave propia -> %s" % m)
aceptado = app.verificar_sello(fabricado, d, n,
                               raices={app._huella_de_clave(cert): "Autoridad de prueba"})
debe(aceptado["raiz"] == "Autoridad de prueba",
     "control: si esa raiz se reconociera, el mismo sello pasaria (esta bien construido)")

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
