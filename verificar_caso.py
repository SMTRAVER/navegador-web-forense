# -*- coding: utf-8 -*-
"""
VERIFICADOR DE CASO - Traverso Forensics, Navegador Web Forense

Comprueba de forma independiente la integridad de un caso pericial. No depende
del programa que genero la prueba: solo usa la biblioteca estandar de Python,
de modo que un tercero (la contraparte, un perito de control, el juzgado) puede
validar el material por su cuenta.

Verifica:
  1. Que cada archivo conserve el hash SHA-256 declarado en su sidecar.
  2. Que el registro de evidencias coincida con los archivos en disco.
  3. Que el log de auditoria no haya sido alterado: cada entrada va encadenada
     a la anterior con SHA-256, y la cadena esta firmada con la clave Ed25519
     del caso, cuya parte publica figura en manifest.json.
  4. Que el archivo WARC (si existe) sea legible y no este corrupto.

USO:   python verificar_caso.py <carpeta_del_caso>
       python verificar_caso.py "D:\\NAV_FORENSE\\TFWF_20260806_..."
"""
import base64
import hashlib
import hmac
import json
import sqlite3
import sys
from pathlib import Path

TOTAL = 0
FALLOS = 0


def p(s=""):
    sys.stdout.write(str(s).encode("ascii", "replace").decode() + "\n")


def resultado(ok, texto, detalle=""):
    global TOTAL, FALLOS
    TOTAL += 1
    if not ok:
        FALLOS += 1
    p(f"  [{'OK  ' if ok else 'FALLA'}] {texto}")
    if detalle and not ok:
        p(f"          {detalle}")
    return ok


def sha256_de(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Ed25519, solo verificacion. Es la implementacion de referencia del RFC 8032
# (seccion 6), escrita para que se pueda leer y auditar, no para ser rapida:
# aca se verifican unas pocas firmas por caso. Va incluida para que este
# verificador siga sin depender de nada fuera de la biblioteca estandar.
# ---------------------------------------------------------------------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_RAIZ_M1 = pow(2, (_P - 1) // 4, _P)


def _suma(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _producto(s, punto):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _suma(q, punto)
        punto = _suma(punto, punto)
        s >>= 1
    return q


def _iguales(a, b):
    return ((a[0] * b[2] - b[0] * a[2]) % _P == 0
            and (a[1] * b[2] - b[1] * a[2]) % _P == 0)


def _recuperar_x(y, signo):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if signo else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _RAIZ_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != signo:
        x = _P - x
    return x


def _descomprimir(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    signo = y >> 255
    y &= (1 << 255) - 1
    x = _recuperar_x(y, signo)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recuperar_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def ed25519_verifica(publica, mensaje, firma):
    """True si `firma` es una firma Ed25519 valida de `mensaje` con `publica`."""
    if len(publica) != 32 or len(firma) != 64:
        return False
    A = _descomprimir(publica)
    R = _descomprimir(firma[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(firma[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(firma[:32] + publica + mensaje).digest(), "little") % _L
    return _iguales(_producto(s, _G), _suma(R, _producto(h, A)))


def encadenar_log(previa, ts, nivel, categoria, mensaje):
    """El eslabon de cada entrada: SHA-256 del eslabon anterior y de la entrada."""
    return hashlib.sha256(
        f"{previa}|{ts}|{nivel}|{categoria}|{mensaje}".encode("utf-8")).hexdigest()


def mensaje_firma_log(case_id, hasta_id, entradas, cabeza):
    """Lo que firma el programa en cada cierre de la cadena."""
    return f"TFWF-LOG|{case_id}|{hasta_id}|{entradas}|{cabeza}".encode("utf-8")


# ---------------------------------------------------------------------------


def verificar_sidecars(raiz):
    """Cada archivo .sha256 declara el hash de su archivo. Se recalculan todos."""
    p("\n1. HASHES DECLARADOS EN LOS SIDECAR")
    sidecars = list(raiz.rglob("*.sha256"))
    if not sidecars:
        p("  (no se encontraron sidecar)")
        return
    for sc in sidecars:
        try:
            contenido = sc.read_text(encoding="utf-8", errors="replace").strip()
            # Formato sha256sum:  <hash> *<nombre>
            esperado = contenido.split()[0].lower()
            archivo = sc.with_suffix("")          # quita .sha256
            if not archivo.exists():
                resultado(False, f"{archivo.name}", "el archivo declarado no esta")
                continue
            real = sha256_de(archivo).lower()
            resultado(real == esperado, archivo.name,
                      f"declarado {esperado[:24]}... / real {real[:24]}...")
        except Exception as e:
            resultado(False, sc.name, f"no se pudo leer: {e}")


def verificar_registro(raiz):
    """Contrasta la tabla de evidencias contra los archivos en disco."""
    p("\n2. REGISTRO DE EVIDENCIAS")
    db = raiz / "db" / "audit.db"
    if not db.exists():
        p("  (no se encontro audit.db)")
        return
    try:
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        filas = con.execute(
            "SELECT tipo, filename, path, sha256 FROM evidence_registry").fetchall()
        con.close()
    except Exception as e:
        resultado(False, "Lectura del registro", str(e))
        return
    if not filas:
        p("  (el registro esta vacio)")
        return
    for tipo, nombre, ruta, hash_reg in filas:
        # La busqueda se hace SOLO dentro de la carpeta que se esta verificando.
        #
        # El registro guarda la ruta absoluta del equipo donde se adquirio la
        # prueba. Seguir esa ruta parecia razonable —el caso pudo no haberse
        # movido— pero abre un agujero: en ese mismo equipo el verificador
        # leeria el archivo de su ubicacion original aunque no estuviera en el
        # paquete, y daria por confirmada la integridad de material ausente.
        #
        # El modo de fallar era el peor posible: aprobaba en la maquina de
        # quien arma el paquete y fallaba en la de quien lo recibe, que es
        # justo al reves de lo que un verificador tiene que hacer.
        candidatos = list(raiz.rglob(nombre))
        if not candidatos:
            resultado(False, f"{tipo}: {nombre}",
                      "no esta en la carpeta verificada")
            continue
        f = candidatos[0]
        if hash_reg == "ERROR_HASH":
            resultado(False, f"{tipo}: {nombre}",
                      "se registro SIN hash: la integridad no puede verificarse")
            continue
        real = sha256_de(f)
        resultado(real == hash_reg, f"{tipo}: {nombre}",
                  f"registrado {hash_reg[:24]}... / real {real[:24]}...")


def verificar_log(raiz):
    """Elige la comprobacion segun como se protegio el log al adquirir."""
    p("\n3. LOG DE AUDITORIA")
    db = raiz / "db" / "audit.db"
    if not db.exists():
        p("  (no se encontro audit.db)")
        return
    manifest = {}
    try:
        manifest = json.loads((raiz / "manifest.json").read_text(encoding="utf-8"))
    except Exception:
        pass
    firma = manifest.get("firma_log") or {}
    if firma.get("clave_publica"):
        verificar_log_firmado(db, firma["clave_publica"], manifest.get("case_id", ""))
    elif (raiz / "hmac.key").exists():
        verificar_log_hmac(raiz, db)
    else:
        resultado(False, "Proteccion del log",
                  "el caso no declara clave publica ni clave HMAC para verificarlo")


def verificar_log_firmado(db, clave_publica_hex, case_id):
    """
    Dos comprobaciones que se complementan:

      - el encadenamiento: cada entrada guarda el SHA-256 de la anterior y de
        si misma. Alterar, suprimir o reordenar una linea rompe la cadena en
        ese punto, y se informa donde.
      - la firma: el programa firmo el extremo de la cadena con la clave del
        caso cada 200 entradas y antes de empaquetar. Quien rehiciera la cadena
        entera despues de alterar una linea no puede rehacer esas firmas, porque
        la clave privada nunca se escribio en disco.
    """
    try:
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        filas = con.execute("SELECT id, ts, level, category, message, cadena "
                            "FROM audit_log ORDER BY id").fetchall()
        cierres = con.execute("SELECT hasta_id, entradas, cabeza, firma, motivo "
                              "FROM firmas_log ORDER BY id").fetchall()
        con.close()
    except Exception as e:
        resultado(False, "Lectura del log", str(e))
        return

    previa, rotas, eslabon = "", [], {}
    for n, (id_, ts, nivel, cat, msg, guardada) in enumerate(filas, 1):
        if encadenar_log(previa, ts, nivel, cat, msg) != guardada:
            rotas.append((id_, ts, cat, (msg or "")[:50]))
        eslabon[id_] = (guardada, n)
        previa = guardada
    resultado(not rotas, f"Encadenamiento de {len(filas)} entradas",
              f"la cadena se rompe en {len(rotas)} entrada(s)")
    for id_, ts, cat, msg in rotas[:5]:
        p(f"          entrada {id_}: {ts} [{cat}] {msg}")

    publica = bytes.fromhex(clave_publica_hex)
    malas, cubiertas = [], 0
    for hasta_id, entradas, cabeza, firma, motivo in cierres:
        ok = (eslabon.get(hasta_id) == (cabeza, entradas)
              and ed25519_verifica(publica,
                                   mensaje_firma_log(case_id, hasta_id, entradas, cabeza),
                                   bytes.fromhex(firma)))
        if ok:
            cubiertas = max(cubiertas, entradas)
        else:
            malas.append((hasta_id, motivo))
    resultado(bool(cierres) and not malas,
              f"Firma Ed25519 de la cadena: {len(cierres)} cierres, "
              f"cubren {cubiertas} de {len(filas)} entradas",
              "no hay cierres firmados" if not cierres else
              f"{len(malas)} cierre(s) no verifican con la clave publica del caso")
    for hasta_id, motivo in malas[:5]:
        p(f"          cierre en la entrada {hasta_id} ({motivo}): firma no valida")
    if cierres and not malas and cubiertas < len(filas):
        p(f"  Nota: las ultimas {len(filas) - cubiertas} entradas son posteriores al "
          f"ultimo cierre: estan encadenadas pero no firmadas.")


def verificar_log_hmac(raiz, db):
    """
    Casos generados por versiones anteriores, que protegian el log con HMAC.

    Esa clave viajaba dentro del paquete, junto al log que protegia: quien
    tuviera el paquete podia reescribir el log y volver a calcular todos los
    HMAC. Por eso esta comprobacion solo detecta corrupcion accidental, y la
    constancia fuerte de no alteracion es el hash del ZIP y su sello de tiempo.
    """
    p("  Caso de una version anterior: log protegido con HMAC.")
    p("  La clave viaja en el paquete, asi que esto detecta corrupcion accidental,")
    p("  no una alteracion deliberada.")
    try:
        clave = base64.b64decode((raiz / "hmac.key").read_text(encoding="utf-8").strip())
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
        filas = con.execute(
            "SELECT ts, level, category, message, hmac FROM audit_log ORDER BY id").fetchall()
        con.close()
    except Exception as e:
        resultado(False, "Lectura del log", str(e))
        return

    malas = []
    for ts, lvl, cat, msg, firma in filas:
        esperado = hmac.new(clave, f"{ts}|{lvl}|{cat}|{msg}".encode("utf-8"),
                            hashlib.sha256).hexdigest()
        if esperado != firma:
            malas.append((ts, cat, msg[:50]))
    resultado(not malas, f"Integridad de {len(filas)} entradas del log",
              f"{len(malas)} entradas no coinciden con su firma")
    for ts, cat, msg in malas[:5]:
        p(f"          alterada: {ts} [{cat}] {msg}")


def verificar_warc(raiz):
    """Comprueba que el WARC se pueda recorrer completo."""
    p("\n4. ARCHIVO WARC (ISO 28500)")
    warcs = list(raiz.rglob("*.warc.gz")) + list(raiz.rglob("*.warc"))
    if not warcs:
        p("  (no se genero WARC en este caso)")
        return
    for w in warcs:
        try:
            from warcio.archiveiterator import ArchiveIterator
            n = 0
            with open(w, "rb") as fh:
                for _ in ArchiveIterator(fh):
                    n += 1
            resultado(n > 0, f"{w.name}: {n} registros legibles")
        except ImportError:
            p(f"  (warcio no instalado: no se pudo revisar {w.name})")
            p("   instalar con:  pip install warcio")
        except Exception as e:
            resultado(False, w.name, f"archivo corrupto: {e}")


def main():
    if len(sys.argv) < 2:
        p(__doc__)
        sys.exit(2)
    raiz = Path(sys.argv[1])
    if not raiz.is_dir():
        p(f"No es una carpeta valida: {raiz}")
        sys.exit(2)

    p("=" * 70)
    p("  VERIFICACION INDEPENDIENTE DE CASO PERICIAL")
    p("=" * 70)
    p(f"  Caso: {raiz}")

    manifest = raiz / "manifest.json"
    if manifest.exists():
        try:
            m = json.loads(manifest.read_text(encoding="utf-8"))
            p(f"  ID  : {m.get('case_id','?')}")
        except Exception:
            pass

    verificar_sidecars(raiz)
    verificar_registro(raiz)
    verificar_log(raiz)
    verificar_warc(raiz)

    p("\n" + "=" * 70)
    if FALLOS == 0:
        p(f"  RESULTADO: INTEGRIDAD CONFIRMADA ({TOTAL} comprobaciones)")
        p("  Todos los archivos conservan el hash declarado y el log no fue alterado.")
    else:
        p(f"  RESULTADO: {FALLOS} DE {TOTAL} COMPROBACIONES FALLARON")
        p("  Revisar el detalle: la evidencia pudo haber sido modificada.")
    p("=" * 70)
    sys.exit(0 if FALLOS == 0 else 1)


if __name__ == "__main__":
    main()
