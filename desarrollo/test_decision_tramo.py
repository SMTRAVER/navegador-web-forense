# -*- coding: utf-8 -*-
"""
Prueba la decision de cada tramo EJECUTANDO la funcion del programa, no una
copia de su logica.

Nace de un fallo real: en Facebook el relevamiento guardaba el texto completo y
ni una sola captura. La causa era que la posicion previa se actualizaba tambien
en las vueltas de espera, de modo que al reintentar 'movio' daba falso y la
foto no se disparaba nunca.

La prueba anterior no lo vio porque replicaba la logica pretendida en vez de
ejecutar la escrita. Por eso esta llama a decidir_tramo() directamente, y por
eso acepta como argumento el archivo a probar: sirve para comprobar que
detecta el fallo contra un respaldo anterior.

  python test_decision_tramo.py [ruta al .py a probar]
"""
import importlib.util
import os
import sys

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

if not hasattr(_mod, "decidir_tramo"):
    print("El archivo no tiene decidir_tramo(): es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

decidir = _mod.decidir_tramo


def nuevos_no_se_pierden():
    """
    Los comentarios que llegan durante una espera tienen que contarse igual.

    En uso real se vio el total subir de 11 a 21 mientras cada tramo informaba
    "0 nuevos": la lectura los tomaba en una vuelta de espera y esa cuenta se
    descartaba. El recorrido se cortaba creyendo que ya no llegaba nada.
    """
    w = {"tramo": 1}
    # tres vueltas de espera que traen 4, 3 y 0; despues la que procesa trae 2
    decidir(w, {"pos": 0, "alto": 5000, "visible": 800, "cargando": True}, 4)
    decidir(w, {"pos": 0, "alto": 5000, "visible": 800, "cargando": True}, 3)
    decidir(w, {"pos": 0, "alto": 5000, "visible": 800, "cargando": True}, 0)
    r = decidir(w, {"pos": 0, "alto": 5000, "visible": 800, "cargando": False}, 2)
    if "nuevos" not in r:
        return -1          # version anterior: ni siquiera devolvia la cuenta
    return r["nuevos"]


def recorrido(cargando_en, tramos=8, avanza=500):
    """
    Simula un recorrido. 'cargando_en' es un conjunto de numeros de tramo en
    los que la pagina informa que todavia esta cargando.

    Devuelve cuantas veces se decidio capturar y cuantas esperar.
    """
    w = {"tramo": 0}
    capturas = esperas = parciales = 0
    pos = 0
    t = 0
    vueltas = 0
    while t < tramos and vueltas < 200:
        vueltas += 1
        w["tramo"] = w.get("tramo", 0) + 1
        d = {"pos": pos, "alto": 6000, "visible": 800,
             "cargando": (w["tramo"] in cargando_en and w.get("esperas", 0) < 5)}
        r = decidir(w, d)
        if r["esperar"]:
            esperas += 1
            w["tramo"] -= 1          # igual que en el programa
            continue                  # se reintenta sin que la vista se mueva
        if r["parcial"]:
            parciales += 1
        if r["capturar"]:
            capturas += 1
        pos += avanza                 # la rueda desplaza recien tras procesar
        t += 1
    return {"capturas": capturas, "esperas": esperas, "parciales": parciales,
            "tramos": t}


print("archivo probado: %s\n" % os.path.basename(RUTA))
ok = True

# 1. Sin demoras: una captura por tramo
a = recorrido(cargando_en=set())
print("  sin demoras            : %(capturas)s capturas en %(tramos)s tramos" % a)
if a["capturas"] != a["tramos"]:
    print("     FALLA: deberia capturar en cada tramo"); ok = False

# 2. Con demora en TODOS los tramos, que es el caso de Facebook.
#    Es el que fallaba: se esperaba, y al reintentar no se capturaba nunca.
b = recorrido(cargando_en=set(range(1, 9)))
print("  con demora en todos    : %(capturas)s capturas, %(esperas)s esperas" % b)
if b["capturas"] != b["tramos"]:
    print("     FALLA: se esperan %d capturas y hubo %d "
          "(el texto sale y las imagenes no)" % (b["tramos"], b["capturas"]))
    ok = False

# 3. Demora que no se resuelve nunca: se captura igual, marcada como parcial
c = recorrido(cargando_en=set(range(1, 9)))
print("  demoras marcadas parcial: %(parciales)s" % c)

# 4. Panel que no se mueve: no se repiten capturas de la misma vista
d = recorrido(cargando_en=set(), avanza=0)
print("  panel que no se mueve  : %(capturas)s capturas en %(tramos)s tramos" % d)
if d["capturas"] != 1:
    print("     FALLA: con la vista quieta solo corresponde la primera"); ok = False

# 5. Lo que llega durante las esperas se cuenta
n = nuevos_no_se_pierden()
print("  nuevos tras 3 esperas  : %d  (4+3+0 en espera, 2 al procesar)" % n)
if n != 9:
    print("     FALLA: se esperan 9 y hubo %d; los de las esperas se perdieron" % n)
    ok = False

print()
print("RESULTADO: %s" % ("correcto" if ok else "HAY UN PROBLEMA"))
sys.exit(0 if ok else 1)
