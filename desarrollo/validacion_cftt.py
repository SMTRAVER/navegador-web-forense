# -*- coding: utf-8 -*-
"""
Arma el informe de validacion de la herramienta y lo deja en VALIDACION.md.

Sigue la forma del CFTT del NIST: requisito -> afirmacion -> caso de prueba ->
resultado. La diferencia con un documento escrito a mano es que este se genera
CORRIENDO las pruebas: cada afirmacion queda con el resultado que dio hoy, en
este equipo y sobre esta version, o con el motivo por el que no se pudo evaluar.

Ninguna categoria del CFTT cubre la captura web. La mas cercana es la de
extraccion de datos en la nube (CDX), cuya version 1.1 de enero de 2025 incluye
una seccion para servicios de mensajeria y redes sociales. De ahi salen los
requisitos CDX; los TF son los que la propia herramienta afirma en su dictamen,
que tambien hay que poder sostener.

  python desarrollo/validacion_cftt.py
"""
import datetime
import importlib.util
import os
import platform
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
PY = str(RAIZ / ".venv-forense" / "Scripts" / "python.exe")
SALIDA = RAIZ / "VALIDACION.md"
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# requisito, de donde sale, afirmacion, pruebas que la verifican
REQUISITOS = [
    ("CDX-CR-04 / CA-04", "NIST CFTT CDX v1.1",
     "La herramienta informa todos los artefactos extraidos, y los presenta de "
     "forma exacta y completa.",
     ["test_cierre_paquete", "test_comentarios_dos_posts", "test_lista_amigos_fb",
      "test_espera_carga", "test_decision_tramo", "test_sello_en_metadatos"]),
    ("CDX-CA-05", "NIST CFTT CDX v1.1",
     "La herramienta transcribe correctamente el texto en ingles.",
     ["test_texto_multilingue"]),
    ("CDX-CA-06", "NIST CFTT CDX v1.1",
     "La herramienta transcribe correctamente el texto que no esta en ingles: "
     "acentos y diereses, alfabetos no latinos, kanji, kana y escritura de "
     "derecha a izquierda.",
     ["test_texto_multilingue"]),
    ("TF-RQ-01", "Afirmado en el dictamen",
     "Cada pieza de evidencia queda con su SHA-256 y su acta de custodia, y la "
     "imagen capturada no se altera al guardarla.",
     ["test_sello_en_metadatos", "test_cierre_paquete"]),
    ("TF-RQ-02", "Afirmado en el dictamen",
     "El sello de tiempo RFC 3161 se verifica antes de aceptarlo: firma, hash "
     "sellado, numero de control y cadena hasta una raiz reconocida. Un sello "
     "que no verifica se rechaza.",
     ["test_sello_verificado"]),
    ("TF-RQ-03", "Afirmado en el dictamen",
     "El log de auditoria no se puede alterar sin que se note, ni siquiera "
     "teniendo el paquete completo.",
     ["test_cadena_log"]),
    ("TF-RQ-04", "Afirmado en el dictamen",
     "La herramienta declara su identidad: hash del ejecutable y del conjunto "
     "de sus archivos, y no se compila con nombres sin definir.",
     ["test_hash_herramienta", "test_nombres_indefinidos"]),
    ("TF-RQ-05", "Afirmado en el dictamen",
     "El reloj del equipo se contrasta contra una hora firmada, que no se puede "
     "falsear en la red, y la discrepancia se informa.",
     ["test_contraste_hora"]),
    ("TF-RQ-06", "Afirmado en el dictamen",
     "Nada entra a la carpeta de evidencia sin que lo pida el programa o lo "
     "acepte el perito, y la decision queda registrada.",
     ["test_descarga_no_pedida"]),
    ("TF-RQ-07", "ISO/IEC 27037",
     "Lo que la herramienta no puede hacer se declara en el dictamen, con lo "
     "que el motor informo en esa diligencia.",
     ["test_codecs_en_dictamen"]),
    ("TF-RQ-08", "Metodo del CFTT",
     "Las funciones criptograficas se contrastan contra vectores publicados "
     "(FIPS 180-4 y RFC 8032), no contra lo que afirme el fabricante.",
     ["test_autodiagnostico", "validacion_forense"]),
    ("TF-RQ-09", "Afirmado en el dictamen",
     "La prueba se puede verificar sin esta herramienta: el verificador usa "
     "solo la biblioteca estandar y el sello se comprueba con openssl.",
     ["test_cadena_log", "test_sello_verificado"]),
    ("TF-RQ-10", "Afirmado en el dictamen",
     "Se comprueba que el codigo que sirvio el sitio sea el que la plataforma "
     "publico ante un tercero (binary transparency).",
     ["test_bt_integrado", "test_seccion_bt"]),
]

# Lo que NO se cumple. Va en el informe: una validacion que solo lista exitos
# no es una validacion.
LIMITES = [
    ("CDX-CR-02 / CA-02", "La herramienta no avisa por si misma que las credenciales son "
     "invalidas: el aviso lo da el sitio en la propia pantalla, que es lo que el perito ve y "
     "lo que queda en la captura. No se cumple como lo pide la especificacion."),
    ("CDX-CR-03 / CA-03", "No se presenta al usuario una lista de servicios soportados. El "
     "programa es un navegador: sirve para cualquier sitio, y tiene recorridos automaticos "
     "para Instagram, Facebook, TikTok y WhatsApp Web. Esta documentado en el README, no en "
     "la interfaz."),
    ("CDX-CA-06 (parcial)", "Las lenguas de derecha a izquierda se componen con HarfBuzz y se "
     "ven correctamente, pero el programa no aplica el algoritmo bidireccional completo de "
     "Unicode: un parrafo que mezcle arabe y latino en la misma linea puede quedar con los "
     "tramos en otro orden. El listado .txt conserva el original."),
    ("Video H.264/AAC", "El motor no reproduce esos codecs y el recuadro del video puede verse "
     "en negro. El video se adquiere como archivo original con su hash. Declarado en el "
     "dictamen."),
    ("Repeticion independiente", "Las pruebas corrieron en un solo equipo. El CFTT espera que "
     "el resultado se repita en otro, con otro operador."),
    ("Revision externa", "La validacion es propia. Ningun laboratorio ni organismo la reviso."),
]

INFORMATIVAS = ["test_peso_dictamen", "test_reporte_comentarios", "test_rueda_scroll",
                "test_fluidez_scroll", "test_velocidad_perfil", "test_comentarios_dos_posts"]


def correr(nombre):
    """Ejecuta una prueba y devuelve (estado, linea de resultado, segundos)."""
    archivo = (RAIZ / "validacion_forense.py" if nombre == "validacion_forense"
               else RAIZ / "desarrollo" / (nombre + ".py"))
    inicio = datetime.datetime.now()
    try:
        r = subprocess.run([PY, "-u", str(archivo)], capture_output=True, text=True,
                           timeout=420, cwd=str(RAIZ), encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return "SIN TERMINAR", "la prueba no termino en 420 s", 420.0
    seg = (datetime.datetime.now() - inicio).total_seconds()
    lineas = [l.strip() for l in (r.stdout or "").splitlines() if "RESULTADO" in l]
    detalle = lineas[0] if lineas else (r.stdout or r.stderr or "").strip().splitlines()[-1:][0][:110]
    if r.returncode == 2:
        return "NO EVALUABLE", detalle, seg
    return ("PASA" if r.returncode == 0 else "NO PASA"), detalle, seg


def main():
    spec = importlib.util.spec_from_file_location(
        "nav", str(RAIZ / "navegador_forense_pro_v1_0.py"))
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)

    pruebas = sorted({p for _, _, _, ps in REQUISITOS for p in ps} | set(INFORMATIVAS))
    print("Corriendo %d pruebas (de a una, las del motor no se solapan)...\n" % len(pruebas))
    resultados = {}
    for n in pruebas:
        estado, detalle, seg = correr(n)
        resultados[n] = (estado, detalle, seg)
        print("  %-30s %-13s %5.0f s  %s" % (n, estado, seg, detalle[:60]))

    manifiesto = RAIZ / "instalador" / ("NavegadorWebForense_%s_archivos.sha256"
                                        % app.SOFTWARE_INFO["version"])
    conjunto = app.sha256_file(str(manifiesto)) if manifiesto.exists() else "no disponible"
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                            text=True, cwd=str(RAIZ)).stdout.strip() or "sin repositorio"

    L = []
    w = L.append
    w("# Validacion de la herramienta\n")
    w("**%s %s** | commit `%s` | %s\n"
      % (app.SOFTWARE_INFO["software"], app.SOFTWARE_INFO["version"], commit,
         datetime.datetime.now().strftime("%d/%m/%Y %H:%M")))
    w("Este informe se genera ejecutando las pruebas, no escribiendolo: cada afirmacion "
      "queda con el resultado que dio en esta corrida. Para rehacerlo:\n")
    w("```bash\npython desarrollo/validacion_cftt.py\n```\n")

    w("## Metodo\n")
    w("Se sigue la forma del programa de pruebas de herramientas forenses del NIST "
      "(Computer Forensics Tool Testing): **requisito -> afirmacion -> caso de prueba -> "
      "resultado**.\n")
    w("Ninguna de las once categorias del CFTT cubre la captura de sitios web o redes "
      "sociales. La mas cercana es la de extraccion de datos en la nube con credenciales "
      "(CDX), cuya especificacion v1.1 de enero de 2025 incorporo una seccion para servicios "
      "de mensajeria y redes sociales. De ahi salen los requisitos **CDX**. Los **TF** son "
      "los que la propia herramienta afirma en su dictamen: si el dictamen lo dice, hay que "
      "poder sostenerlo.\n")
    w("Esta validacion es propia. El NIST no probo esta herramienta ni la avala.\n")

    w("## Resultados\n")
    w("| Requisito | Origen | Afirmacion | Casos de prueba | Resultado |")
    w("|---|---|---|---|---|")
    for req, origen, afirmacion, ps in REQUISITOS:
        estados = [resultados[p][0] for p in ps]
        final = ("PASA" if all(e == "PASA" for e in estados)
                 else ("NO EVALUABLE" if all(e == "NO EVALUABLE" for e in estados) else "REVISAR"))
        casos = "<br>".join("`%s`: %s" % (p, resultados[p][0]) for p in ps)
        w("| **%s** | %s | %s | %s | **%s** |" % (req, origen, afirmacion, casos, final))
    w("")

    w("## Detalle de cada corrida\n")
    w("| Prueba | Resultado | Tiempo | Salida |")
    w("|---|---|---|---|")
    for n in pruebas:
        estado, detalle, seg = resultados[n]
        marca = "informativa" if n in INFORMATIVAS and not any(
            n in ps for _, _, _, ps in REQUISITOS) else ""
        w("| `%s` %s | %s | %.0f s | %s |" % (n, marca, estado, seg, detalle.replace("|", "/")))
    w("")

    w("## Lo que no se cumple\n")
    for que, porque in LIMITES:
        w("- **%s.** %s" % (que, porque))
    w("")

    # Se arma un dictamen vacio para que informe con que fuentes saldria: esa
    # descripcion se completa al cargarlas en un documento.
    app.DictamenForense()
    instalador = RAIZ / "instalador" / ("NavegadorWebForense_%s_Setup.exe"
                                        % app.SOFTWARE_INFO["version"])

    w("## Entorno de la corrida\n")
    w("| | |")
    w("|---|---|")
    w("| Codigo fuente validado | `%s` |" % app.get_self_hash())
    w("| Conjunto de archivos de la version compilada | `%s` |" % conjunto)
    w("| Instalador | `%s` |"
      % (app.sha256_file(str(instalador)) if instalador.exists() else "no disponible"))
    w("| Motor del navegador | %s |" % app.version_motor())
    w("| Fuentes del informe | %s |" % app.FUENTES_DEL_INFORME)
    w("| Raices de sellado reconocidas | %s |" % ", ".join(sorted(app.RAICES_TSA.values())))
    w("| Sistema operativo | %s |" % app.get_windows_version())
    w("| Python | %s |" % platform.python_version())
    w("| Equipo | %s |" % os.environ.get("COMPUTERNAME", "no informado"))
    w("")
    w("## Como repetir una prueba suelta\n")
    w("Cada prueba acepta la ruta de un `.py`, de modo que puede correrse contra un respaldo "
      "anterior para comprobar que ahi falla:\n")
    w("```bat\n.venv-forense\\Scripts\\python.exe -u desarrollo\\test_sello_verificado.py "
      "respaldos\\navegador_forense_pro_v1_0_BACKUP_<fecha>.py\n```\n")
    w("Las que abren el motor del navegador se corren de a una: dos procesos de QtWebEngine "
      "a la vez se tiran abajo.")

    SALIDA.write_text("\n".join(L), encoding="utf-8", newline="\n")
    # El veredicto lo dan las pruebas atadas a un requisito. Las informativas
    # miden y concluyen (rendimiento, peso del informe), y su conclusion cambia
    # con la carga del equipo: no corresponde que tumben una validacion.
    de_requisitos = {p for _, _, _, ps in REQUISITOS for p in ps}
    fallan = [n for n, (e, _, _) in resultados.items()
              if n in de_requisitos and e not in ("PASA", "NO EVALUABLE")]
    otras = [n for n, (e, _, _) in resultados.items()
             if n not in de_requisitos and e != "PASA"]
    print("\n%s" % SALIDA)
    print("pruebas de requisitos: %d | no pasan: %s"
          % (len(de_requisitos), ", ".join(fallan) or "ninguna"))
    if otras:
        print("informativas con observaciones: %s" % ", ".join(otras))
    return 0 if not fallan else 1


if __name__ == "__main__":
    sys.exit(main())
