# -*- coding: utf-8 -*-
"""
La grabacion de sesion usa el perfil de calidad que eligio el perito, y el
dictamen declara cual uso.

El defecto que corrige: el desplegable de calidad se llenaba con los perfiles
de ScreenRecorder —incluido FFV1 sin perdida, que es el que se elige cuando la
grabacion es prueba— pero esa clase no se instanciaba nunca. Se grababa siempre
con OpenCV a 5 cuadros por segundo y despues se transcodificaba a H.264 con
calidad fija. Quien pedia "sin perdida" terminaba con un video comprimido con
perdida y sin forma de advertirlo: el dictamen no decia nada del asunto.

La prueba graba de verdad, con FFmpeg, y comprueba la cadena entera:

  1. que el archivo salga en el codec del perfil pedido, leido con ffprobe
  2. que el acta de custodia y los metadatos declaren ese perfil
  3. que el dictamen lo imprima junto a la evidencia

  python test_grabacion_perfil.py [ruta al .py a probar]
"""
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_grabacion_perfil"
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

if not hasattr(app.TraversoWebForensicsPro, "_video_terminado"):
    print("El programa no graba con perfil: es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

from PyQt6.QtWidgets import QApplication            # noqa: E402

fallas = 0


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


def _escribible(fn, ruta, _exc):
    os.chmod(ruta, 0o666)
    fn(ruta)


def codec_de(ruta):
    """El codec real del archivo, leido con ffprobe."""
    r = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0",
                        "-show_entries", "stream=codec_name", "-of", "csv=p=0", str(ruta)],
                       capture_output=True, text=True)
    return (r.stdout or "").strip()


def duracion_de(ruta):
    """Segundos de video que el archivo declara, segun ffprobe."""
    r = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                        "-of", "csv=p=0", str(ruta)], capture_output=True, text=True)
    try:
        return float((r.stdout or "").strip())
    except ValueError:
        return 0.0


try:
    subprocess.run(["ffmpeg", "-version"], capture_output=True, timeout=10, check=True)
except Exception:
    print("FFmpeg no esta disponible en este equipo: la grabacion con perfil no se puede probar.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

if TMP.exists():
    shutil.rmtree(TMP, onerror=_escribible)
TMP.mkdir(parents=True)
qt = QApplication.instance() or QApplication(sys.argv)

caso = app.ForensicCase(
    {"base_dir": str(TMP), "caratula": "PRUEBA DE GRABACION", "expediente": "S/N",
     "juzgado": "-", "objeto": "perfil de grabacion"}, dict(app.AUTOR_SISTEMA))

print("archivo probado: %s\n" % os.path.basename(RUTA))
print("1. El perfil elegido llega al archivo")

SEGUNDOS = 4
ESPERADO = {"ffv1_lossless": ("ffv1", ".mkv"),
            "h264_high":     ("h264", ".mp4"),
            "h264_balanced": ("h264", ".mp4")}
grabados, limpios = {}, {}
for perfil, (codec_esperado, ext) in ESPERADO.items():
    grabador = app.ScreenRecorder(output_dir=caso.dirs["evidence_vid"], case=caso,
                                  profile=perfil, window_geo=(0, 0, 320, 240))
    grabador.start()
    time.sleep(SEGUNDOS)               # deja correr la captura
    grabador.stop()
    ruta = grabador.output_path
    existe = bool(ruta) and os.path.exists(ruta) and os.path.getsize(ruta) > 0
    codec = codec_de(ruta) if existe else ""
    grabados[perfil] = ruta if existe else ""
    limpios[perfil] = grabador.cierre_limpio
    debe(existe and codec == codec_esperado and ruta.endswith(ext),
         "%-15s -> %s  codec=%s  %.0f KB"
         % (perfil, Path(ruta).name if ruta else "(sin archivo)", codec or "?",
            os.path.getsize(ruta) / 1024 if existe else 0))

print("\n1.b El archivo se cierra entero, sin perder el final")
# Matar a FFmpeg con CTRL_BREAK cortaba el archivo donde estuviera: con FFV1 se
# perdia el ultimo tramo y con H.264 se perdia todo —libx264 analiza cuadros por
# adelantado y a los pocos segundos no habia escrito ninguno—. Se le pide el
# cierre por la entrada estandar y se comprueba que el video dure lo grabado.
for perfil in ESPERADO:
    ruta = grabados.get(perfil, "")
    if not ruta:
        debe(False, "%-15s no hay archivo que medir" % perfil)
        continue
    dur = duracion_de(ruta)
    if perfil.startswith("h264"):
        debe(limpios[perfil] and dur >= SEGUNDOS * 0.75,
             "%-15s cierre normal y %.1f s de video sobre %d s grabados"
             % (perfil, dur, SEGUNDOS))
    else:
        # Matroska no siempre declara la duracion en la cabecera; alcanza con
        # que el cierre haya sido normal (FFmpeg escribio el indice).
        debe(limpios[perfil], "%-15s cierre normal (FFmpeg escribio el indice)" % perfil)

print("\n2. El acta y los metadatos declaran el perfil usado")


class Boton:
    """Un boton que no dibuja nada, solo acepta lo que le piden."""
    def setText(self, *a):
        pass

    def setEnabled(self, *a):
        pass

    setToolTip = setEnabled


class Ventana:
    """Lo minimo que _video_terminado toca de la ventana."""
    def __init__(self, perfil):
        self.case = caso
        self.perito_data = dict(app.AUTOR_SISTEMA)
        self._rec_perfil = perfil
        self.video_roi = (0, 0, 320, 240)
        self._recorder = object()
        self._video_cerrado = False
        self.is_recording = True
        self.btn_rec = Boton()
        self.combo_quality = Boton()
        self.status = type("S", (), {"showMessage": lambda *a, **k: None})()
        self.lineas = []

    def append_console(self, t):
        self.lineas.append(str(t))

    # Los metodos reales del programa, para que las llamadas internas entre
    # ellos resuelvan igual que en la ventana de verdad.
    _video_terminado = app.TraversoWebForensicsPro._video_terminado
    _video_fallo = app.TraversoWebForensicsPro._video_fallo
    toggle_recording = app.TraversoWebForensicsPro.toggle_recording


perfil = "ffv1_lossless"
ruta = grabados.get(perfil, "")
if ruta:
    v = Ventana(perfil)
    v._video_terminado(ruta)
    acta = Path(str(ruta) + ".custodia.txt")
    texto_acta = acta.read_text(encoding="utf-8") if acta.exists() else ""
    debe("FFV1 Lossless" in texto_acta, "el acta de custodia nombra el perfil")
    debe("ffv1" in texto_acta and "-level" in texto_acta,
         "el acta transcribe el codec con sus parametros")
    ev = [e for e in caso.evidences if e["tipo"] == "VIDEO_SESION"]
    meta = json.loads(ev[-1]["metadata"]) if ev else {}
    debe(meta.get("Perfil de grabacion", "").startswith("FFV1"),
         "la evidencia queda registrada con el perfil: %s" % meta.get("Perfil de grabacion"))
    debe(bool(ev) and ev[-1]["sha256"] and ev[-1]["sha256"] != "ERROR_HASH",
         "y con su hash SHA-256")
    debe(meta.get("Cierre del archivo") == "normal",
         "el acta deja constancia de como se cerro el archivo: %s"
         % meta.get("Cierre del archivo"))
else:
    debe(False, "no hubo archivo para registrar")

# Y si el cierre hubo que forzarlo, tambien queda asentado: el video pierde el
# tramo final y eso es una reserva sobre la prueba, no un detalle interno.
forzado = grabados.get("h264_balanced", "")
if forzado:
    v = Ventana("h264_balanced")
    v._recorder = type("G", (), {"cierre_limpio": False})()
    v._video_terminado(forzado)
    meta_f = json.loads([e for e in caso.evidences
                         if e["tipo"] == "VIDEO_SESION"][-1]["metadata"])
    debe(meta_f.get("Cierre del archivo", "").startswith("forzado"),
         "un cierre forzado se asienta como tal: %s" % meta_f.get("Cierre del archivo"))

print("\n2.b Al detener, el video ya esta anotado: no queda para despues")
# El dictamen cuenta las evidencias apenas vuelve de detener la grabacion. La
# señal de cierre del grabador viaja en cola entre hilos, asi que si no se la
# espera el video se registra despues de contar y no entra en el inventario.
antes = len([e for e in caso.evidences if e["tipo"] == "VIDEO_SESION"])
v = Ventana("h264_high")
v._recorder = app.ScreenRecorder(output_dir=caso.dirs["evidence_vid"], case=caso,
                                 profile="h264_high", window_geo=(0, 0, 320, 240))
v._recorder.stopped.connect(v._video_terminado)
v._recorder.error.connect(v._video_fallo)
v._recorder.start()
time.sleep(3)
v.toggle_recording()
# Sin procesar ningun evento mas: tiene que estar anotado ya.
ahora = [e for e in caso.evidences if e["tipo"] == "VIDEO_SESION"]
debe(len(ahora) == antes + 1,
     "al volver de detener hay %d video(s) anotado(s), habia %d" % (len(ahora), antes))
debe(not v.is_recording, "la grabacion queda marcada como detenida")
qt.processEvents()                 # si la señal llega ahora, no debe duplicar
ahora2 = [e for e in caso.evidences if e["tipo"] == "VIDEO_SESION"]
debe(len(ahora2) == len(ahora),
     "la señal que llega despues no vuelve a registrar el mismo video")

# Y si no hay archivo, el fallo tiene que constar. Es el caso que la guarda
# contra el doble registro podia tapar: avisaba una vez y, al entrar por el
# otro camino, volvia sin registrar nada.
v = Ventana("h264_high")
v._recorder = type("G", (), {"cierre_limpio": True, "motor_usado": "ffmpeg"})()
v._video_terminado(str(TMP / "no_existe.mp4"))
debe(any("fallo" in L.lower() for L in v.lineas),
     "un video que no quedo en disco se avisa, no pasa en silencio")
with sqlite3.connect(str(caso.db_path)) as _con:
    _errores = _con.execute(
        "SELECT COUNT(*) FROM audit_log WHERE category='VIDEO' AND level='ERROR' "
        "AND message LIKE '%vacio%'").fetchone()[0]
debe(_errores >= 1, "y queda asentado en el log de auditoria del caso")

print("\n3. El dictamen lo imprime")


class VentanaInforme(Ventana):
    def __init__(self):
        super().__init__(perfil)
        self.setup_data = {}
        self.is_recording = False

    def __getattr__(self, nombre):
        return None


pdf = app.TraversoWebForensicsPro.generate_report(VentanaInforme(), zip_info={"nombre": "p.zip"})
if not pdf or not os.path.exists(str(pdf)):
    cand = sorted(caso.dirs["report"].glob("*.pdf"), key=lambda p: p.stat().st_mtime)
    pdf = str(cand[-1]) if cand else ""
try:
    try:
        import pymupdf
    except ImportError:
        import fitz as pymupdf
    plano = " ".join("".join(p.get_text() for p in pymupdf.open(pdf)).split())
    debe("Grabado con: FFV1 Lossless" in plano,
         "el dictamen declara con que perfil se grabo")
    debe("cuadros por segundo" in plano and "region" in plano,
         "y los cuadros por segundo y la region capturada")
    debe("RESERVA: el cierre del archivo de video fue forzado" in plano,
         "y advierte cuando el cierre del archivo fue forzado")
except ImportError:
    print("  (sin PyMuPDF en este entorno: no se pudo leer el PDF)")

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
