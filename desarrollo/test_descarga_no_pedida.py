# -*- coding: utf-8 -*-
"""
Una descarga que el programa no pidio no entra sola a la evidencia.

Hasta la version anterior el manejador de descargas aceptaba todo lo que
llegaba y lo guardaba en la carpeta de evidencias con su hash y su acta. Una
pagina puede iniciar una descarga sin que nadie haga clic, asi que cualquier
sitio visitado durante la diligencia podia meter un archivo en el caso, y el
dictamen lo habria listado como material adquirido por el perito.

Esta prueba abre el motor real, carga una pagina que dispara una descarga por
su cuenta —sin gesto del usuario— y la entrega al manejador REAL del programa.
Comprueba:

  1. que el programa pregunta, y si el perito rechaza no queda ningun archivo
     y el rechazo queda en el log con el origen
  2. que si el perito acepta, la descarga entra como siempre
  3. que las descargas que pide el propio programa —recorrido de WhatsApp,
     pagina archivada, foto de perfil— no preguntan

  python test_descarga_no_pedida.py [ruta al .py a probar]
"""
import importlib.util
import os
import shutil
import sys
from pathlib import Path

RUTA = (sys.argv[1] if len(sys.argv) > 1
        else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
TMP = Path(os.environ.get("TEMP", ".")) / "prueba_descarga_no_pedida"
os.environ["QT_QPA_PLATFORM"] = "offscreen"

_spec = importlib.util.spec_from_file_location("bajo_prueba", RUTA)
app = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(app)

if not hasattr(app, "descarga_del_programa"):
    print("El archivo acepta cualquier descarga: es anterior a la correccion.")
    print("RESULTADO: no se puede evaluar")
    sys.exit(2)

from PyQt6.QtCore import QTimer, QUrl                     # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox     # noqa: E402
from PyQt6.QtWebEngineCore import (QWebEngineDownloadRequest, QWebEnginePage,  # noqa: E402
                                   QWebEngineProfile)

fallas = 0


def debe(ok, texto):
    global fallas
    print("  [%s] %s" % ("ok " if ok else "MAL", texto))
    if not ok:
        fallas += 1


# Una pagina que descarga un archivo apenas carga, sin que nadie haga clic
PAGINA = """<html><body><script>
setTimeout(function () {
  var a = document.createElement('a');
  a.href = 'data:application/octet-stream;base64,' + btoa('contenido que nadie pidio');
  a.download = 'factura_urgente.exe';
  document.body.appendChild(a);
  a.click();
}, 300);
</script><p>pagina cualquiera</p></body></html>"""


class Caso:
    """Lo que el manejador usa del caso: carpetas y log."""
    def __init__(self, raiz):
        self.dirs = {"evidence_raw": raiz / "raw", "evidence_img": raiz / "img"}
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)
        self.lineas = []

    def log(self, nivel, categoria, mensaje):
        self.lineas.append((nivel, categoria, mensaje))

    def __getattr__(self, nombre):
        return lambda *a, **k: None


class Ventana:
    """Lo minimo de la ventana que toca _on_download_requested."""
    def __init__(self, caso):
        self.case = caso
        self.consola = []
        self._pagina_pendiente = None
        self._wa = {}

    def append_console(self, t):
        self.consola.append(str(t))


manejador = app.TraversoWebForensicsPro._on_download_requested
qt = QApplication.instance() or QApplication(sys.argv)
respuestas = []


def correr(etiqueta, preparar, respuesta):
    """Abre la pagina, entrega la descarga al manejador y devuelve lo ocurrido."""
    carpeta = TMP / etiqueta
    shutil.rmtree(carpeta, ignore_errors=True)
    caso = Caso(carpeta)
    v = Ventana(caso)
    preparar(v)
    preguntas = []

    def pregunta(*a, **k):
        preguntas.append(a[1] if len(a) > 1 else "")
        return respuesta

    QMessageBox.question = staticmethod(pregunta)
    perfil = QWebEngineProfile(qt)          # perfil propio y sin disco
    pagina = QWebEnginePage(perfil, qt)
    visto = {}

    def al_pedir(dl):
        visto["dl"] = dl
        manejador(v, dl)
        # Se mira apenas decide el manejador. Si la acepto se corta aca:
        # completarla llevaria a registrar la evidencia con acta y perito, que
        # no es lo que se prueba y necesitaria un caso completo.
        visto["estado"] = dl.state().name
        if dl.state() == QWebEngineDownloadRequest.DownloadState.DownloadInProgress:
            dl.cancel()
        QTimer.singleShot(1500, qt.quit)

    perfil.downloadRequested.connect(al_pedir)
    pagina.setHtml(PAGINA, QUrl("https://sitio-cualquiera.test/"))
    QTimer.singleShot(8000, qt.quit)
    qt.exec()
    dl = visto.get("dl")
    archivos = [p.name for p in caso.dirs["evidence_raw"].glob("*") if p.is_file()]
    return {"pregunto": bool(preguntas), "llego": dl is not None, "archivos": archivos,
            "estado": visto.get("estado"), "log": caso.lineas}


print("archivo probado: %s\n" % os.path.basename(RUTA))
print("1. La pagina descarga sola y el perito rechaza")
r = correr("rechazada", lambda v: None, QMessageBox.StandardButton.No)
debe(r["llego"], "la pagina efectivamente inicio la descarga sin clic")
debe(r["pregunto"], "el programa pregunto antes de aceptarla")
debe(not r["archivos"], "no quedo ningun archivo en la evidencia (%s)" % (r["archivos"] or "vacio"))
debe(any("rechazada por el perito" in m and "origen: data:" in m for _, _, m in r["log"]),
     "el rechazo quedo en el log con su origen")

print("\n2. La pagina descarga sola y el perito acepta")
r = correr("aceptada", lambda v: None, QMessageBox.StandardButton.Yes)
debe(r["pregunto"] and r["estado"] in ("DownloadInProgress", "DownloadCompleted"),
     "pregunto y, con la aceptacion, el programa la acepto (%s)" % r["estado"])
debe(any("aceptada por el perito" in m for _, _, m in r["log"]),
     "la aceptacion quedo en el log")

print("\n3. Descargas que pide el propio programa")
r = correr("whatsapp", lambda v: setattr(v, "_wa", {"activo": True}),
           QMessageBox.StandardButton.No)
debe(not r["pregunto"] and r["estado"] in ("DownloadInProgress", "DownloadCompleted"),
     "durante el recorrido de WhatsApp no pregunta (%s)" % r["estado"])
r = correr("avisada", lambda v: setattr(v, "_pagina_pendiente",
                                        {"nombre": "Pagina_prueba.mhtml", "url": "x"}),
           QMessageBox.StandardButton.No)
debe(not r["pregunto"], "una descarga avisada por el programa no pregunta")

print()
print("RESULTADO: %s" % ("correcto" if not fallas else "%d FALLAS" % fallas))
sys.exit(0 if not fallas else 1)
