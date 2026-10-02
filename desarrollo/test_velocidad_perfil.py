# -*- coding: utf-8 -*-
"""
De donde sale la lentitud: se carga la MISMA pagina en dos navegadores y se
compara el tiempo.

  A) uno pelado, con el perfil que trae Qt por defecto
  B) uno configurado como el programa: perfil persistente por caso, cache en
     disco, interceptor de red que registra cada peticion

Si B tarda parecido a A, la configuracion no es la causa y hay que buscar
afuera del programa. Si B tarda bastante mas, la causa esta en lo que el
programa le agrega, y el detalle por peticion dice en que.
"""
import os
import sys
import time

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS",
                      "--enable-features=SharedArrayBuffer "
                      "--enable-blink-features=SharedArrayBuffer")

from PyQt6.QtCore import QTimer, QUrl
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (QWebEngineProfile, QWebEnginePage,
                                   QWebEngineUrlRequestInterceptor)

URL = sys.argv[1] if len(sys.argv) > 1 else "https://www.instagram.com/instagram/"
TMP = os.path.join(os.environ.get("TEMP", "."), "medir_velocidad")


class InterceptorComoElPrograma(QWebEngineUrlRequestInterceptor):
    """Hace por peticion lo mismo que el del programa: firmar y anotar."""
    def __init__(self):
        super().__init__()
        import hashlib, hmac, threading
        self.clave = os.urandom(32)
        self.buffer = []
        self.har = []
        self.lock = threading.Lock()
        self.n = 0
        self.tiempo = 0.0
        self._hmac = hmac
        self._hashlib = hashlib

    def interceptRequest(self, info):
        import datetime
        t0 = time.perf_counter()
        url = info.requestUrl().toString()
        ts = datetime.datetime.now().isoformat()
        firma = self._hmac.new(self.clave,
                               ("%s|INFO|NETWORK|GET %s" % (ts, url)).encode("utf-8"),
                               self._hashlib.sha256).hexdigest()
        entrada = {"startedDateTime": ts, "time": 0,
                   "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                               "cookies": [], "headers": [], "queryString": [],
                               "headersSize": -1, "bodySize": -1},
                   "response": {"status": 0, "statusText": "", "httpVersion": "HTTP/1.1",
                                "cookies": [], "headers": [],
                                "content": {"size": 0, "mimeType": "x-unknown"},
                                "redirectURL": "", "headersSize": -1, "bodySize": -1},
                   "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}
        with self.lock:
            self.buffer.append((ts, "INFO", "NETWORK", url, firma))
            self.har.append(entrada)
            self.n += 1
            self.tiempo += time.perf_counter() - t0


resultados = []


def medir(nombre, armar, seguir):
    view = armar()
    view.resize(1400, 900)
    view.show()
    t0 = time.perf_counter()

    def cargado(ok):
        tardo = time.perf_counter() - t0
        resultados.append((nombre, tardo, ok))
        print("  %-34s %6.2f s   %s" % (nombre, tardo, "" if ok else "(carga incompleta)"))
        view.setParent(None)
        QTimer.singleShot(600, seguir)

    view.loadFinished.connect(cargado)
    view.load(QUrl(URL))
    globals()["_vista_viva"] = view          # que no lo junte el recolector


def paso_pelado():
    medir("pelado (perfil de Qt)", lambda: QWebEngineView(), paso_programa)


def paso_programa():
    def armar():
        perfil = QWebEngineProfile("medicion", None)
        perfil.setPersistentStoragePath(TMP)
        perfil.setCachePath(os.path.join(TMP, "cache"))
        perfil.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
        perfil.setHttpCacheMaximumSize(512 * 1024 * 1024)
        perfil.setPersistentCookiesPolicy(
            QWebEngineProfile.PersistentCookiesPolicy.ForcePersistentCookies)
        v = QWebEngineView()
        v.setPage(QWebEnginePage(perfil, v))
        global INTER
        INTER = InterceptorComoElPrograma()
        perfil.setUrlRequestInterceptor(INTER)
        globals()["_perfil_vivo"] = perfil
        return v
    medir("como el programa", armar, informe)


def informe():
    print()
    if len(resultados) >= 2:
        a, b = resultados[0][1], resultados[1][1]
        print("  diferencia: %+.2f s  (%+.0f%%)" % (b - a, (b / a - 1) * 100 if a else 0))
    inter = globals().get("INTER")
    if inter and inter.n:
        print()
        print("  peticiones interceptadas : %d" % inter.n)
        print("  tiempo total en el interceptor: %.0f ms  (%.1f us por peticion)"
              % (inter.tiempo * 1000, inter.tiempo / inter.n * 1e6))
    print()
    print("Nota: la primera carga siempre paga la cache vacia. Correr dos veces")
    print("para separar el costo de la configuracion del de la cache fria.")
    QApplication.quit()


app = QApplication(sys.argv)
print("Cargando %s en los dos navegadores...\n" % URL)
QTimer.singleShot(200, paso_pelado)
sys.exit(app.exec())
