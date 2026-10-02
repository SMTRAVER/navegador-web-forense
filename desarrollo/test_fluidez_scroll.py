# -*- coding: utf-8 -*-
"""
Mide si el scroll se traba, y si la causa es el interceptor de red.

Se carga la misma pagina dos veces y se la desplaza con la rueda mientras la
propia pagina mide el tiempo entre cuadros:

  A) sin interceptor
  B) con el interceptor que usa el programa (firma y anota cada peticion)

Por que el interceptor puede trabar el scroll: Qt lo llama desde el hilo de
red, pero al estar escrito en Python necesita tomar el GIL. Mientras el hilo
principal dibuja, cada peticion queda esperando. Al desplazar, Instagram y
Facebook piden imagenes de forma continua, asi que son decenas de esperas por
segundo justo cuando hace falta fluidez.

Un cuadro por encima de 33 ms se ve como un tiron.
"""
import os
import sys
import time

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS",
                      "--enable-features=SharedArrayBuffer "
                      "--enable-blink-features=SharedArrayBuffer")

from PyQt6.QtCore import QPoint, QPointF, Qt, QTimer, QUrl
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (QWebEngineProfile, QWebEnginePage,
                                   QWebEngineUrlRequestInterceptor)

URL = sys.argv[1] if len(sys.argv) > 1 else "https://www.instagram.com/instagram/"

MEDIR_JS = """
(function(){
  window.__frames = [];
  var t = performance.now();
  function paso(ahora){
    window.__frames.push(ahora - t);
    t = ahora;
    if (window.__frames.length < 600) requestAnimationFrame(paso);
  }
  requestAnimationFrame(paso);
  return 'midiendo';
})()
"""

LEER_JS = """
(function(){
  var f = (window.__frames || []).slice(5);   // los primeros son ruido
  if (!f.length) return JSON.stringify({n:0});
  var orden = f.slice().sort(function(a,b){return a-b;});
  var tirones = f.filter(function(x){ return x > 33; }).length;
  return JSON.stringify({
    n: f.length,
    mediana: Math.round(orden[Math.floor(orden.length/2)]),
    p95: Math.round(orden[Math.floor(orden.length*0.95)]),
    peor: Math.round(orden[orden.length-1]),
    tirones: tirones,
    pct_tirones: Math.round(tirones*100/f.length)
  });
})()
"""


class Interceptor(QWebEngineUrlRequestInterceptor):
    """Lo mismo que hace el del programa por cada peticion."""
    def __init__(self):
        super().__init__()
        import hashlib, hmac, threading, datetime
        self._h, self._hm, self._dt = hashlib, hmac, datetime
        self.clave = os.urandom(32)
        self.lock = threading.Lock()
        self.buffer, self.har, self.n = [], [], 0

    def interceptRequest(self, info):
        url = info.requestUrl().toString()
        ts = self._dt.datetime.now().isoformat()
        firma = self._hm.new(self.clave,
                             ("%s|INFO|NETWORK|GET %s" % (ts, url)).encode("utf-8"),
                             self._h.sha256).hexdigest()
        entrada = {"startedDateTime": ts, "time": 0,
                   "request": {"method": "GET", "url": url, "httpVersion": "HTTP/1.1",
                               "cookies": [], "headers": [], "queryString": [],
                               "headersSize": -1, "bodySize": -1},
                   "response": {"status": 0, "content": {"size": 0, "mimeType": "x-unknown"}},
                   "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0}}
        with self.lock:
            self.buffer.append((ts, "INFO", "NETWORK", url, firma))
            self.har.append(entrada)
            self.n += 1


resultados = []


class Corrida:
    def __init__(self, nombre, con_interceptor, seguir):
        self.nombre, self.seguir = nombre, seguir
        perfil = QWebEngineProfile("fluidez_%s" % nombre.replace(" ", "_"), None)
        self.inter = None
        if con_interceptor:
            self.inter = Interceptor()
            perfil.setUrlRequestInterceptor(self.inter)
        self.view = QWebEngineView()
        self.view.setPage(QWebEnginePage(perfil, self.view))
        self.view.resize(1400, 900)
        self.view.show()
        self.perfil = perfil
        self.view.loadFinished.connect(self.cargado)
        self.view.load(QUrl(URL))
        self.vueltas = 0

    def cargado(self, ok):
        QTimer.singleShot(2500, self.empezar)

    def empezar(self):
        self.view.page().runJavaScript(MEDIR_JS, lambda _: self.rueda())

    def rueda(self):
        self.vueltas += 1
        destino = self.view.focusProxy()
        if destino is not None:
            for _ in range(2):
                pos = QPointF(700.0, 450.0)
                glob = QPointF(self.view.mapToGlobal(pos.toPoint()))
                QApplication.postEvent(destino, QWheelEvent(
                    pos, glob, QPoint(0, -120), QPoint(0, -360),
                    Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
                    Qt.ScrollPhase.NoScrollPhase, False))
        if self.vueltas < 25:
            QTimer.singleShot(180, self.rueda)
        else:
            QTimer.singleShot(1200, self.medir)

    def medir(self):
        self.view.page().runJavaScript(LEER_JS, self.listo)

    def listo(self, r):
        import json
        d = json.loads(r) if r else {}
        d["peticiones"] = self.inter.n if self.inter else 0
        resultados.append((self.nombre, d))
        print("  %-22s mediana %3s ms | p95 %3s ms | peor %4s ms | tirones %3s (%s%%) | peticiones %s"
              % (self.nombre, d.get("mediana"), d.get("p95"), d.get("peor"),
                 d.get("tirones"), d.get("pct_tirones"), d["peticiones"]))
        self.view.setParent(None)
        QTimer.singleShot(800, self.seguir)


def paso_a():
    globals()["_a"] = Corrida("SIN interceptor", False, paso_b)


def paso_b():
    globals()["_b"] = Corrida("CON interceptor", True, informe)


def informe():
    print()
    if len(resultados) >= 2:
        a, b = resultados[0][1], resultados[1][1]
        da = (b.get("tirones", 0) - a.get("tirones", 0))
        print("  diferencia en tirones: %+d" % da)
        if a.get("mediana") and b.get("mediana"):
            print("  diferencia en mediana: %+d ms" % (b["mediana"] - a["mediana"]))
        print()
        if da > 5:
            print("CONCLUSION: el interceptor traba el scroll")
        else:
            print("CONCLUSION: el interceptor NO explica los tirones")
    QApplication.quit()


app = QApplication(sys.argv)
print("Midiendo fluidez del scroll en %s\n" % URL)
QTimer.singleShot(300, paso_a)
sys.exit(app.exec())
