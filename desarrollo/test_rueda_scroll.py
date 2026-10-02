# -*- coding: utf-8 -*-
"""
Prueba cual forma de entregar la rueda del mouse mueve de verdad un panel
desplazable dentro de QWebEngineView.

No usa Instagram: arma una pagina propia con un div que tiene scroll, aplica
cada variante y mide scrollTop antes y despues. Lo que funcione aca es lo que
hay que usar en el programa.
"""
import os
import sys

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--enable-features=SharedArrayBuffer")

from PyQt6.QtCore import QPoint, QPointF, Qt, QTimer, QUrl
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView

PAGINA = """
<html><body style="margin:0">
<div id="panel" style="position:absolute;left:200px;top:50px;width:300px;height:400px;
     overflow-y:scroll;border:2px solid red;background:#eee">
  <div style="height:4000px">%s</div>
</div>
</body></html>
""" % "".join("<p>renglon %d</p>" % i for i in range(200))


class Prueba:
    def __init__(self):
        self.view = QWebEngineView()
        self.view.resize(900, 700)
        self.view.setHtml(PAGINA, QUrl("https://local.test/"))
        self.view.show()
        self.resultados = []
        self.variantes = [
            ("postEvent NoScrollPhase (actual)", self.v_actual),
            ("sendEvent NoScrollPhase", self.v_send),
            ("postEvent ScrollUpdate", self.v_update),
            ("postEvent al view (no focusProxy)", self.v_view),
            ("postEvent x3 seguidos", self.v_triple),
        ]
        self.i = 0
        QTimer.singleShot(1500, self.siguiente)

    # ---------------------------------------------------------- variantes
    def _ev(self, x, y, fase=Qt.ScrollPhase.NoScrollPhase):
        local = QPointF(float(x), float(y))
        glob = QPointF(self.view.mapToGlobal(local.toPoint()))
        return QWheelEvent(local, glob, QPoint(0, -120), QPoint(0, -360),
                           Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
                           fase, False)

    def v_actual(self, x, y):
        QApplication.postEvent(self.view.focusProxy(), self._ev(x, y))

    def v_send(self, x, y):
        QApplication.sendEvent(self.view.focusProxy(), self._ev(x, y))

    def v_update(self, x, y):
        QApplication.postEvent(self.view.focusProxy(),
                               self._ev(x, y, Qt.ScrollPhase.ScrollUpdate))

    def v_view(self, x, y):
        QApplication.postEvent(self.view, self._ev(x, y))

    def v_triple(self, x, y):
        for _ in range(3):
            QApplication.postEvent(self.view.focusProxy(), self._ev(x, y))

    # ---------------------------------------------------------- recorrido
    def siguiente(self):
        if self.i >= len(self.variantes):
            self.informe()
            return
        self.nombre, self.fn = self.variantes[self.i]
        self.view.page().runJavaScript(
            "document.getElementById('panel').scrollTop = 0;"
            "var r = document.getElementById('panel').getBoundingClientRect();"
            "JSON.stringify({x: Math.round(r.left + r.width/2),"
            " y: Math.round(r.top + r.height/2)})", self.aplicar)

    def aplicar(self, res):
        import json
        d = json.loads(res)
        self.fn(d["x"], d["y"])
        QTimer.singleShot(700, self.medir)

    def medir(self):
        self.view.page().runJavaScript(
            "document.getElementById('panel').scrollTop", self.anotar)

    def anotar(self, pos):
        movio = (pos or 0) > 0
        self.resultados.append((self.nombre, pos, movio))
        print("  %-38s scrollTop=%-6s %s" % (self.nombre, pos,
                                             "SE MOVIO" if movio else "no se movio"))
        self.i += 1
        QTimer.singleShot(400, self.siguiente)

    def informe(self):
        print()
        buenas = [n for n, _, m in self.resultados if m]
        if buenas:
            print("FUNCIONAN: " + ", ".join(buenas))
        else:
            print("NINGUNA VARIANTE MOVIO EL PANEL")
        QApplication.quit()


app = QApplication(sys.argv)
print("Probando variantes de rueda sobre un panel desplazable...")
p = Prueba()
sys.exit(app.exec())
