# -*- coding: utf-8 -*-
"""
Prueba de punta a punta del recorrido de la lista de amigos, con el _LISTA_JS
extraido del programa y la rueda entregada como la entrega _ig_rueda.

La pagina es una reproduccion local de la estructura MEDIDA contra la lista de
amigos real: tarjetas con una sola foto y el enlace del perfil, todas bajo un
mismo contenedor, mas los elementos del encabezado que tienen la misma forma y
que el lector debe descartar. Carga mas amigos al acercarse al fondo, como hace
Facebook.

ATENCION: esta prueba fallo una vez de cada varias corridas, con el
desplazamiento detenido a partir del tercer tramo —el mismo sintoma que se
reporto una vez en uso real—. Tres corridas seguidas despues dieron 60 de 60.
Si vuelve a fallar, no descartarlo como azar de la prueba: mirar la columna
pos, que es donde se ve si la rueda dejo de llegar.

Lo que se prueba aca es el motor —descartar el encabezado, acumular sin
repetir, desplazar y traer el lote siguiente—, no los anclajes, que se midieron
aparte contra el sitio.
"""
import io
import json
import os
import re
import sys

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--enable-features=SharedArrayBuffer")

from PyQt6.QtCore import QPoint, QPointF, Qt, QTimer, QUrl
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView

# El JS se toma del modulo y no se recorta del archivo con una expresion
# regular: asi la prueba corre exactamente lo que corre el programa, incluida
# la parte que se inyecta al construir la constante.
sys.path.insert(0, r"C:\navegadorforense")
os.environ.setdefault("QT_QPA_PLATFORM_HINT", "")
import navegador_forense_pro_v1_0 as _app        # noqa: E402
LISTA_JS = _app._LISTA_JS
FINAL_JS = _app._LISTA_FINAL_JS

TOTAL_AMIGOS = 60
POR_LOTE = int(__import__('os').environ.get('LOTE', '8'))

PAGINA = """
<html><body style="margin:0;font-family:sans-serif">
  <!-- Encabezado: misma forma que una tarjeta (una foto + un enlace con texto)
       pero cada uno bajo su propio contenedor. El lector debe descartarlos. -->
  <div><div><img src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" width="40">
       <a href="/stories/create/">Agregar a historia</a></div></div>
  <div><div><img src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" width="40">
       <a href="/profile.php">Editar perfil</a></div></div>
  <div><div><img src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" width="40">
       <a href="/UniversidadFASTA">Universidad FASTA</a></div></div>

  <h2>Amigos</h2>
  <div id="grilla"></div>
  <div style="height:400px"></div>

<script>
var PIX = 'data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';
var cargados = 0, TOTAL = %d, LOTE = %d, cargando = false;
function lote() {
  if (cargando || cargados >= TOTAL) return;
  cargando = true;
  setTimeout(function () {
    var g = document.getElementById('grilla');
    for (var i = 0; i < LOTE && cargados < TOTAL; i++) {
      cargados++;
      var d = document.createElement('div');
      d.style.height = '110px';
      d.innerHTML = '<img src="' + PIX + '" width="80" height="80">' +
        '<a href="https://www.facebook.com/amigo.numero' + cargados + '">Amigo Numero ' +
        cargados + '</a><div>' + (cargados %% 30) + ' amigos en comun</div>';
      g.appendChild(d);
    }
    cargando = false;
  }, 350);
}
lote();
window.addEventListener('scroll', function () {
  if (window.scrollY + window.innerHeight > document.body.scrollHeight - 500) lote();
});
</script>
</body></html>
""" % (TOTAL_AMIGOS, POR_LOTE)


class Prueba:
    def __init__(self):
        self.view = QWebEngineView()
        self.view.resize(1200, 800)
        self.view.setHtml(PAGINA, QUrl("https://www.facebook.com/perfil.de.ejemplo/friends"))
        self.view.show()
        self.n = 0
        self.previo = None
        self.sin_avance = 0
        QTimer.singleShot(1800, self.vuelta)

    def vuelta(self):
        if self.n >= 40 or self.sin_avance >= 6:
            self.view.page().runJavaScript(FINAL_JS, self.final)
            return
        self.n += 1
        self.view.page().runJavaScript(LISTA_JS, self.leido)

    def leido(self, res):
        try:
            d = json.loads(res) if res else {}
        except Exception as e:
            print("  no se pudo leer: %s | %r" % (e, str(res)[:120]))
            QApplication.quit()
            return
        if d.get("error"):
            print("  ERROR: %s" % d["error"])
            QApplication.quit()
            return

        nuevos = int(d.get("nuevos", 0))
        pos = d.get("pos", 0)
        movio = self.previo is None or pos != self.previo
        self.previo = pos
        if not hasattr(self, "capturas"): self.capturas = 0
        if self.n == 1 or movio: self.capturas += 1
        self.sin_avance = 0 if (nuevos or movio) else self.sin_avance + 1
        if self.n <= 3 or nuevos:
            print("  tramo %-3d nuevas=%-3d total=%-3d  panel=%-9s %s/%s  rect=%sx%s centro=(%s,%s) fuera=%s"
                  % (self.n, nuevos, d.get("total"),
                     "propio" if d.get("propio") else "pagina",
                     d.get("pos"), max((d.get("alto", 0) - d.get("visible", 0)), 0),
                     d.get("rect", {}).get("w"), d.get("rect", {}).get("h"),
                     d.get("centro_x"), d.get("centro_y"), d.get("fuera_de_vista")))
        self.rueda(d.get("centro_x", 0), d.get("centro_y", 0))
        QTimer.singleShot(600, self.vuelta)

    def rueda(self, x, y):
        destino = self.view.focusProxy()
        if destino is None or x <= 0:
            return
        local = QPointF(float(x), float(y))
        glob = QPointF(self.view.mapToGlobal(local.toPoint()))
        ev = QWheelEvent(local, glob, QPoint(0, -120), QPoint(0, -360),
                         Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
                         Qt.ScrollPhase.NoScrollPhase, False)
        QApplication.postEvent(destino, ev)

    def final(self, res):
        d = json.loads(res) if res else {}
        orden = d.get("orden") or []
        ids = [c.get("id", "") for c in orden]
        nombres = [c.get("nombre", "") for c in orden]
        print()
        print("  sitio declarado : %s" % d.get("sitio"))
        print("  cuentas         : %d de %d" % (len(orden), TOTAL_AMIGOS))
        print("  capturas         : %d  (una por vista distinta)" % getattr(self, "capturas", 0))
        print("  primera         : %s | %s" % (ids[0] if ids else "-", nombres[0] if nombres else "-"))
        print("  ultima          : %s | %s" % (ids[-1] if ids else "-", nombres[-1] if nombres else "-"))

        intrusos = [i for i in ids if not i.startswith("amigo.numero")]
        repetidos = len(ids) - len(set(ids))
        faltan = [k for k in range(1, TOTAL_AMIGOS + 1)
                  if ("amigo.numero%d" % k) not in ids]
        print()
        print("  del encabezado colados : %s" % (intrusos or "ninguno"))
        print("  repetidos              : %d" % repetidos)
        print("  sin registrar          : %s" % (faltan if faltan else "ninguno"))
        ok = (not intrusos) and repetidos == 0 and not faltan
        print()
        print("RESULTADO: %s" % ("correcto" if ok else "HAY UN PROBLEMA"))
        QApplication.quit()


app = QApplication(sys.argv)
print("Recorriendo una lista de %d amigos que llega de a %d..." % (TOTAL_AMIGOS, POR_LOTE))
p = Prueba()
sys.exit(app.exec())
