# -*- coding: utf-8 -*-
"""
Comprueba que el recorrido espere a que la vista termine de cargar antes de
fotografiarla.

La pagina imita lo que hace Facebook: al desplazarse aparecen bloques grises
con un brillo animado —los marcadores de carga— y recien un rato despues se
reemplazan por las tarjetas de verdad. Capturar en ese intervalo deja la imagen
con franjas en blanco, que es lo que se reporto.

Se verifica lo que importa:
  1. que mientras haya marcadores el lector diga cargando
  2. que no queden marcadores a la vista en el momento de capturar
  3. que si los marcadores no se van nunca, se capture igual y quede constancia
"""
import json
import os
import sys

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--enable-features=SharedArrayBuffer")

from PyQt6.QtCore import QPoint, QPointF, Qt, QTimer, QUrl
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView

sys.path.insert(0, r"C:\navegadorforense")
import navegador_forense_pro_v1_0 as _app          # noqa: E402

LISTA_JS = _app._LISTA_JS

# Con ETERNO=1 los marcadores no se resuelven nunca: es el caso de la pagina
# que deja de responder, donde esperar sin limite colgaria el relevamiento.
ETERNO = os.environ.get("ETERNO") == "1"

PAGINA = """
<html><head><style>
@keyframes brillo { 0%% {opacity:.5} 100%% {opacity:1} }
.esqueleto { background:#e2e5e9; border-radius:8px; animation: brillo 1s infinite alternate; }
</style></head>
<body style="margin:0;font-family:sans-serif">
  <div><div><img src="data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==" width="40">
       <a href="/stories/create/">Agregar a historia</a></div></div>
  <h2>Amigos</h2>
  <div id="grilla"></div>
  <div id="esqueletos"></div>
  <div style="height:400px"></div>
<script>
var PIX='data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==';
var cargados=0, TOTAL=40, LOTE=8, ocupado=false, ETERNO=%s;
function tarjeta(n){
  var d=document.createElement('div'); d.style.height='110px';
  d.innerHTML='<img src="'+PIX+'" width="80" height="80">'+
    '<a href="https://www.facebook.com/amigo.numero'+n+'">Amigo Numero '+n+'</a>';
  return d;
}
function esqueletos(n){
  var c=document.getElementById('esqueletos'); c.innerHTML='';
  for(var i=0;i<n;i++){
    var d=document.createElement('div');
    d.className='esqueleto'; d.style.height='100px'; d.style.margin='6px';
    c.appendChild(d);
  }
}
function lote(){
  if(ocupado||cargados>=TOTAL) return;
  ocupado=true;
  esqueletos(4);                       // primero los marcadores
  setTimeout(function(){
    // Con ETERNO el primer lote si llega —hay algo que leer— y de ahi en mas
    // los marcadores quedan girando sin que aparezcan tarjetas nuevas, que es
    // lo que se ve cuando la pagina deja de responder.
    if(ETERNO && cargados > 0){ ocupado=false; return; }
    var g=document.getElementById('grilla');
    for(var i=0;i<LOTE&&cargados<TOTAL;i++){ cargados++; g.appendChild(tarjeta(cargados)); }
    esqueletos(0);
    ocupado=false;
  }, 1400);
}
lote();
addEventListener('scroll', function(){
  if(scrollY+innerHeight > document.body.scrollHeight-400) lote();
});
</script></body></html>
""" % ("true" if ETERNO else "false")


class Prueba:
    def __init__(self):
        self.view = QWebEngineView()
        self.view.resize(1200, 800)
        self.view.setHtml(PAGINA, QUrl("https://www.facebook.com/perfil/friends"))
        self.view.show()
        self.n = 0
        self.esperas = 0
        self.capturas_limpias = 0
        self.capturas_sucias = 0
        self.sin_avance = 0
        self.previo = None
        QTimer.singleShot(2500, self.vuelta)

    def vuelta(self):
        if self.n >= 30 or self.sin_avance >= 5:
            self.informe()
            return
        self.n += 1
        self.view.page().runJavaScript(LISTA_JS, self.leido)

    def leido(self, res):
        d = json.loads(res) if res else {}
        if d.get("error"):
            print("  ERROR: %s" % d["error"])
            QApplication.quit()
            return

        marcadores = d.get("marcadores", 0)
        # Mismo criterio que el programa: se espera hasta cinco veces.
        if d.get("cargando") and self.esperas < 5:
            self.esperas += 1
            print("  tramo %-3d esperando (%d/5)  marcadores=%d"
                  % (self.n, self.esperas, marcadores))
            self.n -= 1
            QTimer.singleShot(900, self.vuelta)
            return

        if d.get("cargando"):
            self.capturas_sucias += 1
            print("  tramo %-3d CAPTURA CON CARGA A LA VISTA  marcadores=%d" % (self.n, marcadores))
        else:
            self.capturas_limpias += 1
            print("  tramo %-3d captura limpia  total=%-3d marcadores=%d"
                  % (self.n, d.get("total"), marcadores))
        self.esperas = 0

        pos = d.get("pos", 0)
        movio = self.previo is None or pos != self.previo
        self.previo = pos
        self.sin_avance = 0 if (d.get("nuevos") or movio) else self.sin_avance + 1

        self.rueda(d.get("centro_x", 0), d.get("centro_y", 0))
        QTimer.singleShot(600, self.vuelta)

    def rueda(self, x, y):
        destino = self.view.focusProxy()
        if destino is None or x <= 0:
            return
        local = QPointF(float(x), float(y))
        glob = QPointF(self.view.mapToGlobal(local.toPoint()))
        QApplication.postEvent(destino, QWheelEvent(
            local, glob, QPoint(0, -120), QPoint(0, -360),
            Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
            Qt.ScrollPhase.NoScrollPhase, False))

    def informe(self):
        print()
        print("  capturas limpias                 : %d" % self.capturas_limpias)
        print("  capturas con carga a la vista    : %d" % self.capturas_sucias)
        print()
        if ETERNO:
            ok = self.capturas_sucias > 0
            print("RESULTADO: %s" % (
                "correcto - no se cuelga y deja constancia" if ok
                else "HAY UN PROBLEMA - no capturo nunca"))
        else:
            ok = self.capturas_limpias > 0 and self.capturas_sucias == 0
            print("RESULTADO: %s" % (
                "correcto - nunca capturo sobre marcadores de carga" if ok
                else "HAY UN PROBLEMA - capturo con la vista a medio cargar"))
        QApplication.quit()


app = QApplication(sys.argv)
print("Recorriendo con marcadores de carga%s..." % (" QUE NUNCA SE VAN" if ETERNO else ""))
p = Prueba()
sys.exit(app.exec())
