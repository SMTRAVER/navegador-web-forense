# -*- coding: utf-8 -*-
"""
Reproduce el fallo informado: relevar una publicacion, pasar a otra SIN
recargar el documento y volver a relevar. Antes el acumulador sobrevivia y la
segunda heredaba los comentarios de la primera.

Se hace sobre una pagina local que imita la estructura medida (bloques con
<time>, enlace de autor y el corazon de me gusta como boton sin texto con
icono), porque lo que se prueba aca es el acumulador y no los anclajes de
Instagram, que ya se midieron aparte contra el sitio real.
"""
import io
import json
import os
import re
import sys

os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--enable-features=SharedArrayBuffer")

from PyQt6.QtCore import QTimer, QUrl
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineWidgets import QWebEngineView

FUENTE = (sys.argv[1] if len(sys.argv) > 1
          else r"C:\navegadorforense\navegador_forense_pro_v1_0.py")
print("fuente del JS: %s" % FUENTE)
# El JS se toma del modulo indicado y no se recorta con una expresion regular:
# asi la prueba corre lo que corre el programa, incluida la parte que se
# inyecta al construir la constante. Con un respaldo como argumento se carga
# ese archivo, que es lo que permite comprobar que la prueba detecta el fallo.
import importlib.util as _iu                     # noqa: E402
_spec = _iu.spec_from_file_location("bajo_prueba", FUENTE)
_mod = _iu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
COM_JS = _mod._COM_JS
FINAL_JS = _mod._COM_FINAL_JS


def comentario(usuario, txt, fecha):
    return ('<div><div><a href="/%s/">%s</a></div>'
            '<div><span>%s</span></div>'
            '<div><time datetime="%s" title="fecha">1 sem</time>'
            '<div role="button"><svg></svg></div>'
            '<div role="button">Responder</div></div></div>'
            % (usuario, usuario, txt, fecha))


def pagina(titulo, usuarios):
    cs = "".join(comentario(u, "comentario de %s en %s" % (u, titulo),
                            "2026-01-0%dT10:00:00.000Z" % (i + 1))
                 for i, u in enumerate(usuarios))
    return ("<html><body style='margin:0'><h1>%s</h1>"
            "<div id='col'>%s</div></body></html>" % (titulo, cs))


PRIMERA = pagina("PRIMERA", ["ana", "beto", "carla"])
SEGUNDA = pagina("SEGUNDA", ["dario", "elsa"])


class Prueba:
    def __init__(self):
        self.view = QWebEngineView()
        self.view.resize(900, 700)
        self.view.show()
        self.paso = 0
        self.cargar(PRIMERA, "https://www.instagram.com/p/PRIMERA/")

    def cargar(self, html, url):
        self.view.setHtml(html, QUrl(url))
        QTimer.singleShot(1200, self.leer)

    def leer(self):
        self.view.page().runJavaScript(COM_JS, self.leido)

    def leido(self, res):
        d = json.loads(res)
        if "total" not in d:
            print("  RESPUESTA CRUDA: %s" % res)
        print("  lectura: total=%s nuevos=%s" % (d.get("total"), d.get("nuevos")))
        self.view.page().runJavaScript(FINAL_JS, self.acumulado)

    def acumulado(self, res):
        d = json.loads(res)
        autores = [c["autor"] for c in d.get("orden", [])]
        print("  acumulado: %s" % autores)
        print("  url declarada: %s" % d.get("url"))
        self.paso += 1
        if self.paso == 1:
            self.esperado1 = autores
            print("\n-- se pasa a la SEGUNDA publicacion sin recargar --")
            # Cambio de URL sin recargar, como hace el modal de Instagram
            self.view.page().runJavaScript(
                "history.pushState({}, '', '/p/SEGUNDA/');"
                "document.getElementById('col').innerHTML = %s;" % json.dumps(
                    re.search(r"<div id='col'>(.*)</div>", SEGUNDA, re.S).group(1)))
            QTimer.singleShot(900, self.leer)
        else:
            print()
            if autores == ["dario", "elsa"]:
                print("BIEN: la segunda publicacion trae solo sus comentarios")
            elif "ana" in autores:
                print("FALLA: arrastra los comentarios de la primera -> %s" % autores)
            else:
                print("RESULTADO INESPERADO: %s" % autores)
            QApplication.quit()


app = QApplication(sys.argv)
print("Relevando la PRIMERA publicacion...")
p = Prueba()
sys.exit(app.exec())
