# -*- coding: utf-8 -*-
"""
¿Instagram publica el manifiesto de Binary Transparency mas tarde?

En vez de mirar una sola vez, SONDEA la pagina cada segundo durante 45 s,
con y sin sesion, y en varias rutas. Asi se descarta que el resultado
negativo se deba a haber medido demasiado pronto.
"""
import json
import os
import sys

from PyQt6.QtCore import QUrl, QTimer
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage, QWebEngineSettings,
)
from PyQt6.QtNetwork import QNetworkCookie

COOKIES_IG = r"C:\navegadorforense\session_cookies.json"
SONDEO_MS = 1000
MAX_SEG = 45

CASOS = [
    ("instagram.com  (sin sesion)",  "https://www.instagram.com/",          False),
    ("instagram.com  (con sesion)",  "https://www.instagram.com/",          True),
    ("instagram.com/direct (sesion)", "https://www.instagram.com/direct/inbox/", True),
    ("--- control: whatsapp ---",    "https://web.whatsapp.com/",           False),
]

JS = r"""
(function () {
    var el = document.getElementById('binary-transparency-manifest')
          || document.querySelector('[name="binary-transparency-manifest"]');
    var html = document.documentElement.innerHTML;
    return JSON.stringify({
        presente: !!el,
        rev: el ? el.getAttribute('data-manifest-rev') : null,
        menciona: html.indexOf('binary-transparency') !== -1,
        scripts: document.querySelectorAll('script[src]').length,
        html_len: html.length,
        ready: document.readyState,
        logueado: /"USER_ID"\s*:\s*"[1-9]\d+"/.test(html)
    });
})()
"""


def inyectar_cookies(profile):
    if not os.path.exists(COOKIES_IG):
        return 0
    try:
        datos = json.load(open(COOKIES_IG, encoding="utf-8"))
    except Exception:
        return 0
    store = profile.cookieStore()
    n = 0
    for c in datos if isinstance(datos, list) else []:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        if "instagram.com" not in c.get("domain", ""):
            continue
        ck = QNetworkCookie(str(c["name"]).encode(), str(c.get("value", "")).encode())
        ck.setDomain(c.get("domain", ".instagram.com"))
        ck.setPath(c.get("path", "/"))
        ck.setSecure(True)
        store.setCookie(ck, QUrl("https://instagram.com"))
        n += 1
    return n


class Sonda:
    def __init__(self, app):
        self.app = app
        self.pend = list(CASOS)
        self.res = []

    def sig(self):
        if not self.pend:
            self.informe()
            return
        self.nombre, url, con_ck = self.pend.pop(0)
        self.seg = 0
        self.hallado = None
        self.ultimo = {}
        print(f"\n[..] {self.nombre}")
        self.profile = QWebEngineProfile(self.app)
        self.profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
        if con_ck:
            n = inyectar_cookies(self.profile)
            print(f"     cookies inyectadas: {n}")
        self.page = QWebEnginePage(self.profile, self.app)
        self.page.settings().setAttribute(
            QWebEngineSettings.WebAttribute.AutoLoadImages, False)
        self.page.loadFinished.connect(self.arrancar_sondeo)
        self.page.setUrl(QUrl(url))
        # Corte duro por si loadFinished nunca llega
        QTimer.singleShot((MAX_SEG + 10) * 1000, self.cerrar)

    def arrancar_sondeo(self, ok):
        if not ok:
            print("     (no cargo)")
            self.cerrar()
            return
        self.timer = QTimer()
        self.timer.timeout.connect(self.sondear)
        self.timer.start(SONDEO_MS)

    def sondear(self):
        self.seg += 1
        if self.seg > MAX_SEG:
            self.cerrar()
            return
        self.page.runJavaScript(JS, self.leer)

    def leer(self, r):
        try:
            d = json.loads(r) if r else {}
        except Exception:
            return
        self.ultimo = d
        if d.get("presente") and self.hallado is None:
            self.hallado = self.seg
            print(f"     >>> MANIFIESTO APARECIO a los {self.seg} s "
                  f"(rev={d.get('rev')})")
            self.cerrar()
            return
        if self.seg in (5, 15, 30, 45):
            print(f"     t={self.seg:2d}s  presente={d.get('presente')} "
                  f"menciona={d.get('menciona')} scripts={d.get('scripts')} "
                  f"logueado={d.get('logueado')} html={d.get('html_len')}")

    def cerrar(self):
        if any(x[0] == self.nombre for x in self.res):
            return
        try:
            if hasattr(self, "timer"):
                self.timer.stop()
        except Exception:
            pass
        self.res.append((self.nombre, self.hallado, dict(self.ultimo)))
        QTimer.singleShot(400, self.sig)

    def informe(self):
        print("\n" + "=" * 70)
        print("  ¿Instagram publica el manifiesto si se espera mas tiempo?")
        print("=" * 70)
        for nombre, hallado, ult in self.res:
            estado = (f"SI — aparecio a los {hallado} s" if hallado
                      else f"NO — tras {MAX_SEG} s de sondeo continuo")
            print(f"\n  {nombre}")
            print(f"    Manifiesto: {estado}")
            if ult:
                print(f"    Ultimo estado: scripts={ult.get('scripts')} "
                      f"logueado={ult.get('logueado')} "
                      f"menciona_binary_transparency={ult.get('menciona')}")
        print("\n" + "=" * 70)
        self.app.quit()


def main():
    os.environ.setdefault("QT_LOGGING_RULES", "qt.webengine*=false;qt.network.ssl=false")
    app = QApplication(sys.argv)
    s = Sonda(app)
    QTimer.singleShot(0, s.sig)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
