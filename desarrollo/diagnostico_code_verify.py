# -*- coding: utf-8 -*-
"""
DIAGNOSTICO — ¿Publica Meta el manifiesto de Binary Transparency?

Responde una sola pregunta, de forma definitiva y con la sesion real del perito:
¿las paginas de Meta incluyen el elemento 'binary-transparency-manifest' que
necesita Code Verify para poder verificar el codigo de la pagina?

Usa el mismo motor (QtWebEngine) y las mismas cookies que el Navegador Web
Forense, de modo que el resultado refleja exactamente lo que veria la
herramienta durante una diligencia.

USO:  python diagnostico_code_verify.py
      (no modifica nada; solo consulta e imprime el resultado)
"""
import json
import os
import sys
from pathlib import Path

from PyQt6.QtCore import QUrl, QTimer
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage, QWebEngineSettings,
)
from PyQt6.QtNetwork import QNetworkCookie

BASE = Path(r"C:\navegadorforense")
COOKIES = {
    "instagram.com": BASE / "session_cookies.json",
    "facebook.com":  BASE / "cookie-facebook.json",
}
SITIOS = [
    ("Instagram",     "https://www.instagram.com/",  "instagram.com"),
    ("Facebook",      "https://www.facebook.com/",   "facebook.com"),
    ("WhatsApp Web",  "https://web.whatsapp.com/",   None),
]

# Comprueba la precondicion de Code Verify + datos de contexto.
JS = r"""
(function () {
    var el = document.getElementById('binary-transparency-manifest')
          || document.querySelector('[name="binary-transparency-manifest"]');
    var html = document.documentElement.innerHTML;
    var out = {
        manifiesto_presente: !!el,
        data_manifest_rev: el ? el.getAttribute('data-manifest-rev') : null,
        manifiesto_len: el ? (el.textContent || '').length : 0,
        menciona_binary_transparency: html.indexOf('binary-transparency') !== -1,
        scripts_con_src: document.querySelectorAll('script[src]').length,
        readyState: document.readyState,
        titulo: (document.title || '').slice(0, 60)
    };
    var mb = html.match(/btmanifest["']?\s*[:=]\s*["']?([\w.-]{3,40})/i);
    out.btmanifest = mb ? mb[1] : null;
    var mu = html.match(/"USER_ID"\s*:\s*"([1-9]\d+)"/);
    out.sesion_activa = !!mu;
    return JSON.stringify(out);
})()
"""


def cargar_cookies(profile: QWebEngineProfile, dominio: str) -> int:
    """Inyecta las cookies exportadas del dominio en el perfil del navegador."""
    ruta = COOKIES.get(dominio)
    if not ruta or not ruta.exists():
        return 0
    try:
        datos = json.load(open(ruta, encoding="utf-8"))
    except Exception:
        return 0
    store = profile.cookieStore()
    n = 0
    for c in datos if isinstance(datos, list) else []:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        if dominio not in c.get("domain", ""):
            continue
        ck = QNetworkCookie(str(c["name"]).encode(), str(c.get("value", "")).encode())
        ck.setDomain(c.get("domain", "." + dominio))
        ck.setPath(c.get("path", "/"))
        ck.setSecure(bool(c.get("secure", True)))
        store.setCookie(ck, QUrl("https://" + dominio))
        n += 1
    return n


class Diagnostico:
    def __init__(self, app):
        self.app = app
        self.pendientes = list(SITIOS)
        self.resultados = []
        self.profile = None
        self.page = None
        self.timeout = None

    def siguiente(self):
        if not self.pendientes:
            self.informe()
            return
        self.nombre, url, dom = self.pendientes.pop(0)
        print(f"[..] Cargando {self.nombre} ({url}) ...", flush=True)

        self.profile = QWebEngineProfile(self.app)
        self.profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
        n_ck = cargar_cookies(self.profile, dom) if dom else 0
        if n_ck:
            print(f"     cookies de sesion inyectadas: {n_ck}", flush=True)

        self.page = QWebEnginePage(self.profile, self.app)
        self.page.settings().setAttribute(
            QWebEngineSettings.WebAttribute.AutoLoadImages, False)
        self.page.loadFinished.connect(self.al_cargar)

        self.timeout = QTimer()
        self.timeout.setSingleShot(True)
        self.timeout.timeout.connect(lambda: self.registrar(
            {"error": "timeout de carga (30 s)"}))
        self.timeout.start(30000)

        self.page.setUrl(QUrl(url))

    def al_cargar(self, ok):
        if not ok:
            self.registrar({"error": "no se pudo cargar la pagina"})
            return
        # Dar margen a la SPA para inyectar su contenido
        QTimer.singleShot(4000, lambda: self.page.runJavaScript(JS, self.al_leer))

    def al_leer(self, res):
        try:
            self.registrar(json.loads(res) if res else {"error": "sin respuesta del script"})
        except Exception as e:
            self.registrar({"error": f"respuesta ilegible: {e}"})

    def registrar(self, datos):
        if self.timeout and self.timeout.isActive():
            self.timeout.stop()
        if any(r[0] == self.nombre for r in self.resultados):
            return
        self.resultados.append((self.nombre, datos))
        if "error" in datos:
            print(f"     -> {datos['error']}", flush=True)
        else:
            print(f"     -> manifiesto presente: {datos['manifiesto_presente']}"
                  f" | sesion activa: {datos.get('sesion_activa')}"
                  f" | scripts: {datos.get('scripts_con_src')}", flush=True)
        QTimer.singleShot(300, self.siguiente)

    def informe(self):
        print()
        print("=" * 68)
        print("  RESULTADO DEL DIAGNOSTICO — Binary Transparency (Code Verify)")
        print("=" * 68)
        alguno = False
        for nombre, d in self.resultados:
            print(f"\n  {nombre}")
            if "error" in d:
                print(f"    ERROR: {d['error']}")
                continue
            pres = d.get("manifiesto_presente")
            alguno = alguno or bool(pres)
            print(f"    Manifiesto 'binary-transparency-manifest' : "
                  f"{'SI  <-- VERIFICABLE' if pres else 'NO'}")
            print(f"    Menciona 'binary-transparency' en el HTML : "
                  f"{d.get('menciona_binary_transparency')}")
            if pres:
                print(f"    data-manifest-rev                         : {d.get('data_manifest_rev')}")
                print(f"    Tamano del manifiesto                     : {d.get('manifiesto_len')} chars")
            print(f"    Sesion activa detectada                   : {d.get('sesion_activa')}")
            print(f"    Version del bundle (btmanifest)           : {d.get('btmanifest')}")
            print(f"    Scripts con src cargados                  : {d.get('scripts_con_src')}")
        print()
        print("-" * 68)
        if alguno:
            print("  CONCLUSION: al menos un portal PUBLICA el manifiesto.")
            print("  => La verificacion de codigo (Opcion A) es VIABLE en esos sitios.")
        else:
            print("  CONCLUSION: ningun portal publica el manifiesto de transparencia.")
            print("  => Code Verify no tendria nada que verificar. La Opcion A NO es")
            print("     implementable hoy; conviene la Opcion B (preservar el inventario")
            print("     de scripts con su hash como constancia forense).")
        print("-" * 68)
        self.app.quit()


def main():
    os.environ.setdefault("QT_LOGGING_RULES", "qt.webengine*=false;qt.network.ssl=false")
    app = QApplication(sys.argv)
    print("\nDIAGNOSTICO Binary Transparency — Traverso Forensics")
    print("Consulta los portales de Meta con la sesion real del perito.\n")
    d = Diagnostico(app)
    QTimer.singleShot(0, d.siguiente)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
