# -*- coding: utf-8 -*-
"""
Prueba funcional de la verificacion de Binary Transparency tal como quedo
implementada en navegador_forense_pro_v1_0.py:
  - usa el MISMO _BT_MANIFEST_JS del archivo de produccion
  - usa el MISMO endpoint y la misma logica de contraste
  - valida ademas el caso negativo (deteccion de codigo alterado)
"""
import json
import os
import re
import sys

import requests
from PyQt6.QtCore import QUrl, QTimer
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEnginePage, QWebEngineSettings,
)

FUENTE = r"C:\navegadorforense\navegador_forense_pro_v1_0.py"
src = open(FUENTE, encoding="utf-8").read()
JS = re.search(r'_BT_MANIFEST_JS = r"""(.*?)"""', src, re.S).group(1)
CF_API = re.search(r'_BT_CF_API = "([^"]+)"', src).group(1)
ORIGENES = re.findall(r'"([\w.]+)":\s*"[\w.]+",', src[src.index("_BT_ORIGENES = {"):
                                                     src.index("_BT_CF_API")])
print(f"JS extraido del archivo de produccion: {len(JS)} chars")
print(f"Endpoint: {CF_API}")
print(f"Origenes configurados: {ORIGENES}\n")


def contrastar(dominio, version, combinado):
    """Replica exacta de la logica de _contrastar_bt."""
    out = {"dominio": dominio, "version": version, "hash_pagina": combinado}
    r = requests.get(f"{CF_API}/{dominio}/{version}", timeout=20, verify=True)
    out["http_status"] = r.status_code
    if r.status_code == 200:
        raiz = str((r.json() or {}).get("root_hash") or "")
        out["hash_cloudflare"] = raiz
        out["resultado"] = ("VERIFICADO"
                            if raiz.strip().lower() == combinado.strip().lower()
                            else "DISCREPANCIA")
    else:
        out["hash_cloudflare"] = ""
        out["resultado"] = "NO_DISPONIBLE"
    return out


class Test:
    def __init__(self, app):
        self.app = app
        self.res = None

    def correr(self):
        print("[..] Cargando web.whatsapp.com con el motor de la herramienta...")
        self.profile = QWebEngineProfile(self.app)
        self.profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
        self.page = QWebEnginePage(self.profile, self.app)
        self.page.settings().setAttribute(
            QWebEngineSettings.WebAttribute.AutoLoadImages, False)
        self.page.loadFinished.connect(
            lambda ok: QTimer.singleShot(4500, lambda: self.page.runJavaScript(JS, self.leer))
            if ok else self.fin({"error": "no cargo"}))
        QTimer.singleShot(40000, lambda: self.fin({"error": "timeout"}))
        self.page.setUrl(QUrl("https://web.whatsapp.com/"))

    def leer(self, r):
        try:
            self.fin(json.loads(r) if r else {"error": "sin respuesta"})
        except Exception as e:
            self.fin({"error": str(e)})

    def fin(self, d):
        if self.res is not None:
            return
        self.res = d
        print("\n" + "=" * 66)
        print("  PRUEBA FUNCIONAL — Verificacion de integridad del codigo")
        print("=" * 66)
        if d.get("error"):
            print(f"  ERROR: {d['error']}")
            self.app.quit(); return
        print(f"  Manifiesto presente en la pagina : {d.get('presente')}")
        if not d.get("presente"):
            print("  (el portal no publica manifiesto)")
            self.app.quit(); return
        print(f"  Version del codigo               : {d.get('version')}")
        print(f"  Scripts declarados               : {d.get('cant_scripts'):,}")
        print(f"  Hash combinado (pagina)          : {d.get('combined_hash')}")
        print(f"  Hashes parciales                 : "
              f"{list((d.get('hashes_parciales') or {}).keys())}")

        print("\n  --- CASO REAL (codigo intacto) ---")
        ok = contrastar("whatsapp.com", d["version"], d["combined_hash"])
        print(f"  HTTP Cloudflare                  : {ok['http_status']}")
        print(f"  Hash raiz (Cloudflare)           : {ok.get('hash_cloudflare')}")
        print(f"  >>> RESULTADO                    : {ok['resultado']}")

        print("\n  --- CASO NEGATIVO (simula codigo alterado) ---")
        alterado = "0" * 64
        mal = contrastar("whatsapp.com", d["version"], alterado)
        print(f"  Hash falseado                    : {alterado[:32]}...")
        print(f"  >>> RESULTADO                    : {mal['resultado']}")

        print("\n" + "-" * 66)
        exito = (ok["resultado"] == "VERIFICADO" and mal["resultado"] == "DISCREPANCIA")
        print(f"  {'PRUEBA SUPERADA' if exito else 'PRUEBA FALLIDA'}: detecta correctamente "
              f"el codigo intacto y el alterado.")
        print("-" * 66)
        self.app.quit()


def main():
    os.environ.setdefault("QT_LOGGING_RULES", "qt.webengine*=false;qt.network.ssl=false")
    app = QApplication(sys.argv)
    t = Test(app)
    QTimer.singleShot(0, t.correr)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
