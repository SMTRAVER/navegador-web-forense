#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAVERSO FORENSICS · NAVEGADOR WEB FORENSE v1.0
========================================
Navegador forense profesional para adquisicion y preservacion de evidencia
digital web conforme a ISO/IEC 27037:2012, SWGDE y NIST SP 800-86.

Autor del sistema: Miguel Angel Alfredo Traverso
Empresa: Traverso Forensics
Licencia: Codigo Abierto (Open Source)

DEPENDENCIAS:
    pip install PyQt6 PyQt6-WebEngine fpdf2 opencv-python pillow requests pyautogui
    pip install cryptography endesive asn1crypto ntplib

OPCIONALES:
    - ffmpeg (en PATH) para grabacion profesional
    - Certificado digital del perito en formato .p12 (pendrive/token)

DEPENDENCIAS ADICIONALES:
    pip install ntplib

"""

import sys
import os
import re

# Habilitar SharedArrayBuffer en el motor del navegador.
#
# WhatsApp Web entrega las imagenes como blob directo, pero los videos los
# descifra por partes en un worker, y ese camino necesita SharedArrayBuffer.
# QtWebEngine lo trae desactivado aunque las cabeceras de WhatsApp pidan el
# aislamiento de origen cruzado: se comprobo que sin este flag la propiedad
# SharedArrayBuffer no existe, y el resultado era que las fotos se adquirian
# y los videos no.
#
# Va antes de crear QApplication (de hecho antes de importar Qt) porque
# despues de eso el motor ya esta configurado y la variable se ignora. Se
# agrega a lo que hubiera, sin pisarlo.
#
# SharedArrayBuffer queda habilitado para todos los sitios, y eso tiene un
# costo: devuelve a las paginas un reloj de alta resolucion, que es la materia
# prima de los ataques de canal lateral tipo Spectre para leer memoria de otro
# sitio. La contencion es el aislamiento de sitios (cada sitio en un proceso
# propio, asi no hay memoria ajena que leer), y se fuerza con --site-per-process
# en lugar de confiar en el valor por defecto del motor, que Chromium relaja en
# algunos equipos. Las dos cosas quedan declaradas en el dictamen.
_flags_previas = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "")
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    f"{_flags_previas} --enable-features=SharedArrayBuffer "
    f"--enable-blink-features=SharedArrayBuffer --site-per-process"
).strip()

import io
import json
import hashlib
import datetime
import uuid
import threading
import sqlite3
import platform
import socket
import subprocess
import shutil
import signal
import base64
import time
import unicodedata
import warnings
import tempfile
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

# Librerías opcionales con detección en tiempo de ejecución 
try:
    import ntplib as _ntplib
    _HAS_NTPLIB = True
except ImportError:
    _HAS_NTPLIB = False


import cv2
import numpy as np
import pyautogui
from PIL import Image, ImageDraw, ImageFont
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget,
    QLineEdit, QPushButton, QTextEdit, QLabel, QDialog, QFormLayout,
    QFrame, QSplitter, QMessageBox, QFileDialog, QStatusBar,
    QComboBox, QGroupBox, QScrollArea, QTabWidget,
    QSlider, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile, QWebEngineUrlRequestInterceptor,
    QWebEngineDownloadRequest
)
from PyQt6.QtCore import QUrl, Qt, pyqtSignal, QObject, QThread, QTimer, QPointF, QPoint
from PyQt6.QtGui import QPixmap, QFont, QImage, QColor, QWheelEvent

def _has_qt_multimedia() -> bool:
    try:
        from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
        from PyQt6.QtMultimediaWidgets import QVideoWidget
        return True
    except ImportError:
        return False

# Suprimir InsecureRequestWarning solo para urllib3 (usado por requests).
# No usar warnings.filterwarnings global para no silenciar otros módulos.
try:
    import urllib3 as _urllib3
    _urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# Suprimir warnings verbosos de Qt en consola, se unifican TODAS las reglas aquí
# para evitar que un segundo setdefault() más abajo no tenga efecto (setdefault
# no sobreescribe un valor ya existente).

os.environ["QT_LOGGING_RULES"] = (
    "qt.multimedia.*=false;"       # decodificador AAC / media pipeline
    "qt.qpa.window=false;"         # SetProcessDpiAwarenessContext (DPI awareness)
    "qt.network.ssl=false;"        # TLS close_notify / handshake warnings
    "qt.network.tls=false;"        # "Failed to send close message"
    "qt.webengine*=false;"         # mensajes internos de Chromium/WebEngine
    "*.tls=false;"                 # cualquier módulo con categoría tls
    "*.ssl=false"                  # cualquier módulo con categoría ssl
)

# CONSTANTES DEL SOFTWARE 
SOFTWARE_INFO = {
    "software": "Traverso Forensics · Navegador Web Forense",
    "version": "v1.0",
    "norma": "ISO/IEC 27037:2012 / SWGDE / NIST SP 800-86",
}

AUTOR_SISTEMA = {
    "nombre": "Miguel Angel Alfredo Traverso",
    "titulo": "Especialista en Informatica Forense",
    "empresa": "Traverso Forensics",
    "email": "migueltraverso@estudiotraverso.com.ar",
    "linkedin": "https://www.linkedin.com/in/miguel-traverso/"
}

TSA_URL = "http://timestamp.digicert.com"

# Autoridades de Sellado de Tiempo, en orden de preferencia. Se intentan una
# tras otra hasta obtener el sello: si una no responde (caida, bloqueo de red,
# firewall del estudio) la evidencia igual queda con constancia temporal de un
# tercero. Antes se usaba solo la primera, y cuando esa no estaba disponible la
# adquisicion quedaba sin sellar sin que el perito se enterara.
# El orden va de mayor a menor reconocimiento: primero autoridades certificantes
# comerciales, y al final un servicio publico gratuito como ultimo recurso.
#
# Las direcciones son http y no https a proposito. No es un descuido ni una
# rebaja de seguridad: el protocolo RFC 3161 no viaja en claro en el sentido
# que importa, porque lo que se envia es un hash (no el archivo) y lo que
# vuelve es un token firmado por la autoridad. Si alguien lo alterara en el
# camino, la firma no verificaria (y el programa la verifica antes de
# aceptarla, ver verificar_sello). Por eso las TSA publican sus puntos de
# acceso sobre http, y DigiCert directamente rechaza las peticiones por https:
# se comprobo que sobre https agotaba los 5 segundos de espera y fallaba
# siempre, mientras que sobre http responde en menos de medio segundo. Con
# DigiCert primera en la lista, esos 5 segundos se perdian en cada pieza de
# evidencia sellada.
#
# Apple estuvo en la lista hasta que el programa empezo a verificar la firma
# de cada sello: firma con SHA-1, que ya no se acepta (ver _hash_de_firma).
TSA_URLS = [
    ("DigiCert", "http://timestamp.digicert.com"),
    ("Sectigo",  "http://timestamp.sectigo.com"),
    ("Certum",   "http://time.certum.pl"),
    ("FreeTSA",  "https://freetsa.org/tsr"),
]

HAR_VERSION = "1.2"

# CONFIGURACION DEL PERITO (archivo externo)
_PERITO_CONFIG_FILENAME = "perito.json"

def _load_perito_config() -> Dict[str, str]:
    """
    Carga datos del perito desde perito.json (mismo directorio que el script).
    Si no existe, devuelve dict vacío: el usuario completa los campos en el Setup.
    Esto evita que los datos personales del autor queden hardcodeados en el código.

    Formato de perito.json:
    {
        "nombre":    "Juan Perez",
        "titulo":    "Licenciado en Sistemas",
        "empresa":   "Estudio Perez",
        "email":     "juan@perez.com",
        "linkedin":  "https://linkedin.com/in/juan-perez/",
        "matricula": "12345"
    }
    """
    candidates = [
        Path(__file__).parent / _PERITO_CONFIG_FILENAME,
        Path(sys.executable).parent / _PERITO_CONFIG_FILENAME if getattr(sys, "frozen", False) else None,
    ]
    for path in candidates:
        if path and path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
    return {}

# DETECCION AUTOMATICA DEL LOGO 
def get_app_dir() -> Path:
    """Devuelve el directorio donde esta el .exe o el .py (portable)."""
    if getattr(sys, "frozen", False):
        # .exe compilado: sys.executable apunta al .exe real
        return Path(sys.executable).parent.resolve()
    else:
        # Script .py
        return Path(__file__).parent.resolve()

def _resolve_logo_path() -> str:
    """Busca el logo en el directorio del script o dentro del .exe (PyInstaller)."""
    # PyInstaller descomprime recursos en sys._MEIPASS cuando corre como .exe
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base_dir = Path(sys._MEIPASS)
    else:
        base_dir = Path(__file__).parent.resolve()

    candidates = [
        base_dir / "logo_traverso.png",
        base_dir / "traverso_logo.png",
        Path("logo_traverso.png"),
        Path("traverso_logo.png"),
    ]
    for cand in candidates:
        if cand.exists():
            return str(cand)
    return ""

LOGO_PATH: str = _resolve_logo_path()
MAX_RECORD_W = 1920
MAX_RECORD_H = 1080

def get_windows_version() -> str:
    """
    Retorna el nombre correcto del SO en Windows.
    platform.platform() reporta 'Windows-10' en Windows 11 porque la API
    GetVersionEx devuelve major=10/minor=0 para ambas versiones.
    La distinción real se hace por build number: >= 22000 es Windows 11.
    """
    if platform.system() != "Windows":
        return platform.platform()
    try:
        ver = sys.getwindowsversion()
        build = ver.build
        major = ver.major
        minor = ver.minor
        if major == 10 and minor == 0 and build >= 22000:
            win_name = "Windows-11"
        elif major == 10 and minor == 0:
            win_name = "Windows-10"
        elif major == 6 and minor == 3:
            win_name = "Windows-8.1"
        elif major == 6 and minor == 2:
            win_name = "Windows-8"
        elif major == 6 and minor == 1:
            win_name = "Windows-7"
        else:
            win_name = f"Windows-{major}.{minor}"
        return f"{win_name}-{build}-SP0"
    except Exception:
        return f"Windows-{platform.release()}"

AUDIO_EXTS = {".mp3", ".opus", ".aac", ".ogg", ".wav", ".m4a", ".flac", ".wma"}
VIDEO_EXTS = {".mp4", ".mkv", ".avi", ".mov", ".webm", ".flv", ".wmv"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tiff"}
HTML_EXTS  = {".html", ".htm", ".mhtml", ".mht"}

# Estos dos recorridos se reproducen enteros en el anexo de vistas del
# dictamen. El registro de evidencias los muestra en miniatura chica: la
# misma imagen embebida dos veces (media hoja en el registro y otra vez en el
# anexo) duplicaba el peso del informe sin agregar nada, porque el registro
# esta para identificar el archivo y acreditar su hash, no para leerlo.
# Debe coincidir con los tipos del anexo de vistas; la prueba
# desarrollo/test_peso_dictamen.py lo verifica contra el texto del programa.
TIPOS_CON_ANEXO_DE_VISTAS = ("CAPTURA_CHAT", "CAPTURA_COMENTARIOS")

# FILTRO DE CONSOLA
JS_SPAM_PATTERNS = [
    "permissions-policy", "permissions policy", "permission-policy",
    "unrecognized feature", "otp-credentials", "payment", "usb",
    "permissions policy violation", "unload is not allowed",
    "errorutils caught", "subsequent non-fatal errors",
    "fburl.com/debugjs", "[object object]",
    "the user agent does not support", "public key credentials",
    "too many active webgl", "webgl contexts", "oldest context will be lost",
    "sharedimagemanager", "produceskia", "non-existent mailbox",
    "mailbox", "gpu/command_buffer", "chromium/gpu",
    "x-frame-options", "refused to display", "refused to load",
    "content security policy", "img-src", "blob:", "csp directive",
    "cors policy", "access-control-allow-origin",
    "dit.whatsapp.net", "deidentified_telemetry",
    "flows.whatsapp.net", "static.whatsapp.net",
    "storage bucket persistence", "aquire-persistent-storage",
    "performanceobserver", "buffered flag", "entrytypes",
    "moov atom not found", "trun track id unknown", "no tfhd was found",
    "error reading header", "[mov,mp4,m4a,3gp,3g2,mj2",
    # FFmpeg: advertencias normales de audio/red, no indican fallo de adquisición
    "could not update timestamps for skipped samples",
    "failed to send close message",
    "aac @", "[tls @", "[aac @",
]

def is_js_spam(text: str) -> bool:
    if not text:
        return False
    t_lower = text.lower()
    return any(pat in t_lower for pat in JS_SPAM_PATTERNS)

# UTILIDADES CRYPTO
HASH_FALLIDO = "ERROR_HASH"


def sha256_file(path: str) -> str:
    """
    Calcula el SHA-256 del archivo. Si no puede, devuelve HASH_FALLIDO y deja
    constancia del motivo en el registro de errores del proceso.

    No lanza excepcion para no cortar una diligencia en curso, pero quien lo
    llame tiene que comprobar el resultado: una evidencia sin hash valido no
    puede darse por registrada. Antes el fallo se guardaba como si fuera un
    hash y nadie se enteraba.
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        registrar_fallo_critico("HASH", f"No se pudo calcular el SHA-256 de {path}: {e}")
        return HASH_FALLIDO


# Fallos que comprometen la evidencia. Se acumulan aca ademas de escribirse en
# el audit log, para poder listarlos en el dictamen: si algo salio mal durante
# la diligencia, el informe tiene que decirlo, no ocultarlo.
FALLOS_CRITICOS: List[Dict[str, str]] = []


def autodiagnostico(root_caso=None, verificar_red: bool = True) -> List[Dict[str, Any]]:
    """
    Comprueba que la herramienta este en condiciones ANTES de adquirir prueba.

    Nace de un problema real: el sellado de tiempo estuvo fallando sin que se
    notara, y las evidencias quedaron sin constancia temporal. Un control al
    inicio lo habria detectado el primer dia.

    Las funciones criptograficas se prueban contra vectores conocidos (el mismo
    metodo que usa el NIST para validar herramientas forenses): si SHA-256 no
    devuelve el resultado publicado para una entrada conocida, la herramienta
    no esta en condiciones de certificar nada.

    Devuelve una lista de comprobaciones con su resultado, para dejarla en el
    log de auditoria y en el dictamen.
    """
    checks: List[Dict[str, Any]] = []

    def anotar(nombre, ok, detalle):
        checks.append({"prueba": nombre, "ok": bool(ok), "detalle": str(detalle)})

    # SHA-256 contra el vector de prueba publicado (FIPS 180-4)
    ESPERADO_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    try:
        obtenido = hashlib.sha256(b"abc").hexdigest()
        anotar("SHA-256 (vector NIST 'abc')", obtenido == ESPERADO_ABC,
               "coincide con FIPS 180-4" if obtenido == ESPERADO_ABC
               else f"NO coincide: {obtenido[:24]}...")
    except Exception as e:
        anotar("SHA-256 (vector NIST 'abc')", False, f"error: {e}")

    # Ed25519 contra el vector de prueba del RFC 8032 (seccion 7.1, prueba 1):
    # es el algoritmo con que se firma el log de auditoria.
    ESPERADO_ED25519 = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        obtenido = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).sign(b"").hex()
        anotar("Ed25519 (vector RFC 8032)", obtenido == ESPERADO_ED25519,
               "coincide con RFC 8032" if obtenido == ESPERADO_ED25519
               else f"NO coincide: {obtenido[:24]}...")
    except Exception as e:
        anotar("Ed25519 (vector RFC 8032)", False, f"error: {e}")

    # Hash del propio ejecutable: el dictamen lo declara como constancia de
    # que la herramienta no fue alterada.
    h_self = get_self_hash()
    anotar("Hash del software", h_self not in ("", "N/A", HASH_FALLIDO),
           f"{h_self[:32]}..." if h_self not in ("", "N/A", HASH_FALLIDO) else "no disponible")

    # El directorio del caso tiene que admitir escritura
    if root_caso is not None:
        try:
            p = Path(root_caso) / ".escritura.tmp"
            p.write_text("ok", encoding="utf-8")
            p.unlink()
            anotar("Escritura en el directorio del caso", True, str(root_caso))
        except Exception as e:
            anotar("Escritura en el directorio del caso", False, f"{e}")

    if verificar_red:
        # Al menos una autoridad de sellado tiene que responder, si no la
        # prueba se adquiere sin constancia temporal de un tercero.
        sellada = None
        try:
            import hashlib as _h
            digest = _h.sha256(b"autodiagnostico").hexdigest()
            r = TimestampAuthority.stamp(digest)
            if isinstance(r, dict) and r.get("token_b64"):
                sellada = r.get("tsa_nombre") or r.get("tsa_url", "")
        except Exception:
            pass
        anotar("Sellado de tiempo RFC 3161", sellada is not None,
               f"responde {sellada} y su firma verifica" if sellada else
               "ninguna autoridad entrego un sello verificable: la prueba quedara sin sello")

        # El mismo sello mide el reloj del equipo contra una hora que nadie
        # puede cambiar en el camino. La consulta NTP viaja por UDP sin
        # autenticar: quien controle la red puede devolver la hora que quiera,
        # y el dictamen la consignaba como "reloj sincronizado". La hora del
        # sello, en cambio, esta firmada por la autoridad.
        if sellada:
            desfase, margen = r["desfase_reloj_s"], r["incertidumbre_s"]
            anotar("Reloj del equipo contra la hora firmada", abs(desfase) <= 30,
                   f"desfase {desfase:+.2f} s (margen {margen:.2f} s) segun {sellada}"
                   + ("" if abs(desfase) <= 30 else ": el reloj del equipo no es confiable"))
            checks[-1]["contraste_hora"] = {"desfase_s": desfase, "margen_s": margen,
                                            "autoridad": sellada,
                                            "hora_firmada": r.get("timestamp_iso", "")}

    return checks


def exportar_warc(case, destino=None) -> Optional[Dict[str, Any]]:
    """
    Empaqueta la evidencia adquirida en un archivo WARC (norma ISO 28500).

    El WARC es el formato estandar de archivo web: lo usan las bibliotecas
    nacionales y las herramientas de preservacion. Su ventaja para una pericia
    es que cualquiera puede abrirlo con software independiente, hoy o dentro de
    diez anos, sin necesitar esta herramienta ni confiar en ella.

    ALCANCE: se incluye cada artefacto adquirido (capturas, media, informes)
    como registro 'resource', con su hash y su URL de origen, mas registros
    'metadata' con la cadena de custodia. No es un archivo navegable del sitio:
    reconstruir la navegacion completa exigiria interceptar los cuerpos de las
    respuestas, algo que el motor del navegador no expone. Lo que el WARC
    contiene es exactamente lo que se adquirio y certifico.

    Devuelve un resumen con la ruta y la cantidad de registros, o None si la
    libreria no esta disponible.
    """
    try:
        from warcio.warcwriter import WARCWriter
        from warcio.statusandheaders import StatusAndHeaders
    except ImportError:
        registrar_fallo_critico("WARC", "warcio no esta instalado: no se genero el WARC")
        return None

    ruta = Path(destino) if destino else (case.dirs["network"] / f"{case.case_id}.warc.gz")
    escritos = 0
    try:
        with open(ruta, "wb") as fh:
            writer = WARCWriter(fh, gzip=True)

            # Cabecera: quien genero el archivo y en el marco de que actuacion
            writer.write_record(writer.create_warcinfo_record(ruta.name, {
                "software":   f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}",
                "format":     "WARC File Format 1.1",
                "conformsTo": "ISO 28500",
                "case-id":    case.case_id,
                "expediente": str(case.case_data.get("exp", "")),
                "perito":     str(case.perito_data.get("nombre", "")),
                "isPartOf":   "Diligencia pericial informatica",
            }))
            escritos += 1

            for ev in case.evidences:
                p_arch = ev.get("path", "")
                if not p_arch or not os.path.exists(p_arch):
                    continue
                try:
                    with open(p_arch, "rb") as f_ev:
                        datos = f_ev.read()
                except Exception as e:
                    registrar_fallo_critico(
                        "WARC", f"No se pudo incluir {os.path.basename(p_arch)}: {e}")
                    continue

                # La URL de origen identifica de donde salio la prueba; si no
                # la hay (por ejemplo un informe generado) se usa un URI local.
                uri = ev.get("source_url") or Path(p_arch).as_uri()
                rec = writer.create_warc_record(
                    uri, "resource",
                    payload=io.BytesIO(datos),
                    warc_content_type=_tipo_mime(p_arch),
                    warc_headers_dict={
                        "WARC-Date": _warc_fecha(ev.get("ts", "")),
                        "WARC-Block-Digest": "sha256:" + ev.get("sha256", ""),
                    })
                writer.write_record(rec)
                escritos += 1

                # Registro aparte con la cadena de custodia del artefacto
                custodia = json.dumps({
                    "tipo":        ev.get("tipo", ""),
                    "archivo":     ev.get("filename", ""),
                    "sha256":      ev.get("sha256", ""),
                    "tamano":      ev.get("size_bytes", 0),
                    "adquirido":   ev.get("ts", ""),
                    "origen":      ev.get("source_url", ""),
                    "integridad":  ev.get("integridad_ok", True),
                    "sello_tiempo": (ev.get("tsa") or {}).get("timestamp_iso", ""),
                    "autoridad_sello": (ev.get("tsa") or {}).get("tsa_nombre", ""),
                }, ensure_ascii=False).encode("utf-8")
                writer.write_record(writer.create_warc_record(
                    uri, "metadata",
                    payload=io.BytesIO(custodia),
                    warc_content_type="application/json"))
                escritos += 1

        h = sha256_file(str(ruta))
        return {"path": str(ruta), "registros": escritos,
                "sha256": h, "tamano": os.path.getsize(ruta)}
    except Exception as e:
        registrar_fallo_critico("WARC", f"No se pudo generar el WARC: {e}")
        return None


def exportar_dfxml(case, destino=None) -> Optional[Dict[str, Any]]:
    """
    Escribe el inventario del caso en DFXML (Digital Forensics XML).

    Por que suma: el registro de evidencias vive en una base SQLite propia de
    este programa y el dictamen es un PDF para leer. Ninguno de los dos sirve
    para que otra herramienta procese el caso automaticamente. DFXML es el
    formato con que la informatica forense intercambia justamente eso (que
    archivos hay, de que tamano, con que hashes y cuando se tomaron) y lo leen
    utilidades independientes como las de la familia fiwalk / DFXML de NIST.

    Es la contracara del verificador: aquel permite comprobar el caso sin este
    programa, este permite procesarlo sin este programa.

    Se declaran ademas los datos de procedencia que exige el formato: que
    herramienta lo produjo, con que version, en que maquina y cuando. Un
    inventario sin procedencia no sirve para cotejar nada.
    """
    from xml.sax.saxutils import escape as _esc

    ruta = Path(destino) if destino else (case.root / f"{case.case_id}.dfxml")
    try:
        ahora = datetime.datetime.now().isoformat()
        partes = []
        partes.append('<?xml version="1.0" encoding="UTF-8"?>')
        # El espacio de nombres de Dublin Core hay que declararlo: sin eso el
        # documento no es XML valido y ningun lector lo abre.
        partes.append('<dfxml xmloutputversion="1.0" '
                      'xmlns:dc="http://purl.org/dc/elements/1.1/">')
        partes.append('  <metadata>')
        partes.append('    <dc:type>Disk Image Report</dc:type>')
        partes.append('  </metadata>')
        partes.append('  <creator version="1.0">')
        partes.append('    <program>%s</program>' % _esc(SOFTWARE_INFO["software"]))
        partes.append('    <version>%s</version>' % _esc(SOFTWARE_INFO["version"]))
        partes.append('    <build_environment>')
        partes.append('      <interpreter>Python %s</interpreter>'
                      % _esc(platform.python_version()))
        partes.append('    </build_environment>')
        partes.append('    <execution_environment>')
        partes.append('      <os_sysname>%s</os_sysname>' % _esc(platform.system()))
        partes.append('      <os_version>%s</os_version>' % _esc(platform.version()))
        partes.append('      <host>%s</host>' % _esc(platform.node()))
        partes.append('      <start_time>%s</start_time>' % _esc(ahora))
        partes.append('    </execution_environment>')
        partes.append('  </creator>')
        partes.append('  <source>')
        partes.append('    <image_filename>%s</image_filename>' % _esc(case.case_id))
        partes.append('  </source>')

        n = 0
        for ev in case.evidences:
            p = ev.get("path", "")
            if not p or not os.path.exists(p):
                continue
            n += 1
            try:
                rel = str(Path(p).relative_to(case.root))
            except Exception:
                rel = os.path.basename(p)
            partes.append('  <fileobject>')
            partes.append('    <filename>%s</filename>' % _esc(rel.replace("\\", "/")))
            partes.append('    <filesize>%d</filesize>' % int(ev.get("size_bytes") or 0))
            partes.append('    <hashdigest type="sha256">%s</hashdigest>'
                          % _esc(str(ev.get("sha256") or "")))
            partes.append('    <mtime>%s</mtime>' % _esc(str(ev.get("ts") or "")))
            # El tipo de evidencia y la URL de origen no forman parte del
            # esquema: van como anotacion, que es lo que el formato preve para
            # los datos propios de cada herramienta.
            partes.append('    <annotation type="tipo">%s</annotation>'
                          % _esc(str(ev.get("tipo") or "")))
            if ev.get("source_url"):
                partes.append('    <annotation type="source_url">%s</annotation>'
                              % _esc(str(ev["source_url"])[:500]))
            partes.append('  </fileobject>')

        partes.append('</dfxml>')
        ruta.write_text("\n".join(partes) + "\n", encoding="utf-8")
        case.log("INFO", "DFXML", f"DFXML generado: {ruta.name} | {n} objetos")
        return {"path": str(ruta), "objetos": n}
    except Exception as e:
        registrar_fallo_critico("DFXML", f"No se pudo generar el DFXML: {e}")
        return None


def _tipo_mime(path: str) -> str:
    """Tipo MIME segun la extension, para los registros del WARC."""
    import mimetypes
    t, _ = mimetypes.guess_type(path)
    return t or "application/octet-stream"


def _warc_fecha(ts_iso: str) -> str:
    """Convierte el timestamp del caso al formato de fecha que exige WARC."""
    try:
        d = datetime.datetime.fromisoformat(ts_iso)
        if d.tzinfo is None:
            d = d.astimezone()
        return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def registrar_fallo_critico(categoria: str, mensaje: str) -> None:
    """Anota un fallo que afecta la integridad o la trazabilidad de la prueba."""
    entrada = {
        "ts": datetime.datetime.now().isoformat(),
        "categoria": categoria,
        "mensaje": str(mensaje)[:400],
    }
    FALLOS_CRITICOS.append(entrada)
    try:
        log_signals.log_msg.emit(f"⚠ FALLO [{categoria}] {entrada['mensaje'][:120]}")
    except Exception:
        pass


def write_custody_sidecar(path: str, tipo: str, source_url: str,
                           perito: dict, case_id: str, extra: dict = None) -> dict:
    """
    Genera DOS archivos sidecar junto al archivo adquirido, INMEDIATAMENTE
    después de que el archivo está cerrado y su contenido es definitivo.

    Los sidecar son la evidencia primaria de cadena de custodia, existen
    incluso si el reporte principal se pierde o corrompe.

    Archivos generados (mismo nombre base que el archivo, distinta extensión):
      • <archivo>.sha256      , hash SHA-256 raw (formato: HASH *FILENAME)
      • <archivo>.custodia.txt, acta de adquisición legible y verificable

    Retorna dict con todos los datos calculados.
    """
    p = Path(path)
    ts_acq = datetime.datetime.now()
    ts_iso = ts_acq.isoformat()
    ts_legible = ts_acq.strftime("%d/%m/%Y %H:%M:%S")

    sha = sha256_file(path)
    size = os.path.getsize(path)

    # .sha256: formato estándar sha256sum
    # Verificación: sha256sum -c archivo.sha256  (Linux/macOS)
    #               certutil -hashfile archivo SHA256  (Windows)
    sha256_path = str(p) + ".sha256"
    with open(sha256_path, "w", encoding="utf-8") as f:
        f.write(f"{sha} *{p.name}\n")

    # .custodia.txt: acta de adquisición
    custodia_path = str(p) + ".custodia.txt"
    sep = "=" * 70
    acta_lines = [
        sep,
        "  ACTA DE ADQUISICION FORENSE — TRAVERSO FORENSICS · NAVEGADOR WEB FORENSE",
        sep,
        "",
        f"  TIPO DE EVIDENCIA  : {tipo}",
        f"  ARCHIVO            : {p.name}",
        f"  TAMANO             : {size:,} bytes  ({size / 1024:.2f} KB)",
        "",
        "  ── INTEGRIDAD ──────────────────────────────────────────────",
        f"  SHA-256            : {sha}",
        f"  ALGORITMO          : SHA-256 (FIPS 180-4)",
        f"  MOMENTO DEL HASH   : {ts_legible}  [{ts_iso}]",
        "",
        "  ── ORIGEN ──────────────────────────────────────────────────",
        f"  URL ORIGEN         : {(source_url or 'N/A')[:120]}",
        "",
        "  ── DATOS DEL CASO ──────────────────────────────────────────",
        f"  CASE ID            : {case_id}",
    ]
    if extra:
        for k, v in extra.items():
            acta_lines.append(f"  {k.upper():<19}: {v}")

    acta_lines += [
        "",
        "  ── PERITO ACTUANTE ─────────────────────────────────────────",
        f"  NOMBRE             : {perito.get('nombre', '')}",
        f"  TITULO             : {perito.get('titulo', '')}",
        f"  EMPRESA            : {perito.get('empresa', '')}",
        f"  EMAIL              : {perito.get('email', '')}",
        f"  MATRICULA          : {perito.get('matricula', '') or 'No declarada'}",
        "",
        "  ── ENTORNO TECNICO ─────────────────────────────────────────",
        f"  HOSTNAME           : {socket.gethostname()}",
        f"  PLATAFORMA         : {get_windows_version()}",
        f"  HERRAMIENTA        : {SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}",
        f"  HASH HERRAMIENTA   : {get_self_hash()[:32]}...",
        f"  MOTOR NAVEGADOR    : {version_motor()}",
        "",
        "  ── VERIFICACION ────────────────────────────────────────────",
        "  Windows (cmd):",
        f'    certutil -hashfile "{p.name}" SHA256',
        f'    Resultado esperado: {sha}',
        "",
        "  Linux / macOS:",
        f'    sha256sum -c "{p.name}.sha256"',
        "",
        sep,
        f"  FIN DEL ACTA — {ts_legible}",
        sep,
    ]
    with open(custodia_path, "w", encoding="utf-8") as f:
        f.write("\n".join(acta_lines))

    return {
        "sha256":        sha,
        "size":          size,
        "ts_iso":        ts_iso,
        "ts_legible":    ts_legible,
        "sha256_path":   sha256_path,
        "custodia_path": custodia_path,
    }

# SINCRONIZACION NTP
def get_ntp_info() -> Dict[str, Any]:
    """
    Consulta pool.ntp.org y retorna offset del reloj local respecto a UTC.
    ISO 27037 exige documentar la fuente de tiempo, un offset elevado hace
    impugnable toda la línea de tiempo forense.
    Retorna dict con resultado o error si no hay red.
    """
    if _HAS_NTPLIB:
        try:
            c = _ntplib.NTPClient()
            resp = c.request("pool.ntp.org", version=3, timeout=5)
            offset_s = round(resp.offset, 3)
            ntp_utc  = datetime.datetime.fromtimestamp(resp.tx_time, datetime.timezone.utc)
            return {
                "servidor":       "pool.ntp.org",
                "hora_ntp_utc":   ntp_utc.isoformat() + "Z",
                "hora_local":     datetime.datetime.now().isoformat(),
                "offset_segundos": offset_s,
                "offset_legible": f"{offset_s:+.3f} s",
                "sincronizado":   True,
                "alerta":         abs(offset_s) > 30,   # >30s es problemático en forense
            }
        except Exception as e:
            pass
    # Fallback sin ntplib o sin red
    return {
        "servidor":       "pool.ntp.org",
        "hora_local":     datetime.datetime.now().isoformat(),
        "offset_segundos": None,
        "sincronizado":   False,
        "error":          "ntplib no instalado o sin acceso a red. "
                          "Instalar: pip install ntplib",
    }

# METADATOS DE SITIO WEB
def get_site_metadata(url: str) -> Dict[str, Any]:
    """
    Captura DNS, IP, geolocalización y headers HTTP del servidor de destino.
    Se llama en background al navegar: no bloquea la UI.
    """
    import requests as _req
    from urllib.parse import urlparse
    meta: Dict[str, Any] = {"url": url, "ts": datetime.datetime.now().isoformat()}
    try:
        parsed  = urlparse(url)
        host    = parsed.netloc.split(":")[0]
        meta["host"] = host
        # DNS → IP
        try:
            ip = socket.gethostbyname(host)
            meta["ip"] = ip
            # Reverse DNS
            try:
                meta["rdns"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                meta["rdns"] = "N/A"
        except Exception:
            ip = None
            meta["ip"] = "N/A"
        # Geolocalización (ipapi.co, sin API key, uso libre)
        if ip and not ip.startswith(("10.", "192.168.", "172.")):
            try:
                geo = _req.get(f"https://ipapi.co/{ip}/json/",
                               timeout=5, verify=True).json()
                meta["geo"] = {
                    "pais":      geo.get("country_name", "N/A"),
                    "region":    geo.get("region", "N/A"),
                    "ciudad":    geo.get("city", "N/A"),
                    "org":       geo.get("org", "N/A"),
                    "timezone":  geo.get("timezone", "N/A"),
                }
            except Exception:
                meta["geo"] = {"error": "No disponible"}
        # Headers HTTP del servidor
        try:
            r = _req.head(url, timeout=8, allow_redirects=True, verify=True,
                          headers={"User-Agent": "Mozilla/5.0"})
            meta["http_status"]  = r.status_code
            meta["http_headers"] = dict(r.headers)
            meta["final_url"]    = r.url
        except Exception as e:
            meta["http_headers"] = {"error": str(e)}
    except Exception as e:
        meta["error"] = str(e)
    return meta


#  ARCHIVOS DE ACREDITACION DEL ENTORNO
#
#  Acompañan a la evidencia y sirven para sostener condiciones que, de otro
#  modo, habria que pedir que se crean bajo palabra: que el equipo no tenia
#  redirigido el dominio, quien sirvio el contenido, y que codigo entrego la
#  pagina en el momento exacto de la adquisicion.

def registrar_archivo_caso(case, ruta, tipo: str, extra: Dict[str, str],
                           source_url: str = "") -> bool:
    """Le pone hash, acta de custodia y registro a un archivo del caso."""
    try:
        write_custody_sidecar(
            path=str(ruta), tipo=tipo, source_url=source_url,
            perito=case.perito_data, case_id=case.case_id, extra=extra)
        case.register_evidence(tipo, str(ruta), source_url=source_url)
        return True
    except Exception as e:
        case.log("ERROR", "ACREDITACION", f"No se pudo registrar {tipo}: {e}")
        return False


def copiar_archivo_hosts(case) -> bool:
    """
    Copia el archivo hosts del equipo.

    Acredita que durante la adquisicion no habia redirecciones de nombres en
    la maquina: si un dominio hubiera estado desviado a otra direccion,
    constaria aca. Es la contrapartida del registro de DNS e IP; sin este
    archivo, sostener que se visito el sitio real depende de la palabra del
    perito.
    """
    origen = (Path(os.environ.get("SystemRoot", r"C:\Windows")) /
              "System32" / "drivers" / "etc" / "hosts") if os.name == "nt" else Path("/etc/hosts")
    destino = case.dirs["network"] / "Hosts"
    try:
        if not origen.exists():
            case.log("ADVERTENCIA", "ACREDITACION",
                     f"No se encontro el archivo hosts en {origen}")
            return False
        shutil.copy2(str(origen), str(destino))
    except Exception as e:
        case.log("ADVERTENCIA", "ACREDITACION", f"No se pudo copiar el archivo hosts: {e}")
        return False

    # Se cuentan las redirecciones activas: es el dato que se va a mirar
    try:
        lineas = destino.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        lineas = []
    activas = [l.strip() for l in lineas
               if l.strip() and not l.strip().startswith("#")]
    registrar_archivo_caso(
        case, destino, "ARCHIVO_HOSTS",
        {"Origen": str(origen),
         "Entradas activas": str(len(activas)),
         "Significado": ("Sin redirecciones de nombres en el equipo"
                         if not activas else
                         "El equipo tiene redirecciones de nombres declaradas")})
    case.log("INFO", "ACREDITACION",
             f"Archivo hosts copiado | {len(activas)} entradas activas")
    return True


def guardar_certificado_servidor(case, host: str) -> bool:
    """
    Guarda el certificado TLS que presenta el servidor.

    Acredita quien sirvio el contenido: el certificado esta firmado por una
    autoridad y nombra al titular del dominio. Junto con el registro de DNS e
    IP permite sostener que lo adquirido vino de quien se dice, y no de un
    intermediario.
    """
    import ssl
    destino = case.dirs["network"] / f"CertServer_{host}.cer"
    if destino.exists():
        return True                      # ya se guardo en esta sesion
    try:
        pem = ssl.get_server_certificate((host, 443), timeout=8)
    except Exception as e:
        case.log("ADVERTENCIA", "ACREDITACION",
                 f"No se pudo obtener el certificado de {host}: {e}")
        return False

    datos = {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes as _h
        c = x509.load_pem_x509_certificate(pem.encode("ascii"))
        desde = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
        hasta = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
        datos = {
            "Titular":       c.subject.rfc4514_string()[:120],
            "Emisor":        c.issuer.rfc4514_string()[:120],
            "Valido desde":  desde.strftime("%d/%m/%Y %H:%M:%S UTC"),
            "Valido hasta":  hasta.strftime("%d/%m/%Y %H:%M:%S UTC"),
            "Numero de serie": format(c.serial_number, "x"),
            "Huella SHA-256": c.fingerprint(_h.SHA256()).hex(),
        }
    except Exception as e:
        datos = {"Lectura del certificado": f"no se pudo interpretar: {e}"}

    try:
        destino.write_text(pem, encoding="ascii")
    except Exception as e:
        case.log("ERROR", "ACREDITACION", f"No se pudo escribir el certificado: {e}")
        return False

    datos["Host"] = host
    datos["Formato"] = "PEM (X.509)"
    registrar_archivo_caso(case, destino, "CERTIFICADO_SERVIDOR", datos,
                           source_url=f"https://{host}/")
    case.log("INFO", "ACREDITACION",
             f"Certificado de {host} | emisor: {datos.get('Emisor', 'N/A')[:60]} | "
             f"huella: {datos.get('Huella SHA-256', 'N/A')[:32]}")
    return True


def guardar_cabeceras(case, meta: Dict[str, Any]) -> bool:
    """
    Escribe las cabeceras HTTP del servidor en texto plano.

    Ya estan dentro de site_metadata.json, pero ahi conviven con el resto de
    los metadatos y hay que saber leer JSON. En un anexo pericial conviene que
    puedan leerse tal como las envio el servidor.
    """
    host = meta.get("host") or "sitio"
    cab = meta.get("http_headers")
    if not isinstance(cab, dict) or "error" in cab:
        return False
    destino = case.dirs["network"] / f"Headers_{host}.txt"
    try:
        with open(destino, "w", encoding="utf-8") as f:
            f.write(f"CABECERAS HTTP DEL SERVIDOR\n")
            f.write(f"Host        : {host}\n")
            f.write(f"URL         : {meta.get('url', '')}\n")
            f.write(f"URL final   : {meta.get('final_url', '')}\n")
            f.write(f"Estado HTTP : {meta.get('http_status', '')}\n")
            f.write(f"Direccion IP: {meta.get('ip', '')}\n")
            f.write(f"Momento     : {meta.get('ts', '')}\n")
            f.write("=" * 70 + "\n\n")
            for k in sorted(cab):
                f.write(f"{k}: {cab[k]}\n")
    except Exception as e:
        case.log("ERROR", "ACREDITACION", f"No se pudieron escribir las cabeceras: {e}")
        return False

    registrar_archivo_caso(
        case, destino, "CABECERAS_HTTP",
        {"Host": host, "Estado HTTP": str(meta.get("http_status", "")),
         "Cabeceras": str(len(cab))},
        source_url=meta.get("url", ""))
    return True


_SELF_HASH_CACHE: str = ""

def get_self_hash() -> str:
    """Calcula el SHA-256 del script/ejecutable una sola vez y lo cachea."""
    global _SELF_HASH_CACHE
    if not _SELF_HASH_CACHE:
        try:
            # Cuando se compila con PyInstaller, __file__ apunta al directorio
            # temporal de extracción. sys.executable apunta al .exe real.
            target = sys.executable if getattr(sys, "frozen", False) else __file__
            _SELF_HASH_CACHE = sha256_file(target)
        except Exception as e:
            # El dictamen consigna este hash como constancia de que la
            # herramienta no fue alterada. Si no se puede calcular, la
            # afirmacion no se sostiene y tiene que constar.
            registrar_fallo_critico(
                "HASH_SOFTWARE",
                f"No se pudo calcular el hash del propio ejecutable: {e}")
            _SELF_HASH_CACHE = "N/A"
    return _SELF_HASH_CACHE


def resumen_codecs(codecs) -> str:
    """
    Pasa a texto lo que el motor contesto sobre cada formato de video.

    canPlayType devuelve 'probably', 'maybe' o cadena vacia. La vacia es la
    respuesta que importa y por eso se escribe "no": significa que ese formato
    no se puede reproducir dentro del navegador.
    """
    if not codecs:
        return "no se pudo consultar al motor en esta diligencia"
    partes = []
    for nombre, valor in codecs.items():
        if isinstance(valor, bool):
            partes.append(f"{nombre}: {'si' if valor else 'no'}")
        else:
            partes.append(f"{nombre}: {valor or 'no'}")
    return "; ".join(partes)


def sin_codecs_propietarios(codecs) -> bool:
    """Si el motor no puede reproducir H.264/AAC, que es lo que usan WhatsApp e Instagram."""
    if not codecs:
        return False
    return not (codecs.get("H.264+AAC") or codecs.get("MSE con H.264"))


def version_motor() -> str:
    """
    Version del motor del navegador y su nivel de parches de seguridad.

    Qt WebEngine parte de una base de Chromium (hoy la 140) y le incorpora los
    parches de seguridad de versiones posteriores. Para saber si el navegador
    que abrio las paginas tenia vulnerabilidades conocidas, el numero que
    importa es el segundo. Se declara en el dictamen y en cada acta porque el
    motor es el que interpreto el contenido adquirido.
    """
    try:
        from PyQt6.QtWebEngineCore import (qWebEngineChromiumSecurityPatchVersion,
                                           qWebEngineChromiumVersion, qWebEngineVersion)
        return (f"Qt WebEngine {qWebEngineVersion()} - Chromium {qWebEngineChromiumVersion()}, "
                f"parches de seguridad al nivel {qWebEngineChromiumSecurityPatchVersion()}")
    except Exception:
        return "no informado"


# Hash del conjunto de archivos de la herramienta. Son unos 540 MB, asi que se
# calcula en segundo plano desde que se abre el caso y el dictamen lo espera.
_CONJUNTO_HERRAMIENTA: Dict[str, Any] = {}
_hilo_conjunto: Optional[threading.Thread] = None


def manifiesto_de_la_herramienta(carpeta: Optional[str] = None,
                                 exe: str = "TraversoWebForensics.exe") -> Dict[str, Any]:
    """
    Hash de cada archivo del programa instalado y un hash del conjunto.

    El dictamen declaraba solo el hash del .exe. Pero en una compilacion onedir
    el .exe es un lanzador de 16 MB: el codigo del programa, el motor Chromium y
    las bibliotecas estan en _internal, unos 345 archivos que ese hash no
    cubria. Reemplazar cualquiera de esas DLL cambiaba lo que hacia el programa
    y el dictamen seguia declarando el mismo hash de siempre.

    Se cubre exactamente lo que copia el instalador: el .exe y todo _internal.
    Quedan afuera el desinstalador que agrega Inno Setup y las carpetas de
    trabajo (casos, perfiles) que viven al lado y cambian con el uso.

    El manifiesto tiene una linea por archivo, "<sha256>  <ruta>", ordenado por
    ruta; el hash del conjunto es el SHA-256 de ese texto. Un tercero puede
    comprobar el conjunto con certutil sobre el manifiesto y, si no coincide
    con el oficial de la version, ver cual archivo cambio.

    Sin `carpeta` se calcula sobre el programa en ejecucion. Corriendo desde el
    codigo fuente no hay carpeta instalada, y el conjunto es el propio .py.
    """
    if carpeta is None and not getattr(sys, "frozen", False):
        base, archivos, modo = Path(__file__).parent, [Path(__file__)], "codigo fuente"
    else:
        if carpeta is None:
            base, exe = Path(sys.executable).parent, Path(sys.executable).name
        else:
            base = Path(carpeta)
        if not (base / exe).is_file():
            return {"conjunto": "N/A", "error": f"no se encuentra {exe} en {base}"}
        archivos = [base / exe] + list((base / "_internal").rglob("*"))
        modo = "instalado"
    lineas, total = [], 0
    for f in archivos:
        if f.is_file():
            lineas.append((f.relative_to(base).as_posix(), sha256_file(str(f))))
            total += f.stat().st_size
    lineas.sort()
    texto = "".join(f"{h}  {ruta}\n" for ruta, h in lineas)
    return {"conjunto": hashlib.sha256(texto.encode("utf-8")).hexdigest(),
            "archivos": len(lineas), "bytes": total, "manifiesto": texto, "modo": modo}


def iniciar_hash_de_la_herramienta():
    """Arranca el calculo del conjunto en segundo plano. Se llama al abrir el caso."""
    global _hilo_conjunto
    if _hilo_conjunto is not None:
        return

    def _calcular():
        try:
            r = manifiesto_de_la_herramienta()
        except Exception as e:
            r = {"conjunto": "N/A", "error": str(e)}
        if r.get("conjunto") == "N/A":
            registrar_fallo_critico(
                "HASH_SOFTWARE",
                f"No se pudo calcular el hash del conjunto de la herramienta: {r.get('error')}")
        _CONJUNTO_HERRAMIENTA.update(r)

    _hilo_conjunto = threading.Thread(target=_calcular, daemon=True, name="hash_herramienta")
    _hilo_conjunto.start()


def hash_de_la_herramienta() -> Dict[str, Any]:
    """El resultado del calculo del conjunto; si todavia no termino, lo espera."""
    iniciar_hash_de_la_herramienta()
    _hilo_conjunto.join()
    return dict(_CONJUNTO_HERRAMIENTA)


def descarga_del_programa(pendiente, wa_activo: bool) -> bool:
    """
    Si una descarga la pidio el propio programa.

    Las pide en dos casos: cuando archiva una pagina o baja una foto de perfil
    (y entonces deja el aviso en _pagina_pendiente) y durante el recorrido de
    multimedia de WhatsApp, que hace clic en cada archivo. Cualquier otra
    descarga la inicio la pagina o el perito a mano, y no puede entrar sola a
    la carpeta de evidencias: una pagina puede disparar descargas sin que nadie
    haga clic.
    """
    return bool(pendiente) or bool(wa_activo)


def encadenar_log(previa: str, ts: str, nivel: str, categoria: str, mensaje: str) -> str:
    """
    Eslabon de una entrada del log de auditoria: SHA-256 del eslabon anterior
    y de la entrada. Alterar, suprimir o reordenar una linea rompe la cadena en
    ese punto. verificar_caso.py tiene la misma funcion, porque tiene que poder
    verificar sin este programa: si cambia aca, cambia alla.
    """
    return hashlib.sha256(
        f"{previa}|{ts}|{nivel}|{categoria}|{mensaje}".encode("utf-8")).hexdigest()


def mensaje_firma_log(case_id: str, hasta_id: int, entradas: int, cabeza: str) -> bytes:
    """Lo que se firma en cada cierre de la cadena. Igual en verificar_caso.py."""
    return f"TFWF-LOG|{case_id}|{hasta_id}|{entradas}|{cabeza}".encode("utf-8")


def verificar_log(db_path, clave_publica_hex: str, case_id: str) -> Dict[str, Any]:
    """
    Recorre el log de auditoria y comprueba el encadenamiento y las firmas.

    Devuelve las entradas donde la cadena se rompe ('rotas'), los cierres cuya
    firma no verifica ('cierres_invalidos') y cuantas entradas estan cubiertas
    por una firma valida ('firmadas'). Durante la sesion es normal que las
    ultimas entradas (hasta FIRMA_LOG_CADA) esten encadenadas y sin firmar.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    con = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        filas = con.execute("SELECT id, ts, level, category, message, cadena "
                            "FROM audit_log ORDER BY id").fetchall()
        cierres = con.execute("SELECT hasta_id, entradas, cabeza, firma "
                              "FROM firmas_log ORDER BY id").fetchall()
    finally:
        con.close()
    rotas, eslabon, previa = [], {}, ""
    for n, (id_, ts, nivel, cat, msg, guardada) in enumerate(filas, 1):
        if encadenar_log(previa, ts, nivel, cat, msg) != guardada:
            rotas.append(id_)
        eslabon[id_] = (guardada, n)
        previa = guardada
    publica = Ed25519PublicKey.from_public_bytes(bytes.fromhex(clave_publica_hex))
    invalidos, firmadas = [], 0
    for hasta_id, entradas, cabeza, firma in cierres:
        ok = eslabon.get(hasta_id) == (cabeza, entradas)
        if ok:
            try:
                publica.verify(bytes.fromhex(firma),
                               mensaje_firma_log(case_id, hasta_id, entradas, cabeza))
            except (InvalidSignature, ValueError):
                ok = False
        if ok:
            firmadas = max(firmadas, entradas)
        else:
            invalidos.append(hasta_id)
    return {"entradas": len(filas), "rotas": rotas, "cierres": len(cierres),
            "cierres_invalidos": invalidos, "firmadas": firmadas,
            "integro": not rotas and not invalidos}


def restringir_a_usuario_actual(ruta) -> bool:
    """
    Deja el archivo accesible solo para el usuario que ejecuta el programa.

    Se usa con los archivos que contienen material sensible, como la sesion
    importada del navegador. Por defecto Windows
    hereda permisos amplios de la carpeta (el grupo Users suele quedar con
    control total), y en un equipo compartido eso significa que cualquiera
    puede leer las cookies de sesion del perito.

    Nunca interrumpe la operacion: si el sistema no permite cambiar los
    permisos, el archivo queda como estaba y se devuelve False.
    """
    try:
        if platform.system() == "Windows":
            usuario = os.getenv("USERNAME", "")
            if not usuario:
                return False
            r = subprocess.run(
                ["icacls", str(ruta), "/inheritance:r", "/grant:r", f"{usuario}:(R,W)"],
                capture_output=True, check=False
            )
            return r.returncode == 0
        os.chmod(ruta, 0o600)
        return True
    except Exception:
        return False

# Fuentes del dictamen. Arranca con las del propio PDF, que solo cubren el
# alfabeto latino, y pasa a las Unicode cuando se logran cargar.
FUENTE_INFORME = "helvetica"
FUENTE_MONO = "courier"
FUENTES_DEL_INFORME = "fuentes base del PDF (alfabeto latino solamente)"
_FUENTES_EN_EL_EQUIPO = None

# Las que hacen falta: Arial en sus cuatro variantes y Courier New para los
# bloques de hash. Las trae cualquier Windows.
_ARCHIVOS_DE_FUENTE = (("texto", "", "arial.ttf"), ("texto", "B", "arialbd.ttf"),
                       ("texto", "I", "ariali.ttf"), ("texto", "BI", "arialbi.ttf"),
                       ("mono", "", "cour.ttf"), ("mono", "B", "courbd.ttf"))


def carpeta_de_fuentes() -> Path:
    return Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"


def hay_fuentes_unicode() -> bool:
    """
    Si el equipo tiene las fuentes con que se escribe el informe.

    Se consulta una sola vez. No alcanza con preguntarselo al documento ya
    creado: sanitize_text se usa antes y despues de armarlo, y si la respuesta
    dependiera de eso el mismo texto saldria distinto segun el orden.
    """
    global _FUENTES_EN_EL_EQUIPO
    if _FUENTES_EN_EL_EQUIPO is None:
        carpeta = carpeta_de_fuentes()
        _FUENTES_EN_EL_EQUIPO = all((carpeta / a).exists() for _, _, a in _ARCHIVOS_DE_FUENTE)
    return _FUENTES_EN_EL_EQUIPO


def cargar_fuentes_unicode(pdf) -> bool:
    """
    Incrusta en el informe fuentes que cubran cualquier alfabeto.

    Hasta esta version el dictamen usaba las fuentes base del PDF, que solo
    entienden latin-1, y antes de escribir pasaba todo por sanitize_text, que
    borraba el resto. El efecto medido: "Munoz" en lugar de "Muñoz", y un
    comentario en arabe, persa, ruso, hebreo, chino o japones quedaba en un
    renglon vacio. La prueba estaba en el caso: se capturaron comentarios de
    cuentas persas. El original nunca se perdio —el listado .txt va en UTF-8 y
    la captura PNG muestra la pantalla— pero el dictamen, que es lo que lee el
    juzgado, mutilaba la transcripcion.

    Se usan las fuentes de Windows: Arial, que es metricamente igual a
    Helvetica y por eso no mueve la maquetacion de las tablas, y Courier New
    para los bloques de hash. Como respaldo, Microsoft YaHei para chino y
    japones y Segoe UI Emoji. Las cuatro permiten incrustarse (fsType 8). Al
    PDF entra solo el subconjunto de glifos que se usa.

    Las lenguas que se escriben de derecha a izquierda necesitan ademas un
    motor de composicion: sin el, el arabe sale sin ligar y al reves. Lo provee
    uharfbuzz a traves de fpdf2.

    Es lo que pide la afirmacion CDX-CA-06 de la especificacion del NIST para
    herramientas de extraccion en la nube, tomada aca como referencia: "the
    tool renders non-English text correctly".

    Si en el equipo faltara alguna fuente, el informe sigue saliendo con las
    de antes: feo para otros alfabetos, pero sale.
    """
    global FUENTE_INFORME, FUENTE_MONO, FUENTES_DEL_INFORME, _FUENTES_EN_EL_EQUIPO
    carpeta = carpeta_de_fuentes()
    try:
        if not hay_fuentes_unicode():
            raise FileNotFoundError("faltan fuentes en %s" % carpeta)
        for familia, estilo, archivo in _ARCHIVOS_DE_FUENTE:
            pdf.add_font(familia, estilo, str(carpeta / archivo))
    except Exception as e:
        _FUENTES_EN_EL_EQUIPO = False
        registrar_fallo_critico(
            "FUENTES",
            f"El dictamen se genera sin fuentes Unicode ({e}): los textos que no sean "
            f"del alfabeto latino no se van a transcribir")
        return False

    respaldos = []
    for nombre, archivo in (("cjk", "msyh.ttc"), ("emoji", "seguiemj.ttf")):
        try:
            pdf.add_font(nombre, "", str(carpeta / archivo))
            respaldos.append(nombre)
        except Exception:
            pass
    if respaldos:
        pdf.set_fallback_fonts(respaldos)
    try:
        pdf.set_text_shaping(True)
        composicion = True
    except Exception:
        composicion = False

    FUENTE_INFORME, FUENTE_MONO = "texto", "mono"
    FUENTES_DEL_INFORME = (
        "Arial y Courier New incrustadas"
        + (", con respaldo de %s" % " y ".join(
            {"cjk": "Microsoft YaHei (chino y japones)",
             "emoji": "Segoe UI Emoji"}[r] for r in respaldos) if respaldos else "")
        + (", y composicion de derecha a izquierda con HarfBuzz" if composicion
           else "; sin motor de composicion: el arabe y el hebreo salen sin ligar"))
    return True


def sanitize_text(text: Any) -> str:
    """
    Prepara un texto para el informe sin alterarlo.

    Solo saca los caracteres de control, que romperian el PDF. Lo demas queda
    como fue adquirido: una transcripcion que cambia el texto no sirve de
    transcripcion. Ver cargar_fuentes_unicode.

    Si no se pudieron cargar las fuentes Unicode se vuelve al comportamiento
    anterior —pasar a latin-1 y descartar el resto— porque con las fuentes
    base del PDF un caracter fuera de ese juego aborta la generacion, y es
    preferible un informe con el texto degradado a no tener informe.
    """
    if not text:
        return "N/A"
    t = str(text).replace("\r", " ")
    t = "".join(c for c in t
                if c in "\n\t" or unicodedata.category(c)[0] != "C")
    if hay_fuentes_unicode():
        return t
    n = unicodedata.normalize("NFKD", t)
    return "".join(c for c in n if not unicodedata.combining(c)) \
        .encode("latin-1", "ignore").decode("latin-1")

def is_valid_video(path: str) -> bool:
    try:
        if path.lower().endswith(".enc"):
            return False
        if os.path.getsize(path) < 1024:
            return False
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            cap.release()
            return False
        # Algunos videos tienen headers largos; intentar hasta 15 frames
        for _ in range(15):
            ret, frame = cap.read()
            if ret and frame is not None:
                cap.release()
                return True
        cap.release()
        return False
    except Exception:
        return False

def extract_video_frame(video_path: str, output_dir: Path) -> Optional[str]:
    if not is_valid_video(video_path):
        return None
    try:
        cap = cv2.VideoCapture(video_path)
        ret, frame = False, None
        # Robustez: leer hasta 30 frames para saltar headers/corruptos
        for _ in range(30):
            ret, frame = cap.read()
            if ret and frame is not None:
                break
        cap.release()
        if not ret or frame is None:
            return None
        ts = datetime.datetime.now().strftime("%H%M%S_%f")
        out_path = str(output_dir / f"thumb_video_{ts}.jpg")
        cv2.imwrite(out_path, frame, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
        return out_path if os.path.exists(out_path) else None
    except Exception:
        return None

def decidir_tramo(w: Dict[str, Any], d: Dict[str, Any], nuevos: int = 0,
                  tope_esperas: int = 5) -> Dict[str, Any]:
    """
    Decide que hacer con un tramo de un recorrido: esperar a que cargue,
    fotografiarlo, o seguir de largo.

    La usan el recorrido de comentarios y el de listas, que hacen lo mismo.
    Tenerla suelta y no repetida adentro de cada uno es a proposito: cuando
    estaban duplicadas, una correccion se aplico a una y no a la otra, y ningun
    ojo lo noto hasta que fallo en uso real.

    Devuelve:
      esperar  : hay que reintentar el tramo sin capturar
      parcial  : se captura aunque la vista siga cargando (se agoto la espera)
      capturar : corresponde fotografiar
      movio    : la vista cambio de posicion respecto del tramo anterior
      quieto   : no se movio y tampoco esta al fondo

    EL ERROR QUE CORRIGE. La posicion previa se actualiza SOLO cuando el tramo
    se procesa de verdad. Antes se actualizaba tambien en las vueltas de
    espera, de modo que al reintentar la posicion coincidia con la anterior,
    'movio' daba falso y la captura no se disparaba nunca. En Facebook, donde
    casi todos los tramos pasan por la espera, el relevamiento terminaba con el
    texto completo y sin una sola imagen que lo respaldara.
    """
    pos = int(d.get("pos", 0) or 0)
    alto = int(d.get("alto", 0) or 0)
    visible = int(d.get("visible", 0) or 0)
    fondo = max(alto - visible, 0)

    # Los comentarios que llegan durante las vueltas de espera se suman: la
    # lectura los toma en la vuelta que los ve, y si esa vuelta es una espera
    # la cuenta se perdia. En el log se veia el total subir de 11 a 21 mientras
    # cada tramo informaba "0 nuevos", y el recorrido se cortaba creyendo que
    # ya no llegaba nada.
    w["nuevos_acum"] = w.get("nuevos_acum", 0) + int(nuevos or 0)

    if d.get("cargando") and w.get("esperas", 0) < tope_esperas:
        w["esperas"] = w.get("esperas", 0) + 1
        return {"esperar": True, "parcial": False, "capturar": False,
                "movio": False, "quieto": False, "pos": pos, "fondo": fondo,
                "nuevos": 0}

    parcial = bool(d.get("cargando"))
    w["esperas"] = 0
    nuevos_tramo = w.get("nuevos_acum", 0)
    w["nuevos_acum"] = 0

    previa = w.get("pos_previa")
    movio = previa is None or pos != previa
    quieto = previa is not None and pos == previa and pos < fondo - 4
    w["pos_previa"] = pos

    return {"esperar": False, "parcial": parcial,
            "capturar": (w.get("tramo") == 1 or movio),
            "movio": movio, "quieto": quieto, "pos": pos, "fondo": fondo,
            "nuevos": nuevos_tramo}


def datos_del_sello(lineas):
    """
    Prepara los datos del sello para grabarlos DENTRO del PNG.

    El sello dejo de dibujarse sobre la imagen. Primero estuvo encima y tapaba
    contenido (en la pagina completa se comia los ultimos 126 pixeles, y en el
    recorte de una columna de comentarios, los comentarios). Despues paso a una
    franja negra agregada abajo, que no tapaba nada pero seguia ensuciando una
    imagen que se acompana como prueba de como se veia la pagina.

    Ahora no se ve: los mismos datos (herramienta, causa, momento, hash y
    perito) van en los campos de texto del propio PNG. La imagen queda limpia,
    sin un pixel agregado, y el archivo se sigue identificando solo aunque se
    lo separe de su acta. Se leen con cualquier visor de metadatos, o con
    Pillow: Image.open(ruta).text

    La constancia fuerte de integridad no es ni fue nunca el sello, sino el
    hash del archivo, su sidecar y el acta de custodia.
    """
    from PIL import PngImagePlugin
    meta = PngImagePlugin.PngInfo()
    puestas = set()
    for i, linea in enumerate(lineas):
        texto = str(linea)
        if ":" in texto:
            clave, valor = texto.split(":", 1)
            clave, valor = clave.strip()[:60], valor.strip()
        else:
            # La primera linea sin rotulo es el nombre de la herramienta; las
            # siguientes son la descripcion de lo capturado.
            clave = "Herramienta" if i == 0 else "Detalle"
            valor = texto.strip()
        # Un mismo rotulo dos veces perderia el primero al leerlo.
        if clave in puestas:
            clave = "%s_%d" % (clave, i)
        puestas.add(clave)
        meta.add_text(clave, valor)
    return meta


def imagen_para_informe(origen: str, ancho_mm: float, carpeta_temp: Path,
                        dpi: int = 200, calidad: int = 80) -> str:
    """
    Devuelve una copia de la imagen lista para insertar en el dictamen: al
    tamaño con que se va a ver y comprimida con perdida.

    Sin esto el informe se vuelve inmanejable. Se midio sobre un dictamen real:
    110 MB en 417 hojas, de los cuales 109,9 MB eran imagenes y solo 0,7 MB
    texto. Las capturas se embebian enteras (2560 px de ancho, que impresas a
    135 mm son 482 dpi) y ademas sin perdida, a 900 KB cada una, para mostrarse
    del tamaño de media hoja.

    Lo que se recorta es resolucion sobrante y no contenido: a 200 dpi el texto
    de una captura de chat se lee igual en pantalla y en papel. Un dictamen que
    no se puede abrir ni mandar por correo tampoco cumple su funcion.

    La calidad se bajo de 92 a 80 despues de compararlas ampliadas cuatro veces
    sobre una captura de comentarios: a igual resolucion no se distingue una de
    otra y el archivo pesa la mitad. Lo que si se nota es el submuestreo de
    color, por eso va desactivado (subsampling=0): con el que trae JPEG por
    defecto los enlaces azules y el texto gris chico se ensucian, que es
    justamente lo que hay que poder leer. Baja resolucion no, calidad si: la
    resolucion es la que sostiene la legibilidad.

    Esto NO toca la prueba. El original queda intacto en la carpeta de
    evidencias con su hash y su acta; lo que se achica es la reproduccion que
    lleva el informe, del mismo modo que una fotocopia de un documento no
    reemplaza al documento.

    Si algo falla se devuelve el original: es preferible un informe pesado a un
    informe sin la imagen.
    """
    try:
        if not os.path.exists(origen):
            return origen
        objetivo_px = max(1, int(ancho_mm / 25.4 * dpi))
        with Image.open(origen) as im:
            if im.width <= objetivo_px and origen.lower().endswith((".jpg", ".jpeg")):
                return origen            # ya esta al tamaño y ya es con perdida
            # Las imagenes con transparencia se componen sobre BLANCO. Pasar
            # de RGBA a RGB sin decirlo las compone sobre negro, y un icono o
            # una ficha con texto oscuro sobre fondo transparente quedaba
            # ilegible en el informe sin que nada lo avisara.
            if im.mode in ("RGBA", "LA", "P"):
                im = im.convert("RGBA")
                fondo = Image.new("RGB", im.size, (255, 255, 255))
                fondo.paste(im, mask=im.split()[-1])
                im = fondo
            else:
                im = im.convert("RGB")
            if im.width > objetivo_px:
                alto = max(1, round(im.height * objetivo_px / im.width))
                im = im.resize((objetivo_px, alto), Image.LANCZOS)
            ts = datetime.datetime.now().strftime("%H%M%S_%f")
            destino = str(carpeta_temp / f"inf_{Path(origen).stem[:40]}_{ts}.jpg")
            im.save(destino, "JPEG", quality=calidad, optimize=True,
                    progressive=True, subsampling=0)
        return destino if os.path.exists(destino) else origen
    except Exception:
        return origen


_LOGO_PORTADA: Optional[str] = None


def logo_para_portada() -> str:
    """
    El logo del membrete, reducido a la medida en que se imprime.

    El archivo original mide 800x638 px y pesa 617 KB. La portada lo muestra en
    42 mm, que a 200 dpi son 330 px: todo lo demas es resolucion que nadie ve.
    fpdf2 embebe los PNG sin perdida, asi que ese logo agregaba 737 KB medidos
    a CADA dictamen (mas que todo el texto de un informe de 417 hojas, que
    pesaba 0,7 MB). Reducido cuesta 25 KB.

    Se calcula una sola vez por ejecucion y queda en el temporal del sistema,
    fuera de la carpeta del caso: es papeleria del informe, no evidencia. Si
    algo falla se usa el original, porque un dictamen pesado sigue siendo mejor
    que uno sin membrete.
    """
    global _LOGO_PORTADA
    if _LOGO_PORTADA and os.path.exists(_LOGO_PORTADA):
        return _LOGO_PORTADA
    if not (LOGO_PATH and os.path.exists(LOGO_PATH)):
        return LOGO_PATH
    _LOGO_PORTADA = imagen_para_informe(LOGO_PATH, 42.0,
                                        Path(tempfile.gettempdir()))
    return _LOGO_PORTADA


def generate_speaker_icon(output_dir: Path, size: int = 100) -> str:
    try:
        img = Image.new("RGB", (size, size), (240, 240, 240))
        draw = ImageDraw.Draw(img)

        box_x1, box_y1 = size * 0.15, size * 0.30
        box_x2, box_y2 = size * 0.45, size * 0.70
        draw.rectangle([box_x1, box_y1, box_x2, box_y2], fill=(80, 80, 80), outline=(40, 40, 40), width=2)

        cone_points = [
            (box_x2, box_y1),
            (size * 0.80, size * 0.15),
            (size * 0.80, size * 0.85),
            (box_x2, box_y2)
        ]
        draw.polygon(cone_points, fill=(100, 100, 100), outline=(40, 40, 40))

        cx, cy = size * 0.80, size * 0.50
        for radius in [size * 0.12, size * 0.20, size * 0.28]:
            draw.arc(
                [cx - radius, cy - radius, cx + radius, cy + radius],
                start=-60, end=60,
                fill=(46, 125, 50), width=3
            )

        try:
            font = ImageFont.truetype("arial.ttf", int(size * 0.12))
        except Exception:
            font = ImageFont.load_default()
        draw.text((size * 0.10, size * 0.82), "AUDIO", fill=(46, 125, 50), font=font)

        ts = datetime.datetime.now().strftime("%H%M%S_%f")
        out_path = str(output_dir / f"icon_audio_{ts}.png")
        img.save(out_path, "PNG")
        return out_path
    except Exception:
        return ""

#  SELLO DE TIEMPO RFC 3161
#
# Un sello vale lo que vale la verificacion de su firma. Hasta la version
# anterior el token se pedia y se guardaba sin comprobar nada: ni la firma, ni
# que sellara el hash pedido, ni que respondiera a este pedido. Como casi todas
# las autoridades responden por http, cualquiera en el camino de red podia
# devolver un token inventado (o uno autentico de otro archivo) y el programa
# lo consignaba en el dictamen como sello valido. Solo lo habria descubierto un
# tercero corriendo openssl.
#
# Estas son las raices que el programa acepta, identificadas por el hash
# SHA-256 de su clave publica y no por el certificado: la misma raiz circula en
# dos versiones (autofirmada y firmada en forma cruzada por una raiz anterior)
# y cada autoridad manda una u otra. La clave es la misma en las dos.
#
# No se usa el almacen de certificados de Windows para decidir: el resultado
# cambiaria de un equipo a otro, y cualquier programa con permisos puede
# agregarle raices. Estas cuatro salieron de respuestas reales cuyas cadenas
# verificaron contra el almacen de Windows; la de FreeTSA, contra el
# certificado que la autoridad publica por HTTPS en freetsa.org.
RAICES_TSA = {
    "59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c": "DigiCert Trusted Root G4",
    "a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795": "Sectigo Public Time Stamping Root R46",
    "6b3b57e9ec88d1bb3d01637ff33c7698b3c9758255e9f01ea9178f3e7f3b2b52": "Certum Trusted Network CA 2",
    "52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5": "FreeTSA Root CA",
}
_OID_SELLADO_TIEMPO = "1.3.6.1.5.5.7.3.8"


class SelloNoVerificado(Exception):
    """La respuesta de la autoridad no verifica: no cuenta como sello."""


def _hash_de_firma(nombre: str):
    # SHA-1 queda afuera a proposito: hoy se pueden fabricar colisiones, y un
    # sello cuya firma descansa en SHA-1 no se puede defender. Apple firma asi
    # sus sellos y por eso salio de la lista de autoridades.
    from cryptography.hazmat.primitives import hashes
    algos = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
    if nombre not in algos:
        raise SelloNoVerificado(f"firmado con {nombre}, algoritmo que no se acepta")
    return algos[nombre]()


def _huella_de_clave(cert) -> str:
    from cryptography.hazmat.primitives import serialization
    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _nombre_comun(cert) -> str:
    from cryptography.x509.oid import NameOID
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn[0].value if cn else cert.subject.rfc4514_string()


def verificar_sello(respuesta: bytes, digest: bytes, nonce: int,
                    raices: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Comprueba una respuesta RFC 3161 y devuelve el token con sus datos, o
    lanza SelloNoVerificado con el motivo.

    Lo que se exige, en este orden:
      1. que la autoridad haya otorgado el sello
      2. que responda a ESTE pedido (el numero de control) y selle ESTE hash
      3. que traiga el certificado de quien firmo
      4. que la firma sea valida y cubra el contenido y ese certificado
      5. que el certificado este habilitado para sellar tiempo
      6. que la cadena suba, eslabon por eslabon, hasta una raiz de RAICES_TSA,
         con todos los certificados vigentes en el momento del sello

    `raices` existe para las pruebas: permite comprobar que un sello armado
    con una clave propia se rechaza por su raiz y no por un defecto de
    construccion.
    """
    from asn1crypto import tsp
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    raices = RAICES_TSA if raices is None else raices

    try:
        resp = tsp.TimeStampResp.load(respuesta)
        estado = resp["status"]["status"].native
        token = resp["time_stamp_token"]
        sd = token["content"]
        encap = sd["encap_content_info"]
        info = encap["content"].parsed
        crudo_info = encap["content"].contents
    except Exception as e:
        raise SelloNoVerificado(f"respuesta ilegible ({type(e).__name__})")
    if estado not in ("granted", "granted_with_mods"):
        raise SelloNoVerificado(f"la autoridad no otorgo el sello ({estado})")
    if encap["content_type"].native != "tst_info":
        raise SelloNoVerificado("el contenido firmado no es un sello de tiempo")

    if info["nonce"].native != nonce:
        raise SelloNoVerificado("el numero de control no coincide: la respuesta "
                                "no corresponde a este pedido")
    imp = info["message_imprint"]
    if (imp["hash_algorithm"]["algorithm"].native != "sha256"
            or imp["hashed_message"].native != digest):
        raise SelloNoVerificado("el hash sellado no es el del archivo")
    momento = info["gen_time"].native

    certs = [c.chosen for c in sd["certificates"]
             if c.name == "certificate"] if sd["certificates"].native else []
    if len(sd["signer_infos"]) != 1:
        raise SelloNoVerificado("la respuesta trae mas de un firmante")
    si = sd["signer_infos"][0]
    sid = si["sid"]
    firmante_asn = None
    for c in certs:
        if sid.name == "issuer_and_serial_number":
            ias = sid.chosen
            if (c["tbs_certificate"]["issuer"].dump() == ias["issuer"].dump()
                    and c.serial_number == ias["serial_number"].native):
                firmante_asn = c
        elif c.key_identifier == sid.chosen.native:
            firmante_asn = c
    if firmante_asn is None:
        raise SelloNoVerificado("la respuesta no trae el certificado de quien la firmo")

    alg = si["digest_algorithm"]["algorithm"].native
    h = _hash_de_firma(alg)
    attrs = {a["type"].native: a["values"] for a in si["signed_attrs"]}
    if attrs.get("content_type") is None or attrs["content_type"][0].native != "tst_info":
        raise SelloNoVerificado("falta el tipo de contenido firmado")
    if (attrs.get("message_digest") is None
            or attrs["message_digest"][0].native != hashlib.new(alg, crudo_info).digest()):
        raise SelloNoVerificado("el contenido del sello fue alterado")
    # El certificado que viene en la respuesta tiene que ser el que firmo: si
    # no, alguien podria reemplazarlo por otro de la misma autoridad.
    der_firmante = firmante_asn.dump()
    if "signing_certificate_v2" in attrs:
        ident = attrs["signing_certificate_v2"][0]["certs"][0]
        h_id = ident["hash_algorithm"]["algorithm"].native
        coincide = ident["cert_hash"].native == hashlib.new(h_id, der_firmante).digest()
    elif "signing_certificate" in attrs:
        ident = attrs["signing_certificate"][0]["certs"][0]
        coincide = ident["cert_hash"].native == hashlib.sha1(der_firmante).digest()
    else:
        raise SelloNoVerificado("la firma no identifica el certificado firmante")
    if not coincide:
        raise SelloNoVerificado("el certificado incluido no es el que firmo")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        firmante = x509.load_der_x509_certificate(der_firmante)
        otros = [x509.load_der_x509_certificate(c.dump()) for c in certs]
    # Se firma la codificacion DER de los atributos como SET OF (etiqueta
    # 0x31), no con la etiqueta implicita [0] que llevan dentro del mensaje.
    firmado = b"\x31" + si["signed_attrs"].dump()[1:]
    algo_firma = si["signature_algorithm"]
    try:
        h_firma = _hash_de_firma(algo_firma.hash_algo)
    except (ValueError, KeyError):
        h_firma = h
    try:
        if algo_firma.signature_algo == "rsassa_pkcs1v15":
            firmante.public_key().verify(si["signature"].native, firmado,
                                         padding.PKCS1v15(), h_firma)
        elif algo_firma.signature_algo == "rsassa_pss":
            p = algo_firma["parameters"]
            firmante.public_key().verify(
                si["signature"].native, firmado,
                padding.PSS(mgf=padding.MGF1(_hash_de_firma(
                    p["mask_gen_algorithm"]["parameters"]["algorithm"].native)),
                    salt_length=p["salt_length"].native),
                _hash_de_firma(p["hash_algorithm"]["algorithm"].native))
        elif algo_firma.signature_algo == "ecdsa":
            firmante.public_key().verify(si["signature"].native, firmado, ec.ECDSA(h_firma))
        else:
            raise SelloNoVerificado(f"algoritmo de firma no admitido: {algo_firma.signature_algo}")
    except InvalidSignature:
        raise SelloNoVerificado("la firma de la autoridad no es valida")

    try:
        eku = firmante.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        raise SelloNoVerificado("el certificado firmante no esta habilitado para sellar tiempo")
    if not eku.critical or _OID_SELLADO_TIEMPO not in [o.dotted_string for o in eku.value]:
        raise SelloNoVerificado("el certificado firmante no esta habilitado para sellar tiempo")

    cadena = [firmante]
    actual = firmante
    raiz = None
    for _ in range(6):
        if not (actual.not_valid_before_utc <= momento <= actual.not_valid_after_utc):
            raise SelloNoVerificado(f"'{_nombre_comun(actual)}' no estaba vigente al sellar")
        huella = _huella_de_clave(actual)
        if huella in raices:
            raiz = raices[huella]
            break
        if actual.subject == actual.issuer:
            raise SelloNoVerificado(f"la cadena termina en '{_nombre_comun(actual)}', "
                                    f"que no es una raiz reconocida")
        emisor = None
        for c in otros:
            if c.subject == actual.issuer and c.subject != actual.subject:
                try:
                    actual.verify_directly_issued_by(c)
                    emisor = c
                    break
                except Exception:
                    continue
        if emisor is None:
            raise SelloNoVerificado(f"no se encuentra quien emitio '{_nombre_comun(actual)}'")
        try:
            es_ca = emisor.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        except x509.ExtensionNotFound:
            es_ca = False
        if not es_ca:
            raise SelloNoVerificado(f"'{_nombre_comun(emisor)}' no es una autoridad certificante")
        cadena.append(emisor)
        actual = emisor
    if raiz is None:
        raise SelloNoVerificado("la cadena no llega a una raiz reconocida")

    precision_s = None
    if info["accuracy"].native:
        p = info["accuracy"].native
        precision_s = ((p.get("seconds") or 0) + (p.get("millis") or 0) / 1e3
                       + (p.get("micros") or 0) / 1e6)
    return {"token": token.dump(), "momento": momento, "firmante": _nombre_comun(firmante),
            "raiz": raiz, "cadena": cadena, "precision_s": precision_s}


def _raiz_que_cierra(cert):
    """
    Busca en el almacen de Windows la raiz autofirmada que emitio `cert`.

    No interviene en la decision de aceptar el sello (eso lo resuelve
    RAICES_TSA). Sirve para el tercero que verifique con openssl: tres de las
    cuatro autoridades mandan su raiz firmada en forma cruzada, y openssl no
    cierra la cadena sin la version autofirmada de quien la firmo.
    """
    import ssl
    from cryptography import x509
    if cert.subject == cert.issuer or not hasattr(ssl, "enum_certificates"):
        return None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for der, cod, _ in ssl.enum_certificates("ROOT"):
            if cod != "x509_asn":
                continue
            try:
                r = x509.load_der_x509_certificate(der)
                if r.subject == cert.issuer and r.subject == r.issuer:
                    cert.verify_directly_issued_by(r)
                    return r
            except Exception:
                continue
    return None


class TimestampAuthority:
    # Timeout de la consulta a la TSA: alcanza para una respuesta normal y no
    # deja la interfaz colgada cuando el equipo esta sin red.
    TSA_TIMEOUT_S: int = 5

    @staticmethod
    def _sellar_en(tsa_url: str, data_hash: str, con_cadena: bool = False) -> Dict[str, Any]:
        """
        Pide el sello a una autoridad concreta y lo verifica antes de aceptarlo.
        Propaga la excepcion si la autoridad no responde o si el sello no verifica.

        Se aprovecha el viaje para medir el reloj del equipo contra la hora que
        la autoridad firma: a diferencia de la consulta NTP, esa hora no la
        puede falsear nadie en el camino.
        """
        import secrets
        import requests as _rq
        from asn1crypto import tsp
        digest = bytes.fromhex(data_hash)
        nonce = secrets.randbits(62) + 1
        pedido = tsp.TimeStampReq({
            "version": 1,
            "message_imprint": {"hash_algorithm": {"algorithm": "sha256"},
                                "hashed_message": digest},
            "nonce": nonce,
            # Se pide que la respuesta traiga los certificados: sin ellos no
            # se puede verificar aca, y tampoco podria hacerlo un tercero.
            "cert_req": True,
        }).dump()
        t0 = time.time()
        r = _rq.post(tsa_url, data=pedido, timeout=TimestampAuthority.TSA_TIMEOUT_S,
                     headers={"Content-Type": "application/timestamp-query"})
        t1 = time.time()
        r.raise_for_status()
        v = verificar_sello(r.content, digest, nonce)
        res = {
            "token_b64": base64.b64encode(v["token"]).decode("ascii"),
            "timestamp_iso": v["momento"].isoformat().replace("+00:00", "Z"),
            "tsa_url": tsa_url,
            "hash": data_hash,
            "verificado": True,
            "firmante": v["firmante"],
            "raiz": v["raiz"],
            # La hora firmada cae entre el envio y la respuesta; el margen es
            # medio viaje mas la precision que declara la autoridad, o un
            # segundo si no la declara (la mayoria sella al segundo).
            "desfase_reloj_s": round(v["momento"].timestamp() - (t0 + t1) / 2, 3),
            "incertidumbre_s": round((t1 - t0) / 2 + (v["precision_s"]
                                     if v["precision_s"] is not None else 1.0), 3),
        }
        if con_cadena:
            from cryptography.hazmat.primitives import hashes, serialization
            certs = list(v["cadena"])
            cierre = _raiz_que_cierra(certs[-1])
            if cierre is not None:
                certs.append(cierre)
            res["respuesta_b64"] = base64.b64encode(r.content).decode("ascii")
            res["cadena_pem"] = b"".join(
                c.public_bytes(serialization.Encoding.PEM) for c in certs).decode("ascii")
            res["raiz_cierre"] = _nombre_comun(certs[-1])
            res["raiz_cierre_sha256"] = certs[-1].fingerprint(hashes.SHA256()).hex()
        return res

    @staticmethod
    def stamp(data_hash: str, tsa_url: Optional[str] = None,
              con_cadena: bool = False) -> Optional[Dict[str, Any]]:
        """
        Obtiene el sello de tiempo RFC 3161 del hash indicado, ya verificado.

        Recorre las autoridades de TSA_URLS hasta que una entrega un sello que
        verifica. Si se pasa `tsa_url` se usa solo esa. El resultado incluye
        'tsa_nombre' y, cuando hubo que recurrir a una alternativa,
        'tsa_intentos' con el detalle de las que fallaron, para que quede
        asentado en la cadena de custodia.

        Una respuesta que no verifica no es un corte de red: es una respuesta
        que alguien pudo haber fabricado. Por eso, ademas de pasar a la
        siguiente autoridad, queda registrada como fallo y sale en el dictamen.
        """
        candidatas = ([("Indicada", tsa_url)] if tsa_url else TSA_URLS)
        fallidas = []
        for nombre, url in candidatas:
            try:
                res = TimestampAuthority._sellar_en(url, data_hash, con_cadena)
                res["tsa_nombre"] = nombre
                if fallidas:
                    res["tsa_intentos"] = fallidas
                return res
            except SelloNoVerificado as e:
                fallidas.append(f"{nombre}: sello rechazado ({e})")
                registrar_fallo_critico(
                    "SELLO_TIEMPO",
                    f"{nombre} devolvio un sello que no verifica: {e}")
            except Exception as e:
                fallidas.append(f"{nombre}: {type(e).__name__}")

        return {
            "error": "Ninguna autoridad de sellado entrego un sello verificable",
            "tsa_intentos": fallidas,
            "hash": data_hash,
            "tsa_url": candidatas[0][1] if candidatas else TSA_URL,
        }


def escribir_sello_aparte(ruta: str, digest_hex: str) -> Optional[Dict[str, Any]]:
    """
    Sella un archivo y deja a su lado lo que un tercero necesita para
    comprobar el sello por su cuenta con openssl:

      <archivo>.tsr      la respuesta completa de la autoridad
      <archivo>.tsa.pem  su cadena de certificados, hasta una raiz autofirmada

    Antes se escribia solo el token con extension .tsr, y la instruccion del
    dictamen (openssl ts -verify -in <caso>.zip.tsr) fallaba tal como estaba
    escrita: openssl espera la respuesta, no el token. Se comprobo con
    OpenSSL 3.5 sobre respuestas reales de las cuatro autoridades.
    """
    s = TimestampAuthority.stamp(digest_hex, con_cadena=True)
    if not (isinstance(s, dict) and s.get("token_b64")):
        return s
    tsr = Path(str(ruta) + ".tsr")
    tsr.write_bytes(base64.b64decode(s.pop("respuesta_b64")))
    pem = Path(str(ruta) + ".tsa.pem")
    pem.write_text(s.pop("cadena_pem"), encoding="ascii")
    s["tsr_path"], s["pem_path"] = str(tsr), str(pem)
    return s

# CONTENEDOR DE CASO FORENSE 
class ForensicCase:
    def __init__(self, case_data: Dict[str, str], perito_data: Dict[str, str]):
        self.case_data = case_data
        self.perito_data = perito_data
        self.ts_start = datetime.datetime.now()
        self.case_id = f"TFWF_{self.ts_start.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        base_dir = case_data.get("base_dir", "").strip()
        if base_dir:
            self.root = Path(base_dir) / "NAV_FORENSE" / self.case_id
        else:
            self.root = get_app_dir() / "NAV_FORENSE" / self.case_id

        self.dirs = {
            "evidence_raw": self.root / "evidence" / "raw",
            "evidence_img": self.root / "evidence" / "screenshots",
            "evidence_vid": self.root / "evidence" / "session_video",
            "thumbs": self.root / "evidence" / "thumbnails",
            "network": self.root / "network",
            "db": self.root / "db",
            "report": self.root / "report",
            "export": self.root / "export",
        }
        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)

        # Firma del log de auditoria (ver log() y firmar_cabeza()).
        #
        # La clave se genera aca y NO se escribe nunca en disco. Antes el log
        # se protegia con un HMAC cuya clave quedaba en hmac.key, dentro del
        # mismo paquete que el log: quien tuviera el ZIP podia reescribir el
        # log y volver a calcular los HMAC. Con una firma, la parte publica va
        # en el manifiesto y alcanza para verificar pero no para firmar; la
        # privada existe solo mientras el programa esta abierto.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self._clave_log = Ed25519PrivateKey.generate()
        self.clave_publica_log = self._clave_log.public_key().public_bytes_raw().hex()
        self._log_lock = threading.RLock()
        self._cabeza_log = ""
        self._entradas_log = 0
        self._sin_firmar = 0

        # Sincronización NTP al inicio del caso: ISO 27037 exige documentar
        # la fuente de tiempo. Se hace antes de escribir el manifest.
        self.ntp_info = get_ntp_info()

        self.db_path = self.dirs["db"] / "audit.db"
        self._init_db()
        self.manifest_path = self.root / "manifest.json"
        self._write_manifest()

        # Autodiagnostico antes de adquirir nada: si una funcion criptografica
        # o el sellado no estan en condiciones, conviene saberlo ahora y no al
        # revisar el dictamen. Queda asentado en el log y en el informe.
        self.caso_cerrado = False
        self.diagnostico = autodiagnostico(root_caso=self.root, verificar_red=True)
        for c in self.diagnostico:
            self.log("INFO" if c["ok"] else "WARN", "AUTODIAGNOSTICO",
                     f"{'OK' if c['ok'] else 'FALLA'} | {c['prueba']} | {c['detalle']}")
            if not c["ok"]:
                registrar_fallo_critico("AUTODIAGNOSTICO",
                                        f"{c['prueba']}: {c['detalle']}")
        # Si la hora NTP no coincide con la firmada, alguien pudo haber
        # respondido la consulta NTP en lugar del servidor. Manda la firmada.
        _ch = next((c["contraste_hora"] for c in self.diagnostico
                    if c.get("contraste_hora")), None)
        _ntp = self.ntp_info.get("offset_segundos")
        if _ch and _ntp is not None and abs(_ntp - _ch["desfase_s"]) > _ch["margen_s"] + 2:
            _aviso = (f"La consulta NTP informo un desfase de {_ntp:+.2f} s y la hora firmada "
                      f"por {_ch['autoridad']}, {_ch['desfase_s']:+.2f} s: no coinciden, y se "
                      f"toma como referencia la firmada")
            self.log("ADVERTENCIA", "TIEMPO", _aviso)
            registrar_fallo_critico("TIEMPO", _aviso)

        # Tabla para metadatos de sitios visitados
        self.site_metadata: List[Dict] = []

        # Verificaciones de Binary Transparency (integridad del codigo de los
        # portales de Meta contra el hash raiz publicado por Cloudflare)
        self.bt_verifications: List[Dict] = []

        self.har_path = self.dirs["network"] / "session.har"
        self.har_entries: List[Dict] = []
        self.har_started = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        self.evidences: List[Dict] = []

        # Buffer en memoria para el log de red (categoría NETWORK). Evita abrir
        # una conexión SQLite por cada petición: se vuelca en lote periódicamente.
        self._net_buffer: List[tuple] = []
        self._net_lock = threading.Lock()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    level TEXT NOT NULL,
                    category TEXT NOT NULL,
                    message TEXT NOT NULL,
                    cadena TEXT NOT NULL,
                    UNIQUE(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS firmas_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    hasta_id INTEGER NOT NULL,
                    entradas INTEGER NOT NULL,
                    cabeza TEXT NOT NULL,
                    firma TEXT NOT NULL,
                    motivo TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_registry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    tipo TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER,
                    source_url TEXT,
                    tsa_token TEXT,
                    metadata TEXT
                )
            """)

    def _write_manifest(self):
        manifest = {
            "format": "TFWF_PRO",
            "version": "1.2",
            "case_id": self.case_id,
            "created": self.ts_start.isoformat(),
            "perito": self.perito_data,
            "case": self.case_data,
            "system": {
                "hostname": socket.gethostname(),
                "platform": get_windows_version(),
                "python": platform.python_version(),
            },
            "tool_integrity": {
                "self_hash_sha256": get_self_hash(),
                "software": SOFTWARE_INFO["software"],
                "version": SOFTWARE_INFO["version"],
            },
            "tiempo_forense": self.ntp_info,
            # Clave publica de la firma del log. Queda aca desde el primer
            # minuto del caso y viaja en el paquete, que se sella al cerrar:
            # cambiarla despues cambiaria el hash del ZIP.
            "firma_log": {
                "algoritmo": "Ed25519 (RFC 8032) sobre una cadena SHA-256",
                "clave_publica": self.clave_publica_log,
                "nota": ("Cada entrada del log se encadena a la anterior con SHA-256 y el "
                         "extremo de la cadena se firma con esta clave cada 200 entradas, "
                         "al emitir el dictamen y antes de empaquetar. La clave privada se "
                         "genero al abrir el caso, vive solo en la memoria del programa y "
                         "no se escribe en disco."),
            },
        }
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

    def log(self, level: str, category: str, message: str):
        ts = datetime.datetime.now().isoformat()
        with self._log_lock:
            ok = self._insertar_log([(ts, level, category, message)])
        # Tras cerrar el caso la base queda en solo-lectura a proposito, y
        # que falle es lo esperado: el cierre ya esta certificado por el
        # ZIP, el dictamen y los sidecar. Antes de cerrar, en cambio, un
        # fallo aca significa perder trazabilidad y hay que avisarlo.
        if not ok and not getattr(self, "caso_cerrado", False):
            registrar_fallo_critico(
                "AUDIT_LOG",
                f"No se pudo escribir en el log de auditoria ({category})")

    def log_network(self, message: str):
        """
        Registro de red de alto volumen (categoría NETWORK). Solo lo guarda en
        un buffer en memoria: NO abre la base de datos. El volcado a SQLite se
        hace en lote con flush_network_log(). Esto evita cientos de escrituras a
        disco por segundo durante la navegación, que hacían que las
        publicaciones cargaran lento.

        El eslabon de la cadena se calcula al volcar y no aca: la cadena tiene
        que seguir el orden en que las entradas quedan guardadas.
        """
        ts = datetime.datetime.now().isoformat()
        with self._net_lock:
            self._net_buffer.append((ts, "INFO", "NETWORK", message))

    def flush_network_log(self):
        """Vuelca el buffer de red a SQLite en una sola transacción (rápido)."""
        with self._net_lock:
            if not self._net_buffer:
                return
            pending = self._net_buffer
            self._net_buffer = []
        with self._log_lock:
            ok = self._insertar_log(pending)
        # DB en solo-lectura tras el cierre: se descarta el buffer sin abortar.
        if not ok and not getattr(self, "caso_cerrado", False):
            registrar_fallo_critico(
                "AUDIT_LOG",
                f"Se perdieron {len(pending)} registros de red del log de auditoria")

    # Cada cuantas entradas se firma el extremo de la cadena. Si el programa
    # se corta, lo firmado hasta el ultimo cierre sigue siendo verificable.
    FIRMA_LOG_CADA = 200

    def _insertar_log(self, filas) -> bool:
        """
        Encadena e inserta entradas del log. Se llama con _log_lock tomado: la
        cadena sigue el orden de insercion, que es el de los id, y dos hilos
        insertando a la vez la desordenarian.

        Si la base rechaza la escritura, el extremo de la cadena no avanza y
        sigue coincidiendo con lo que quedo guardado.
        """
        cabeza = self._cabeza_log
        registros = []
        for ts, level, category, message in filas:
            cabeza = encadenar_log(cabeza, ts, level, category, message)
            registros.append((ts, level, category, message, cabeza))
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.executemany(
                    "INSERT INTO audit_log (ts, level, category, message, cadena) "
                    "VALUES (?,?,?,?,?)", registros)
        except sqlite3.OperationalError:
            return False
        self._cabeza_log = cabeza
        self._entradas_log += len(registros)
        self._sin_firmar += len(registros)
        if self._sin_firmar >= self.FIRMA_LOG_CADA:
            self.firmar_cabeza("periodica")
        return True

    def firmar_cabeza(self, motivo: str) -> Optional[Dict[str, Any]]:
        """
        Firma el extremo actual de la cadena del log y lo guarda en firmas_log.

        Se firma el caso, la ultima entrada, cuantas hay y el eslabon de esa
        entrada. Quien rehaga el log despues (aunque recalcule la cadena
        entera) no puede producir firmas que verifiquen con la clave publica
        del manifiesto.

        Devuelve lo firmado, o None si ya no hay clave (caso empaquetado) o si
        la base no admite escritura.
        """
        with self._log_lock:
            if self._clave_log is None or not self._entradas_log:
                return None
            cabeza, entradas = self._cabeza_log, self._entradas_log
            try:
                with sqlite3.connect(str(self.db_path)) as conn:
                    hasta_id = conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0]
                    firma = self._clave_log.sign(
                        mensaje_firma_log(self.case_id, hasta_id, entradas, cabeza)).hex()
                    conn.execute(
                        "INSERT INTO firmas_log (ts, hasta_id, entradas, cabeza, firma, motivo) "
                        "VALUES (?,?,?,?,?,?)",
                        (datetime.datetime.now().isoformat(), hasta_id, entradas,
                         cabeza, firma, motivo))
            except sqlite3.OperationalError:
                return None
            self._sin_firmar = 0
            return {"hasta_id": hasta_id, "entradas": entradas, "cabeza": cabeza,
                    "firma": firma}

    def descartar_clave_log(self):
        """
        Suelta la clave privada una vez empaquetado el caso: desde ese momento
        el programa ya no puede firmar nada mas en este log.

        Python no permite borrar memoria de forma segura. Lo que se garantiza es
        que la clave nunca estuvo en disco y que el programa deja de tenerla.
        """
        with self._log_lock:
            self._clave_log = None

    def register_evidence(self, tipo: str, path: str, source_url: str = "",
                          metadata: Optional[Dict] = None) -> Dict:
        ts = datetime.datetime.now().isoformat()
        h = sha256_file(path)
        size = os.path.getsize(path) if os.path.exists(path) else 0

        # Una evidencia sin hash valido no tiene integridad verificable. Se
        # registra igual, porque borrarla seria peor, pero queda marcada como
        # comprometida y el fallo aparece en el dictamen.
        if h == HASH_FALLIDO:
            registrar_fallo_critico(
                "EVIDENCIA",
                f"{tipo} '{os.path.basename(path)}' quedo SIN hash de integridad")
            self.log("ERROR", "EVIDENCE",
                     f"SIN HASH: {tipo} | {os.path.basename(path)} | "
                     f"la evidencia no puede verificarse")

        tsa_result = TimestampAuthority.stamp(h)
        tsa_token = json.dumps(tsa_result) if isinstance(tsa_result, dict) else ""

        # Sin sello de tiempo la prueba pierde la constancia temporal de un
        # tercero. No invalida la adquisicion, pero tiene que constar.
        if isinstance(tsa_result, dict) and not tsa_result.get("token_b64"):
            motivo = tsa_result.get("error") or tsa_result.get("warning") or "causa desconocida"
            registrar_fallo_critico(
                "SELLO_TIEMPO",
                f"{os.path.basename(path)} sin sello RFC 3161: {motivo}")

        ev = {
            "ts": ts,
            "tipo": tipo,
            "filename": os.path.basename(path),
            "path": path,
            "sha256": h,
            "size_bytes": size,
            "source_url": source_url,
            "tsa": tsa_result,
            "integridad_ok": h != HASH_FALLIDO,
            "metadata": json.dumps(metadata) if metadata else "{}"
        }

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                INSERT INTO evidence_registry
                (ts, tipo, filename, path, sha256, size_bytes, source_url, tsa_token, metadata)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (ts, tipo, ev["filename"], path, h, size, source_url, tsa_token, ev["metadata"]))

        self.evidences.append(ev)
        self.log("INFO", "EVIDENCE", f"Registrada {tipo}: {ev['filename']} | SHA256: {h[:16]}...")
        return ev

    def add_har_entry(self, entry: Dict):
        self.har_entries.append(entry)

    def save_har(self):
        # Volcar el buffer de red pendiente antes de persistir/certificar.
        self.flush_network_log()
        har = {
            "log": {
                "version": HAR_VERSION,
                "creator": {"name": SOFTWARE_INFO["software"], "version": SOFTWARE_INFO["version"]},
                "pages": [{
                    "startedDateTime": self.har_started,
                    "id": self.case_id,
                    "title": f"Sesion forense {self.case_id}",
                    "pageTimings": {"onContentLoad": -1, "onLoad": -1}
                }],
                "entries": self.har_entries
            }
        }
        with open(self.har_path, "w", encoding="utf-8") as f:
            json.dump(har, f, indent=2, ensure_ascii=False)
        self.log("INFO", "NETWORK", f"HAR guardado: {self.har_path}")
        return str(self.har_path)

# INTERCEPTOR DE RED
class ForensicNetworkInterceptor(QWebEngineUrlRequestInterceptor):
    # Client Hints requeridos por Instagram/reCAPTCHA desde mid-2026
    _CH_HEADERS = {
        "Sec-CH-UA":                  '"Google Chrome";v="140", "Chromium";v="140", "Not/A)Brand";v="24"',
        "Sec-CH-UA-Mobile":           "?0",
        "Sec-CH-UA-Platform":         '"Windows"',
        "Sec-CH-UA-Full-Version-List": '"Google Chrome";v="140.0.0.0", "Chromium";v="140.0.0.0", "Not/A)Brand";v="24.0.0.0"',
        "Sec-CH-UA-Platform-Version": '"10.0.0"',
        "Sec-CH-UA-Arch":             '"x86"',
        "Sec-CH-UA-Bitness":          '"64"',
        "Sec-CH-UA-Model":            '""',
        "Sec-CH-Prefers-Color-Scheme": "light",
    }
    _CH_DOMAINS = ("instagram.com", "facebook.com", "fbcdn.net", "google.com", "gstatic.com")

    def __init__(self, case: ForensicCase):
        super().__init__()
        self.case = case
        self._lock = threading.Lock()

    @staticmethod
    def _classify_media(url: str) -> Optional[str]:
        """
        Clasifica una URL como tipo de media o None si no es media relevante.
        Retorna: 'VIDEO', 'AUDIO', 'STREAM', 'ENCRIPTADO' o None.
        Las imágenes NO se detectan (se descartan): la lista de media es solo
        para video/audio, que es lo que el perito adquiere desde el dropdown.
        """
        u = url.lower()

        # Excluir explícitamente thumbnails, previews, avatares e imágenes de UI
        thumbnail_indicators = [
            "thumbnail", "thumb", "preview", "sticker",
            "profile_pic", "avatar", "emoji",
            "s150x150", "s320x320", "s640x640",
            "p240x240", "p320x320",
            "_t.jpg", "_t.jpeg",
            "scontent-", "fbexternal",
            "logging", "analytics", "beacon",
        ]
        if any(t in u for t in thumbnail_indicators):
            return None

        # El manifiesto de transparencia es el inventario de codigo del portal,
        # no un medio que el perito vaya a adquirir. Como el nombre lleva
        # "manifest" caeria en STREAM y ensuciaria la lista. Su verificacion se
        # registra por separado.
        if "btmanifest" in u:
            return None

        # Imágenes estáticas de CDN (no son el video que el perito está viendo)
        if any(u.endswith(ext) or (ext + "?") in u or (ext + "&") in u
               for ext in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".svg")):
            return None

        # Video
        if any(ind in u for ind in [
            ".mp4", ".m4v", ".mov", ".mkv", ".avi", ".flv", ".webm",
            "mms-type=video", "video_redirect", "video/mp4",
        ]):
            return "VIDEO"

        # Audio
        if any(ind in u for ind in [
            ".opus", ".aac", ".mp3", ".ogg", ".wav", ".m4a",
            "mms-type=audio", "audio/",
        ]):
            return "AUDIO"

        # Stream adaptativo (HLS/DASH)
        if any(ind in u for ind in [".m3u8", ".mpd", "manifest", "/segments/", "/chunk"]):
            return "STREAM"

        # WhatsApp encriptado
        if any(ind in u for ind in [".enc?", ".enc&", "/fna.whatsapp.net", "/cdn.whatsapp.net"]):
            return "ENCRIPTADO"

        # CDN Instagram/Facebook con path de media (contiene /v/ o /t/ en el path)
        # Solo si no es imagen ya filtrada arriba
        if ("cdninstagram" in u or "fbcdn" in u):
            # Los videos de Instagram tienen /v/ en el path o extensión de video
            if "/v/" in u or "/video/" in u or ".mp4" in u:
                return "VIDEO"
            # Los audios tienen /a/ o mms-type=audio
            if "/a/" in u or "audio" in u:
                return "AUDIO"
            # Descartar el resto (son imágenes del CDN)
            return None

        return None

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        Normaliza la URL quitando parámetros de firma/token que varían
        entre reintentos pero identifican el mismo archivo.
        Permite deduplicar: misma URL normalizada = mismo recurso.
        """
        from urllib.parse import urlparse, urlencode, parse_qsl
        try:
            p = urlparse(url)
            # Parámetros de firma/token a descartar
            skip = {
                "_nc_sid", "_nc_ht", "_nc_cat", "_nc_ohc", "_nc_hash",
                "efg", "oh", "oe", "ig_cache_key",       # Instagram
                "bytestart", "byteend",                   # segmentos de stream
                "ccb", "dl", "rl", "vt",                  # Facebook
                "token", "signature", "Expires",          # genéricos
                "X-Amz-Signature", "X-Amz-Date",          # AWS
            }
            filtered = [(k, v) for k, v in parse_qsl(p.query) if k not in skip]
            normalized = p._replace(query=urlencode(filtered), fragment="").geturl()
            return normalized
        except Exception:
            return url

    def interceptRequest(self, info):
        ts     = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        url    = info.requestUrl().toString()
        method = info.requestMethod().data().decode()

        # Inyectar Client Hints para Instagram/reCAPTCHA
        if any(d in url for d in self._CH_DOMAINS):
            for header, value in self._CH_HEADERS.items():
                info.setHttpHeader(header.encode(), value.encode())

        self.case.log_network(f"{method} {url}")

        entry = {
            "startedDateTime": ts, "time": 0,
            "request": {
                "method": method, "url": url, "httpVersion": "HTTP/1.1",
                "cookies": [], "headers": [], "queryString": [],
                "headersSize": -1, "bodySize": -1
            },
            "response": {
                "status": 0, "statusText": "", "httpVersion": "HTTP/1.1",
                "cookies": [], "headers": [],
                "content": {"size": 0, "mimeType": "x-unknown"},
                "redirectURL": "", "headersSize": -1, "bodySize": -1
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0}
        }
        with self._lock:
            self.case.add_har_entry(entry)

        media_type = self._classify_media(url)
        if media_type:
            # Descartar segmentos DASH (bytestart/byteend): son fragmentos parciales,
            # no el video completo: no son descargables directamente.
            if "bytestart=" in url and "byteend=" in url:
                return
            norm = self._normalize_url(url)
            log_signals.media_detected.emit(url + "\x00" + media_type + "\x00" + norm)

# SEÑALES GLOBALES 
class LoggerSignals(QObject):
    log_msg = pyqtSignal(str)
    media_detected = pyqtSignal(str)
    progress = pyqtSignal(int)

log_signals = LoggerSignals()

# GRABADOR DE PANTALLA v1.0 
class ScreenRecorder(QThread):
    """
    Graba SOLO la ventana de la aplicacion usando coordenadas exactas.
    Windows: gdigrab con offset_x/y + video_size (100% confiable).
    Linux: x11grab con coordenadas exactas.
    """
    frame_captured = pyqtSignal(int)
    error = pyqtSignal(str)
    stopped = pyqtSignal(str)

    CODEC_PROFILES = {
        "ffv1_lossless": {
            "label": "FFV1 Lossless (forense, archivos grandes)",
            "ext": ".mkv",
            "args": ["-c:v", "ffv1", "-level", "3", "-g", "1", "-pix_fmt", "bgr0"]
        },
        "h264_high": {
            "label": "H.264 Alta Calidad (~10x mas pequeno)",
            "ext": ".mp4",
            "args": ["-c:v", "libx264", "-crf", "18", "-preset", "fast", "-pix_fmt", "yuv420p", "-movflags", "+faststart"]
        },
        "h264_balanced": {
            "label": "H.264 Balanceado (~20x mas pequeno)",
            "ext": ".mp4",
            "args": ["-c:v", "libx264", "-crf", "23", "-preset", "fast", "-pix_fmt", "yuv420p", "-movflags", "+faststart"]
        }
    }

    def __init__(self, output_dir: Path, case: ForensicCase,
                 profile: str = "h264_high", window_geo: Optional[Tuple[int,int,int,int]] = None):
        super().__init__()
        self.output_dir = output_dir
        self.case = case
        self.profile = profile if profile in self.CODEC_PROFILES else "h264_high"
        self.recording = False
        self._stopped_flag = False
        self.use_ffmpeg = self._check_ffmpeg()
        self._proc = None
        self.output_path = ""
        self.window_geo = window_geo

    def _check_ffmpeg(self) -> bool:
        try:
            subprocess.run(["ffmpeg", "-version"], capture_output=True, check=True)
            return True
        except Exception:
            return False

    def run(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = self.CODEC_PROFILES[self.profile]["ext"]
        self.output_path = str(self.output_dir / f"Sesion_{ts}{ext}")

        if self.use_ffmpeg:
            self._record_ffmpeg()
        else:
            self._record_opencv()

    def _record_ffmpeg(self):
        try:
            profile_args = self.CODEC_PROFILES[self.profile]["args"]

            if self.window_geo:
                x, y, w, h = self.window_geo
                # Limitar resolucion
                scale = 1.0
                if w > MAX_RECORD_W:
                    scale = MAX_RECORD_W / w
                if h * scale > MAX_RECORD_H:
                    scale = MAX_RECORD_H / h
                if scale < 1.0:
                    w = int(w * scale) // 2 * 2
                    h = int(h * scale) // 2 * 2
            else:
                x, y, w, h = 0, 0, 1920, 1080

            if platform.system() == "Windows":
                # Windows: gdigrab con coordenadas exactas (offset + video_size)
                # Esto es 100% confiable porque no depende de encontrar la ventana por titulo
                self.case.log("INFO", "VIDEO", f"FFmpeg gdigrab {w}x{h} @ {x},{y} -> {self.output_path}")

                cmd = [
                    "ffmpeg", "-y",
                    "-f", "gdigrab",
                    "-framerate", "10",
                    "-offset_x", str(x),
                    "-offset_y", str(y),
                    "-video_size", f"{w}x{h}",
                    "-i", "desktop",
                ] + profile_args + [self.output_path]

                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                display = os.environ.get("DISPLAY", ":0")
                self.case.log("INFO", "VIDEO", f"FFmpeg x11grab {w}x{h} @ {x},{y} -> {self.output_path}")
                cmd = [
                    "ffmpeg", "-y",
                    "-f", "x11grab",
                    "-framerate", "10",
                    "-draw_mouse", "0",
                    "-video_size", f"{w}x{h}",
                    "-i", f"{display}+{x},{y}",
                ] + profile_args + [self.output_path]

                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )

            self.recording = True
            # communicate() drena stdout/stderr concurrentemente con wait(),
            # evitando deadlock cuando el buffer del pipe se llena (>64 KB en Windows).
            try:
                _, stderr_bytes = self._proc.communicate()
                return_code = self._proc.returncode
                stderr_output = stderr_bytes.decode("utf-8", errors="ignore")[-500:] if stderr_bytes else ""
            except Exception as _comm_err:
                return_code = -1
                stderr_output = str(_comm_err)

            self.case.log("INFO", "VIDEO", f"FFmpeg termino con codigo {return_code}")
            if stderr_output:
                self.case.log("INFO", "VIDEO", f"FFmpeg stderr: {stderr_output[:200]}")

            if os.path.exists(self.output_path) and os.path.getsize(self.output_path) > 0:
                self.stopped.emit(self.output_path)
            else:
                self.error.emit(f"FFmpeg no genero archivo. Codigo: {return_code}. Stderr: {stderr_output[:200]}")

        except Exception as e:
            self.error.emit(str(e))
            self.case.log("ERROR", "VIDEO", f"FFmpeg fallo: {e}")

    def _record_opencv(self):
        try:
            self.case.log("INFO", "VIDEO", f"OpenCV fallback -> {self.output_path}")
            if self.window_geo:
                x, y, w, h = self.window_geo
            else:
                x, y, w, h = 0, 0, 1920, 1080

            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            out = cv2.VideoWriter(self.output_path, fourcc, 10.0, (w, h))
            if not out.isOpened():
                self.error.emit("No se pudo abrir VideoWriter")
                return

            self.recording = True
            frame_count = 0
            while self.recording and not self.isInterruptionRequested():
                img = pyautogui.screenshot(region=(x, y, w, h))
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                out.write(frame)
                frame_count += 1
                if frame_count % 30 == 0:
                    self.frame_captured.emit(frame_count)
                self.msleep(100)

            out.release()
            if os.path.exists(self.output_path) and os.path.getsize(self.output_path) > 0:
                self.stopped.emit(self.output_path)
            else:
                self.error.emit("OpenCV no genero archivo de video valido")

        except Exception as e:
            self.error.emit(str(e))
            self.case.log("ERROR", "VIDEO", f"OpenCV fallo: {e}")

    def stop(self):
        self._stopped_flag = True
        self.recording = False

        if self._proc and self._proc.poll() is None:
            try:
                if platform.system() == "Windows":
                    os.kill(self._proc.pid, signal.CTRL_BREAK_EVENT)
                else:
                    self._proc.terminate()

                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.case.log("WARN", "VIDEO", "FFmpeg no respondio, forzando kill")
                self._proc.kill()
                self._proc.wait(timeout=3)
            except Exception as e:
                self.case.log("ERROR", "VIDEO", f"Error al detener FFmpeg: {e}")

        self.requestInterruption()
        if not self.wait(8000):
            self.case.log("WARN", "VIDEO", "Thread no respondio, forzando terminate")
            self.terminate()
            self.wait(2000)

# ADQUISICIÓN DE MEDIA
# NOTA: Los videos/audios de WhatsApp Web circulan como archivos .enc
# cifrados con E2E (AES-256-CBC + HKDF). Sin la media_key del dispositivo
# origen no es posible desencriptarlos ni reproducirlos. Por eso se elimino
# la funcionalidad de captura/previsualizacion de .enc de esta herramienta.
# Los URLs .enc detectados en trafico se registran como ENCRIPTADO en el
# inventario de medios para dejar constancia forense de su existencia.

class MediaAcquisition(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, url: str, case: ForensicCase, headers: Optional[Dict] = None):
        super().__init__()
        self.url = url
        self.case = case
        self.headers = headers or {}
        self.ts = datetime.datetime.now().strftime("%H%M%S")

    def run(self):
        import requests as _req
        url       = self.url
        url_lower = url.lower()
        ts        = self.ts

        default_headers = {
            "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
            "Accept":          "*/*",
            "Accept-Language": "es-AR,es;q=0.9,en;q=0.8",
            "Accept-Encoding": "identity",   # sin compresion: bytes raw
            "DNT":             "1",
            "Connection":      "keep-alive",
            "Sec-Fetch-Dest":  "video",
            "Sec-Fetch-Mode":  "no-cors",
            "Sec-Fetch-Site":  "cross-site",
        }
        default_headers.update(self.headers)

        max_reintentos = 3
        timeout_base   = 30

        for intento in range(max_reintentos):
            try:
                self.progress.emit(f"Intento {intento + 1}/{max_reintentos}...")

                r = _req.get(
                    url,
                    headers=default_headers,
                    stream=True,
                    timeout=(15, timeout_base),
                    allow_redirects=True,
                    verify=True
                )
                r.raise_for_status()

                cd = r.headers.get("Content-Disposition", "")
                ct = r.headers.get("Content-Type", "").lower()

                ext     = self._detect_extension(cd, ct, url)
                tipo_ev = "MEDIA_ADQUIRIDA"

                path       = self.case.dirs["evidence_raw"] / f"Adquisicion_{ts}{ext}"
                size_total = int(r.headers.get("Content-Length", 0))
                size_actual = 0
                with open(path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            size_actual += len(chunk)
                            if size_total and size_actual % (512 * 1024) == 0:
                                pct  = int((size_actual / size_total) * 100)
                                mb_a = size_actual / (1024 * 1024)
                                mb_t = size_total  / (1024 * 1024)
                                self.progress.emit(f"Descargando {pct}% | {mb_a:.1f}/{mb_t:.1f} MB")

                if size_actual == 0:
                    raise Exception("Archivo descargado vacio (0 bytes)")

                # CADENA DE CUSTODIA: sidecar inmediato
                # El archivo ya está cerrado. El hash es definitivo e irrefutable.
                sid = write_custody_sidecar(
                    path       = str(path),
                    tipo       = tipo_ev,
                    source_url = url,
                    perito     = self.case.perito_data if hasattr(self.case, "perito_data") else {},
                    case_id    = self.case.case_id,
                    extra      = {
                        "Content-Type":   ct or "desconocido",
                        "Tamano descarg": f"{size_actual:,} bytes",
                        "Intento":        f"{intento + 1}/{max_reintentos}",
                    }
                )

                ev = self.case.register_evidence(
                    tipo=tipo_ev,
                    path=str(path),
                    source_url=url,
                    metadata={"content_type": ct, "content_length": size_actual}
                )
                self.finished.emit(ev)
                self.progress.emit("─" * 55)
                self.progress.emit(f"✓ ADQUISICION  : {path.name}")
                self.progress.emit(f"  SHA-256      : {sid['sha256']}")
                self.progress.emit(f"  Tipo         : {tipo_ev}  ({ext})")
                self.progress.emit(f"  Tamaño       : {size_actual:,} bytes  ({size_actual/1024:.1f} KB)")
                self.progress.emit(f"  Momento      : {sid['ts_legible']}")
                self.progress.emit(f"  Sidecar      : {Path(sid['sha256_path']).name}")
                self.progress.emit(f"  Acta         : {Path(sid['custodia_path']).name}")
                self.progress.emit("─" * 55)
                return

            except _req.exceptions.Timeout:
                self.progress.emit(f"Timeout en intento {intento + 1}. Reintentando...")
            except _req.exceptions.ConnectionError:
                self.progress.emit(f"Error de conexion en intento {intento + 1}. Reintentando...")
            except _req.exceptions.HTTPError as e:
                status = e.response.status_code if hasattr(e, "response") and e.response else "?"
                self.progress.emit(f"HTTP {status} en intento {intento + 1}. Reintentando...")
            except _req.exceptions.RequestException as e:
                self.progress.emit(f"Error de solicitud: {str(e)[:80]}")
            except Exception as e:
                self.error.emit(str(e))
                self.case.log("ERROR", "ACQUISITION", f"Fallo descarga {url}: {e}")
                return

        self.error.emit(
            "Descarga fallida tras 3 intentos. "
            "Para WhatsApp: usa el boton Download del chat — el handler forense lo intercepta automaticamente."
        )

    def _detect_extension(self, cd: str, ct: str, url: str) -> str:
        """
        Detecta la extensión del archivo a descargar.
        ORDEN DE PRIORIDAD (de mayor a menor confiabilidad):
          1. URL contiene extensión explícita reconocible
          2. Content-Disposition filename
          3. Content-Type (video/audio ANTES que imagen, evita tomar preview JPG)
          4. Fallback .bin
        """
        url_lower = url.lower().split("?")[0]   # ignorar query string para la extensión

        # 1. Extensión explícita en la URL (parte path, antes del ?)
        for ext in [".mp4", ".webm", ".mkv", ".mov", ".avi", ".flv",
                    ".mp3", ".opus", ".aac", ".ogg", ".wav", ".m4a",
                    ".m3u8", ".ts",
                    ".png", ".jpg", ".jpeg", ".gif", ".webp"]:
            if url_lower.endswith(ext):
                return ext

        # 3. Content-Disposition (nombre de archivo real dado por el servidor)
        if "filename=" in cd:
            try:
                fname = cd.split("filename=")[1].strip().strip("\"'")
                fname = fname.split(";")[0].strip()   # eliminar parámetros adicionales
                if "." in fname:
                    ext_cd = "." + fname.rsplit(".", 1)[1].lower()[:6]
                    if ext_cd in {".mp4", ".webm", ".mkv", ".mov", ".avi", ".flv",
                                  ".mp3", ".opus", ".aac", ".ogg", ".wav",
                                  ".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                        return ext_cd
            except Exception:
                pass

        # 4. Content-Type, VIDEO/AUDIO primero, imagen al final
        # Esto evita que un thumbnail JPG interceptado antes del video
        # se clasifique como imagen cuando el Content-Type real es video/*
        ct_map_ordered = [
            # Video primero
            ("video/mp4",            ".mp4"),
            ("video/webm",           ".webm"),
            ("video/quicktime",      ".mov"),
            ("video/x-matroska",     ".mkv"),
            ("video/x-msvideo",      ".avi"),
            ("video/x-flv",          ".flv"),
            ("video/",               ".mp4"),   # genérico video/*
            # Audio
            ("audio/webm",           ".webm"),
            ("audio/opus",           ".opus"),
            ("audio/mpeg",           ".mp3"),
            ("audio/mp3",            ".mp3"),
            ("audio/aac",            ".aac"),
            ("audio/ogg",            ".ogg"),
            ("audio/wav",            ".wav"),
            ("audio/x-wav",          ".wav"),
            ("audio/mp4",            ".m4a"),
            ("audio/",               ".mp3"),   # genérico audio/*
            # Imagen (al final: baja prioridad)
            ("image/jpeg",           ".jpg"),
            ("image/png",            ".png"),
            ("image/webp",           ".webp"),
            ("image/gif",            ".gif"),
        ]
        for mime, ext in ct_map_ordered:
            if mime in ct:
                return ext

        return ".bin"

# REPRODUCTOR FORENSE GENERAL 
class MediaPlayerDialog(QDialog):
    """
    Reproductor forense para cualquier video/audio (URL directa o archivo local).
    No registra evidencia: es solo para VERIFICAR el contenido.
    """

    def __init__(self, source_url: str = "", default_open_dir: str = "", parent=None):
        super().__init__(parent)
        self.source_url      = source_url
        self.default_open_dir = default_open_dir or str(Path.home())
        self._seeking        = False

        self.setWindowTitle("▶  Reproductor Forense — Verificación de contenido")
        self.setMinimumSize(860, 560)
        self.setStyleSheet("background: #0d1b2a; color: #e8f0f8;")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._status = QLabel("Iniciando reproductor…")
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setStyleSheet(
            "color: #7dd3fc; font-size: 9pt; padding: 5px; "
            "background: #0a1520; border-bottom: 1px solid #1b263b;"
        )
        layout.addWidget(self._status)

        self._has_mm = _has_qt_multimedia()
        if self._has_mm:
            from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
            from PyQt6.QtMultimediaWidgets import QVideoWidget

            self._video = QVideoWidget()
            self._video.setStyleSheet("background: black;")
            layout.addWidget(self._video, 1)

            ctrl = QWidget()
            ctrl.setFixedHeight(52)
            ctrl.setStyleSheet("background: #111e2e; border-top: 1px solid #1b3a5c;")
            c_lay = QHBoxLayout(ctrl)
            c_lay.setContentsMargins(14, 0, 14, 0)
            c_lay.setSpacing(8)

            slider_style = """
                QSlider::groove:horizontal { height:4px; background:#2d3d50; border-radius:2px; }
                QSlider::handle:horizontal { background:#25D366; width:14px; height:14px; margin:-5px 0; border-radius:7px; }
                QSlider::sub-page:horizontal { background:#25D366; border-radius:2px; }
            """
            btn_s = ("QPushButton{background:#006d5b;color:white;border:none;border-radius:18px;font-size:15px;}"
                     "QPushButton:hover{background:#008e75;}"
                     "QPushButton:disabled{background:#1b263b;color:#444;}")
            sm_s  = ("QPushButton{background:#1b263b;color:#9ca3af;border:1px solid #2d3d50;"
                     "border-radius:4px;font-size:9pt;padding:2px 8px;}"
                     "QPushButton:hover{background:#243447;color:white;}")

            self._btn_play = QPushButton("▶")
            self._btn_play.setFixedSize(36, 36)
            self._btn_play.setStyleSheet(btn_s)
            self._btn_play.setEnabled(False)
            self._btn_play.clicked.connect(self._toggle_play)
            c_lay.addWidget(self._btn_play)

            self._lbl_pos = QLabel("0:00")
            self._lbl_pos.setFixedWidth(44)
            self._lbl_pos.setStyleSheet("color:#9ca3af;font-size:10px;")
            c_lay.addWidget(self._lbl_pos)

            self._seek = QSlider(Qt.Orientation.Horizontal)
            self._seek.setRange(0, 1000)
            self._seek.setStyleSheet(slider_style)
            self._seek.setEnabled(False)
            self._seek.sliderPressed.connect(lambda: setattr(self, "_seeking", True))
            self._seek.sliderReleased.connect(self._on_seek_released)
            c_lay.addWidget(self._seek, 1)

            self._lbl_dur = QLabel("0:00")
            self._lbl_dur.setFixedWidth(44)
            self._lbl_dur.setStyleSheet("color:#9ca3af;font-size:10px;")
            c_lay.addWidget(self._lbl_dur)

            vol = QSlider(Qt.Orientation.Horizontal)
            vol.setRange(0, 100)
            vol.setValue(80)
            vol.setFixedWidth(70)
            vol.setStyleSheet(slider_style)
            c_lay.addWidget(QLabel("🔊"))

            self._btn_spd = QPushButton("1x")
            self._btn_spd.setFixedSize(38, 28)
            self._btn_spd.setStyleSheet(sm_s)
            self._speeds = [0.5, 1.0, 1.5, 2.0]
            self._spd_idx = 1
            self._btn_spd.clicked.connect(self._cycle_speed)
            c_lay.addWidget(self._btn_spd)

            btn_open = QPushButton("📂 Abrir archivo")
            btn_open.setFixedHeight(28)
            btn_open.setStyleSheet(sm_s)
            btn_open.clicked.connect(self._open_file)
            c_lay.addWidget(btn_open)

            layout.addWidget(ctrl)

            self._player = QMediaPlayer()
            self._audio  = QAudioOutput()
            self._audio.setVolume(0.8)
            vol.valueChanged.connect(lambda v: self._audio.setVolume(v / 100))
            self._player.setAudioOutput(self._audio)
            self._player.setVideoOutput(self._video)
            self._player.playbackStateChanged.connect(self._on_state)
            self._player.durationChanged.connect(self._on_duration)
            self._player.positionChanged.connect(self._on_position)
            self._player.errorOccurred.connect(self._on_err)

            if source_url:
                from PyQt6.QtCore import QUrl as _QUrl
                self._status.setText(f"Intentando stream: {source_url[:80]}…  (si falla, usá ADQUIRIR y luego 📂 Abrir archivo)")
                self._player.setSource(_QUrl(source_url))
                self._player.play()
                self._btn_play.setEnabled(True)
                self._seek.setEnabled(True)
            else:
                self._status.setText("Usá 📂 Abrir archivo para elegir un video del caso.")
        else:
            layout.addWidget(QLabel(
                "Qt Multimedia no está disponible.\n"
                "Instalá PyQt6-Qt6-Multimedia para usar el reproductor.",
                alignment=Qt.AlignmentFlag.AlignCenter
            ), 1)

    def _toggle_play(self):
        from PyQt6.QtMultimedia import QMediaPlayer as _QMP
        if self._player.playbackState() == _QMP.PlaybackState.PlayingState:
            self._player.pause()
        else:
            self._player.play()

    def _on_state(self, state):
        from PyQt6.QtMultimedia import QMediaPlayer as _QMP
        self._btn_play.setText("⏸" if state == _QMP.PlaybackState.PlayingState else "▶")

    def _on_duration(self, ms):
        self._lbl_dur.setText(self._fmt(ms))

    def _on_position(self, ms):
        self._lbl_pos.setText(self._fmt(ms))
        if not self._seeking and self._player.duration():
            self._seek.setValue(int(ms / self._player.duration() * 1000))

    def _on_seek_released(self):
        self._seeking = False
        if self._player.duration():
            self._player.setPosition(int(self._seek.value() / 1000 * self._player.duration()))

    def _cycle_speed(self):
        self._spd_idx = (self._spd_idx + 1) % len(self._speeds)
        s = self._speeds[self._spd_idx]
        self._player.setPlaybackRate(s)
        self._btn_spd.setText(f"{s:g}x")

    def _on_err(self, err, msg: str):
        self._status.setText(f"✗ No se pudo reproducir: {msg}.  Usá ADQUIRIR y luego 📂 Abrir archivo.")
        self._status.setStyleSheet("color:#ef4444;font-size:10pt;padding:6px;background:#0a1520;")

    def _open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Abrir video/audio", self.default_open_dir,
            "Video/Audio (*.mp4 *.mkv *.webm *.mov *.avi *.mp3 *.aac *.m4a *.opus);;Todos (*.*)"
        )
        if path:
            from PyQt6.QtCore import QUrl as _QUrl
            self._status.setText(f"Reproduciendo: {Path(path).name}")
            self._status.setStyleSheet("color:#7dd3fc;font-size:9pt;padding:5px;background:#0a1520;border-bottom:1px solid #1b263b;")
            self._player.setSource(_QUrl.fromLocalFile(path))
            self._player.play()
            self._btn_play.setEnabled(True)
            self._seek.setEnabled(True)

    def closeEvent(self, event):
        if self._has_mm:
            try:
                self._player.stop()
            except Exception:
                pass
        super().closeEvent(event)

    @staticmethod
    def _fmt(ms: int) -> str:
        s = ms // 1000
        return f"{s // 60}:{s % 60:02d}"


# ADQUISICIÓN CON YT-DLP (Instagram / Facebook páginas) 
class YtDlpAcquisition(QThread):
    """Descarga videos de Instagram/Facebook usando yt-dlp con cadena de custodia."""
    finished = pyqtSignal(dict)
    progress = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, page_url: str, case, cookies_path: str = "", parent=None):
        super().__init__(parent)
        self.page_url     = page_url
        self.case         = case
        self.cookies_path = cookies_path

    def run(self):
        try:
            import yt_dlp
        except ImportError:
            self.error.emit("yt-dlp no está instalado. Ejecutá: pip install yt-dlp")
            return

        ts  = datetime.datetime.now().strftime("%H%M%S")
        out = self.case.dirs["evidence_raw"] / f"Adquisicion_{ts}.%(ext)s"

        ydl_opts = {
            "outtmpl":             str(out),
            # Preferir un único archivo progresivo mp4 (video+audio juntos, SIN merge
            # de FFmpeg) cuando exista; solo si no hay progresivo se recurre a
            # bestvideo+bestaudio. Esto evita el paso de remux, que es lo más lento.
            "format": ("best[ext=mp4][vcodec!=none][acodec!=none]/"
                       "bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best"),
            "quiet":               True,
            "no_warnings":         True,
            "merge_output_format": "mp4",
            "progress_hooks":      [self._hook],
            # ACELERACIÓN
            # Descargar fragmentos DASH/HLS en paralelo (Instagram/Facebook los
            # sirven fragmentados). Es el mayor factor de velocidad.
            "concurrent_fragment_downloads": 8,
            # Evitar reintentos largos que cuelgan la adquisición.
            "retries":          3,
            "fragment_retries": 3,
            "socket_timeout":   20,
        }
        # Si aria2c está instalado, usarlo como descargador externo: multiplica
        # conexiones y suele ser mucho más rápido que el descargador interno.
        _aria2 = shutil.which("aria2c")
        if _aria2:
            ydl_opts["external_downloader"] = "aria2c"
            ydl_opts["external_downloader_args"] = {
                "aria2c": ["-x", "16", "-s", "16", "-k", "1M"]
            }
            self.progress.emit("  Acelerador: aria2c (16 conexiones)")
        else:
            self.progress.emit("  Acelerador: descargador interno (8 fragmentos en paralelo)")
        if self.cookies_path and Path(self.cookies_path).exists():
            ydl_opts["cookiefile"] = self.cookies_path

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info     = ydl.extract_info(self.page_url, download=True)
                filename = ydl.prepare_filename(info)
                if not Path(filename).exists():
                    filename = str(filename).rsplit(".", 1)[0] + ".mp4"
        except Exception as e:
            self.error.emit(f"yt-dlp: {e}")
            return

        if not Path(filename).exists():
            self.error.emit("yt-dlp completó pero no se encontró el archivo de salida.")
            return

        sid = write_custody_sidecar(
            path       = filename,
            tipo       = "MEDIA_ADQUIRIDA",
            source_url = self.page_url,
            perito     = {},
            case_id    = self.case.case_id,
            extra      = {"metodo": "yt-dlp", "url_pagina": self.page_url}
        )
        ev = self.case.register_evidence("MEDIA_ADQUIRIDA", filename)
        self.progress.emit(f"  Archivo : {Path(filename).name}")
        self.progress.emit(f"  Tamaño  : {sid['size'] / (1024*1024):.2f} MB")
        self.progress.emit(f"  SHA-256 : {sid['sha256'][:32]}…")
        self.finished.emit(ev)

    def _hook(self, d):
        if d.get("status") == "downloading":
            pct = d.get("_percent_str", "").strip()
            spd = d.get("_speed_str", "").strip()
            eta = d.get("_eta_str", "").strip()
            self.progress.emit(f"  Descargando {pct}  {spd}  ETA {eta}")


#  SONDEO DE MEDIA (HEAD request en background) 
class MediaProbeWorker(QThread):
    """
    Hace HEAD requests en background para obtener Content-Length y
    Content-Type de cada URL de media detectada.
    Emite (url, size_bytes, content_type) cuando obtiene respuesta.
    """
    probe_result = pyqtSignal(str, int, str)   # url, bytes, content_type

    _SKIP_PARAMS = {
        "_nc_sid", "_nc_ht", "_nc_cat", "_nc_ohc", "_nc_hash",
        "efg", "oh", "oe", "bytestart", "byteend",
    }

    _UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/140.0.0.0 Safari/537.36"
    )

    def __init__(self, url: str, referer: str = ""):
        super().__init__()
        self.url     = url
        self.referer = referer

    def run(self):
        import requests as _req
        headers = {
            "User-Agent":      self._UA,
            "Accept":          "*/*",
            "Accept-Encoding": "identity",
            "Sec-Fetch-Dest":  "video",
            "Sec-Fetch-Mode":  "no-cors",
        }
        if self.referer:
            headers["Referer"] = self.referer
            headers["Origin"]  = "/".join(self.referer.split("/")[:3])

        try:
            r = _req.head(
                self.url, headers=headers,
                timeout=8, allow_redirects=True, verify=True
            )
            size = int(r.headers.get("Content-Length", 0))
            ct   = r.headers.get("Content-Type", "").split(";")[0].strip()
            # Si HEAD no devuelve Content-Length, intentar con Range: bytes=0-0
            if size == 0:
                headers["Range"] = "bytes=0-0"
                r2 = _req.get(
                    self.url, headers=headers,
                    timeout=8, allow_redirects=True, verify=True, stream=True
                )
                cr = r2.headers.get("Content-Range", "")  # "bytes 0-0/TOTAL"
                if "/" in cr:
                    try:
                        size = int(cr.split("/")[1])
                    except Exception:
                        pass
                if size == 0:
                    size = int(r2.headers.get("Content-Length", 0))
                r2.close()
            self.probe_result.emit(self.url, size, ct)
        except Exception:
            self.probe_result.emit(self.url, -1, "")   # -1 = no disponible


#  UID de Instagram, leido de la pagina 
# Instagram solo deja el UID en el HTML cuando no hay sesion iniciada, dentro
# de los datos de ruta ("page_id":"profilePage_<UID>"). Con sesion devuelve el
# cascaron de la SPA y los datos llegan despues por XHR, asi que el perfil se
# abre aparte, sin cookies, y de ahi se lee. No pasa por web_profile_info, que
# viene fallando con 400 en cuentas de empresa.
#
# El UID se acepta solo si la propia pagina dice ser la del perfil buscado,
# sea por su URL canonica o por el titulo. En el DOM conviven ids de otras
# cuentas y confundirlos significaria atribuirle a alguien el identificador de
# un tercero. __REQ__ se reemplaza por el usuario, ya escapado como JSON.
_IG_UID_JS = r"""
(function () {
    var USER    = __REQ__;
    var ULOW    = USER.toLowerCase();
    var USER_RE = USER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    var out = { uid: "", fuente: "", diag: {} };

    // Verificar que la pagina cargada ES la del perfil buscado
    function userDeUrl(u) {
        if (!u) { return ""; }
        var m = String(u).match(/instagram\.com\/([^\/?#]+)/i);
        return m ? decodeURIComponent(m[1]).toLowerCase() : "";
    }
    var canon = (document.querySelector('link[rel="canonical"]') || {}).href || "";
    var ogurl = (document.querySelector('meta[property="og:url"]') || {}).content || "";
    var userPagina = userDeUrl(canon) || userDeUrl(ogurl) || userDeUrl(location.href);

    // El titulo es la otra declaracion de identidad de la pagina
    var mt = (document.title || "").match(/\(@([A-Za-z0-9._]+)\)/);
    var userTitulo = mt ? mt[1].toLowerCase() : "";

    var verificada = (userPagina === ULOW) || (userTitulo === ULOW);
    var contradice = (userTitulo !== "" && userTitulo !== ULOW) ||
                     (userPagina !== "" && userPagina !== ULOW &&
                      userPagina !== "accounts" && userTitulo === "");

    out.diag.canonical  = canon;
    out.diag.user_url   = userPagina;
    out.diag.user_tit   = userTitulo;
    out.diag.verificada = verificada;

    var blobs = document.querySelectorAll('script[type="application/json"], script[data-sjs]');
    out.diag.blobs = blobs.length;

    if (!verificada || contradice) {
        out.diag.motivo = "la pagina no declara ser el perfil buscado";
        return JSON.stringify(out);
    }

    // 1) Datos de ruta: "page_id":"profilePage_<UID>"
    var rutaPats = [
        /"page_id"\s*:\s*"profilePage_(\d{4,20})"/,
        /"name"\s*:\s*"profilePage"[^{}]*,\s*"params"\s*:\s*\{[^{}]*?"profile_id"\s*:\s*"(\d{4,20})"/,
        /profilePage_(\d{4,20})/
    ];
    var vistos = {};
    for (var s = 0; s < blobs.length; s++) {
        var raw = blobs[s].textContent || "";
        if (raw.indexOf("profilePage") === -1) { continue; }
        var t = raw.indexOf('\\"') !== -1 ? raw.replace(/\\"/g, '"') : raw;
        for (var p = 0; p < rutaPats.length; p++) {
            var m = t.match(rutaPats[p]);
            if (m) { vistos[m[1]] = true; break; }
        }
    }
    var ids = Object.keys(vistos);
    out.diag.ids_ruta = ids;
    if (ids.length === 1) {
        out.uid = ids[0];
        out.fuente = "ruta profilePage de la pagina renderizada (/" + userPagina + "/)";
    } else if (ids.length > 1) {
        // Varios perfiles descritos: no se arriesga la atribucion.
        out.diag.motivo = "el DOM describe " + ids.length + " perfiles distintos";
    }

    // 2) Correlacion id<->username en el mismo objeto JSON
    if (!out.uid) {
        var cor = [
            new RegExp('"(?:id|pk)"\\s*:\\s*"(\\d{4,20})"[^{}]{0,400}?"username"\\s*:\\s*"' + USER_RE + '"', 'i'),
            new RegExp('"username"\\s*:\\s*"' + USER_RE + '"[^{}]{0,400}?"(?:id|pk)"\\s*:\\s*"(\\d{4,20})"', 'i')
        ];
        for (var s2 = 0; s2 < blobs.length && !out.uid; s2++) {
            var t2 = blobs[s2].textContent || "";
            if (t2.indexOf(USER) === -1) { continue; }
            for (var p2 = 0; p2 < cor.length; p2++) {
                var m2 = t2.match(cor[p2]);
                if (m2) {
                    out.uid = m2[1];
                    out.fuente = "JSON embebido (id correlacionado con @" + USER + ")";
                    break;
                }
            }
        }
    }

    return JSON.stringify(out);
})()
"""


# UID de Facebook, leido de la pagina 
# Facebook expone el UID en el meta app-link al:android:url (fb://profile/<UID>)
# incluso detras del muro de login, asi que alcanza con leerlo del DOM.
#
# Antes de aceptarlo hay que confirmar que la pagina cargada es la del perfil
# pedido, y ahi hay dos casos distintos porque Facebook redirige. Si se pidio
# un vanity, la URL canonica tiene que declararlo. Si se pidio profile.php?id=N
# la canonica termina siendo el vanity y ya no sirve para comparar, asi que lo
# que se exige es que el UID del meta sea igual a N.
#
# Cualquier otro id del DOM se descarta. Las paginas vinculadas traen su propio
# delegate_page.id y no es el del perfil que se esta peritando.
# __REQ__ se reemplaza por el perfil pedido, vanity o numero, escapado como JSON.
_FB_UID_JS = r"""
(function () {
    var REQ  = __REQ__;
    var REQL = REQ.toLowerCase();
    // Consistente con profile_id.isdigit() de Python: un vanity de Facebook
    // nunca es todo digitos, asi que "todo digitos" = ID numerico pedido.
    var esNumerico = /^\d+$/.test(REQ);
    var out = { uid: "", email: "", fuente: "", diag: {} };

    function meta(p) {
        var m = document.querySelector('meta[property="' + p + '"],meta[name="' + p + '"]');
        return m ? m.getAttribute("content") : null;
    }
    function pathUser(u) {
        if (!u) { return ""; }
        var m = String(u).match(/facebook\.com\/([^\/?#]+)/i);
        return m ? decodeURIComponent(m[1]).toLowerCase() : "";
    }

    var canon = (document.querySelector('link[rel="canonical"]') || {}).href || "";
    var userCanon = pathUser(canon) || pathUser(meta("og:url")) || pathUser(location.href);

    // UID autoritativo: el meta app-link que declara la propia pagina
    var al = meta("al:android:url") || meta("al:ios:url") || "";
    var mu = al.match(/fb:\/\/(?:profile|page)\/(\d+)/);
    var uidMeta = mu ? mu[1] : "";

    out.diag.canon_user = userCanon;
    out.diag.uid_meta   = uidMeta;
    out.diag.numerico   = esNumerico;

    if (!uidMeta) {
        out.diag.motivo = "la pagina no expone el meta app-link fb://profile";
        return JSON.stringify(out);
    }

    var verificado, fuente;
    if (esNumerico) {
        verificado = (uidMeta === REQ);
        fuente = "meta app-link fb://profile (UID = ID numerico pedido)";
    } else {
        verificado = (userCanon === REQL);
        fuente = "meta app-link fb://profile (canonica /" + userCanon + "/ verificada)";
    }

    if (!verificado) {
        out.diag.motivo = "la pagina cargada no corresponde al perfil pedido";
        return JSON.stringify(out);
    }

    out.uid = uidMeta;
    out.fuente = fuente;
    var a = document.querySelector('a[href^="mailto:"]');
    if (a) {
        out.email = (a.getAttribute("href") || "").replace(/^mailto:/i, "").split("?")[0];
    }
    return JSON.stringify(out);
})()
"""


# Integridad del codigo servido por Meta (Binary Transparency)
# Cada portal de Meta publica en su pagina un manifiesto con el hash SHA-256 de
# los scripts autorizados de esa version, mas un hash combinado del conjunto.
# Cloudflare publica por separado el hash raiz de la misma version en
# api.privacy-auditability.cloudflare.com/v1/hash/<dominio>/<version>. Si los
# dos coinciden, el manifiesto es autentico: el sitio declaro el inventario que
# Meta publico y no uno fabricado. Es lo que hace Code Verify (Meta, MIT).
#
# Ojo con lo que se afirma despues en el dictamen. Esto prueba que el
# manifiesto es autentico, no que cada script cargado coincida con su hash.
# Comprobar script por script es la otra mitad de Code Verify y obliga a
# hashear cada recurso antes de que se ejecute, ademas de quitar las cadenas
# dinamicas que Meta marca con /*BTDS*/. Tampoco dice nada sobre fallas del
# codigo legitimo, ni sirve si el comprometido fuera Cloudflare.
#
# Los tres portales devuelven VERIFICADO. Instagram no trae el manifiesto en el
# HTML inicial: lo baja de static.cdninstagram.com/btmanifest/... y recien
# despues lo inyecta, con una demora medida de 11 s. De ahi que la lectura se
# reintente en lugar de mirar una sola vez.
_BT_ORIGENES = {
    "facebook.com":  "facebook.com",
    "messenger.com": "messenger.com",
    "whatsapp.com":  "whatsapp.com",
    "instagram.com": "instagram.com",
}
_BT_CF_API = "https://api.privacy-auditability.cloudflare.com/v1/hash"

_BT_MANIFEST_JS = r"""
(function () {
    var el = document.getElementById('binary-transparency-manifest')
          || document.querySelector('[name="binary-transparency-manifest"]');
    if (!el) { return JSON.stringify({presente: false}); }
    var out = {presente: true, version: el.getAttribute('data-manifest-rev')};
    try {
        var j = JSON.parse(el.textContent || '');
        out.combined_hash = (j.manifest_hashes || {}).combined_hash || null;
        out.hashes_parciales = j.manifest_hashes || null;
        out.cant_scripts = Array.isArray(j.manifest) ? j.manifest.length : 0;
    } catch (e) {
        out.error = String(e).slice(0, 120);
    }
    return JSON.stringify(out);
})()
"""



#  ADQUISICION DE WHATSAPP WEB
#
#  Todo el multimedia se pide por la opcion Descargar del menu del mensaje.
#  Es la via de la propia aplicacion: WhatsApp entrega el archivo descifrado y
#  lo recoge el manejador de descargas del programa, que le calcula el hash y
#  levanta el acta de custodia. No se descifra nada por fuera.
#
#  Anclajes: data-testid, que en WhatsApp Web son semanticos y estables. Las
#  clases CSS estan ofuscadas y cambian entre versiones.

# Posicion del panel de la conversacion, para recortar la captura al chat.
_WA_RECT_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({error: 'sin conversacion'}); }
    var r = main.getBoundingClientRect();

    // Tambien la posicion del scroll: si no se movio desde la captura
    // anterior, la imagen seria identica y no hay por que repetirla.
    var cont = null, divs = main.querySelectorAll('div');
    for (var i = 0; i < divs.length; i++) {
        if (divs[i].scrollHeight > divs[i].clientHeight + 50 && divs[i].clientHeight > 200) {
            cont = divs[i]; break;
        }
    }
    return JSON.stringify({x: Math.round(r.left), y: Math.round(r.top),
                           w: Math.round(r.width), h: Math.round(r.height),
                           scroll: cont ? Math.round(cont.scrollTop) : -1});
})()
"""

# Inventaria el tramo visible: que multimedia hay y que dice cada mensaje.
_WA_ESCANEAR_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({error: 'no hay conversacion abierta'}); }

    if (!window.__wa) { window.__wa = {media: {}}; }
    var est = window.__wa, lista = [];

    var filas = main.querySelectorAll('[role="row"]');
    for (var f = 0; f < filas.length; f++) {
        var fila = filas[f];
        var msg = fila.querySelector('[data-testid^="conv-msg-"]');
        if (!msg) { continue; }
        var id = msg.getAttribute('data-testid').substring(9);
        if (!id || est.media[id]) { continue; }

        // Una vista previa de enlace —un video de YouTube, por ejemplo— se
        // parece a un video: tiene miniatura y boton de reproducir. Pero no
        // es multimedia de WhatsApp, no hay nada que descargar, y el enlace
        // ya queda en la captura del chat. Se reconoce porque la miniatura
        // esta dentro de un enlace a otro sitio.
        var enlace = msg.querySelector('a[href^="http"]');
        if (enlace && enlace.querySelector('img') &&
            enlace.getAttribute('href').indexOf('whatsapp') < 0) { continue; }

        // El orden importa: la miniatura de un video tambien es una imagen,
        // asi que el video se reconoce antes que la foto.
        var tipo = null;
        if (fila.querySelector('video, [data-icon*="play"], [data-icon*="video"], [data-testid*="video"]')) {
            tipo = 'video';
        } else if (fila.querySelector('[data-testid="ptt-status"]')) {
            tipo = 'audio';
        } else if (fila.querySelector('[data-testid="document-thumb"]')) {
            tipo = 'documento';
        } else if (fila.querySelector('[data-testid="sticker-container"]')) {
            tipo = 'sticker';
        } else if (fila.querySelector('img[src^="blob:"]')) {
            tipo = 'imagen';
        }
        if (!tipo) { continue; }

        est.media[id] = true;
        lista.push({id: id, tipo: tipo});
    }

    // Fechas del tramo, en el orden en que aparecen los mensajes. Salen de
    // data-pre-plain-text, que WhatsApp arma para su funcion de copiado con
    // el formato "[hora, fecha] Autor:". Se devuelven tal cual: la lectura se
    // hace del lado del programa y queda asentada.
    //
    // De cada mensaje se toma la ULTIMA, no la primera. Cuando un mensaje
    // responde a otro, la burbuja trae dos: primero la del mensaje citado
    // —que puede ser de hace meses— y despues la propia. Quedarse con la
    // primera hacia que el recorrido se cortara apenas aparecia una
    // respuesta, muchisimo antes de la fecha pedida.
    var fechas = [];
    for (var q = 0; q < filas.length; q++) {
        var conFecha = filas[q].querySelectorAll('[data-pre-plain-text]');
        if (!conFecha.length) { continue; }
        var t = conFecha[conFecha.length - 1].getAttribute('data-pre-plain-text') || '';
        var mm = t.match(/\[([^\],]+),\s*([^\]]+)\]/);
        if (mm) { fechas.push(mm[2].trim()); }
    }
    return JSON.stringify({lista: lista, fechas: fechas, mensajes: filas.length});
})()
"""

# El multimedia que todavia no se trajo del servidor se muestra con un boton
# que indica su tamano ("4 MB"). Mientras ese boton este ahi, el archivo no
# esta en la pagina: WhatsApp no lo bajo ni lo descifro, y el menu no tiene
# nada que entregar. Por eso hay que pulsarlo primero y esperar.
#
# Se reconoce por el tamano (KB, MB, GB son iguales en todos los idiomas) y
# por el icono de descarga.
_WA_TRAER_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({error: 'sin conversacion'}); }
    var msg = main.querySelector('[data-testid="conv-msg-__MSGID__"]');
    if (!msg) { return JSON.stringify({error: 'el mensaje quedo fuera de la vista'}); }

    var ctrl = msg.querySelectorAll('button, [role="button"], [data-icon]');
    for (var i = 0; i < ctrl.length; i++) {
        var e = ctrl[i];
        var ic = e.getAttribute('data-icon') || '';
        var tx = (e.innerText || '') + ' ' + (e.getAttribute('aria-label') || '');
        if (/download/i.test(ic) || /\d[\d.,]*\s*(KB|MB|GB)\b/i.test(tx)) {
            var b = e.closest('button') || e.closest('[role="button"]') || e;
            var r = b.getBoundingClientRect();
            var ev = {bubbles: true, cancelable: true, view: window,
                      clientX: Math.round(r.left + r.width / 2),
                      clientY: Math.round(r.top + r.height / 2)};
            try {
                ['pointerover', 'pointerdown', 'pointerup'].forEach(function (t) {
                    b.dispatchEvent(new PointerEvent(t, Object.assign(
                        {pointerId: 1, pointerType: 'mouse', isPrimary: true, button: 0,
                         buttons: t === 'pointerup' ? 0 : 1}, ev)));
                });
            } catch (e2) { /* sin PointerEvent alcanzan los de mouse */ }
            ['mousedown', 'mouseup', 'click'].forEach(function (t) {
                b.dispatchEvent(new MouseEvent(t, ev));
            });
            return JSON.stringify({traendo: true, etiqueta: tx.trim().slice(0, 20)});
        }
    }
    return JSON.stringify({traendo: false});
})()
"""

# Los stickers no tienen opcion de descarga en el menu de WhatsApp, pero
# llegan a la pagina ya descifrados: se arma un enlace sobre su blob y se
# pulsa, con lo que la descarga la recoge el manejador del programa igual que
# cualquier otra, con su hash y su acta.
_WA_BLOB_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({error: 'sin conversacion'}); }
    var msg = main.querySelector('[data-testid="conv-msg-__MSGID__"]');
    if (!msg) { return JSON.stringify({error: 'el mensaje quedo fuera de la vista'}); }

    // La imagen mas grande del mensaje: la foto de perfil del remitente
    // tambien es un <img> con blob, y no es lo que se busca.
    var mejor = null, area = 0, ims = msg.querySelectorAll('img[src^="blob:"]');
    for (var k = 0; k < ims.length; k++) {
        var r = ims[k].getBoundingClientRect();
        var a = r.width * r.height;
        if (a > area) { area = a; mejor = ims[k]; }
    }
    if (!mejor || area < 2500) { return JSON.stringify({ok: false}); }

    var esSticker = !!msg.querySelector('[data-testid="sticker-container"]');
    var limpio = '__MSGID__'.replace(/[^A-Za-z0-9_-]/g, '_').slice(-40);
    try {
        var a2 = document.createElement('a');
        a2.href = mejor.src;
        a2.download = 'WA_' + (esSticker ? 'sticker_' : 'imagen_') + limpio +
                      (esSticker ? '.webp' : '.jpg');
        document.body.appendChild(a2);
        a2.click();
        document.body.removeChild(a2);
        return JSON.stringify({ok: true});
    } catch (e) {
        return JSON.stringify({ok: false, error: 'el blob ya fue liberado'});
    }
})()
"""

# Consulta si el archivo ya llego, sin pulsar nada. Va aparte de _WA_TRAER_JS
# a proposito: mientras WhatsApp esta bajando, ese mismo boton pasa a ser el
# de cancelar, y volver a pulsarlo abortaria la descarga.
_WA_PENDIENTE_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({error: 'sin conversacion'}); }
    var msg = main.querySelector('[data-testid="conv-msg-__MSGID__"]');
    if (!msg) { return JSON.stringify({error: 'el mensaje quedo fuera de la vista'}); }
    var ctrl = msg.querySelectorAll('button, [role="button"], [data-icon]');
    for (var i = 0; i < ctrl.length; i++) {
        var e = ctrl[i];
        var ic = e.getAttribute('data-icon') || '';
        var tx = (e.innerText || '') + ' ' + (e.getAttribute('aria-label') || '');
        if (/download/i.test(ic) || /\d[\d.,]*\s*(KB|MB|GB)\b/i.test(tx)) {
            return JSON.stringify({pendiente: true});
        }
    }
    return JSON.stringify({pendiente: false});
})()
"""

# Abrir el menu de un mensaje lleva tres pasos, y no se pueden juntar. El
# boton que lo abre solo existe mientras el puntero esta sobre la burbuja, y
# React lo dibuja un instante despues del hover: buscarlo en la misma
# ejecucion que envia el hover no lo encuentra, y se termina abriendo el menu
# de otro mensaje.
_WA_HOVER_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({error: 'sin conversacion'}); }
    var msg = main.querySelector('[data-testid="conv-msg-__MSGID__"]');
    if (!msg) { return JSON.stringify({error: 'el mensaje quedo fuera de la vista'}); }

    var cont = msg.querySelector('[data-testid="msg-container"]') || msg;
    cont.scrollIntoView({block: 'center'});
    var r = cont.getBoundingClientRect();
    var ev = {bubbles: true, cancelable: true, view: window,
              clientX: Math.round(r.left + r.width / 2),
              clientY: Math.round(r.top + r.height / 2)};

    // Tambien eventos de puntero: React escucha pointerover y no siempre
    // reacciona solo a los de mouse.
    try {
        ['pointerover', 'pointerenter', 'pointermove'].forEach(function (t) {
            var p = Object.assign({pointerId: 1, pointerType: 'mouse', isPrimary: true}, ev);
            msg.dispatchEvent(new PointerEvent(t, p));
            cont.dispatchEvent(new PointerEvent(t, p));
        });
    } catch (e) { /* sin PointerEvent alcanzan los de mouse */ }
    ['mouseover', 'mouseenter', 'mousemove'].forEach(function (t) {
        msg.dispatchEvent(new MouseEvent(t, ev));
        cont.dispatchEvent(new MouseEvent(t, ev));
    });
    return JSON.stringify({ok: true});
})()
"""

_WA_CHEVRON_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({error: 'sin conversacion'}); }
    var msg = main.querySelector('[data-testid="conv-msg-__MSGID__"]');
    if (!msg) { return JSON.stringify({error: 'el mensaje quedo fuera de la vista'}); }

    // Se busca dentro del mensaje: con cualquier chevron de la pagina se
    // abriria el menu de otra burbuja.
    var chev = msg.querySelector('[data-testid="icon-down-context"], [data-icon="down-context"]');
    if (!chev) { return JSON.stringify({ok: false}); }

    var b = chev.closest('button') || chev.closest('[role="button"]') || chev.parentElement;
    var r = b.getBoundingClientRect();
    var ev = {bubbles: true, cancelable: true, view: window,
              clientX: Math.round(r.left + r.width / 2),
              clientY: Math.round(r.top + r.height / 2)};
    try {
        ['pointerover', 'pointerdown', 'pointerup'].forEach(function (t) {
            b.dispatchEvent(new PointerEvent(t, Object.assign(
                {pointerId: 1, pointerType: 'mouse', isPrimary: true, button: 0,
                 buttons: t === 'pointerup' ? 0 : 1}, ev)));
        });
    } catch (e) { /* sin PointerEvent alcanzan los de mouse */ }
    ['mousedown', 'mouseup', 'click'].forEach(function (t) {
        b.dispatchEvent(new MouseEvent(t, ev));
    });
    return JSON.stringify({ok: true});
})()
"""

_WA_MENU_JS = r"""
(function () {
    var items = document.querySelectorAll(
        '[role="menuitem"], li[data-animate-dropdown-item], [data-animate-dropdown-item]');
    if (!items.length) { return JSON.stringify({abierto: false}); }

    var vistos = [], elegido = null;
    for (var i = 0; i < items.length; i++) {
        var e = items[i];
        var ic = e.querySelector('[data-icon]');
        var icono = ic ? ic.getAttribute('data-icon') : '';
        var txt = (e.innerText || '').trim();
        vistos.push(icono ? icono : txt.slice(0, 22));

        // En este mismo menu estan Eliminar y Reportar. Pulsar cualquiera de
        // los dos destruiria o alteraria la prueba, que es lo contrario de lo
        // que hace esta herramienta. Se descartan de entrada, antes de
        // evaluar nada: ningun emparejamiento puede terminar ahi.
        if (/delete|trash|report|block/i.test(icono) ||
            /^(eliminar|borrar|delete|reportar|denunciar|report|bloquear)/i.test(txt)) {
            continue;
        }

        // Descargar todo entrega un ZIP con varias piezas y un nombre que no
        // identifica a ninguna. Para la pericia interesa cada archivo por
        // separado, con su hash propio.
        if (/\b(todo|todos|todas|all)\b/i.test(txt) || /all/i.test(icono)) {
            continue;
        }

        // Primero por el icono, que no depende del idioma de la interfaz
        if (!elegido && (/download/i.test(icono) ||
            /^(descargar|download|baixar|scarica|telecharger|herunterladen)\b/i.test(txt))) {
            elegido = e;
            // Se deja constancia de que se pulso, no solo de que se abrio
            var eic = ic ? ic.getAttribute('data-icon') : '';
            elegido.setAttribute('data-nav-forense-elegido', eic || txt.slice(0, 22));
        }
    }

    if (elegido) {
        var r = elegido.getBoundingClientRect();
        var ev = {bubbles: true, cancelable: true, view: window,
                  clientX: Math.round(r.left + r.width / 2),
                  clientY: Math.round(r.top + r.height / 2)};
        try {
            ['pointerover', 'pointerdown', 'pointerup'].forEach(function (t) {
                elegido.dispatchEvent(new PointerEvent(t, Object.assign(
                    {pointerId: 1, pointerType: 'mouse', isPrimary: true, button: 0,
                     buttons: t === 'pointerup' ? 0 : 1}, ev)));
            });
        } catch (e2) { /* sin PointerEvent alcanzan los de mouse */ }
        ['mousedown', 'mouseup', 'click'].forEach(function (t) {
            elegido.dispatchEvent(new MouseEvent(t, ev));
        });
        return JSON.stringify({
            pedido: true, items: vistos,
            pulsado: elegido.getAttribute('data-nav-forense-elegido') || ''});
    }

    // Sin opcion de descarga: se cierra el menu y se sigue
    document.body.dispatchEvent(new KeyboardEvent('keydown',
        {key: 'Escape', keyCode: 27, which: 27, bubbles: true}));
    return JSON.stringify({abierto: true, pedido: false, items: vistos});
})()
"""

# Cierra lo que haya quedado abierto (un menu, un visor, una ficha de contacto)
_WA_CERRAR_JS = r"""
(function () {
    document.body.dispatchEvent(new KeyboardEvent('keydown',
        {key: 'Escape', keyCode: 27, which: 27, bubbles: true}));
    document.dispatchEvent(new KeyboardEvent('keydown',
        {key: 'Escape', keyCode: 27, which: 27, bubbles: true}));
    return JSON.stringify({ok: true});
})()
"""

# Avanza un tramo hacia los mensajes mas recientes y avisa si llego al final.
#
# Es el sentido que usa la captura de pantalla: el perito deja la conversacion
# donde quiere empezar y el recorrido va desde ahi hasta el ultimo mensaje.
# Asi las capturas quedan en orden cronologico (la 001 es la mas antigua) y el
# punto de partida lo elige el perito, no el programa.
_WA_AVANZAR_JS = r"""
(function () {
    var main = document.querySelector('#main');
    if (!main) { return JSON.stringify({fin: true, error: 'sin conversacion'}); }
    var cont = null, divs = main.querySelectorAll('div');
    for (var i = 0; i < divs.length; i++) {
        if (divs[i].scrollHeight > divs[i].clientHeight + 50 && divs[i].clientHeight > 200) {
            cont = divs[i]; break;
        }
    }
    if (!cont) { return JSON.stringify({fin: true, error: 'sin contenedor de scroll'}); }
    var antes = cont.scrollTop;
    var maximo = cont.scrollHeight - cont.clientHeight;
    cont.scrollTop = Math.min(maximo, antes + Math.round(cont.clientHeight * 0.8));
    // Ya estaba abajo del todo antes de moverse: no queda chat por delante
    return JSON.stringify({fin: antes >= maximo - 4});
})()
"""




#  CAPTURA DE LA PAGINA COMPLETA
#
#  Una publicacion larga no entra en la pantalla, y una captura por pantallazo
#  obliga a leerla salteada. Se recorre la pagina de arriba a abajo tomando
#  vistas sucesivas y se unen en una sola imagen continua.

# Medidas de la pagina y posicion actual del scroll.
_PAG_MEDIDAS_JS = r"""
(function () {
    var d = document.documentElement, b = document.body;
    return JSON.stringify({
        alto_total: Math.max(d.scrollHeight, b ? b.scrollHeight : 0,
                             d.offsetHeight, b ? b.offsetHeight : 0),
        alto_visible: window.innerHeight,
        ancho: window.innerWidth,
        pos: Math.round(window.scrollY || d.scrollTop || 0)
    });
})()
"""

# Lleva la pagina a una posicion y devuelve donde quedo realmente.
#
# Se informa la posicion alcanzada y no la pedida: en paginas que cargan
# contenido al desplazarse, o que fijan su propio desplazamiento, las dos
# pueden no coincidir, y unir vistas suponiendo la pedida produciria una
# imagen con tramos repetidos o faltantes.
_PAG_IR_JS = r"""
(function () {
    window.scrollTo(0, __POS__);
    var d = document.documentElement, b = document.body;
    return JSON.stringify({
        pos: Math.round(window.scrollY || d.scrollTop || 0),
        alto_total: Math.max(d.scrollHeight, b ? b.scrollHeight : 0,
                             d.offsetHeight, b ? b.offsetHeight : 0)
    });
})()
"""

#  RELEVAMIENTO DE PERFILES DE INSTAGRAM
#
#  Todo se lee de la pagina que el perito tiene a la vista, con su sesion, tal
#  como la sirve Instagram. No se consultan interfaces no documentadas ni se
#  usan clientes de ingenieria inversa: lo que se registra es lo que la
#  aplicacion muestra, que es lo unico que se puede sostener despues.
#
#  Anclajes: el JSON que Instagram embebe en la pagina y los enlaces de perfil
#  (/usuario/), que son lo mas estable que publica. Las clases CSS estan
#  ofuscadas y cambian entre versiones.

# Datos del perfil, leidos de la pagina tal como se muestra.
#
# Se leen del DOM renderizado y NO del JSON que Instagram embebe. Se comprobo
# contra una pagina real que ese JSON ya no trae los datos del perfil visitado:
# follower_count, media_count e is_verified no aparecen, y los campos que si
# estan (full_name, biography, profile_pic_url_hd) corresponden al usuario con
# la sesion abierta, no al perfil que se esta mirando.
#
# Leerlos de ahi habria registrado los datos del propio perito como si fueran
# los del investigado. Lo que la pagina muestra, en cambio, es lo que el perito
# ve y puede sostener, y coincide con lo que queda en la captura de pantalla.
_IG_DATOS_JS = r"""
(function () {
    var out = {campos: {}, ubicaciones: [], diag: {}};
    var canon = (document.querySelector('link[rel="canonical"]') || {}).href || location.href;
    var mu = String(canon).match(/instagram\.com\/([^\/?#]+)/i);
    var USER = mu ? decodeURIComponent(mu[1]) : "";
    out.usuario = USER;
    out.url = canon;
    function norm(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }

    var h = document.querySelector('header') || document.querySelector('main section');
    if (!h) {
        out.diag.motivo = 'no se hallo el encabezado del perfil';
        return JSON.stringify(out);
    }

    // La foto de perfil nombra al titular en su texto alternativo. Sirve para
    // comprobar que lo que se lee es el perfil que declara la direccion.
    var img = null, imgs = h.querySelectorAll('img');
    for (var i = 0; i < imgs.length; i++) {
        if ((imgs[i].getAttribute('alt') || '').toLowerCase()
                .indexOf(USER.toLowerCase()) >= 0) { img = imgs[i]; break; }
    }
    if (!img && imgs.length) { img = imgs[0]; }
    out.diag.foto_nombra_al_perfil = !!(img && (img.getAttribute('alt') || '')
        .toLowerCase().indexOf(USER.toLowerCase()) >= 0);

    // Los contadores se muestran abreviados —686 M— pero la cifra exacta
    // viaja en el atributo title del mismo elemento, y es la que interesa.
    var exactos = {};
    h.querySelectorAll('[title]').forEach(function (e) {
        var tit = norm(e.getAttribute('title'));
        if (/^[\d.,]+$/.test(tit)) { exactos[norm(e.innerText)] = tit; }
    });

    var CONT = /^([\d.,]+\s*[KMB]?)\s+(publicaciones|posts|seguidores|followers|seguidos|following)$/i;
    var vistos = {};
    h.querySelectorAll('a, li, span').forEach(function (e) {
        var m = norm(e.innerText).match(CONT);
        if (!m) { return; }
        var c = m[2].toLowerCase();
        var key = /public|post/.test(c) ? 'publicaciones'
                : /seguidores|follower/.test(c) ? 'seguidores' : 'seguidos';
        if (vistos[key]) { return; }
        vistos[key] = true;
        var val = norm(m[1]);
        out.campos[key] = val;
        if (exactos[val]) { out.campos[key + '_exacto'] = exactos[val]; }
    });

    // Nombre y biografia: las lineas del encabezado que no son el usuario,
    // ni un contador, ni un boton. Se descarta solo la PRIMERA aparicion del
    // usuario: cuando el nombre coincide con el, la segunda es el nombre.
    var lineas = (h.innerText || '').split('\n').map(norm).filter(function (x) { return x; });
    var usado = false;
    var cand = lineas.filter(function (x) {
        if (!usado && x.toLowerCase() === USER.toLowerCase()) { usado = true; return false; }
        return !CONT.test(x) &&
               !/^(seguir|siguiendo|follow|following|mensaje|message|editar perfil|edit profile|contactar|contact)$/i.test(x);
    });
    if (cand.length) { out.campos.nombre = cand[0]; }
    if (cand.length > 1) { out.campos.biografia = cand[1]; }

    var ext = h.querySelector('a[href^="http"]:not([href*="instagram.com"]):not([href*="threads."])');
    if (ext) { out.campos.sitio_web = norm(ext.innerText) || ext.getAttribute('href'); }

    out.campos.verificado = !!h.querySelector(
        '[aria-label*="erificad"], [aria-label*="erified"], svg[aria-label*="erif"]');
    if (img) {
        out.campos.foto = img.src;
        out.campos.foto_medida = img.naturalWidth + 'x' + img.naturalHeight;
    }

    // Lugares etiquetados. Instagram elimina el EXIF de las imagenes, pero
    // conserva el sitio que el titular declaro al publicar. Se exige que el
    // enlace lleve identificador numerico: sin el es un menu, no un lugar.
    document.querySelectorAll('a[href^="/explore/locations/"]').forEach(function (a) {
        if (!/\/explore\/locations\/\d+/.test(a.getAttribute('href') || '')) { return; }
        var n = norm(a.innerText);
        if (n && out.ubicaciones.indexOf(n) < 0) { out.ubicaciones.push(n); }
    });

    out.diag.hallados = Object.keys(out.campos);
    return JSON.stringify(out);
})()
"""
# Como esta dibujando el navegador: por placa de video o por software.
#
# Es un dato del entorno de adquisicion, como la version del sistema o la hora
# NTP, y por eso queda registrado. Ademas resuelve una pregunta practica: si el
# motor cae al dibujado por software todo se vuelve lento, y desde afuera no
# hay modo de saberlo (se ve igual, solo que tarda).
#
# Se pregunta por WebGL porque es la unica via que la pagina tiene para
# informar que motor grafico hay debajo.
_RENDER_JS = r"""
(function () {
    var out = {dpr: window.devicePixelRatio, nucleos: navigator.hardwareConcurrency};
    try {
        var c = document.createElement('canvas');
        var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (!gl) {
            out.motor = 'sin WebGL: el navegador dibuja por software';
            out.acelerado = false;
        } else {
            var d = gl.getExtension('WEBGL_debug_renderer_info');
            var r = d ? gl.getParameter(d.UNMASKED_RENDERER_WEBGL)
                      : gl.getParameter(gl.RENDERER);
            out.motor = String(r);
            var b = out.motor.toLowerCase();
            out.acelerado = !(b.indexOf('swiftshader') >= 0 || b.indexOf('llvmpipe') >= 0 ||
                              b.indexOf('software') >= 0);
        }
    } catch (e) {
        out.motor = 'no se pudo determinar: ' + e;
        out.acelerado = null;
    }
    // Que formatos de video puede reproducir. canPlayType contesta
    // 'probably', 'maybe' o vacio; vacio es que no puede.
    try {
        var v = document.createElement('video');
        out.codecs = {
            'H.264+AAC': v.canPlayType('video/mp4; codecs="avc1.42E01E, mp4a.40.2"'),
            'H.264': v.canPlayType('video/mp4; codecs="avc1.42E01E"'),
            'AAC': v.canPlayType('audio/mp4; codecs="mp4a.40.2"'),
            'VP9': v.canPlayType('video/webm; codecs="vp9"'),
            'AV1': v.canPlayType('video/mp4; codecs="av01.0.05M.08"'),
            'Opus': v.canPlayType('audio/webm; codecs="opus"'),
            'MSE con H.264': !!(window.MediaSource &&
                MediaSource.isTypeSupported('video/mp4; codecs="avc1.42E01E"'))
        };
    } catch (e) {
        out.codecs = null;
    }
    return JSON.stringify(out);
})()
"""

# Medida de la caja sobre la que se trabaja, compartida por los dos lectores.
#
# De aca salen las tres cosas que el recorrido necesita: donde aplicar la
# rueda, que recortar en la captura y en que posicion del panel se esta.
#
# La caja se recorta a lo que se ve de ella. Cuando de esa interseccion no
# queda nada util (la columna se fue de la vista, o asoma una franja de pocos
# pixeles) se apunta a la ventana entera: con un rectangulo degenerado el
# recorte sale inservible y la rueda cae sobre un borde, y el recorrido se
# detiene sin avisar. Los dos casos se midieron: centro (692,-120) con la
# columna por encima de la vista, y una caja de 1692 x 48 con la lista de
# amigos al fondo de la pagina.
_JS_MEDIR = r"""
    // El panel de comentarios: el contenedor con barra propia del que cuelgan
    // MAS bloques.
    //
    // EL ERROR QUE CORRIGE. Antes se tomaba el ancestro comun de todos los
    // bloques. En Facebook eso no sirve: mientras el dialogo de comentarios
    // esta abierto, la pagina que queda detras conserva los mismos
    // comentarios, de modo que el ancestro comun sube hasta el cuerpo del
    // documento. El recorrido quedaba sin panel que desplazar —el log decia
    // "panel de la pagina 0/0"— y la rueda no movia nada.
    //
    // Se midio sobre una publicacion real: 20 bloques, 10 colgando del panel
    // del dialogo (700 x 707, con 2093 px para desplazar) y 10 sueltos en la
    // pagina de atras, sin contenedor con scroll.
    function panelDe(bloques) {
        if (!bloques || !bloques.length) { return null; }
        var conts = [], grupos = [];
        for (var i = 0; i < bloques.length; i++) {
            var m = bloques[i], hallado = null;
            while (m && m !== document.body) {
                if (m.scrollHeight > m.clientHeight + 40 && m.clientHeight > 100) {
                    hallado = m; break;
                }
                m = m.parentElement;
            }
            var k = conts.indexOf(hallado);
            if (k < 0) { conts.push(hallado); grupos.push([bloques[i]]); }
            else { grupos[k].push(bloques[i]); }
        }
        var mejor = 0;
        for (var g = 1; g < grupos.length; g++) {
            if (grupos[g].length > grupos[mejor].length) { mejor = g; }
        }
        // Con panel propio, ese es. Sin el —el modal de Instagram cuando los
        // comentarios entran sin desplazar— vale el ancestro comun del grupo.
        return conts[mejor] || ancestroComun(grupos[mejor]);
    }

    function medirCaja(ancla) {
        var cont = null, m = ancla;
        while (m && m !== document.body) {
            if (m.scrollHeight > m.clientHeight + 40 && m.clientHeight > 100) {
                cont = m; break;
            }
            m = m.parentElement;
        }
        var caja = cont || ancla || document.documentElement;
        var r = caja.getBoundingClientRect();
        var x0 = Math.max(r.left, 0), y0 = Math.max(r.top, 0);
        var x1 = Math.min(r.right, window.innerWidth);
        var y1 = Math.min(r.bottom, window.innerHeight);
        var fuera = !(x1 > x0 + 40 && y1 > y0 + 120);
        if (fuera) { x0 = 0; y0 = 0; x1 = window.innerWidth; y1 = window.innerHeight; }
        // Marcadores de carga DENTRO de la caja que se esta recorriendo.
        // Facebook no usa el circulito que gira sino bloques grises con un
        // brillo animado, que el detector de svg[aria-label=Cargando] no ve.
        // Se los reconoce por lo que son: un bloque sin texto, de tamano
        // visible, con una animacion corriendo. No depende del nombre de la
        // clase, que Facebook ofusca.
        //
        // Mirar la pagina entera no servia: en una publicacion con el dialogo
        // abierto quedan dos marcadores permanentes fuera del panel —el hueco
        // de la imagen del posteo y un avatar del cuadro de escribir— que no
        // se van nunca. Cada tramo agotaba las cinco esperas por algo que no
        // tenia relacion con los comentarios.
        var cargando = 0;
        var divs = caja.querySelectorAll('div');
        for (var k = 0; k < divs.length; k++) {
            var e = divs[k];
            if ((e.innerText || '').trim()) { continue; }
            var q = e.getBoundingClientRect();
            if (q.width < 40 || q.height < 12) { continue; }
            if (q.bottom < 0 || q.top > window.innerHeight) { continue; }
            if (getComputedStyle(e).animationName !== 'none') { cargando++; }
        }

        return {
            marcadores: cargando,
            propio: !!cont,
            alto: cont ? cont.scrollHeight : document.documentElement.scrollHeight,
            visible: cont ? cont.clientHeight : window.innerHeight,
            pos: Math.round(cont ? cont.scrollTop : (window.scrollY || 0)),
            fuera_de_vista: fuera,
            centro_x: Math.round((x0 + x1) / 2),
            centro_y: Math.round((y0 + y1) / 2),
            rect: {x: Math.round(x0), y: Math.round(y0),
                   w: Math.round(x1 - x0), h: Math.round(y1 - y0)}
        };
    }
"""


# Lee las cuentas de la lista que el perito dejo abierta.
#
# Solo lee: el desplazamiento lo hace el programa con la rueda del mouse, no
# este script. Se comprobo contra Instagram que mover la lista asignando
# scrollTop no dispara la carga del siguiente lote (el indicador de carga
# queda girando y no llegan mas cuentas), mientras que la rueda de verdad si.
# Es el mismo comportamiento que con el multimedia de WhatsApp: hay acciones
# que la pagina solo atiende cuando la entrada viene del sistema.
_LISTA_JS = r"""
(function () {
    /* MEDIR_CAJA */
    function limpiar(t) { return (t || '').replace(/\s+/g, ' ').trim(); }

    // Instagram: la lista de seguidores o seguidos se abre en un dialogo y
    // cada cuenta es un enlace de perfil.
    function leerInstagram() {
        var dlg = document.querySelector('div[role="dialog"]');
        if (!dlg) { return null; }
        var items = [], reservadas = ['explore', 'reels', 'accounts', 'direct', 'p',
                                      'stories', 'about', 'legal', 'privacy'];
        var enlaces = dlg.querySelectorAll('a[href^="/"]');
        for (var i = 0; i < enlaces.length; i++) {
            var m = (enlaces[i].getAttribute('href') || '').match(/^\/([A-Za-z0-9._]{1,30})\/$/);
            if (!m) { continue; }
            if (reservadas.indexOf(m[1]) >= 0) { continue; }
            items.push({id: m[1], nombre: ''});
        }
        var cont = null, divs = dlg.querySelectorAll('div');
        for (var d = 0; d < divs.length; d++) {
            if (divs[d].scrollHeight > divs[d].clientHeight + 10) { cont = divs[d]; break; }
        }
        return {items: items, caja: cont || dlg};
    }

    // Facebook: la lista de amigos es una grilla de tarjetas. No hay atributo
    // que las marque, pero cada una tiene una sola foto y el enlace al perfil.
    //
    // El encabezado de la pagina tiene elementos con la misma forma —"Agregar
    // a historia", los estudios—, asi que no alcanza con reconocer la tarjeta:
    // se agrupan por contenedor y se toma el grupo mas numeroso, que es la
    // grilla. Se midio sobre una lista real: los intrusos quedan en grupos de
    // uno y los amigos en un grupo de ocho.
    function leerFacebook() {
        var tarjetas = [];
        var imgs = document.querySelectorAll('img');
        for (var i = 0; i < imgs.length; i++) {
            var b = imgs[i], card = null;
            for (var k = 0; k < 6 && b.parentElement; k++) {
                b = b.parentElement;
                if (b.querySelectorAll('img').length === 1) {
                    var enl = b.querySelectorAll('a[href]'), con = null;
                    for (var j = 0; j < enl.length; j++) {
                        if (limpiar(enl[j].innerText)) { con = enl[j]; break; }
                    }
                    if (con) { card = b; break; }
                }
            }
            if (card) { tarjetas.push(card); }
        }
        if (!tarjetas.length) { return null; }

        var grupos = [], padres = [];
        for (var t = 0; t < tarjetas.length; t++) {
            var p = tarjetas[t].parentElement;
            var idx = padres.indexOf(p);
            if (idx < 0) { padres.push(p); grupos.push([tarjetas[t]]); }
            else { grupos[idx].push(tarjetas[t]); }
        }
        var mejor = 0;
        for (var g = 1; g < grupos.length; g++) {
            if (grupos[g].length > grupos[mejor].length) { mejor = g; }
        }
        if (grupos[mejor].length < 2) { return null; }

        var items = [];
        for (var c = 0; c < grupos[mejor].length; c++) {
            var enl = grupos[mejor][c].querySelectorAll('a[href]'), a = null;
            for (var j2 = 0; j2 < enl.length; j2++) {
                if (limpiar(enl[j2].innerText)) { a = enl[j2]; break; }
            }
            if (!a) { continue; }
            var href = (a.getAttribute('href') || '').split('&')[0]
                       .replace(/^https?:\/\/[^\/]+\//, '').replace(/\/$/, '');
            items.push({id: href || limpiar(a.innerText), nombre: limpiar(a.innerText)});
        }
        return {items: items, caja: padres[mejor]};
    }

    var host = location.hostname;
    var sitio = host.indexOf('instagram.com') >= 0 ? 'Instagram'
              : (host.indexOf('facebook.com') >= 0 ? 'Facebook' : '');
    if (!sitio) {
        return JSON.stringify({error: 'esta funcion trabaja sobre Instagram o Facebook'});
    }
    var lect = sitio === 'Instagram' ? leerInstagram() : leerFacebook();
    if (!lect) {
        return JSON.stringify({error: sitio === 'Instagram'
            ? 'no hay ninguna lista abierta'
            : 'no se ve una lista de amigos en esta pagina'});
    }

    if (window.__lista && window.__lista.url !== location.href) { window.__lista = null; }
    if (!window.__lista) {
        window.__lista = {vistos: {}, orden: [], sitio: sitio, url: location.href};
    }
    var est = window.__lista;
    est.sitio = sitio;

    var nuevos = 0;
    for (var n = 0; n < lect.items.length; n++) {
        var it = lect.items[n];
        if (!it.id || est.vistos[it.id]) { continue; }
        est.vistos[it.id] = true;
        est.orden.push(it);
        nuevos++;
    }

    var salida = medirCaja(lect.caja);
    salida.sitio = sitio;
    salida.nuevos = nuevos;
    salida.total = est.orden.length;
    salida.cargando = salida.marcadores > 0 || document.querySelectorAll(
        'svg[aria-label*="argand"], svg[aria-label*="oading"]').length > 0;
    return JSON.stringify(salida);
})()
""".replace("    /* MEDIR_CAJA */", _JS_MEDIR)

# Devuelve la lista completa acumulada.
_LISTA_FINAL_JS = r"""
(function () {
    if (!window.__lista) { return JSON.stringify({orden: [], sitio: '', url: ''}); }
    return JSON.stringify({orden: window.__lista.orden, sitio: window.__lista.sitio,
                           url: window.__lista.url});
})()
"""


# Comentarios de una publicacion.
#
# Un solo motor para los dos sitios: lo que cambia entre Instagram y Facebook
# es de donde se leen los comentarios, no como se los recorre. El
# desplazamiento se hace con la rueda del mouse de verdad, por la misma razon
# medida en la lista de contactos: asignar scrollTop mueve el panel pero no
# dispara la carga del lote siguiente.
#
# Los anclajes de cada sitio se midieron contra publicaciones reales, no se
# supusieron. En Instagram no hay atributo que marque un comentario, asi que se
# parte del <time> y se sube al ancestro mas alto que siga conteniendo uno
# solo; subir un numero fijo de niveles no sirve porque la profundidad cambia
# entre 4 y 6 segun el comentario tenga respuestas, me gusta o nada. En
# Facebook si lo hay: cada comentario es un [role="article"] con su aria-label.
# En TikTok tambien: cada parte lleva su data-e2e.
#
# Las fechas no se toman del texto a la vista ("18 h", "4 h"), que es relativo
# al momento de mirar y no sirve en un dictamen. Instagram publica el instante
# exacto en el atributo datetime del <time>; Facebook lo publica en el
# aria-label del enlace de la hora ("jueves, 27 de agosto de 2026 a las 9:12
# pm"). Se guarda eso.
#
# TikTok es la excepcion: no publica el instante en ninguna parte del documento
# (solo "8-15" o "Hace 5 dia(s)") asi que ahi se guarda lo que hay y el listado
# lo dice. La limitacion es de la plataforma; ocultarla seria dar por precisa
# una fecha que no lo es.
_COM_JS = r"""
(function () {
    /* MEDIR_CAJA */
    function limpiar(t) { return (t || '').replace(/\s+/g, ' ').trim(); }
    function numero(s) {
        var m = (s || '').match(/(\d[\d.,]*)/);
        return m ? m[1].replace(/[.,]/g, '') : '';
    }

    // Un comentario lleva el corazon de me gusta: un boton sin texto con un
    // icono adentro. La descripcion de la publicacion no lo tiene. Es la unica
    // diferencia que se sostiene en las dos vistas de Instagram —la pagina de
    // la publicacion y el modal de la grilla— y no depende del idioma.
    //
    // Contar botones a secas no servia: en el modal la descripcion tambien
    // trae un boton sin texto, pero vacio, sin icono. Por contarlo como
    // corazon la descripcion entraba al listado como si fuera el primer
    // comentario.
    function tieneCorazon(bloque) {
        var bs = bloque.querySelectorAll('[role="button"]');
        for (var i = 0; i < bs.length; i++) {
            if (!limpiar(bs[i].innerText) && bs[i].querySelector('svg')) { return true; }
        }
        return false;
    }

    // Ancestro comun mas profundo de los comentarios: es la columna de
    // comentarios. Sirve para desplazar y para recortar la captura aun cuando
    // el panel todavia no tiene barra propia —con pocos comentarios no la
    // tiene, y por eso las capturas salian de la ventana entera.
    function ancestroComun(bloques) {
        if (!bloques || !bloques.length) { return null; }
        var a = bloques[0];
        while (a && a.parentElement) {
            var todos = true;
            for (var i = 1; i < bloques.length; i++) {
                if (!a.contains(bloques[i])) { todos = false; break; }
            }
            if (todos) { break; }
            a = a.parentElement;
        }
        return a;
    }

    // Texto del bloque sin los controles de la interfaz. Se los aparta por lo
    // que son (role="button") y no por como se llaman, de modo que funcione
    // igual con la interfaz en cualquier idioma.
    function partir(bloque, autor, marcaTiempo) {
        var controles = [], botones = bloque.querySelectorAll('[role="button"]');
        for (var i = 0; i < botones.length; i++) {
            var s = limpiar(botones[i].innerText);
            if (s) { controles.push(s); }
        }
        var lineas = (bloque.innerText || '').split('\n');
        var corte = -1;
        for (var k = 0; k < lineas.length; k++) {
            lineas[k] = limpiar(lineas[k]);
            if (corte < 0 && marcaTiempo && lineas[k] === marcaTiempo) { corte = k; }
        }
        if (corte < 0) { corte = 0; }
        var marcas = [], cuerpo = [];
        for (var j = 0; j < lineas.length; j++) {
            var L = lineas[j];
            if (!L || L === autor || L === '\u2022' || L === '\u00b7') { continue; }
            if (controles.indexOf(L) >= 0) { continue; }
            if (j < corte) { marcas.push(L); } else if (j > corte) { cuerpo.push(L); }
        }
        var megusta = '', respuestas = '';
        for (var c = 0; c < controles.length; c++) {
            var C = controles[c];
            if (/^\d/.test(C)) { if (!megusta) { megusta = numero(C); } }
            else if (/\d/.test(C)) { if (!respuestas) { respuestas = numero(C); } }
        }
        return {texto: cuerpo.join(' '), marcas: marcas.join(' '),
                megusta: megusta, respuestas: respuestas};
    }

    // Instagram tiene dos vistas y no reparten el texto igual. En la pagina de
    // la publicacion innerText devuelve la hora, los me gusta y el responder
    // en renglones separados; en el modal de la grilla los devuelve pegados en
    // uno solo: "38 sem3 Me gustaResponder". Cortar por la linea que fuera
    // exactamente igual a la hora funcionaba en la primera vista y en la
    // segunda dejaba los controles dentro del comentario y sacaba los numeros
    // de cualquier lado —de la hora, o incluso del nombre del usuario, que fue
    // como un @monic4455 termino declarando 4455 respuestas plegadas.
    //
    // Ahora la linea de la hora se reconoce porque EMPIEZA con ella, y lo que
    // sobra de esa linea son los me gusta. Vale para las dos vistas.
    function partirIG(bloque, autor, tTexto) {
        var controles = [], bs = bloque.querySelectorAll('[role="button"]');
        for (var i = 0; i < bs.length; i++) {
            var s = limpiar(bs[i].innerText);
            if (s) { controles.push(s); }
        }
        var lineas = (bloque.innerText || '').split('\n');
        for (var q = 0; q < lineas.length; q++) { lineas[q] = limpiar(lineas[q]); }

        var cuerpo = [], marcas = [], meta = '', megusta = '', respuestas = '';
        for (var k = 0; k < lineas.length; k++) {
            var L = lineas[k];
            if (!L || L === autor || L === '\u2022') { continue; }

            // Respuestas plegadas: "Ver respuestas (1)", "View replies (1)".
            var mr = L.match(/\((\d+)\)\s*$/);
            if (mr) { if (!respuestas) { respuestas = mr[1]; } continue; }

            if (tTexto && L.indexOf(tTexto) === 0) {
                meta = limpiar(L.slice(tTexto.length));
                continue;
            }
            if (controles.indexOf(L) >= 0) {
                var mc = L.match(/^(\d[\d.,]*)/);
                if (mc && !megusta) { megusta = mc[1].replace(/[.,]/g, ''); }
                continue;
            }
            // Marca que la pagina agrega antes de la hora ("Editado"). Se la
            // reconoce porque el renglon siguiente es el separador.
            if (k + 1 < lineas.length && lineas[k + 1] === '\u2022') {
                marcas.push(L);
                continue;
            }
            cuerpo.push(L);
        }
        if (!megusta && meta) {
            var mm = meta.match(/^(\d[\d.,]*)/);
            if (mm) { megusta = mm[1].replace(/[.,]/g, ''); }
        }
        return {texto: cuerpo.join(' '), marcas: marcas.join(' '),
                megusta: megusta, respuestas: respuestas};
    }

    function leerInstagram() {
        var tiempos = document.querySelectorAll('time');
        if (!tiempos.length) { return null; }
        var items = [], desc = null, bloques = [];
        for (var i = 0; i < tiempos.length; i++) {
            var t = tiempos[i], b = t;
            while (b.parentElement &&
                   b.parentElement.querySelectorAll('time').length === 1) {
                b = b.parentElement;
            }
            // La fecha del pie de la publicacion tambien es un <time>, pero no
            // tiene autor: no es un comentario.
            var a = b.querySelector('a[href^="/"]');
            if (!a) { continue; }
            var autor = (a.getAttribute('href') || '').replace(/^\/|\/$/g, '');
            if (!autor || autor.indexOf('/') >= 0) { continue; }

            var p = partirIG(b, autor, limpiar(t.innerText));
            var item = {autor: autor, perfil: autor, texto: p.texto, marcas: p.marcas,
                        megusta: p.megusta, respuestas: p.respuestas,
                        fecha: t.getAttribute('datetime') || '',
                        fecha_vista: t.getAttribute('title') || ''};
            if (!tieneCorazon(b)) { if (!desc) { desc = item; } continue; }
            bloques.push(b);
            items.push(item);
        }
        return {items: items, desc: desc, bloques: bloques};
    }

    function leerFacebook() {
        var arts = document.querySelectorAll('[role="article"][aria-label]');
        if (!arts.length) { return null; }
        var items = [], bloques = [];
        for (var i = 0; i < arts.length; i++) {
            var a = arts[i];
            var autor = '', perfil = '', fecha = '', relativa = '';
            var enlaces = a.querySelectorAll('a[href]');
            for (var j = 0; j < enlaces.length; j++) {
                var tx = limpiar(enlaces[j].innerText);
                if (tx && !autor) {
                    autor = tx;
                    perfil = (enlaces[j].getAttribute('href') || '')
                             .split('?')[0].replace(/^https?:\/\/[^\/]+\//, '');
                }
                var al = enlaces[j].getAttribute('aria-label') || '';
                if (!fecha && al && /\d{4}/.test(al)) {
                    fecha = al; relativa = limpiar(enlaces[j].innerText);
                }
            }
            if (!autor) { continue; }
            var p = partir(a, autor, relativa);
            bloques.push(a);
            items.push({autor: autor, perfil: perfil, texto: p.texto, marcas: p.marcas,
                        megusta: p.megusta, respuestas: p.respuestas,
                        fecha: fecha, fecha_vista: relativa});
        }
        return {items: items, desc: null, bloques: bloques};
    }

    // TikTok rotula cada parte del comentario con su propio data-e2e, que es
    // el mismo recurso que usa WhatsApp Web con data-testid: un anclaje que la
    // pagina mantiene aunque cambien las clases de estilo.
    //
    // A diferencia de Instagram y Facebook, TikTok no publica en ninguna parte
    // el instante exacto del comentario: muestra "8-15" o "Hace 5 dia(s)" y
    // nada mas. Se guarda tal cual y se deja constancia de la limitacion, que
    // es de la plataforma y no del relevamiento.
    function leerTikTok() {
        var us = document.querySelectorAll('[data-e2e="comment-username-1"]');
        if (!us.length) { return null; }
        var items = [], bloques = [];
        for (var i = 0; i < us.length; i++) {
            var b = us[i];
            for (var k = 0; k < 6 && b.parentElement; k++) {
                b = b.parentElement;
                if (b.querySelector('[data-e2e="comment-level-1"]')) { break; }
            }
            var lvl = b.querySelector('[data-e2e="comment-level-1"]');
            if (!lvl) { continue; }
            var autor = limpiar(us[i].innerText);
            var a = b.querySelector('a[href^="/@"]');
            var perfil = a ? (a.getAttribute('href') || '').replace('/@', '') : autor;
            var texto = limpiar(lvl.innerText);

            // De las hojas de texto del bloque, lo que no es el autor, el
            // comentario ni el control de responder es la fecha; el numero
            // suelto es la cantidad de me gusta.
            var fecha = '', megusta = '', hojas = b.querySelectorAll('*');
            for (var h = 0; h < hojas.length; h++) {
                var e = hojas[h];
                if (e.children.length) { continue; }
                var t = limpiar(e.innerText);
                if (!t || t === autor || t === texto) { continue; }
                if (e.getAttribute('data-e2e') === 'comment-reply-1') { continue; }
                if (/^\d+$/.test(t)) { if (!megusta) { megusta = t; } continue; }
                if (!fecha) { fecha = t; }
            }
            bloques.push(b);
            items.push({autor: autor, perfil: perfil, texto: texto, marcas: '',
                        megusta: megusta, respuestas: '',
                        fecha: fecha, fecha_vista: fecha});
        }
        return {items: items, desc: null, bloques: bloques};
    }

    var host = location.hostname;
    var sitio = host.indexOf('instagram.com') >= 0 ? 'Instagram'
              : (host.indexOf('facebook.com') >= 0 ? 'Facebook'
              : (host.indexOf('tiktok.com') >= 0 ? 'TikTok' : ''));
    if (!sitio) {
        return JSON.stringify(
            {error: 'esta funcion trabaja sobre Instagram, Facebook o TikTok'});
    }

    var lect = sitio === 'Instagram' ? leerInstagram()
             : (sitio === 'Facebook' ? leerFacebook() : leerTikTok());
    if (!lect || !lect.items) {
        return JSON.stringify({error: 'no se ve ninguna publicacion con comentarios'});
    }

    if (window.__com && window.__com.url !== location.href) { window.__com = null; }
    if (!window.__com) {
        window.__com = {vistos: {}, orden: [], desc: null, sitio: sitio,
                        url: location.href};
    }
    var est = window.__com;
    est.sitio = sitio;
    if (lect.desc && !est.desc) { est.desc = lect.desc; }

    var nuevos = 0;
    for (var n = 0; n < lect.items.length; n++) {
        var it = lect.items[n];
        var clave = it.perfil + '|' + it.fecha + '|' + it.texto;
        if (est.vistos[clave]) { continue; }
        est.vistos[clave] = true;
        est.orden.push(it);
        nuevos++;
    }

    // La columna de comentarios es el ancestro comun de los comentarios: se
    // halla igual cuando el panel todavia no tiene barra propia, caso en que
    // antes se terminaba capturando la ventana entera.
    var salida = medirCaja(panelDe(lect.bloques));
    salida.sitio = sitio;
    salida.nuevos = nuevos;
    salida.total = est.orden.length;
    salida.cargando = salida.marcadores > 0 || document.querySelectorAll(
        'svg[aria-label*="argand"], svg[aria-label*="oading"]').length > 0;
    return JSON.stringify(salida);
})()
""".replace("    /* MEDIR_CAJA */", _JS_MEDIR)

# Devuelve todo lo acumulado.
_COM_FINAL_JS = r"""
(function () {
    if (!window.__com) { return JSON.stringify({orden: [], desc: null, sitio: ''}); }
    return JSON.stringify({orden: window.__com.orden, desc: window.__com.desc,
                           sitio: window.__com.sitio, url: window.__com.url});
})()
"""

#  REPORTE PDF 
class DictamenForense(FPDF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cargar_fuentes_unicode(self)

    C_VERDE = (46, 125, 50)
    C_VERDE_OS = (27, 94, 32)
    C_AZUL = (13, 71, 161)
    C_FILA_PAR = (232, 245, 233)
    C_FILA_IMP = (255, 255, 255)

    def _s(self, t):
        return sanitize_text(t)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font(FUENTE_INFORME, "B", 8)
        self.set_fill_color(*self.C_VERDE_OS)
        self.set_text_color(255, 255, 255)
        self.cell(0, 6, self._s(f"  {SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}  -  {SOFTWARE_INFO['norma']}"),
                  fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def footer(self):
        self.set_y(-13)
        self.set_font(FUENTE_INFORME, "I", 7)
        self.set_text_color(120, 120, 120)
        self.cell(0, 5, self._s(f"Pagina {self.page_no()}"), align="C")

    def cover_page(self, case_data: Dict, ts_gen: str, case_id: str, perito_data: Dict):
        self.add_page()
        self.set_line_width(0.8)
        self.set_draw_color(*self.C_VERDE_OS)
        self.rect(5, 5, 200, 287)

        logo_y = 28
        if LOGO_PATH and os.path.exists(LOGO_PATH):
            self.image(logo_para_portada(), 14, logo_y, 42)
        else:
            self.set_fill_color(*self.C_VERDE)
            self.rect(14, logo_y, 42, 42, "F")
            self.set_font(FUENTE_INFORME, "B", 28)
            self.set_text_color(255, 255, 255)
            self.set_xy(14, logo_y + 8)
            self.cell(42, 26, "T", align="C")

        self.set_xy(62, logo_y)
        self.set_font(FUENTE_INFORME, "B", 18)
        self.set_text_color(*self.C_VERDE_OS)
        w_right = self.w - self.r_margin - 62
        self.multi_cell(w_right, 10, self._s(SOFTWARE_INFO['software']), align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(62)
        self.set_font(FUENTE_INFORME, "", 10)
        self.set_text_color(60, 60, 60)
        self.cell(0, 6, "Reporte Forense Certificado de Navegacion Web", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(62)
        self.cell(0, 6, self._s(f"ID del caso: {case_id}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(62)
        self.cell(0, 6, self._s(f"Generacion: {ts_gen}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Autor del software (siempre fijo: independiente del perito actuante)
        self.set_x(62)
        self.set_font(FUENTE_INFORME, "B", 9)
        self.set_text_color(*self.C_VERDE_OS)
        self.cell(0, 6, self._s(
            f"Desarrollado por: Miguel Angel A. TRAVERSO ({AUTOR_SISTEMA['titulo']})"
        ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(62)
        self.set_font(FUENTE_INFORME, "I", 8)
        self.set_text_color(80, 80, 80)
        self.multi_cell(w_right, 5, self._s(
            f"{AUTOR_SISTEMA['empresa']} | {AUTOR_SISTEMA['email']} | {AUTOR_SISTEMA['linkedin']}\n"
            f"Codigo Abierto | {SOFTWARE_INFO['norma']}"
        ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_y(100)
        self.set_fill_color(*self.C_VERDE)
        self.set_text_color(255, 255, 255)
        self.set_font(FUENTE_INFORME, "B", 10)
        self.cell(0, 8, "   DATOS DEL CASO PERICIAL", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        filas = [
            # Con "or" y no con el valor por defecto del get: un campo que
            # existe pero quedo vacio tiene que verse como guion, no en blanco.
            ("Expediente N.", case_data.get('exp') or '-'),
            ("Tribunal / Juzgado", case_data.get('juz') or '-'),
            ("Caratula", case_data.get('car') or '-'),
            ("Escribano / Notario", case_data.get('esc') or '-'),
            ("   Registro / Matricula", case_data.get('esc_reg') or '-'),
            ("   Colegio / Jurisdiccion", case_data.get('esc_col') or '-'),
            ("Objeto de la pericia", case_data.get('obj') or '-'),
        ]
        for i, (k, v) in enumerate(filas):
            w_label = 55
            page_w = self.w - self.l_margin - self.r_margin
            w_value = max(page_w - w_label, 30)
            y0 = self.get_y()
            self.set_fill_color(*(self.C_FILA_PAR if i % 2 == 0 else self.C_FILA_IMP))
            self.set_font(FUENTE_INFORME, "B", 9)
            self.set_xy(self.l_margin, y0)
            self.multi_cell(w_label, 6, self._s(f"  {k}"), fill=True, border=1, new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font(FUENTE_INFORME, "", 9)
            self.set_xy(self.l_margin + w_label, y0)
            self.multi_cell(w_value, 6, self._s(f"  {v}"), fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            y_after = self.get_y()
            self.set_y(max(y_after, y0 + 6))

    def section_title(self, tag: str, title: str):
        self.ln(4)
        self.set_fill_color(*self.C_VERDE)
        self.set_text_color(255, 255, 255)
        self.set_font(FUENTE_INFORME, "B", 10)
        self.cell(0, 8, self._s(f"  [{tag}]  {title.upper()}"), fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def tabla_fila(self, label: str, value: str, idx: int = 0, w_label: int = 60):
        page_w = self.w - self.l_margin - self.r_margin
        w_value = max(page_w - w_label, 30)
        etiqueta, valor = self._s(f"  {label}"), self._s(f"  {value}")

        # Cuanto alto necesita la fila, medido ANTES de dibujar nada.
        #
        # La etiqueta y el valor se dibujan a la misma altura, cada uno en su
        # celda. Si el valor no entraba en lo que quedaba de hoja, el salto
        # automatico partia la fila: la etiqueta quedaba en una pagina y su
        # texto en la siguiente. En el informe eso se lee como una celda vacia
        # seguida de un fragmento suelto, que fue lo que apareció al final del
        # anexo de verificacion.
        def _lineas(texto, ancho, negrita):
            self.set_font(FUENTE_INFORME, "B" if negrita else "", 9)
            try:
                return len(self.multi_cell(ancho, 6, texto, dry_run=True,
                                           output="LINES", border=1))
            except Exception:
                # Si la version de fpdf no permite medir en seco se estima por
                # ancho del texto. Sobrestimar es lo preferible: manda la fila
                # a la hoja siguiente, que es justamente lo que se busca.
                util = max(1.0, ancho - 3)
                return max(1, int(self.get_string_width(texto) / util) + 1)

        alto = 6 * max(_lineas(etiqueta, w_label, True),
                       _lineas(valor, w_value, False), 1)

        # Se pregunta a fpdf si la fila entera provoca salto, en vez de
        # comparar a mano contra el margen: la comparacion manual dejaba pasar
        # el caso justo y una fila se seguia partiendo.
        try:
            no_entra = self.will_page_break(alto)
        except Exception:
            no_entra = (self.get_y() + alto) > (self.page_break_trigger - 1)
        if no_entra:
            self.add_page()

        y_before = self.get_y()
        self.set_fill_color(*(self.C_FILA_PAR if idx % 2 == 0 else self.C_FILA_IMP))
        self.set_font(FUENTE_INFORME, "B", 9)
        self.set_xy(self.l_margin, y_before)
        self.multi_cell(w_label, 6, etiqueta, fill=True, border=1, new_x=XPos.RIGHT, new_y=YPos.TOP)
        y_after_label = self.get_y()
        self.set_font(FUENTE_INFORME, "", 9)
        self.set_xy(self.l_margin + w_label, y_before)
        self.multi_cell(w_value, 6, valor, fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        y_after_value = self.get_y()
        self.set_y(max(y_after_label, y_after_value))

    def cuerpo_texto(self, texto: str, size: int = 9):
        self.set_font(FUENTE_INFORME, "", size)
        self.set_text_color(40, 40, 40)
        w_full = self.w - self.l_margin - self.r_margin
        self.set_x(self.l_margin)
        self.multi_cell(w_full, 5, self._s(texto), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def bloque_hash(self, label: str, valor: str):
        self.set_font(FUENTE_INFORME, "B", 8)
        self.set_text_color(40, 40, 40)
        self.cell(0, 5, self._s(label), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_fill_color(245, 245, 245)
        self.set_draw_color(*self.C_VERDE_OS)
        self.set_line_width(0.4)
        self.set_font(FUENTE_MONO, "", 7)
        self.set_text_color(*self.C_VERDE_OS)
        w_full = self.w - self.l_margin - self.r_margin
        self.set_x(self.l_margin)
        self.multi_cell(w_full, 5, self._s(valor), fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(0, 0, 0)
        self.set_line_width(0.2)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def miniatura(self, img_path: str, caption: str = "", max_w_mm: float = 140, max_h_mm: float = 80,
                  temp_dir: Optional[Path] = None, temporales: Optional[List[str]] = None):
        try:
            if not os.path.exists(img_path):
                return
            with Image.open(img_path) as im:
                iw, ih = im.size
                ratio = min(max_w_mm / iw, max_h_mm / ih)
                w_mm = iw * ratio
                h_mm = ih * ratio

            # Se inserta una copia al tamaño que se va a ver. Ver
            # imagen_para_informe: embeber el original entero era el 99% del
            # peso del dictamen.
            a_insertar = img_path
            if temp_dir is not None:
                a_insertar = imagen_para_informe(img_path, w_mm, temp_dir,
                                                 dpi=150)
                if a_insertar != img_path and temporales is not None:
                    temporales.append(a_insertar)

            x_center = (self.w - self.l_margin - self.r_margin - w_mm) / 2 + self.l_margin
            self.image(a_insertar, x=x_center, w=w_mm)
            if caption:
                self.set_font(FUENTE_INFORME, "I", 7)
                self.set_text_color(100, 100, 100)
                self.cell(0, 5, self._s(caption), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self.set_text_color(0, 0, 0)
            self.ln(2)
        except Exception:
            pass

    def miniatura_no_disponible(self, motivo: str = "Miniatura no disponible"):
        self.set_fill_color(245, 245, 245)
        self.set_draw_color(180, 180, 180)
        self.set_line_width(0.3)
        self.set_font(FUENTE_INFORME, "I", 8)
        self.set_text_color(120, 120, 120)
        w_box = 80
        h_box = 30
        x_center = (self.w - self.l_margin - self.r_margin - w_box) / 2 + self.l_margin
        self.rect(x_center, self.get_y(), w_box, h_box, style="DF")
        self.set_xy(x_center, self.get_y() + h_box / 2 - 3)
        self.cell(w_box, 6, self._s(motivo), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_draw_color(0, 0, 0)
        self.ln(2)

# PAGINA FORENSE (filtro de spam JS)
# Definida a nivel de módulo para no recrear la clase en cada llamada a init_ui().
from PyQt6.QtWebEngineCore import QWebEnginePage as _QWebEnginePage

class ForensicPage(_QWebEnginePage):
    """QWebEnginePage que suprime mensajes JS de spam (Permissions-Policy, WebAuthn, etc.)
    sin afectar errores reales de la aplicación."""

    # Aviso opcional que fija la ventana principal para dejar constancia
    aviso_popup = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Paginas auxiliares creadas para los enlaces con target="_blank"
        self._auxiliares = set()

    def javaScriptConsoleMessage(self, level, message, line, source):
        if not is_js_spam(message):
            super().javaScriptConsoleMessage(level, message, line, source)

    def createWindow(self, tipo):
        """
        Enlaces que piden abrirse en una ventana nueva (target="_blank").

        Sin esta implementacion QWebEngineView los descarta sin avisar y el
        enlace no hace nada: era el caso de los mensajes de WhatsApp que
        enlazan a Instagram u otros sitios.

        Hay que devolver una pagina nueva de verdad. Devolver self parece lo
        natural y es un atajo bastante difundido, pero Qt lo ignora y el
        enlace sigue sin abrirse. Entonces se crea una pagina auxiliar solo
        para que Qt le entregue la navegacion; en cuanto se sabe la URL se
        carga en la vista principal y la auxiliar se descarta.

        La carga va a la vista principal a proposito: una ventana aparte
        quedaria fuera del interceptor y del HAR, y esa navegacion no
        constaria en el caso.
        """
        # Con el mismo perfil que la pagina que la pidio: si tomara el de por
        # defecto, la navegacion saldria por otro almacenamiento y por fuera
        # del interceptor del caso.
        aux = ForensicPage(self.profile(), self.parent())

        def _al_saber_la_url(url):
            destino = url.toString()
            if not destino or destino == "about:blank":
                return
            if callable(self.aviso_popup):
                try:
                    self.aviso_popup(destino)
                except Exception:
                    pass
            self.setUrl(url)
            self._auxiliares.discard(aux)
            aux.deleteLater()

        aux.urlChanged.connect(_al_saber_la_url)
        # Se conserva la referencia: sin ella Python puede recolectar la
        # pagina auxiliar antes de que Qt le entregue la URL.
        self._auxiliares.add(aux)
        return aux


#  VENTANA PRINCIPAL 
class TraversoWebForensicsPro(QMainWindow):
    def __init__(self, setup_data: Dict[str, str], perito_data: Dict[str, str]):
        super().__init__()
        self.perito_data = perito_data
        self.case = ForensicCase(setup_data, perito_data)
        self.setWindowTitle(f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']} | {self.case.case_id}")
        self.resize(1500, 1000)

        self.detected_media_urls: list = []   # lista de URLs detectadas en la sesión
        self._detected_norms: set  = set()    # URLs normalizadas para deduplicar
        self._media_sizes: dict    = {}       # url → (size_bytes, content_type)
        self._probes: set          = set()    # workers HEAD activos (evita GC y race en discard)
        self.last_media_url: Optional[str] = None
        self.recorder: Optional[ScreenRecorder] = None
        self.is_recording = False
        self._ffmpeg_ok: Optional[bool] = None
        # Perfil/página off-the-record para leer el UID de Instagram sin sesión
        self._uid_prof = None
        self._uid_page = None
        # Binary Transparency: pares (dominio, version) ya verificados en la
        # sesión, para no repetir la comprobación en cada recarga de la SPA.
        self._bt_verificados: set = set()

        self.init_ui()
        self.connect_signals()
        QTimer.singleShot(800, self._autoload_cookies)

        # Copia del archivo hosts: acredita que el equipo no tenia el dominio
        # redirigido en el momento de la adquisicion.
        try:
            copiar_archivo_hosts(self.case)
        except Exception as _e:
            self.case.log("ADVERTENCIA", "ACREDITACION", f"Archivo hosts: {_e}")

        iniciar_hash_de_la_herramienta()
        self.case.log("INFO", "SYSTEM", f"Suite iniciada. Case ID: {self.case.case_id}")
        self.case.log("INFO", "SYSTEM", f"SHA-256 del software: {get_self_hash()}")
        self.case.log("INFO", "SYSTEM", f"Motor del navegador: {version_motor()}")
        self.append_console(f"Caso iniciado: {self.case.case_id}")
        self.append_console(f"SHA-256 software: {get_self_hash()[:24]}...")
        self.append_console(f"Motor: {version_motor()}")
        self.append_console(f"Perito: {perito_data.get('nombre','')} - {perito_data.get('titulo','')}")

        # Informar estado de sincronización NTP
        ntp = self.case.ntp_info
        if ntp.get("sincronizado"):
            offset_s = ntp.get("offset_segundos", 0)
            if abs(offset_s) > 30:
                self.append_console(
                    f"⚠️ ALERTA NTP: offset del reloj = {ntp['offset_legible']} "
                    f"(>30s — la línea de tiempo forense puede ser impugnable)"
                )
            else:
                self.append_console(
                    f"✓ NTP sincronizado: {ntp['servidor']} | "
                    f"Offset: {ntp['offset_legible']} | UTC: {ntp['hora_ntp_utc'][:19]}"
                )
        else:
            self.append_console(
                "⚠️ NTP no disponible — timestamps basados en reloj local. "
                "Instalar: pip install ntplib"
            )

        self.append_console(f"✓ Sellado RFC 3161: cada sello se verifica contra "
                            f"{len(RAICES_TSA)} raices reconocidas antes de aceptarlo")

    def init_ui(self):
        central = QWidget()
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Header original v1.0, 120px con logo, info y todos los botones
        header = QFrame()
        header.setFixedHeight(120)
        header.setStyleSheet("background-color: #0d1b2a; border-bottom: 3px solid #1b263b;")
        h_lay = QHBoxLayout(header)

        if LOGO_PATH and os.path.exists(LOGO_PATH):
            logo = QLabel()
            logo.setPixmap(QPixmap(LOGO_PATH).scaled(100, 100, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
            h_lay.addWidget(logo)

        txt_lay = QVBoxLayout()
        t1 = QLabel("TRAVERSO FORENSICS · Navegador Web Forense")
        t1.setStyleSheet("color: white; font-weight: bold; font-size: 22px; border:none;")
        t2 = QLabel(f"Exp: {self.case.case_data.get('exp','-')} | Perito: {self.perito_data.get('nombre','')} | Case: {self.case.case_id}")
        t2.setStyleSheet("color: #e8f0f8; font-size: 13px; border:none; font-weight: normal;")
        txt_lay.addWidget(t1)
        txt_lay.addWidget(t2)
        h_lay.addLayout(txt_lay)
        h_lay.addStretch()

        quality_group = QGroupBox("Calidad Video")
        quality_group.setStyleSheet("QGroupBox { color: white; border: 1px solid #34495e; }")
        q_lay = QVBoxLayout(quality_group)
        self.combo_quality = QComboBox()
        self.combo_quality.setStyleSheet("color: black; background: white;")
        for key, val in ScreenRecorder.CODEC_PROFILES.items():
            self.combo_quality.addItem(val["label"], key)
        q_lay.addWidget(self.combo_quality)
        h_lay.addWidget(quality_group)

        btn_style = """
            QPushButton { background-color: #1b263b; color: white; font-weight: bold; padding: 12px; min-width: 120px; border-radius: 4px; border: 1px solid #34495e; }
            QPushButton:hover { background-color: #2c3e50; }
            QPushButton:pressed { background-color: #000; }
            QPushButton:disabled { background-color: #0a111a; color: #444; }
        """
        self.btn_rec = QPushButton("🔴 GRABAR SESION")
        self.btn_rec.clicked.connect(self.toggle_recording)
        btn_cap = QPushButton("📸 CAPTURA")
        # Captura de la pagina entera. Util cuando la publicacion no entra en
        # pantalla: recorre con scroll y une las vistas en una sola imagen.
        self.btn_pag = QPushButton("🖼 PAGINA COMPLETA")
        self.btn_pag.setToolTip("Captura la pagina entera recorriendola con scroll")
        self.btn_pag.clicked.connect(self.capturar_pagina_completa)
        btn_cap.clicked.connect(self.capture_screenshot)
        # Los dos recorridos de WhatsApp van por separado. Descargar archivos y
        # capturar la pantalla son tareas distintas: cada descarga abre menus y
        # espera al servidor, y eso ensuciaba y demoraba las capturas. Cada una
        # por su lado hace lo suyo sin estorbar a la otra.
        #
        # Solo tienen sentido dentro de WhatsApp Web: aparecen al navegar ahi
        # (ver _on_url_changed).
        self.btn_wa = QPushButton("🎬 MEDIA WHATSAPP")
        self.btn_wa.setToolTip("Descarga fotos, videos, audios y documentos del chat abierto")
        self.btn_wa.clicked.connect(self._wa_boton_media)
        self.btn_wa.setVisible(False)

        # Relevamiento de Instagram: aparecen solo en instagram.com
        self.btn_ig_perfil = QPushButton("🔍 RELEVAR PERFIL")
        self.btn_ig_perfil.setToolTip("Registra datos, foto y ubicaciones del perfil a la vista")
        self.btn_ig_perfil.clicked.connect(self.relevar_perfil_instagram)
        self.btn_ig_perfil.setVisible(False)

        self.btn_ig_lista = QPushButton("👥 LISTA DE CONTACTOS")
        self.btn_ig_lista.setToolTip(
            "Recorre la lista abierta: seguidores o seguidos en Instagram, amigos en Facebook")
        self.btn_ig_lista.clicked.connect(self.listar_contactos_instagram)
        self.btn_ig_lista.setVisible(False)

        self.btn_ig_com = QPushButton("💬 COMENTARIOS")
        self.btn_ig_com.setToolTip("Recorre y registra los comentarios de la publicacion a la vista")
        self.btn_ig_com.clicked.connect(self.capturar_comentarios)
        self.btn_ig_com.setVisible(False)

        self.btn_wa_chat = QPushButton("📷 CAPTURAR CHAT")
        self.btn_wa_chat.setToolTip("Captura la pantalla del chat abierto, tramo por tramo")
        self.btn_wa_chat.clicked.connect(self._wa_boton_chat)
        self.btn_wa_chat.setVisible(False)
        btn_exit = QPushButton("🚪 SALIR")
        btn_exit.clicked.connect(self.exit_and_package)
        btn_exit.setStyleSheet(btn_style.replace("#1b263b", "#4a1010").replace("#2c3e50", "#6b1a1a"))

        for b in [self.btn_rec, btn_cap, self.btn_pag, self.btn_wa, self.btn_wa_chat,
                  self.btn_ig_perfil, self.btn_ig_lista, self.btn_ig_com]:
            b.setStyleSheet(btn_style)
            h_lay.addWidget(b)
        h_lay.addWidget(btn_exit)
        main_layout.addWidget(header)

        # Barra de navegación original v1.0, 55px
        nav = QFrame()
        nav.setStyleSheet("background: #f8f9fa; border-bottom: 1px solid #ddd;")
        nav_lay = QHBoxLayout(nav)
        nav_lay.setContentsMargins(8, 6, 8, 6)
        nav_lay.setSpacing(6)
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("https://...")
        self.url_bar.setMinimumHeight(46)             # altura mínima garantizada, los descendentes nunca se cortan
        self.url_bar.setStyleSheet(
            "color: black; padding: 8px 10px; font-size: 13pt; "
            "border: 1px solid #bbb; border-radius: 3px;"
        )
        self.url_bar.returnPressed.connect(self.navigate)
        btn_go = QPushButton("IR A URL")
        btn_go.clicked.connect(self.navigate)
        btn_go.setMinimumHeight(46)
        btn_go.setStyleSheet(
            "background: #0d1b2a; color: white; font-weight: bold; "
            "padding: 8px 22px; border-radius: 3px; font-size: 11pt;"
        )
        btn_chrome = QPushButton("🍪 Sesión Chrome")
        btn_chrome.clicked.connect(self._import_chrome_cookies)
        btn_chrome.setMinimumHeight(46)
        btn_chrome.setToolTip("Importar cookies de Instagram/Facebook desde Chrome para evitar captcha")
        btn_chrome.setStyleSheet(
            "background: #1a6b3c; color: white; font-weight: bold; "
            "padding: 8px 14px; border-radius: 3px; font-size: 10pt;"
        )
        btn_cookie_help = QPushButton("?")
        btn_cookie_help.clicked.connect(self._show_cookie_help)
        btn_cookie_help.setMinimumHeight(46)
        btn_cookie_help.setFixedWidth(36)
        btn_cookie_help.setToolTip("Cómo exportar cookies de Chrome")
        btn_cookie_help.setStyleSheet(
            "background: #444; color: white; font-weight: bold; "
            "padding: 4px; border-radius: 3px; font-size: 12pt;"
        )
        self.btn_capture_profile = QPushButton("🪪 CAPTURAR PERFIL")
        self.btn_capture_profile.setMinimumHeight(46)
        self.btn_capture_profile.setVisible(False)
        self.btn_capture_profile.setToolTip("Capturar ID del perfil de Facebook o Instagram visitado")
        self.btn_capture_profile.clicked.connect(self._capture_profile_id)
        self.btn_capture_profile.setStyleSheet(
            "background: #6d28d9; color: white; font-weight: bold; "
            "padding: 8px 14px; border-radius: 3px; font-size: 10pt;"
        )

        nav_lay.addWidget(self.url_bar, 1)
        nav_lay.addWidget(btn_go)
        nav_lay.addWidget(self.btn_capture_profile)
        nav_lay.addWidget(btn_chrome)
        nav_lay.addWidget(btn_cookie_help)
        main_layout.addWidget(nav)

        # Panel de media detectada
        media_bar = QFrame()
        media_bar.setStyleSheet("background: #0d1b2a; border-bottom: 1px solid #1b3a5c;")
        media_bar.setFixedHeight(48)
        media_lay = QHBoxLayout(media_bar)
        media_lay.setContentsMargins(8, 4, 8, 4)
        media_lay.setSpacing(6)

        lbl_media = QLabel("📦 Media detectada:")
        lbl_media.setStyleSheet("color: #7dd3fc; font-weight: bold; font-size: 9pt;")
        media_lay.addWidget(lbl_media)

        self.combo_media = QComboBox()
        self.combo_media.setMinimumWidth(500)
        self.combo_media.setStyleSheet(
            "QComboBox { color: #e8f0f8; background: #1b263b; border: 1px solid #34495e; "
            "padding: 4px 8px; font-size: 9pt; font-family: Consolas, monospace; border-radius: 3px; }"
            "QComboBox::drop-down { border: none; }"
            "QComboBox QAbstractItemView { color: #e8f0f8; background: #0d1b2a; "
            "selection-background-color: #1b4d3e; font-size: 9pt; }"
        )
        self.combo_media.addItem("— Sin media detectada —")
        self.combo_media.setEnabled(False)
        media_lay.addWidget(self.combo_media, 1)

        self.btn_media = QPushButton("📦 ADQUIRIR")
        self.btn_media.setEnabled(False)
        self.btn_media.setFixedHeight(36)
        self.btn_media.setStyleSheet(
            "QPushButton { background: #1b4d3e; color: white; font-weight: bold; "
            "padding: 4px 16px; border-radius: 3px; border: 1px solid #25D366; font-size: 9pt; }"
            "QPushButton:hover { background: #25a87a; }"
            "QPushButton:disabled { background: #0a2a1e; color: #444; border-color: #1a4a2a; }"
        )
        self.btn_media.clicked.connect(self.acquire_media)
        media_lay.addWidget(self.btn_media)

        self.btn_ver = QPushButton("▶ VER")
        self.btn_ver.setEnabled(False)
        self.btn_ver.setFixedHeight(36)
        self.btn_ver.setToolTip("Reproducir el video seleccionado para verificar contenido (no registra evidencia)")
        self.btn_ver.setStyleSheet(
            "QPushButton { background: #1a3a5c; color: #7dd3fc; font-weight: bold; "
            "padding: 4px 14px; border-radius: 3px; border: 1px solid #2563eb; font-size: 9pt; }"
            "QPushButton:hover { background: #1e4a7a; color: white; }"
            "QPushButton:disabled { background: #0a1020; color: #2d3d50; border-color: #1a2a3a; }"
        )
        self.btn_ver.clicked.connect(self._ver_media)
        media_lay.addWidget(self.btn_ver)

        btn_clear_media = QPushButton("🗑 Limpiar lista")
        btn_clear_media.setFixedHeight(36)
        btn_clear_media.setStyleSheet(
            "QPushButton { background: #1b263b; color: #9ca3af; font-size: 9pt; "
            "padding: 4px 12px; border-radius: 3px; border: 1px solid #34495e; }"
            "QPushButton:hover { background: #2c3e50; color: white; }"
        )
        btn_clear_media.clicked.connect(self._clear_media_list)
        media_lay.addWidget(btn_clear_media)

        self.lbl_media_count = QLabel("0 URLs")
        self.lbl_media_count.setStyleSheet("color: #4a5568; font-size: 8pt; min-width: 50px;")
        media_lay.addWidget(self.lbl_media_count)

        main_layout.addWidget(media_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.browser = QWebEngineView()

        # Perfil propio del caso, con almacenamiento en disco.
        #
        # El perfil por defecto de Qt es off-the-record y no guarda nada. Con
        # el, setHttpCacheType, setHttpCacheMaximumSize y
        # setPersistentCookiesPolicy no hacen absolutamente nada: se comprobo
        # que la ruta de cache queda vacia y la politica en
        # NoPersistentCookies, aunque el codigo pida lo contrario.
        #
        # Lo determinante es que sin almacenamiento persistente no pueden
        # registrarse los service workers. WhatsApp Web usa uno para entregar
        # el multimedia ya descifrado; sin el, lo que se descarga es el .enc
        # del CDN, cifrado extremo a extremo y sin valor como prueba.
        #
        # Se guarda dentro de la carpeta del caso: cada pericia arranca con un
        # navegador limpio y lo que quede forma parte del expediente. La
        # contrapartida es que hay que vincular WhatsApp Web una vez por caso.
        # Va FUERA de la carpeta del caso, a proposito.
        #
        # Es material de trabajo del programa, no evidencia, y ademas guarda
        # las cookies de la sesion: dejarla adentro significaba empaquetar
        # credenciales activas del perito en el ZIP que se entrega. Tambien
        # rompia el empaquetado, porque el navegador mantiene abiertos sus
        # archivos y el ZIP no podia leerlos.
        perfil_dir = get_app_dir() / "perfiles_navegador" / self.case.case_id
        self._perfil_dir = perfil_dir
        try:
            perfil_dir.mkdir(parents=True, exist_ok=True)
            self._perfil = QWebEngineProfile(f"caso_{self.case.case_id}", self.browser)
            self._perfil.setPersistentStoragePath(str(perfil_dir))
            self._perfil.setCachePath(str(perfil_dir / "cache"))
            self.browser.setPage(ForensicPage(self._perfil, self.browser))
            self.case.log("INFO", "SYSTEM",
                          f"Perfil de navegacion del caso (fuera del expediente, "
                          f"contiene credenciales de sesion): {perfil_dir}")
        except Exception as _e:
            # Sin perfil propio el programa sigue andando, pero WhatsApp no va
            # a poder entregar el multimedia descifrado: tiene que constar.
            self._perfil = None
            self.browser.setPage(ForensicPage(self.browser))
            registrar_fallo_critico(
                "SYSTEM",
                f"No se pudo crear el perfil persistente ({_e}). El navegador queda "
                f"sin almacenamiento en disco y la descarga de multimedia de "
                f"WhatsApp puede entregar archivos cifrados")
        # Los enlaces que piden ventana nueva se abren en esta misma vista,
        # para que la navegacion siga quedando registrada en el caso.
        self.browser.page().aviso_popup = lambda destino: (
            self.append_console(f"Enlace abierto en esta ventana: {destino[:90]}"),
            self.case.log("INFO", "NAVEGACION",
                          f"Enlace con target=_blank abierto en la vista principal: {destino}"),
        )

        self.interceptor = ForensicNetworkInterceptor(self.case)
        profile = self.browser.page().profile()
        profile.setUrlRequestInterceptor(self.interceptor)
        profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
        )
        # Rendimiento de navegación
        # Caché de disco HTTP: evita re-descargar imágenes/JS repetidos del
        # perfil, acelerando la carga de publicaciones al hacer scroll.
        try:
            from PyQt6.QtWebEngineCore import QWebEngineSettings as _QWES
            profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.DiskHttpCache)
            profile.setHttpCacheMaximumSize(512 * 1024 * 1024)   # 512 MB
            profile.setPersistentCookiesPolicy(
                QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies)
            _s = self.browser.settings()
            _s.setAttribute(_QWES.WebAttribute.LocalStorageEnabled, True)
            _s.setAttribute(_QWES.WebAttribute.ScrollAnimatorEnabled, False)
            # Precarga de DNS: resuelve dominios de imágenes antes de pedirlos.
            _s.setAttribute(_QWES.WebAttribute.DnsPrefetchEnabled, True)
        except Exception as _e:
            self.append_console(f"⚠ No se pudo optimizar el caché del navegador: {_e}")
        # Stealth JS: evita que Instagram detecte QWebEngine como bot
        from PyQt6.QtWebEngineCore import QWebEngineScript as _QWEScript
        _stealth = _QWEScript()
        _stealth.setName("nav_stealth")
        _stealth.setInjectionPoint(_QWEScript.InjectionPoint.DocumentCreation)
        _stealth.setWorldId(_QWEScript.ScriptWorldId.MainWorld)
        _stealth.setRunsOnSubFrames(True)
        _stealth.setSourceCode("""(function(){
            try { Object.defineProperty(navigator,'webdriver',{get:()=>undefined,configurable:true}); } catch(e){}
            try {
                if(!window.chrome) window.chrome={};
                if(!window.chrome.runtime) window.chrome.runtime={};
                if(!window.chrome.app) window.chrome.app={isInstalled:false};
                if(!window.chrome.loadTimes) window.chrome.loadTimes=function(){return{};};
                if(!window.chrome.csi) window.chrome.csi=function(){return{};};
            } catch(e){}
            try {
                const oq=navigator.permissions.query.bind(navigator.permissions);
                navigator.permissions.query=p=>p.name==='notifications'
                    ?Promise.resolve({state:Notification.permission})
                    :oq(p);
            } catch(e){}
        })();""")
        profile.scripts().insert(_stealth)

        # Entrega de archivos grandes en WhatsApp Web
        #
        # Las fotos llegan como blob y se descargan sin mas. Los videos no:
        # WhatsApp los escribe directo a disco con showSaveFilePicker, de la
        # File System Access API. Y esa API exige un gesto real del usuario.
        #
        # Se comprobo en este mismo motor: un clic sintetico llega con
        # isTrusted en false, no otorga activacion, y la llamada termina en
        # "SecurityError: Must be handling a user gesture". Por eso las fotos
        # se adquirian y los videos no, aunque el clic en Descargar entrara
        # bien y WhatsApp llegara a pedir el archivo al servidor.
        #
        # Con un clic real enviado desde Qt la API si funciona, pero abre el
        # dialogo de guardar y habria que confirmar cada video a mano. Asi que
        # se reemplaza la funcion: recibe lo que WhatsApp escribe y, al
        # cerrar, lo entrega como una descarga comun, que es la via que el
        # programa ya sabe registrar con su hash y su acta.
        #
        # No se altera el contenido: los bytes son exactamente los que produjo
        # WhatsApp. Lo unico que cambia es el destino, que pasa a ser la
        # carpeta del caso en vez de una eleccion manual.
        _entrega = _QWEScript()
        _entrega.setName("nav_entrega_archivos")
        _entrega.setInjectionPoint(_QWEScript.InjectionPoint.DocumentCreation)
        _entrega.setWorldId(_QWEScript.ScriptWorldId.MainWorld)
        _entrega.setRunsOnSubFrames(True)
        _entrega.setSourceCode(r"""(function(){
            // Solo en WhatsApp Web: en el resto de los sitios el navegador
            // se comporta como cualquier otro.
            if (location.hostname.indexOf('web.whatsapp.com') < 0) { return; }
            if (window.__nav_entrega) { return; }
            window.__nav_entrega = true;

            // Registro de por donde intenta salir cada archivo. Sirve para
            // saber que hace WhatsApp cuando una descarga no llega, en vez de
            // suponerlo: se vuelca al log del caso cuando algo falla.
            var diag = window.__nav_diag = {
                picker: 0, blobs: [], enlaces: [], errores: [], iframes: 0
            };

            // Se conserva el propio Blob, no su URL: WhatsApp revoca la URL en
            // cuanto termina, y con la referencia al Blob el archivo sigue
            // disponible para entregarlo despues.
            var guardados = [];
            var _crear = URL.createObjectURL;
            URL.createObjectURL = function (o) {
                try {
                    if (o && typeof o.size === 'number') {
                        diag.blobs.push((o.type || 'sin tipo') + ' ' + o.size + 'B');
                        if (diag.blobs.length > 12) { diag.blobs.shift(); }
                        if (o.size > 8192) {
                            guardados.push({blob: o, tipo: o.type || '', entregado: false});
                            if (guardados.length > 8) { guardados.shift(); }
                        }
                    }
                } catch (e) { }
                return _crear.apply(URL, arguments);
            };

            // Entrega el ultimo archivo del tipo pedido que WhatsApp haya
            // dejado preparado en la pagina.
            //
            // Se comprobo que con los videos WhatsApp descifra el archivo,
            // arma el Blob y ahi se detiene: nunca dispara la descarga. El
            // contenido ya esta, asi que se lo entrega por la misma via que
            // el programa usa para todo lo demas. Los bytes son los que
            // produjo WhatsApp; no se toca nada del contenido.
            window.__nav_entregar = function (prefijo, nombre) {
                for (var i = guardados.length - 1; i >= 0; i--) {
                    var g = guardados[i];
                    if (g.entregado) { continue; }
                    if (prefijo && g.tipo.indexOf(prefijo) !== 0) { continue; }
                    try {
                        g.entregado = true;
                        // La extension sale del tipo del propio archivo: sin
                        // ella el video queda sin abrir en el equipo.
                        var ext = {
                            'video/mp4': '.mp4', 'video/webm': '.webm',
                            'video/quicktime': '.mov', 'video/3gpp': '.3gp',
                            'audio/ogg': '.ogg', 'audio/mpeg': '.mp3',
                            'audio/mp4': '.m4a', 'audio/aac': '.aac',
                            'image/jpeg': '.jpg', 'image/png': '.png',
                            'image/webp': '.webp', 'application/pdf': '.pdf'
                        }[g.tipo.split(';')[0]] || '';
                        if (ext && nombre.slice(-ext.length) !== ext) { nombre += ext; }

                        var u = _crear.call(URL, g.blob);
                        var a = document.createElement('a');
                        a.href = u;
                        a.download = nombre;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        setTimeout(function () { URL.revokeObjectURL(u); }, 60000);
                        return JSON.stringify({ok: true, tipo: g.tipo, size: g.blob.size});
                    } catch (e) {
                        return JSON.stringify({ok: false, error: String(e).slice(0, 70)});
                    }
                }
                return JSON.stringify({ok: false, motivo: 'no hay archivo de ese tipo'});
            };

            document.addEventListener('click', function (ev) {
                try {
                    var a = ev.target && ev.target.closest
                          ? ev.target.closest('a[download], a[href^="blob:"]') : null;
                    if (a) {
                        diag.enlaces.push((a.getAttribute('download') || a.href || '')
                                          .slice(0, 40));
                        if (diag.enlaces.length > 12) { diag.enlaces.shift(); }
                    }
                } catch (e) { }
            }, true);

            function anotar(t) {
                diag.errores.push(String(t).slice(0, 110));
                if (diag.errores.length > 12) { diag.errores.shift(); }
            }
            window.addEventListener('error', function (e) {
                anotar('error: ' + (e.message || ''));
            });
            window.addEventListener('unhandledrejection', function (e) {
                var r = e.reason;
                anotar('rechazo: ' + (r && r.name ? r.name + ': ' + r.message : r));
            });

            window.showSaveFilePicker = function (op) {
                diag.picker++;
                op = op || {};
                var nombre = op.suggestedName || ('WhatsApp_' + Date.now());
                var partes = [];
                return Promise.resolve({
                    kind: 'file',
                    name: nombre,
                    createWritable: function () {
                        return Promise.resolve({
                            write: function (d) {
                                // Admite write(dato) y write({type:'write', data})
                                if (d && d.type === 'write') { d = d.data; }
                                if (d !== null && d !== undefined) { partes.push(d); }
                                return Promise.resolve();
                            },
                            seek:     function () { return Promise.resolve(); },
                            truncate: function () { return Promise.resolve(); },
                            abort:    function () { partes = []; return Promise.resolve(); },
                            close: function () {
                                try {
                                    var blob = new Blob(partes);
                                    var a = document.createElement('a');
                                    a.href = URL.createObjectURL(blob);
                                    a.download = nombre;
                                    document.body.appendChild(a);
                                    a.click();
                                    document.body.removeChild(a);
                                    setTimeout(function () {
                                        URL.revokeObjectURL(a.href);
                                    }, 60000);
                                } catch (e) { }
                                return Promise.resolve();
                            }
                        });
                    },
                    getFile: function () {
                        return Promise.resolve(new File(partes, nombre));
                    }
                });
            };
        })();""")
        profile.scripts().insert(_entrega)

        profile.downloadRequested.connect(self._on_download_requested)
        self.browser.urlChanged.connect(self._on_url_changed)
        # Verificacion de integridad del codigo en portales de Meta
        self.browser.loadFinished.connect(self._on_load_finished_bt)
        # Una sola vez, al terminar la primera carga: como dibuja el navegador.
        QTimer.singleShot(4000, self._informar_render)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background: #0a0a0a; color: #00ff41; font-family: Consolas, monospace; font-size: 10pt;")
        # La consola es una vista en vivo, no la evidencia: esa queda en el
        # audit_log y en el HAR. Sin tope, en paginas con cientos de lineas
        # [MEDIA] el QTextEdit se agranda y cada append va poniendose mas lento.
        self.console.document().setMaximumBlockCount(3000)

        splitter.addWidget(self.browser)
        splitter.addWidget(self.console)
        splitter.setSizes([900, 120])

        # TAB WIDGET principal
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: none; }
            QTabBar::tab {
                background: #1b263b; color: #aaa;
                padding: 10px 22px; font-size: 11pt; font-weight: bold;
                border-top-left-radius: 4px; border-top-right-radius: 4px;
                margin-right: 2px;
            }
            QTabBar::tab:selected { background: #0d1b2a; color: #fff; border-bottom: 3px solid #25D366; }
            QTabBar::tab:hover { background: #243447; color: white; }
        """)
        self.tabs.addTab(splitter, "🌐  Navegador Forense")
        self.tabs.addTab(self._build_evidence_tab(), "🗂  Evidencias")
        self.tabs.addTab(self._build_custody_tab(), "🔐  Cadena de Custodia")
        self.tabs.currentChanged.connect(self._on_tab_changed)

        main_layout.addWidget(self.tabs)

        self.status = QStatusBar()
        self.status.showMessage(f"Caso: {self.case.case_id} | Listo")
        self.setStatusBar(self.status)

        self.setCentralWidget(central)

    # ══════════════════════════════════════════════════════════════════════
    #  TAB EVIDENCIAS: inventario en vivo con verificación de integridad
    # ══════════════════════════════════════════════════════════════════════
    _EV_HEADERS = ["#", "Fecha / Hora", "Tipo", "Archivo", "Tamaño",
                   "SHA-256", "Sellado TSA", "URL de origen"]

    def _build_evidence_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        # Barra superior: título + acciones
        bar = QHBoxLayout()
        title = QLabel("🗂  Inventario de Evidencias Digitales")
        title.setStyleSheet("color: #0d1b2a; font-size: 15pt; font-weight: bold;")
        bar.addWidget(title)
        bar.addStretch()

        self.lbl_ev_summary = QLabel("0 evidencias")
        self.lbl_ev_summary.setStyleSheet("color: #1a6b3c; font-weight: bold; font-size: 10pt;")
        bar.addWidget(self.lbl_ev_summary)

        btn_verify = QPushButton("✔ Verificar integridad")
        btn_verify.setToolTip("Recalcula el SHA-256 de cada archivo y lo compara con el registrado")
        btn_verify.setStyleSheet(
            "QPushButton { background: #1a6b3c; color: white; font-weight: bold; "
            "padding: 8px 16px; border-radius: 4px; }"
            "QPushButton:hover { background: #25a87a; }"
        )
        btn_verify.clicked.connect(self._verify_evidence_integrity)
        bar.addWidget(btn_verify)

        btn_refresh_ev = QPushButton("⟳ Actualizar")
        btn_refresh_ev.setStyleSheet(
            "QPushButton { background: #1b263b; color: white; font-weight: bold; "
            "padding: 8px 16px; border-radius: 4px; }"
            "QPushButton:hover { background: #2c3e50; }"
        )
        btn_refresh_ev.clicked.connect(self.refresh_evidence_table)
        bar.addWidget(btn_refresh_ev)
        lay.addLayout(bar)

        info = QLabel(
            "Cada archivo adquirido queda registrado con su huella criptográfica SHA-256 y "
            "sellado de tiempo (RFC 3161), conforme ISO/IEC 27037. Verifique la integridad "
            "antes de exportar el informe pericial."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #55606b; font-size: 9pt; padding: 2px 0 6px 0;")
        lay.addWidget(info)

        self.tbl_evidence = QTableWidget(0, len(self._EV_HEADERS))
        self.tbl_evidence.setHorizontalHeaderLabels(self._EV_HEADERS)
        self.tbl_evidence.setStyleSheet(self._table_style())
        self.tbl_evidence.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_evidence.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_evidence.setAlternatingRowColors(True)
        hh = self.tbl_evidence.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.tbl_evidence.verticalHeader().setVisible(False)
        lay.addWidget(self.tbl_evidence)
        return w

    def _build_custody_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        lay.setSpacing(8)

        bar = QHBoxLayout()
        title = QLabel("🔐  Registro de Auditoría — Cadena de Custodia")
        title.setStyleSheet("color: #0d1b2a; font-size: 15pt; font-weight: bold;")
        bar.addWidget(title)
        bar.addStretch()

        self.lbl_custody_status = QLabel("—")
        self.lbl_custody_status.setStyleSheet("font-weight: bold; font-size: 10pt;")
        bar.addWidget(self.lbl_custody_status)

        btn_refresh_c = QPushButton("⟳ Actualizar y verificar la cadena")
        btn_refresh_c.setToolTip("Recarga el registro y comprueba el encadenamiento y la firma Ed25519")
        btn_refresh_c.setStyleSheet(
            "QPushButton { background: #1b263b; color: white; font-weight: bold; "
            "padding: 8px 16px; border-radius: 4px; }"
            "QPushButton:hover { background: #2c3e50; }"
        )
        btn_refresh_c.clicked.connect(self.refresh_custody_table)
        bar.addWidget(btn_refresh_c)
        lay.addLayout(bar)

        info = QLabel(
            "Bitácora inalterable de todas las acciones del peritaje. Cada entrada se encadena a "
            "la anterior con SHA-256 y la cadena se firma con una clave Ed25519 que existe solo "
            "mientras el programa está abierto; una línea alterada o suprimida rompe la cadena y "
            "se marca en rojo."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #55606b; font-size: 9pt; padding: 2px 0 6px 0;")
        lay.addWidget(info)

        self.tbl_custody = QTableWidget(0, 5)
        self.tbl_custody.setHorizontalHeaderLabels(
            ["#", "Fecha / Hora", "Nivel", "Categoría", "Descripción"])
        self.tbl_custody.setStyleSheet(self._table_style())
        self.tbl_custody.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_custody.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_custody.setAlternatingRowColors(True)
        ch = self.tbl_custody.horizontalHeader()
        ch.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        ch.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.tbl_custody.verticalHeader().setVisible(False)
        lay.addWidget(self.tbl_custody)
        return w

    @staticmethod
    def _table_style() -> str:
        return (
            "QTableWidget { background: #ffffff; color: #1a2530; gridline-color: #d5dbe1; "
            "font-size: 9pt; border: 1px solid #cdd4db; }"
            "QTableWidget::item { padding: 4px 6px; }"
            "QTableWidget::item:selected { background: #cfe8ff; color: #0d1b2a; }"
            "QHeaderView::section { background: #0d1b2a; color: white; font-weight: bold; "
            "padding: 6px; border: none; border-right: 1px solid #1b3a5c; }"
        )

    def _on_tab_changed(self, index: int):
        label = self.tabs.tabText(index)
        if "Evidencias" in label:
            self.refresh_evidence_table()
        elif "Custodia" in label:
            self.refresh_custody_table()

    def refresh_evidence_table(self):
        evs = list(getattr(self.case, "evidences", []))
        self.tbl_evidence.setRowCount(len(evs))
        total_bytes = 0
        for row, ev in enumerate(evs):
            size = ev.get("size_bytes", 0) or 0
            total_bytes += size
            tsa = ev.get("tsa")
            tsa_ok = "✔ Sí" if isinstance(tsa, dict) and tsa else "—"
            ts_raw = ev.get("ts", "")
            ts_fmt = ts_raw.replace("T", "  ")[:19] if ts_raw else ""
            cells = [
                str(row + 1),
                ts_fmt,
                ev.get("tipo", ""),
                ev.get("filename", ""),
                self._fmt_size(size),
                ev.get("sha256", ""),
                tsa_ok,
                ev.get("source_url", "") or "—",
            ]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                if col == 5:
                    item.setFont(QFont("Consolas", 8))
                    item.setToolTip(ev.get("sha256", ""))
                if col in (0, 4, 6):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.tbl_evidence.setItem(row, col, item)
        self.lbl_ev_summary.setText(
            f"{len(evs)} evidencia(s)  ·  {self._fmt_size(total_bytes)} en total")

    def _verify_evidence_integrity(self):
        evs = list(getattr(self.case, "evidences", []))
        if not evs:
            QMessageBox.information(self, "Verificación de integridad",
                                    "No hay evidencias registradas todavía.")
            return
        ok = alt = missing = 0
        for row, ev in enumerate(evs):
            path = ev.get("path", "")
            expected = ev.get("sha256", "")
            if not path or not os.path.exists(path):
                estado, color = "✗ No encontrado", "#c0392b"
                missing += 1
            else:
                actual = sha256_file(path)
                if actual == expected:
                    estado, color = "✔ Íntegro", "#1a6b3c"
                    ok += 1
                else:
                    estado, color = "✗ ALTERADO", "#c0392b"
                    alt += 1
            item = QTableWidgetItem(estado)
            item.setForeground(Qt.GlobalColor.white)
            item.setBackground(QColor(color))
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            # columna SHA-256 (5): reflejar estado con color de fondo
            sha_item = self.tbl_evidence.item(row, 5)
            if sha_item:
                sha_item.setBackground(QColor("#e8f6ee") if estado.startswith("✔") else QColor("#fbe6e6"))
        self.case.log("INFO", "INTEGRITY",
                      f"Verificación manual: {ok} íntegras, {alt} alteradas, {missing} no encontradas")
        icon = QMessageBox.Icon.Information if (alt == 0 and missing == 0) else QMessageBox.Icon.Warning
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle("Resultado de verificación de integridad")
        box.setText(
            f"Evidencias íntegras:   {ok}\n"
            f"Evidencias alteradas:  {alt}\n"
            f"Archivos no hallados:  {missing}\n\n"
            + ("Todas las huellas SHA-256 coinciden con el registro."
               if (alt == 0 and missing == 0)
               else "⚠ Se detectaron discrepancias. Revise la columna SHA-256.")
        )
        box.exec()

    def refresh_custody_table(self):
        try:
            with sqlite3.connect(str(self.case.db_path)) as conn:
                rows = conn.execute(
                    "SELECT id, ts, level, category, message FROM audit_log ORDER BY id ASC"
                ).fetchall()
            v = verificar_log(self.case.db_path, self.case.clave_publica_log, self.case.case_id)
        except Exception as e:
            self.lbl_custody_status.setText("Error al leer audit_log")
            self.lbl_custody_status.setStyleSheet("color: #c0392b; font-weight: bold;")
            self.append_console(f"✗ No se pudo leer el registro de auditoría: {e}")
            return

        rotas = set(v["rotas"])
        self.tbl_custody.setRowCount(len(rows))
        for i, (id_, ts, level, category, message) in enumerate(rows):
            valid = id_ not in rotas
            ts_fmt = (ts or "").replace("T", "  ")[:19]
            cells = [str(i + 1), ts_fmt, level, category, message]
            for col, val in enumerate(cells):
                item = QTableWidgetItem(val)
                if col in (0, 2):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if not valid:
                    item.setBackground(QColor("#fbe6e6"))
                    item.setForeground(QColor("#8a1420"))
                elif level == "ERROR":
                    item.setForeground(QColor("#c0392b"))
                elif level == "WARNING":
                    item.setForeground(QColor("#b8860b"))
                self.tbl_custody.setItem(i, col, item)
        rojo = "color: #c0392b; font-weight: bold; font-size: 10pt;"
        if v["integro"]:
            self.lbl_custody_status.setText(
                f"✔ Íntegro — {v['entradas']} entradas encadenadas, "
                f"{v['firmadas']} ya cubiertas por la firma")
            self.lbl_custody_status.setStyleSheet("color: #1a6b3c; font-weight: bold; font-size: 10pt;")
        elif v["rotas"]:
            self.lbl_custody_status.setText(f"✗ La cadena se rompe en {len(v['rotas'])} entrada(s)")
            self.lbl_custody_status.setStyleSheet(rojo)
        else:
            self.lbl_custody_status.setText(
                f"✗ {len(v['cierres_invalidos'])} firma(s) del log no verifican")
            self.lbl_custody_status.setStyleSheet(rojo)
        self.tbl_custody.scrollToBottom()

    @staticmethod
    def _fmt_size(num: int) -> str:
        n = float(num or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024.0:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
            n /= 1024.0
        return f"{n:.2f} TB"

    # ══════════════════════════════════════════════════════════════════════
    def connect_signals(self):
        log_signals.log_msg.connect(self.append_console)
        log_signals.media_detected.connect(self.on_media_detected)

        # Refresco en vivo de los paneles forenses (solo actualiza el tab visible;
        # corre en el hilo principal via QTimer, sin riesgo de acceso concurrente a Qt).
        self._forensic_timer = QTimer(self)
        self._forensic_timer.setInterval(3000)
        self._forensic_timer.timeout.connect(self._tick_forensic_panels)
        self._forensic_timer.start()

    def _tick_forensic_panels(self):
        # Volcar el log de red acumulado a la base cada ciclo (no bloquea la
        # navegación porque ocurre en el hilo principal, en lote y cada 3s).
        try:
            self.case.flush_network_log()
        except Exception:
            pass
        try:
            label = self.tabs.tabText(self.tabs.currentIndex())
        except Exception:
            return
        if "Evidencias" in label:
            self.refresh_evidence_table()
        elif "Custodia" in label:
            self.refresh_custody_table()

    def append_console(self, text: str):
        if is_js_spam(text):
            return
        # Resolución UID → usuario: navegar al perfil resuelto
        if text.startswith("\x00NAVIGATE_TO\x00"):
            parts = text.split("\x00")
            if len(parts) >= 5:
                target_url, uid, username = parts[2], parts[3], parts[4]
                self.url_bar.setText(target_url)
                self.browser.setUrl(QUrl(target_url))
                self.case.log("INFO", "UID_RESOLVE",
                              f"UID {uid} resuelto a @{username} → {target_url}")
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                self.console.append(f"[{ts}] ✓ UID {uid} → @{username}. Abriendo perfil…")
            return
        if text.startswith("\x00UID_RESOLVE_ERR\x00"):
            parts = text.split("\x00")
            uid = parts[2] if len(parts) > 2 else ""
            err = parts[3] if len(parts) > 3 else ""
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self.console.append(f"[{ts}] ✗ No se pudo resolver el UID {uid}: {err}")
            return
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{ts}] {text}")

    def navigate(self):
        from urllib.parse import urlparse as _urlparse
        u = self.url_bar.text().strip()
        if not u:
            return
        parsed = _urlparse(u)
        # Solo permitir http/https. Rechazar file://, javascript:, data:, ftp://, etc.
        # para evitar que el motor de red acceda al sistema de archivos local
        # o ejecute código arbitrario desde la barra de URL.
        if parsed.scheme not in ("http", "https"):
            if "://" in u:
                self.append_console(f"✗ Esquema no permitido: '{parsed.scheme}'. Solo http/https.")
                return
            u = "https://" + u  # completar dominio sin esquema

        # Instagram no permite navegar por UID numérico. Si el usuario ingresa
        # instagram.com/<solo-digitos>, resolvemos el UID → nombre de usuario y
        # redirigimos al perfil real automáticamente.
        _reparse = _urlparse(u)
        if "instagram.com" in _reparse.netloc.lower():
            _path = _reparse.path.strip("/")
            if _path.isdigit() and len(_path) >= 5:
                self.append_console(f"🔎 UID numérico detectado ({_path}). Resolviendo nombre de usuario…")
                threading.Thread(target=self._resolve_ig_uid, args=(_path,), daemon=True).start()
                return

        self.browser.setUrl(QUrl(u))
        self.case.log("INFO", "NAVIGATION", f"Navegando a: {u}")
        self.append_console(f"Navegando a: {u}")
        # Capturar metadatos del sitio en background sin bloquear UI
        t = threading.Thread(target=self._capture_site_metadata, args=(u,), daemon=True)
        t.start()

    def _resolve_ig_uid(self, uid: str):
        """
        Resuelve un UID numérico de Instagram a su nombre de usuario usando el
        endpoint privado i.instagram.com/api/v1/users/<uid>/info/. Usa las cookies
        de sesión importadas (si existen) para mejorar la tasa de éxito.
        Emite una orden de navegación al perfil resuelto, o un error.
        """
        import requests as _req
        cookie_header = ""
        try:
            if self._COOKIES_FILE.exists():
                with open(self._COOKIES_FILE, encoding="utf-8") as f:
                    _ck = json.load(f)
                pares = [f"{c.get('name')}={c.get('value')}" for c in _ck
                         if isinstance(c, dict) and "instagram.com" in c.get("domain", "")
                         and c.get("name") and c.get("value")]
                cookie_header = "; ".join(pares)
        except Exception:
            pass

        headers = {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
            "X-IG-App-ID":     "936619743392459",
            "Accept":          "application/json",
            "Accept-Language": "es-AR,es;q=0.9,en;q=0.8",
            "Referer":         "https://www.instagram.com/",
        }
        if cookie_header:
            headers["Cookie"] = cookie_header

        username = ""
        error_msg = ""
        try:
            api = f"https://i.instagram.com/api/v1/users/{uid}/info/"
            r = _req.get(api, headers=headers, timeout=12)
            if r.status_code == 200:
                user = r.json().get("user") or {}
                username = user.get("username", "")
                if not username:
                    error_msg = "Respuesta OK pero sin nombre de usuario."
            elif r.status_code in (401, 403):
                error_msg = ("Requiere sesión activa. Importá tus cookies con "
                             "🍪 Sesión Chrome y reintentá.")
            elif r.status_code == 404:
                error_msg = "UID inexistente o cuenta eliminada (HTTP 404)."
            else:
                error_msg = f"HTTP {r.status_code}"
        except Exception as e:
            error_msg = str(e)

        if username:
            log_signals.log_msg.emit(
                f"\x00NAVIGATE_TO\x00https://www.instagram.com/{username}/\x00{uid}\x00{username}")
        else:
            log_signals.log_msg.emit(f"\x00UID_RESOLVE_ERR\x00{uid}\x00{error_msg}")

    # VERIFICACION DE INTEGRIDAD DEL CODIGO (BINARY TRANSPARENCY)

    def _informar_render(self):
        """Deja constancia de si el navegador usa la placa o dibuja por software."""
        if getattr(self, "_render_informado", False):
            return
        self._render_informado = True
        try:
            self.browser.page().runJavaScript(_RENDER_JS, self._render_leido)
        except Exception as e:
            self.case.log("ADVERTENCIA", "ENTORNO",
                          f"No se pudo determinar el modo de dibujado: {e}")

    def _render_leido(self, res):
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        motor = d.get("motor") or "no informado"
        acelerado = d.get("acelerado")

        self.append_console("-" * 60)
        self.append_console("[ENTORNO] Motor grafico del navegador")
        self.append_console(f"  Dibujado  : {'por placa de video' if acelerado else 'POR SOFTWARE'}")
        self.append_console(f"  Motor     : {motor[:90]}")
        self.append_console(f"  Escala    : {d.get('dpr', '?')}x   Nucleos: {d.get('nucleos', '?')}")
        if acelerado is False:
            # No es un detalle de rendimiento: con dibujado por software una
            # sesion larga se vuelve inmanejable y las capturas se demoran.
            self.append_console("  AVISO: sin aceleracion por hardware el navegador va a ir lento.")
            self.case.log("ADVERTENCIA", "ENTORNO",
                          f"El navegador dibuja por software ({motor}): el rendimiento "
                          f"sera notablemente menor")
        self.append_console("-" * 60)
        self.case.log("INFO", "ENTORNO",
                      f"Motor grafico: {motor} | acelerado por hardware: {acelerado} | "
                      f"escala {d.get('dpr')} | nucleos {d.get('nucleos')}")

        # Que formatos de video puede reproducir el navegador. Se consigna
        # siempre, y se avisa cuando faltan los de WhatsApp e Instagram: el
        # recuadro del video queda en negro y sin este aviso parece que la
        # publicacion no tenia video.
        codecs = d.get("codecs")
        self.append_console(f"  Video     : {resumen_codecs(codecs)}")
        self.case.log("INFO", "ENTORNO", f"Codecs del motor: {resumen_codecs(codecs)}")
        if sin_codecs_propietarios(codecs):
            self.append_console(
                "  AVISO: el motor no reproduce H.264/AAC (WhatsApp, Instagram). El video "
                "no se vera en el navegador; se adquiere como archivo con su hash.")
            self.case.log("ADVERTENCIA", "ENTORNO",
                          "El motor no reproduce H.264/AAC: el video de WhatsApp e Instagram "
                          "no se vera en pantalla ni en la grabacion. Se adquiere como archivo "
                          "original con su SHA-256 y se reproduce en el visor del programa")
        self._render_info = d

    def _on_load_finished_bt(self, ok: bool):
        """
        Cuando termina de cargar un portal de Meta, comprueba que el codigo
        servido sea el que Meta publico ante Cloudflare. Arranca con retardo
        porque el manifiesto se inyecta despues del load.
        """
        if not ok:
            return
        try:
            from urllib.parse import urlparse
            host = urlparse(self.browser.url().toString()).netloc.lower()
        except Exception:
            return
        dominio = next((d for d in _BT_ORIGENES if host.endswith(d)), None)
        if not dominio:
            return
        QTimer.singleShot(2000, lambda: self._verificar_bt(dominio))

    def _verificar_bt(self, dominio: str, intento: int = 1):
        """
        Lee el manifiesto de transparencia de la pagina que esta cargada.

        El manifiesto tarda en aparecer porque no viene en el HTML inicial: la
        aplicacion lo baja aparte y despues lo inyecta. En Instagram medimos
        11 s, y con la grabacion de la diligencia activa tarda mas todavia,
        porque la codificacion H.264 se lleva la CPU. Por eso reintenta ~40 s
        antes de darlo por ausente. Con una sola comprobacion nos quedariamos
        sin constancia de integridad justo en la diligencia que se documenta.
        """
        MAX_INTENTOS = 20          # ~40 s con reintentos cada 2 s, lo puse en 40 por si es muy lenta la carga

        def _al_leer(res):
            try:
                d = json.loads(res) if res else {}
            except Exception:
                d = {}
            if not d.get("presente"):
                # Aun no aparecio: reintentar hasta agotar la ventana
                if intento < MAX_INTENTOS:
                    QTimer.singleShot(
                        2000, lambda: self._verificar_bt(dominio, intento + 1))
                return          # el portal no publica manifiesto: nada que verificar
            version = str(d.get("version") or "")
            combinado = str(d.get("combined_hash") or "")
            if not version or not combinado:
                return
            clave = (dominio, version)
            if clave in self._bt_verificados:
                return
            self._bt_verificados.add(clave)
            self.append_console(
                f"[INTEGRIDAD] {dominio} v{version} — contrastando contra Cloudflare…")
            threading.Thread(
                target=self._contrastar_bt,
                args=(dominio, version, combinado, int(d.get("cant_scripts") or 0)),
                daemon=True).start()

        try:
            self.browser.page().runJavaScript(_BT_MANIFEST_JS, _al_leer)
        except Exception:
            pass

    def _contrastar_bt(self, dominio: str, version: str,
                       combinado: str, cant_scripts: int):
        """
         Compara el hash que declaro la pagina contra el que publica Cloudflare
        y deja el resultado en la cadena de custodia: audit log, JSON del caso
        y dictamen.
        """
        import requests as _req
        ts = datetime.datetime.now()
        registro = {
            "ts":            ts.isoformat(),
            "ts_legible":    ts.strftime("%d/%m/%Y %H:%M:%S"),
            "dominio":       dominio,
            "version":       version,
            "hash_pagina":   combinado,
            "cant_scripts":  cant_scripts,
            "fuente_externa": f"{_BT_CF_API}/{dominio}/{version}",
        }
        try:
            r = _req.get(f"{_BT_CF_API}/{dominio}/{version}", timeout=20, verify=True)
            registro["http_status"] = r.status_code
            if r.status_code == 200:
                raiz = str((r.json() or {}).get("root_hash") or "")
                registro["hash_cloudflare"] = raiz
                registro["resultado"] = (
                    "VERIFICADO" if raiz.strip().lower() == combinado.strip().lower()
                    else "DISCREPANCIA")
            else:
                registro["hash_cloudflare"] = ""
                registro["resultado"] = "NO_DISPONIBLE"
                registro["detalle"] = (r.text or "")[:120]
        except Exception as e:
            registro["resultado"] = "ERROR"
            registro["detalle"] = str(e)[:120]

        self.case.bt_verifications.append(registro)
        ruta = self.case.dirs["network"] / "verificacion_codigo.json"
        try:
            previos = json.load(open(ruta, encoding="utf-8")) if ruta.exists() else []
            previos.append(registro)
            with open(ruta, "w", encoding="utf-8") as f:
                json.dump(previos, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        res = registro["resultado"]
        self.case.log(
            "INFO" if res == "VERIFICADO" else "WARN", "INTEGRIDAD_CODIGO",
            f"{dominio} v{version} | {res} | pagina={combinado[:24]}... | "
            f"cloudflare={registro.get('hash_cloudflare','')[:24]}... | "
            f"scripts={cant_scripts}")

        if res == "VERIFICADO":
            log_signals.log_msg.emit(
                f"✓ MANIFIESTO DE CODIGO VERIFICADO — {dominio} v{version}")
            log_signals.log_msg.emit(
                "  El inventario de codigo declarado por el portal coincide con el "
                "publicado por Meta ante Cloudflare (tercero independiente)")
            log_signals.log_msg.emit(
                f"  Hash raiz: {combinado[:48]}…  |  Scripts declarados: {cant_scripts:,}")
        elif res == "DISCREPANCIA":
            log_signals.log_msg.emit(
                f"✗ ALERTA — {dominio} v{version}: el manifiesto declarado por el portal "
                f"NO coincide con el publicado por Meta ante Cloudflare.")
        else:
            log_signals.log_msg.emit(
                f"[INTEGRIDAD] {dominio} v{version}: {res} "
                f"({registro.get('detalle','')[:60]})")

    def _capture_site_metadata(self, url: str):
        meta = get_site_metadata(url)
        self.case.site_metadata.append(meta)
        # Guardar en archivo JSON de metadatos de red
        meta_path = self.case.dirs["network"] / "site_metadata.json"
        try:
            existing = []
            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            existing.append(meta)
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
        # Acreditacion del servidor: su certificado y sus cabeceras, una vez
        # por host. Prueban quien sirvio el contenido y en que condiciones.
        host = meta.get("host") or ""
        if host:
            try:
                guardar_certificado_servidor(self.case, host)
            except Exception as _e:
                self.case.log("ADVERTENCIA", "ACREDITACION", f"Certificado: {_e}")
            try:
                guardar_cabeceras(self.case, meta)
            except Exception as _e:
                self.case.log("ADVERTENCIA", "ACREDITACION", f"Cabeceras: {_e}")

        geo = meta.get("geo", {})
        pais = geo.get("pais", "") if isinstance(geo, dict) else ""
        ip   = meta.get("ip", "N/A")
        log_signals.log_msg.emit(
            f"[META] {meta.get('host','?')} → IP: {ip}"
            + (f" | {pais}" if pais and pais != "N/A" else "")
            + (f" | HTTP {meta.get('http_status','?')}" if meta.get('http_status') else "")
        )
        self.case.log("INFO", "SITE_META",
            f"Host: {meta.get('host','?')} | IP: {ip} | "
            f"Pais: {pais} | Status: {meta.get('http_status','N/A')}")

    def on_media_detected(self, payload: str):
        # payload = "url\x00tipo\x00url_normalizada"
        parts = payload.split("\x00")
        url        = parts[0]
        media_type = parts[1] if len(parts) > 1 else "MEDIA"
        url_norm   = parts[2] if len(parts) > 2 else url

        # Deduplicar por URL normalizada
        if url_norm in self._detected_norms:
            return
        self._detected_norms.add(url_norm)
        self.detected_media_urls.append(url)
        self.last_media_url = url

        icons = {
            "VIDEO":      "🎬",
            "AUDIO":      "🎵",
            "IMAGEN":     "🖼",
            "STREAM":     "📡",
            "ENCRIPTADO": "🔒",
        }
        icon = icons.get(media_type, "📦")

        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")[:22]
        fname  = parsed.path.split("/")[-1][:32] or parsed.path[-22:]
        n      = len(self.detected_media_urls)
        combo_idx = self.combo_media.count() if self.combo_media.isEnabled() else 0

        # Etiqueta inicial con tamaño pendiente
        label = f"{icon} [{n:02d}] {media_type:<11}  ⏳ sondeando...   {domain}  —  {fname}"

        if self.combo_media.count() == 1 and not self.combo_media.isEnabled():
            self.combo_media.clear()
            combo_idx = 0

        self.combo_media.addItem(label, url)
        self.combo_media.setCurrentIndex(self.combo_media.count() - 1)
        self.combo_media.setEnabled(True)
        self.btn_media.setEnabled(True)
        self.btn_ver.setEnabled(True)

        self.lbl_media_count.setText(f"{n} URL{'s' if n != 1 else ''}")
        self.lbl_media_count.setStyleSheet("color: #25D366; font-size: 8pt; font-weight: bold;")

        self.case.log("INFO", "DETECTION", f"Media [{n}] {media_type}: {url}")
        self.append_console(f"[MEDIA {n:02d}] {icon} {media_type}  {url[:80]}...")

        u_lower = url.lower()

        # Las URL de multimedia de WhatsApp no se sondean.
        #
        # Vienen firmadas y pensadas para que las use la sesion del navegador.
        # El sondeo sale por fuera, desde requests y sin las credenciales de la
        # pagina, y eso invalida la URL: cuando WhatsApp va a buscar el archivo
        # ya no puede, el mensaje vuelve al estado "descargar" y queda trabado
        # sin manera de recuperarlo.
        #
        # Tampoco se pierde nada por no sondearlas: son .enc cifrados extremo a
        # extremo, asi que el tamano y el tipo que devolveria el sondeo no
        # dicen nada del contenido. La URL igual queda registrada arriba.
        if "whatsapp.net" in u_lower or "whatsapp.com" in u_lower:
            self.case.log("INFO", "DETECTION",
                          f"Media de WhatsApp: no se sondea para no invalidar la URL | {url}")
            return

        # Lanzar sondeo HEAD en background para obtener tamaño
        referer = ""
        if "instagram" in u_lower or "cdninstagram" in u_lower:
            referer = "https://www.instagram.com/"
        elif "facebook" in u_lower or "fbcdn" in u_lower:
            referer = "https://www.facebook.com/"

        probe = MediaProbeWorker(url, referer)
        probe.probe_result.connect(
            lambda u, sz, ct, _icon=icon, _type=media_type, _domain=domain, _fname=fname, _n=n:
            self._on_probe_result(u, sz, ct, _icon, _type, _domain, _fname, _n)
        )
        # Al terminar, eliminarse del set para no acumular workers inactivos
        probe.finished.connect(lambda _p=probe: self._probes.discard(_p))
        probe.start()
        self._probes.add(probe)  # inicializado en __init__ → sin race condition

    def _on_probe_result(self, url: str, size: int, ct: str,
                         icon: str, media_type: str,
                         domain: str, fname: str, n: int):
        """Callback cuando el HEAD request devuelve el tamaño. Actualiza el combo."""
        self._media_sizes[url] = (size, ct)

        if size > 0:
            mb = size / (1024 * 1024)
            if mb >= 1.0:
                size_str = f"{mb:.1f} MB"
                # Destacar los que pesan más (probablemente video completo)
                size_tag = "★" if mb >= 5.0 else " "
            else:
                kb = size / 1024
                size_str = f"{kb:.0f} KB"
                size_tag = " "
        else:
            size_str = "? tamaño"
            size_tag = " "

        label = f"{icon} [{n:02d}] {media_type:<11}  {size_tag}{size_str:<10}  {domain}  —  {fname}"

        # Buscar el ítem en el combo por userData (url) y actualizar su texto
        for i in range(self.combo_media.count()):
            if self.combo_media.itemData(i) == url:
                self.combo_media.setItemText(i, label)
                break

        if size > 0:
            mb = size / (1024 * 1024)
            self.append_console(
                f"[SONDEO {n:02d}] {icon} {size_str}  {ct or 'tipo desconocido'}"
            )

    def _clear_media_list(self):
        """Limpia la lista de media detectada para comenzar fresco."""
        self.detected_media_urls.clear()
        self._detected_norms.clear()
        self._media_sizes.clear()
        if hasattr(self, "_probes"):
            self._probes.clear()   # funciona tanto para list como set
        self.last_media_url = None
        self.combo_media.clear()
        self.combo_media.addItem("— Sin media detectada —")
        self.combo_media.setEnabled(False)
        self.btn_media.setEnabled(False)
        self.btn_ver.setEnabled(False)
        self.lbl_media_count.setText("0 URLs")
        self.lbl_media_count.setStyleSheet("color: #4a5568; font-size: 8pt;")
        self.append_console("[MEDIA] Lista de detecciones limpiada.")

    def capture_screenshot(self):
        """
        Captura el contenido del navegador y lo registra como evidencia forense.
        El grab() Qt se ejecuta en el UI thread (obligatorio). La parte pesada
        (compresión PNG + SHA-256 + sidecar) se delega a un thread de fondo para
        no bloquear la interfaz, especialmente durante grabación activa.
        """
        try:
            ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            path     = self.case.dirs["evidence_img"] / f"Captura_{ts}.png"
            url_text = self.url_bar.text()[:80]

            # El codigo de la pagina en el mismo instante que la imagen.
            #
            # La captura muestra como se veia; el HTML muestra de que estaba
            # hecho. Con los dos se puede sostener que lo mostrado se
            # corresponde con lo que entrego el servidor, y examinar lo que la
            # imagen no alcanza a registrar: enlaces reales detras de un texto,
            # atributos, contenido fuera de la parte visible.
            self.browser.page().toHtml(
                lambda html, _ts=ts, _u=url_text: self._guardar_codigo_html(html, _ts, _u))

            # Y la pagina completa, con sus recursos adentro.
            #
            # El HTML solo no reproduce lo que se vio: al abrirlo queda el
            # texto sin estilos ni imagenes, porque las hojas de estilo, las
            # fuentes y las imagenes viven en otras direcciones que ya no
            # responden. El formato MHTML guarda todo eso en un unico archivo,
            # de modo que la pagina se abre con el aspecto que tenia.
            self._guardar_pagina_completa(ts, url_text)

            # grab() DEBE ejecutarse en el UI thread
            pixmap  = self.browser.grab()
            qimage  = pixmap.toImage().convertToFormat(QImage.Format.Format_RGB32)
            ptr     = qimage.bits()
            ptr.setsize(qimage.sizeInBytes())
            arr     = np.frombuffer(ptr, np.uint8).reshape(
                        (qimage.height(), qimage.width(), 4)).copy()  # .copy() libera el buffer Qt
            w_px, h_px = qimage.width(), qimage.height()

            self.append_console(f"📸 Capturando... ({w_px}×{h_px}px)")

        except Exception as e:
            self.case.log("ERROR", "SCREENSHOT", str(e))
            self.append_console(f"ERROR captura: {e}")
            return

        # Captura del estado necesario antes de pasar al thread (evita race con UI)
        case_ref    = self.case
        perito_ref  = dict(self.perito_data)
        self_hash   = get_self_hash()
        case_id     = case_ref.case_id

        def _save_in_background():
            try:
                img = Image.fromarray(arr[:, :, 2::-1], "RGB")

                # PNG con compresión moderada (1) para ser rápido; calidad forense
                # no depende del nivel de compresión sino del hash post-escritura.
                img.save(str(path), "PNG", compress_level=1,
                         pnginfo=datos_del_sello([
                             f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}",
                             f"Case: {case_id}",
                             f"Timestamp: {datetime.datetime.now().isoformat()}",
                             f"URL: {url_text}",
                             f"Tool Hash: {self_hash[:16]}...",
                             f"Perito: {perito_ref.get('nombre','')}",
                         ]))

                sid = write_custody_sidecar(
                    path       = str(path),
                    tipo       = "CAPTURA_PANTALLA",
                    source_url = url_text,
                    perito     = perito_ref,
                    case_id    = case_id,
                    extra      = {
                        "Resolucion":  f"{img.width}x{img.height} px",
                        "URL captura": url_text[:100],
                    }
                )
                case_ref.register_evidence("CAPTURA_PANTALLA", str(path), source_url=url_text)

                # Reportar al UI thread via append_console (thread-safe por Qt signals)
                self.append_console("─" * 60)
                self.append_console(f"✓ CAPTURA  : {path.name}")
                self.append_console(f"  SHA-256  : {sid['sha256']}")
                self.append_console(f"  Tamaño   : {sid['size']:,} bytes")
                self.append_console(f"  Momento  : {sid['ts_legible']}")
                self.append_console(f"  Sidecar  : {Path(sid['sha256_path']).name}")
                self.append_console(f"  Acta     : {Path(sid['custodia_path']).name}")
                self.append_console("─" * 60)

            except Exception as e:
                case_ref.log("ERROR", "SCREENSHOT", str(e))
                self.append_console(f"ERROR guardando captura: {e}")

        t = threading.Thread(target=_save_in_background, daemon=True)
        t.start()


    def _guardar_pagina_completa(self, ts: str, url: str):
        """
        Guarda la pagina tal como se ve, con sus recursos embebidos (MHTML).

        Es lo que falta para que el archivo sirva de veras: el codigo HTML
        solo trae el marcado, y al abrirlo despues las hojas de estilo, las
        fuentes y las imagenes ya no estan disponibles, asi que se ve el texto
        pero no la pagina. El MHTML mete todo en un unico archivo.

        La descarga la produce el propio motor, de modo que pasa por el
        manejador de descargas: se le avisa por _pagina_pendiente para que la
        nombre y la registre como pagina archivada y no como una descarga mas.
        """
        destino = self.case.dirs["evidence_raw"] / f"Pagina_{ts}.mhtml"
        try:
            from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest as _DR
            self._pagina_pendiente = {"nombre": destino.name, "url": url}
            self.browser.page().save(str(destino),
                                     _DR.SavePageFormat.MimeHtmlSaveFormat)
        except Exception as e:
            self._pagina_pendiente = None
            self.case.log("ERROR", "ACREDITACION",
                          f"No se pudo archivar la pagina completa: {e}")
            self.append_console(f"  ✗ No se pudo archivar la pagina completa: {e}")

    def _guardar_codigo_html(self, html: str, ts: str, url: str):
        """
        Guarda el codigo de la pagina que acompaña a una captura.

        Lleva el mismo sello de tiempo en el nombre que la imagen, de modo que
        quede claro cual corresponde a cual: Captura_<ts>.png y Code_<ts>.html
        son el mismo instante.
        """
        if not html:
            return
        destino = self.case.dirs["evidence_raw"] / f"Code_{ts}.html"
        try:
            destino.write_text(html, encoding="utf-8", errors="replace")
        except Exception as e:
            self.case.log("ERROR", "ACREDITACION", f"No se pudo guardar el codigo: {e}")
            return
        registrar_archivo_caso(
            self.case, destino, "CODIGO_PAGINA",
            {"Captura asociada": f"Captura_{ts}.png",
             "Tamano del codigo": f"{len(html):,} caracteres",
             "Momento": ts},
            source_url=url)
        log_signals.log_msg.emit(
            f"  Codigo de la pagina: {destino.name}  ({len(html):,} caracteres)")

    #  CAPTURA DE LA PAGINA COMPLETA
    #
    #  Se recorre la pagina tomando vistas sucesivas y se unen en una sola
    #  imagen. Cada vista se obtiene con el mismo grab() que la captura comun,
    #  asi que lo que se une es exactamente lo que mostraba la pantalla.
    #
    #  El recorrido se puede cortar: en una publicacion de miles de mensajes la
    #  imagen resultante seria inmanejable, y el perito tiene que poder decidir
    #  hasta donde llega sin esperar a que termine.

    # Limites del recorrido. No son arbitrarios: una imagen de mas de 30.000
    # pixeles de alto no la abre comodamente ningun visor, y a partir de ahi
    # deja de servir como anexo.
    _PAG_MAX_VISTAS = 60
    _PAG_MAX_ALTO_PX = 30000

    def capturar_pagina_completa(self):
        """Recorre la pagina de arriba a abajo y la guarda como una sola imagen."""
        if getattr(self, "_pag", {}).get("activo"):
            self._pag_cancelar()
            return

        self._pag = {"activo": True, "vistas": [], "pos": 0, "cancelado": False,
                     "ts": datetime.datetime.now(), "url": self.url_bar.text()[:200],
                     "sin_avance": 0}
        self._pag_modo_boton(True)
        self.append_console("-" * 60)
        self.append_console("[PAGINA] Recorriendo la pagina para capturarla entera...")
        self.case.log("INFO", "SCREENSHOT", "Inicio de captura de pagina completa")
        self.browser.page().runJavaScript(_PAG_MEDIDAS_JS, self._pag_medidas)

    def _pag_modo_boton(self, corriendo: bool):
        if corriendo:
            self.btn_pag.setText("⏹ CANCELAR")
            self.btn_pag.setToolTip("Corta el recorrido; se conserva lo capturado hasta aqui")
        else:
            self.btn_pag.setText("🖼 PAGINA COMPLETA")
            self.btn_pag.setToolTip("Captura la pagina entera recorriendola con scroll")

    def _pag_cancelar(self):
        """
        Corta el recorrido a pedido del perito.

        Lo recorrido hasta aqui se guarda igual: una captura parcial sirve, y
        descartarla obligaria a repetir todo. Que fue interrumpida queda
        escrito en el acta y en la propia imagen, para que no se la confunda
        con la pagina completa.
        """
        if not getattr(self, "_pag", {}).get("activo"):
            return
        self._pag["cancelado"] = True
        self.append_console("[PAGINA] Cancelado por el perito; se guarda lo capturado.")
        self.case.log("ADVERTENCIA", "SCREENSHOT",
                      f"Captura de pagina completa cancelada por el perito tras "
                      f"{len(self._pag['vistas'])} vistas")
        self._pag_unir()

    def _pag_medidas(self, res):
        p = self._pag
        if not p.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        alto_total = int(d.get("alto_total", 0))
        alto_vis = int(d.get("alto_visible", 0))
        if alto_vis <= 0:
            self.append_console("[PAGINA] no se pudieron obtener las medidas de la pagina")
            p["activo"] = False
            self._pag_modo_boton(False)
            return

        p["alto_visible"] = alto_vis
        p["alto_total"] = alto_total
        p["escala"] = 0.0
        vistas = max(1, -(-alto_total // alto_vis))     # division hacia arriba
        p["vistas_previstas"] = min(vistas, self._PAG_MAX_VISTAS)
        self.append_console(
            f"  Pagina de {alto_total} px de alto; ventana de {alto_vis} px "
            f"-> {p['vistas_previstas']} vistas")
        # Se arranca desde arriba, este donde este la pagina
        self._pag_ir(0)

    def _pag_ir(self, pos: int):
        if not self._pag.get("activo"):
            return
        self.browser.page().runJavaScript(
            _PAG_IR_JS.replace("__POS__", str(int(pos))), self._pag_posicionado)

    def _pag_posicionado(self, res):
        p = self._pag
        if not p.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        p["pos"] = int(d.get("pos", 0))
        # La pagina puede crecer al desplazarse: se vuelve a mirar cada vez
        nuevo_alto = int(d.get("alto_total", p["alto_total"]))
        if nuevo_alto > p["alto_total"]:
            p["alto_total"] = nuevo_alto
        # Se le da tiempo a que dibuje lo que acaba de entrar en pantalla
        QTimer.singleShot(450, self._pag_tomar)

    def _pag_tomar(self):
        p = self._pag
        if not p.get("activo"):
            return
        try:
            pix = self.browser.grab()
            img = pix.toImage().convertToFormat(QImage.Format.Format_RGB32)
            ptr = img.bits()
            ptr.setsize(img.sizeInBytes())
            arr = np.frombuffer(ptr, np.uint8).reshape(
                (img.height(), img.width(), 4)).copy()
        except Exception as e:
            self.case.log("ERROR", "SCREENSHOT", f"No se pudo tomar la vista: {e}")
            self._pag_unir()
            return

        if not p.get("escala"):
            p["escala"] = img.width() / max(1, self.browser.width())
        p["vistas"].append({"px": arr, "pos": p["pos"]})
        n = len(p["vistas"])
        self.append_console(f"  vista {n} de {p['vistas_previstas']}  (posicion {p['pos']} px)")

        alto_acumulado = sum(v["px"].shape[0] for v in p["vistas"])
        fin_pagina = p["pos"] + p["alto_visible"] >= p["alto_total"] - 2
        if (fin_pagina or n >= self._PAG_MAX_VISTAS
                or alto_acumulado >= self._PAG_MAX_ALTO_PX):
            p["por_limite"] = not fin_pagina
            self._pag_unir()
            return

        siguiente = min(p["pos"] + p["alto_visible"], p["alto_total"] - p["alto_visible"])
        if siguiente <= p["pos"]:
            p["sin_avance"] += 1
            if p["sin_avance"] >= 3:
                self._pag_unir()
                return
        else:
            p["sin_avance"] = 0
        QTimer.singleShot(120, lambda: self._pag_ir(siguiente))

    def _pag_unir(self):
        """Une las vistas en una sola imagen y la registra como evidencia."""
        p = self._pag
        if not p.get("activo"):
            return
        p["activo"] = False
        self._pag_modo_boton(False)
        vistas = p.get("vistas") or []
        if not vistas:
            self.append_console("[PAGINA] no se capturo ninguna vista")
            return

        escala = p.get("escala") or 1.0
        try:
            # Cada vista se pega a partir de la posicion que le corresponde en
            # la pagina. Se usa la posicion real de cada una y no el paso
            # teorico: si la pagina se movio sola o cargo contenido, pegar por
            # paso fijo dejaria tramos repetidos o cortados.
            trozos = [vistas[0]["px"]]
            for i in range(1, len(vistas)):
                avance_css = vistas[i]["pos"] - vistas[i - 1]["pos"]
                avance_px = int(round(avance_css * escala))
                alto_v = vistas[i]["px"].shape[0]
                if avance_px <= 0:
                    continue                       # no avanzo: no aporta nada
                if avance_px >= alto_v:
                    trozos.append(vistas[i]["px"])
                else:
                    # Solapa con la anterior: se recorta lo ya capturado
                    trozos.append(vistas[i]["px"][alto_v - avance_px:])
            union = np.vstack(trozos)
        except Exception as e:
            registrar_fallo_critico("SCREENSHOT", f"No se pudieron unir las vistas: {e}")
            self.append_console(f"  x No se pudieron unir las vistas: {e}")
            return

        ts = p["ts"]
        destino = self.case.dirs["evidence_img"] / f"PaginaCompleta_{ts:%Y%m%d_%H%M%S}.png"
        cancelado = p.get("cancelado")
        por_limite = p.get("por_limite")
        url = p.get("url", "")
        case_ref, perito_ref = self.case, dict(self.perito_data)
        self_hash, case_id = get_self_hash(), self.case.case_id
        n_vistas, alto_pagina = len(vistas), p.get("alto_total", 0)

        def _guardar():
            try:
                im = Image.fromarray(union[:, :, 2::-1], "RGB")
                estado = ("RECORRIDO INCOMPLETO - cancelado por el perito" if cancelado
                          else "RECORRIDO INCOMPLETO - se alcanzo el limite" if por_limite
                          else "pagina recorrida hasta el final")
                im.save(str(destino), "PNG", compress_level=1,
                        pnginfo=datos_del_sello([
                            f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}",
                            f"Case: {case_id}",
                            f"Timestamp: {datetime.datetime.now().isoformat()}",
                            f"URL: {url[:90]}",
                            f"Pagina completa: {n_vistas} vistas unidas - {estado}",
                            f"Tool Hash: {self_hash[:16]}...",
                            f"Perito: {perito_ref.get('nombre','')}",
                        ]))

                sid = write_custody_sidecar(
                    path=str(destino), tipo="CAPTURA_PAGINA_COMPLETA",
                    source_url=url, perito=perito_ref, case_id=case_id,
                    extra={"Resolucion": f"{im.width}x{im.height} px",
                           "Vistas unidas": str(n_vistas),
                           "Alto de la pagina": f"{alto_pagina} px CSS",
                           "Estado": estado,
                           "Metodo": "recorrido con scroll y union de las vistas "
                                     "sucesivas, sin recomponer ni escalar"})
                case_ref.register_evidence("CAPTURA_PAGINA_COMPLETA", str(destino),
                                           source_url=url)
                log_signals.log_msg.emit("-" * 60)
                log_signals.log_msg.emit(f"✓ PAGINA COMPLETA: {destino.name}")
                log_signals.log_msg.emit(f"  Medida   : {im.width}x{im.height} px "
                                         f"({n_vistas} vistas)")
                log_signals.log_msg.emit(f"  Estado   : {estado}")
                log_signals.log_msg.emit(f"  SHA-256  : {sid['sha256']}")
                log_signals.log_msg.emit("-" * 60)
            except Exception as e:
                case_ref.log("ERROR", "SCREENSHOT", f"No se pudo guardar la pagina: {e}")
                log_signals.log_msg.emit(f"  x No se pudo guardar la pagina completa: {e}")

        if cancelado or por_limite:
            registrar_fallo_critico(
                "SCREENSHOT",
                f"La captura de pagina completa quedo incompleta "
                f"({'cancelada por el perito' if cancelado else 'limite de recorrido'}): "
                f"la imagen no abarca la pagina entera")
        threading.Thread(target=_guardar, daemon=True).start()

    def _capturar_region(self, rect, nombre_base: str, descripcion: str,
                         tipo: str = "CAPTURA_CHAT"):
        """
        Captura una parte de la vista del navegador y la registra como evidencia.

        Sirve para dejar constancia visual de una region concreta (el panel de
        la conversacion, por ejemplo) sin arrastrar el resto de la ventana del
        programa, que no forma parte de lo observado.

        Sigue el mismo camino que capture_screenshot: el grab() va en el hilo
        de la interfaz, que es obligatorio, y el guardado con su hash y su acta
        se hace en segundo plano.
        """
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        path = self.case.dirs["evidence_img"] / f"{nombre_base}_{ts}.png"
        url_text = self.url_bar.text()[:80]

        pixmap = self.browser.grab()
        qimage = pixmap.toImage().convertToFormat(QImage.Format.Format_RGB32)
        ptr    = qimage.bits()
        ptr.setsize(qimage.sizeInBytes())
        arr    = np.frombuffer(ptr, np.uint8).reshape(
                    (qimage.height(), qimage.width(), 4)).copy()

        # El grab devuelve pixeles fisicos y el rectangulo de la pagina viene
        # en pixeles CSS: en pantallas con escalado no coinciden.
        escala  = qimage.width() / max(1, self.browser.width())
        recorte = "vista completa"
        if isinstance(rect, dict) and not rect.get("error"):
            x = max(0, int(rect.get("x", 0) * escala))
            y = max(0, int(rect.get("y", 0) * escala))
            w = int(rect.get("w", 0) * escala)
            h = int(rect.get("h", 0) * escala)
            if w > 40 and h > 40:
                arr = arr[y:y + h, x:x + w].copy()
                recorte = f"panel del chat ({rect.get('w')}x{rect.get('h')} px CSS)"

        case_ref   = self.case
        perito_ref = dict(self.perito_data)
        self_hash  = get_self_hash()
        case_id    = case_ref.case_id

        def _guardar_region():
            try:
                vista = Image.fromarray(arr[:, :, 2::-1], "RGB")
                lineas = [
                    f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}",
                    f"Case: {case_id}",
                    f"Timestamp: {datetime.datetime.now().isoformat()}",
                    descripcion,
                    f"Tool Hash: {self_hash[:16]}...",
                    f"Perito: {perito_ref.get('nombre','')}",
                ]

                # La marca de agua va en una FRANJA DEBAJO de lo capturado, no
                # encima.
                #
                # EL ERROR QUE CORRIGE. Antes se escribian estas seis lineas
                # sobre la propia imagen, a 110 pixeles del borde inferior. En
                # una captura de pantalla completa eso cae sobre la barra de
                # tareas y no molesta; en el recorte de una columna de
                # comentarios cae sobre los comentarios, y los tapa. La captura
                # dejaba de servir para lo unico que se hace: leer lo que decia
                # la publicacion.
                #
                # Se agranda el lienzo y se escribe abajo. Lo capturado queda
                # INTACTO, pixel por pixel, y los datos que atan la imagen al
                # caso -herramienta, causa, momento, hash y perito- siguen
                # grabados en el propio archivo, que es lo que se necesita que
                # viaje con la imagen aunque se la separe de su acta.
                vista.save(str(path), "PNG", compress_level=1,
                           pnginfo=datos_del_sello(lineas))
                sid = write_custody_sidecar(
                    path       = str(path),
                    tipo       = tipo,
                    source_url = url_text,
                    perito     = perito_ref,
                    case_id    = case_id,
                    extra      = {"Resolucion": f"{vista.width}x{vista.height} px",
                                  "Detalle":    descripcion,
                                  "Recorte":    recorte,
                                  "Marca de agua":
                                      "ninguna sobre la imagen: la captura queda "
                                      "intacta pixel por pixel. Los datos de la "
                                      "diligencia van en los campos de texto del "
                                      "propio PNG y se leen con cualquier visor de "
                                      "metadatos"},
                )
                case_ref.register_evidence(tipo, str(path), source_url=url_text)
                log_signals.log_msg.emit(
                    f"  Captura {path.name} | SHA-256 {sid['sha256'][:20]}...")
            except Exception as ex:
                case_ref.log("ERROR", "SCREENSHOT", f"{nombre_base}: {ex}")
                log_signals.log_msg.emit(f"  x No se pudo guardar la captura: {ex}")

        threading.Thread(target=_guardar_region, daemon=True).start()

    # AUDIO / FFMPEG HELPERS

    def _is_ffmpeg_available(self) -> bool:
        """Cachea disponibilidad de FFmpeg para no relanzar subproceso en cada llamada."""
        if self._ffmpeg_ok is None:
            try:
                r = subprocess.run(["ffmpeg", "-version"], capture_output=True, timeout=5)
                self._ffmpeg_ok = (r.returncode == 0)
            except Exception:
                self._ffmpeg_ok = False
        return self._ffmpeg_ok

    def _mux_and_register(self, video_path: str, ts: str):
        """
        Hilo: transcodifica el video de sesion a H.264 y registra la evidencia.

        La grabacion es solo imagen, sin pista de audio. Antes se capturaba
        tambien el sonido del equipo, y cuando no habia un dispositivo de
        mezcla disponible FFmpeg caia al microfono: la grabacion terminaba
        registrando lo que se hablara en la oficina. Eso no forma parte de lo
        que se esta documentando y puede recoger conversaciones ajenas a la
        causa, asi que se saco de raiz y no como una opcion que se pueda
        activar por error.
        """
        # N3: time importado globalmente: import local eliminado
        vid_dir = self.case.dirs.get("evidence_vid", Path("."))
        final_path = str(vid_dir / f"Sesion_{ts}_final.mp4")

        try:
            # -an descarta cualquier pista de audio. Es redundante porque la
            # fuente no la tiene, y esta puesto igual: deja constancia de que
            # el archivo resultante no puede contener sonido.
            cmd = [
                "ffmpeg", "-y",
                "-i", video_path,
                "-an",
                "-c:v", "libx264", "-crf", "28", "-preset", "fast",
                "-movflags", "+faststart",
                final_path
            ]
            r = subprocess.run(
                cmd, capture_output=True, timeout=300,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
            )
            if r.returncode != 0:
                raise RuntimeError(r.stderr.decode("utf-8", errors="ignore")[-500:])
        except Exception as e:
            self.case.log("WARN", "VIDEO", f"Mux/transcode error: {e} — usando video original")
            final_path = video_path
        else:
            # Eliminar archivos temporales si el mux fue exitoso
            try:
                if final_path != video_path:
                    os.remove(video_path)
            except Exception:
                pass

        if os.path.exists(final_path) and os.path.getsize(final_path) > 0:
            sid = write_custody_sidecar(
                path       = final_path,
                tipo       = "VIDEO_SESION",
                source_url = "",
                perito     = self.perito_data,
                case_id    = self.case.case_id,
                extra      = {
                    "FPS grabado":  str(self._rec_fps),
                    "ROI (px)":    str(self.video_roi),
                    # Consta expresamente que no hay audio: en un video de
                    # pericia, que no tenga sonido tiene que ser un dato
                    # declarado y no algo que el receptor deduzca.
                    "Audio":       "no - la grabacion es solo imagen",
                }
            )
            self.case.register_evidence("VIDEO_SESION", final_path)
            self.append_console("─" * 60)
            self.append_console(f"✓ VIDEO    : {Path(final_path).name}")
            self.append_console(f"  SHA-256  : {sid['sha256']}")
            self.append_console(f"  Tamaño   : {sid['size']:,} bytes  ({sid['size']/1024/1024:.2f} MB)")
            self.append_console("  Audio    : no (grabacion de imagen unicamente)")
            self.append_console(f"  Momento  : {sid['ts_legible']}")
            self.append_console(f"  Sidecar  : {Path(sid['sha256_path']).name}")
            self.append_console(f"  Acta     : {Path(sid['custodia_path']).name}")
            self.append_console("─" * 60)
            self.case.log("INFO", "VIDEO",
                f"Video certificado: {final_path} | SHA256: {sid['sha256']} | sin audio")
        else:
            self.append_console("✗ ERROR: Archivo de video final no encontrado o vacío")

    def toggle_recording(self):
        if not self.is_recording:
            # INICIO DE GRABACION
            profile = self.combo_quality.currentData()
            dpr = self.devicePixelRatio()
            geom = self.geometry()
            p = self.mapToGlobal(self.rect().topLeft())

            # Asegurar dimensiones pares (requerido por codecs H.264/mp4v)
            w_raw = int(geom.width()  * dpr)
            h_raw = int(geom.height() * dpr)
            w = w_raw if w_raw % 2 == 0 else w_raw - 1
            h = h_raw if h_raw % 2 == 0 else h_raw - 1

            self.video_roi = (int(p.x() * dpr), int(p.y() * dpr), w, h)
            self._rec_fps   = 5           # 5fps: equilibrio calidad/CPU
            self._rec_spf   = 1.0 / self._rec_fps

            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            fn = str(self.case.dirs["evidence_vid"] / f"Sesion_{ts}.mp4")

            # mp4v a FPS fijo declarado: tiempo entre frames lo controla time.sleep()
            self.video_out = cv2.VideoWriter(
                fn, cv2.VideoWriter_fourcc(*"mp4v"),
                float(self._rec_fps),
                (self.video_roi[2], self.video_roi[3])
            )
            if not self.video_out.isOpened():
                self.append_console("ERROR: No se pudo abrir VideoWriter.")
                self.video_out = None
                return

            self.video_path   = fn
            self._rec_lock    = threading.Lock()
            # threading.Event es thread-safe sin GIL; evita race condition
            # entre el UI thread (stop) y _grab_thread (lectura del flag).
            self._rec_stop_event = threading.Event()
            self.is_recording = True
            self.btn_rec.setText("⏹ DETENER GRABACION")
            self.combo_quality.setEnabled(False)
            self.append_console(f"▶ Grabacion INICIADA | {self._rec_fps}fps | "
                                f"ROI: {self.video_roi} | solo imagen, sin audio")
            self.status.showMessage("GRABANDO...")
            self.case.log("INFO", "VIDEO",
                          f"Grabacion iniciada -> {fn} | ROI: {self.video_roi} | "
                          f"sin captura de audio")

            self._rec_thread = threading.Thread(target=self._grab_thread, daemon=True)
            self._rec_thread.start()

        else:
            # DETENCION
            # 1. Señalizar al hilo que debe detenerse
            if hasattr(self, "_rec_stop_event"):
                self._rec_stop_event.set()
            self.is_recording = False
            self.btn_rec.setText("🔴 GRABAR SESION")
            self.btn_rec.setEnabled(True)
            self.combo_quality.setEnabled(True)
            self.status.showMessage(f"Caso: {self.case.case_id} | Listo")

            # 2. Esperar a que el hilo termine completamente (max 5 s)
            #    Solo llamar release() DESPUÉS de que el hilo haya salido
            #    para evitar write() concurrente con release().
            if hasattr(self, "_rec_thread") and self._rec_thread.is_alive():
                self._rec_thread.join(timeout=5.0)

            # 3. release() cierra el archivo y escribe el moov atom correctamente
            if self.video_out:
                with self._rec_lock:
                    self.video_out.release()
                    self.video_out = None

            video_path = getattr(self, "video_path", "")

            if video_path and os.path.exists(video_path) and os.path.getsize(video_path) > 0:
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                if self._is_ffmpeg_available():
                    self.append_console("⏳ Procesando video (transcodificando H.264)...")
                    # C3: guardar referencia para join() en closeEvent
                    self._mux_thread = threading.Thread(
                        target=self._mux_and_register,
                        args=(video_path, ts),
                        daemon=True
                    )
                    self._mux_thread.start()
                else:
                    # Sin FFmpeg: registrar video mp4v directamente
                    sid = write_custody_sidecar(
                        path       = video_path,
                        tipo       = "VIDEO_SESION",
                        source_url = "",
                        perito     = self.perito_data,
                        case_id    = self.case.case_id,
                        extra      = {
                            "FPS grabado": str(self._rec_fps),
                            "ROI (px)":   str(self.video_roi),
                            "Audio":       "no (FFmpeg no disponible)",
                        }
                    )
                    self.case.register_evidence("VIDEO_SESION", video_path)
                    self.append_console("─" * 60)
                    self.append_console(f"✓ VIDEO    : {Path(video_path).name}")
                    self.append_console(f"  SHA-256  : {sid['sha256']}")
                    self.append_console(f"  Tamaño   : {sid['size']:,} bytes  ({sid['size']/1024/1024:.2f} MB)")
                    self.append_console(f"  Momento  : {sid['ts_legible']}")
                    self.append_console(f"  Sidecar  : {Path(sid['sha256_path']).name}")
                    self.append_console(f"  Acta     : {Path(sid['custodia_path']).name}")
                    self.append_console("─" * 60)
                    self.case.log("INFO", "VIDEO",
                        f"Video certificado: {video_path} | SHA256: {sid['sha256']}")
            else:
                self.append_console("✗ ERROR: Archivo de video vacio o no encontrado")

    def _grab_thread(self):
        """
        Hilo de captura de pantalla.

        Correcciones vs v1.0:
          • time.sleep() en lugar de cv2.waitKey(), cv2.waitKey() en threads sin
            ventana OpenCV no garantiza el delay y produce timestamps irregulares
            que corrompen el moov atom del MP4 (libavformat assertion next_dts).
          • Tiempo de captura descontado del sleep (FPS estable).
          • try/except por frame: un error puntual (pantalla negra, screenshot
            bloqueado) no mata el hilo: registra y sigue.
          • Lock en video_out.write() para evitar race condition con release().
          • threading.Event (_rec_stop_event) para señalización thread-safe.
            El hilo sale ANTES de que toggle_recording() llame a release().
          • 5fps (reducido de 8) para no interferir con capturas manuales.
          • Prioridad del thread reducida en Windows (THREAD_PRIORITY_BELOW_NORMAL)
            para ceder CPU al hilo principal durante capturas de pantalla.
        """
        # Bajar prioridad del thread de grabación en Windows para que las
        # capturas manuales (UI thread) no queden bloqueadas por pyautogui.
        try:
            import ctypes
            ctypes.windll.kernel32.SetThreadPriority(
                ctypes.windll.kernel32.GetCurrentThread(), -1  # THREAD_PRIORITY_BELOW_NORMAL
            )
        except Exception:
            pass

        spf = self._rec_spf
        stop_event = getattr(self, "_rec_stop_event", None)
        while not (stop_event and stop_event.is_set()):
            t0 = time.monotonic()
            try:
                img = pyautogui.screenshot(region=self.video_roi)
                frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
                with self._rec_lock:
                    if self.video_out and self.video_out.isOpened():
                        self.video_out.write(frame)
            except Exception as e:
                # Un frame fallido no debe matar el hilo
                self.case.log("WARN", "VIDEO", f"Frame descartado: {e}")

            elapsed = time.monotonic() - t0
            remaining = spf - elapsed
            if remaining > 0:
                time.sleep(remaining)

    # I4/N5: usar get_app_dir() para que funcione en PyInstaller (frozen).
    # Path(__file__) apunta al .py fuente; en .exe apunta al temp dir de extracción.
    # El nombre "session_cookies" refleja que se usa para Instagram Y Facebook.
    _COOKIES_FILE        = get_app_dir() / "session_cookies.json"
    _COOKIES_ORIGIN_FILE = get_app_dir() / "session_cookies_origen.json"


    def _save_cookie_origin(self, origen_data: dict):
        """
        Persiste la declaración de origen para que el autoload la recupere.
        I3: acepta el dict completo retornado por _dialog_cookie_origin para evitar
        pasar los campos como argumentos posicionales (orden equivocado es un bug silencioso).
        """
        data = {
            "origen":      origen_data.get("origen", ""),
            "plataforma":  origen_data.get("plataforma", ""),
            "usuario":     origen_data.get("usuario", ""),
            "ts":          datetime.datetime.now().isoformat(),
            "perito":      self.perito_data.get("nombre", ""),
        }
        try:
            with open(self._COOKIES_ORIGIN_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _load_cookie_origin(self) -> dict:
        """Lee la declaración de origen guardada. Devuelve dict vacío si no existe."""
        try:
            if self._COOKIES_ORIGIN_FILE.exists():
                with open(self._COOKIES_ORIGIN_FILE, encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _log_cookie_origin(self, total: int, origen_data: dict):
        """Registra en consola y audit_log la declaración formal de origen de cookies."""
        origen    = origen_data.get("origen", "No declarado")
        plat      = origen_data.get("plataforma", "")
        usuario   = origen_data.get("usuario", "")
        perito    = origen_data.get("perito", self.perito_data.get("nombre", ""))
        ts_decl   = origen_data.get("ts", datetime.datetime.now().isoformat())
        sep = "─" * 60
        self.append_console(sep)
        self.append_console(f"  DECLARACION DE ORIGEN DE COOKIES DE AUTENTICACION")
        self.append_console(sep)
        self.append_console(f"  Plataforma : {plat or 'No especificada'}")
        self.append_console(f"  Origen     : {origen}")
        if usuario:
            self.append_console(f"  Usuario    : {usuario}")
        self.append_console(f"  Perito     : {perito}")
        self.append_console(f"  Declarado  : {ts_decl}")
        self.append_console(f"  Cookies    : {total} cookies cargadas")
        self.append_console(sep)
        self.append_console(
            "  NOTA: Las cookies de autenticacion son credenciales de sesion "
            "que permiten el acceso a la plataforma sin ingresar usuario/contrasena. "
            "Su uso en este contexto pericial queda documentado en el audit log "
            "conforme ISO/IEC 27037:2012."
        )
        self.append_console(sep)
        log_msg = (
            f"DECLARACION ORIGEN COOKIES | Plataforma: {plat} | "
            f"Origen: {origen} | Usuario: {usuario} | "
            f"Perito: {perito} | Cookies: {total} | Declarado: {ts_decl}"
        )
        self.case.log("INFO", "AUTH_ORIGEN", log_msg)

    def _dialog_cookie_origin(self, plataforma_default: str = "Instagram / Facebook") -> dict:
        """
        Muestra diálogo para que el perito declare el origen de las cookies.
        Retorna dict con origen/plataforma/usuario o vacío si cancela.
        """
        dlg = QDialog(self)
        dlg.setWindowTitle("Declaración de origen de cookies de autenticación")
        dlg.setMinimumWidth(520)
        dlg.setStyleSheet("background:#0d1b2a; color:#e8f0f8;")
        lay = QVBoxLayout(dlg)
        lay.setSpacing(12)
        lay.setContentsMargins(18, 18, 18, 18)
        label_style = "color:#e8f0f8; font-size:10pt;"
        input_style = (
            "background:#1b263b; color:#e8f0f8; border:1px solid #34495e; "
            "border-radius:3px; padding:6px; font-size:10pt;"
        )
        btn_style = (
            "QPushButton{background:#1565C0;color:white;font-weight:bold;"
            "padding:9px 22px;border-radius:4px;font-size:10pt;}"
            "QPushButton:hover{background:#1976D2;}"
        )
        btn_cancel_style = (
            "QPushButton{background:#2d3d50;color:#9ca3af;border:1px solid #34495e;"
            "border-radius:4px;padding:9px 22px;font-size:10pt;}"
            "QPushButton:hover{background:#3a4f68;}"
        )
        group_style = "QGroupBox{color:#7dd3fc;border:1px solid #1b3a5c;border-radius:4px;margin-top:8px;padding-top:8px;}"
        hdr = QLabel(
            "<b>Declaración forense de origen de cookies</b><br>"
            "<span style='font-size:9pt;color:#7dd3fc;'>"
            "Esta declaración queda registrada en el audit log del caso "
            "conforme ISO/IEC 27037:2012.</span>"
        )
        hdr.setWordWrap(True)
        hdr.setStyleSheet(label_style)
        lay.addWidget(hdr)
        grp_plat = QGroupBox("Plataforma")
        grp_plat.setStyleSheet(group_style)
        gp = QVBoxLayout(grp_plat)
        combo_plat = QComboBox()
        combo_plat.setStyleSheet(input_style)
        combo_plat.addItems(["Instagram", "Facebook", "Instagram y Facebook", "Otra (especificar abajo)"])
        if "facebook" in plataforma_default.lower() and "instagram" in plataforma_default.lower():
            combo_plat.setCurrentIndex(2)
        elif "facebook" in plataforma_default.lower():
            combo_plat.setCurrentIndex(1)
        gp.addWidget(combo_plat)
        lay.addWidget(grp_plat)
        grp_orig = QGroupBox("Origen de las cookies")
        grp_orig.setStyleSheet(group_style)
        go = QVBoxLayout(grp_orig)
        combo_orig = QComboBox()
        combo_orig.setStyleSheet(input_style)
        combo_orig.addItems([
            "Cuenta propia del perito actuante",
            "Cuenta del peritado/imputado (dispositivo examinado con orden judicial)",
            "Cuenta de la víctima (dispositivo examinado con orden judicial)",
            "Cuenta de tercero (con consentimiento documentado)",
        ])
        go.addWidget(combo_orig)
        lay.addWidget(grp_orig)
        grp_usr = QGroupBox("Usuario o email de la cuenta (opcional pero recomendado)")
        grp_usr.setStyleSheet(group_style)
        gu = QVBoxLayout(grp_usr)
        edit_usr = QLineEdit()
        edit_usr.setPlaceholderText("ej: @miusuario  o  correo@ejemplo.com")
        edit_usr.setStyleSheet(input_style)
        gu.addWidget(edit_usr)
        lay.addWidget(grp_usr)
        warn = QLabel(
            "<b style='color:#f59e0b;'>Atención:</b> Si las cookies no pertenecen a una cuenta "
            "propia, asegúrese de contar con la orden judicial o consentimiento "
            "correspondiente antes de continuar."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet("color:#f59e0b; font-size:9pt; padding:6px; "
                           "border:1px solid #78350f; border-radius:3px; background:#1c1000;")
        lay.addWidget(warn)
        def _toggle_warn(idx):
            warn.setVisible(idx != 0)
        combo_orig.currentIndexChanged.connect(_toggle_warn)
        _toggle_warn(0)
        btn_row = QHBoxLayout()
        btn_ok = QPushButton("✓  Confirmar declaración")
        btn_ok.setStyleSheet(btn_style)
        btn_cancel = QPushButton("Cancelar")
        btn_cancel.setStyleSheet(btn_cancel_style)
        btn_ok.clicked.connect(dlg.accept)
        btn_cancel.clicked.connect(dlg.reject)
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        lay.addLayout(btn_row)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return {}
        return {
            "plataforma": combo_plat.currentText(),
            "origen":     combo_orig.currentText(),
            "usuario":    edit_usr.text().strip(),
            "perito":     self.perito_data.get("nombre", ""),
            "ts":         datetime.datetime.now().isoformat(),
        }

    def _load_cookies_from_file(self, path: str) -> tuple:
        """Carga cookies desde un archivo JSON de Cookie-Editor. Retorna (ok, total)."""
        try:
            with open(path, encoding="utf-8") as f:
                cookies = json.load(f)
            if not isinstance(cookies, list):
                return False, 0
            profile = self.browser.page().profile()
            cookie_store = profile.cookieStore()
            from PyQt6.QtNetwork import QNetworkCookie
            from PyQt6.QtCore import QByteArray, QDateTime
            count = 0
            for c in cookies:
                name = c.get("name", "")
                value = c.get("value", "")
                domain = c.get("domain", "")
                path_c = c.get("path", "/")
                if not name or not domain:
                    continue
                cookie = QNetworkCookie(
                    QByteArray(name.encode()),
                    QByteArray(value.encode())
                )
                cookie.setDomain(domain)
                cookie.setPath(path_c)
                if c.get("secure"):
                    cookie.setSecure(True)
                if c.get("httpOnly"):
                    cookie.setHttpOnly(True)
                expiry = c.get("expirationDate") or c.get("expires")
                if expiry:
                    try:
                        dt = QDateTime.fromSecsSinceEpoch(int(expiry))
                        cookie.setExpirationDate(dt)
                    except Exception:
                        pass
                cookie_store.setCookie(cookie)
                count += 1
            return count > 0, count
        except Exception as e:
            self.append_console(f"ERROR cargando cookies: {e}")
            return False, 0

    def _autoload_cookies(self):
        """Carga automáticamente las cookies al iniciar si existe el archivo guardado."""
        if self._COOKIES_FILE.exists():
            ok, total = self._load_cookies_from_file(str(self._COOKIES_FILE))
            if ok:
                self.append_console(f"✓ Sesión restaurada ({total} cookies cargadas automáticamente)")
                self.case.log("INFO", "AUTH", f"Auto-login: {total} cookies cargadas desde {self._COOKIES_FILE.name}")
                origen_data = self._load_cookie_origin()
                if origen_data:
                    self._log_cookie_origin(total, origen_data)
                else:
                    # N6: no hay declaración de origen guardada, ofrecer el diálogo
                    # directamente en lugar de solo mostrar un aviso pasivo.
                    self.append_console(
                        "  AVISO: No se encontró declaración de origen para estas cookies.\n"
                        "  Se abrirá el formulario de declaración para registrar el origen formalmente."
                    )
                    QTimer.singleShot(800, lambda: self._solicitar_origen_autoload(total))

    def _solicitar_origen_autoload(self, total: int):
        """
        N6: Abre el diálogo de declaración de origen cuando se autocargan cookies
        sin declaración previa. Si el usuario cancela, las cookies siguen cargadas
        pero queda registrado el aviso en el audit log.
        """
        origen_data = self._dialog_cookie_origin("Instagram / Facebook")
        if origen_data:
            self._save_cookie_origin(origen_data)
            self._log_cookie_origin(total, origen_data)
        else:
            self.append_console(
                "  AVISO: Declaración de origen no completada. "
                "Las cookies están cargadas pero el origen no quedó documentado formalmente."
            )
            self.case.log("WARN", "AUTH",
                          "Autoload de cookies sin declaración de origen — usuario canceló el diálogo")

    def _show_cookie_help(self):
        """Muestra instrucciones paso a paso para exportar cookies de Chrome."""
        msg = QMessageBox(self)
        msg.setWindowTitle("Cómo importar sesión de Instagram/Facebook desde Chrome")
        msg.setIcon(QMessageBox.Icon.Information)
        msg.setText(
            "<b>Pasos para importar tu sesión:</b><br><br>"
            "<b>1.</b> Abrí <b>Google Chrome</b> e ingresá a <b>instagram.com</b> o <b>facebook.com</b><br>"
            "&nbsp;&nbsp;&nbsp;(iniciá sesión si todavía no estás logueado)<br><br>"
            "<b>2.</b> Instalá la extensión <b>Cookie-Editor</b> en Chrome<br>"
            "&nbsp;&nbsp;&nbsp;(Chrome Web Store → 'Cookie-Editor by cgagnier')<br><br>"
            "<b>3.</b> Mientras estás en el sitio, hacé clic en el ícono de Cookie-Editor<br>"
            "&nbsp;&nbsp;&nbsp;en la barra de extensiones de Chrome<br><br>"
            "<b>4.</b> En Cookie-Editor, hacé clic en <b>Export → Export as JSON</b><br>"
            "&nbsp;&nbsp;&nbsp;y guardá el archivo (ej: <i>instagram_cookies.json</i>)<br><br>"
            "<b>5.</b> Volvé acá y hacé clic en <b>🍪 Sesión Chrome</b><br>"
            "&nbsp;&nbsp;&nbsp;y seleccioná el archivo que guardaste<br><br>"
            "<i>Las cookies se cargan automáticamente al iniciar el programa la próxima vez.</i>"
        )
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg.exec()

    def _import_chrome_cookies(self):
        """Importa cookies desde un archivo JSON exportado con Cookie-Editor (Chrome)."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Importar cookies de Instagram / Facebook (JSON de Cookie-Editor)",
            str(Path.home()),
            "JSON (*.json);;Todos (*.*)"
        )
        if not path:
            return

        origen_data = self._dialog_cookie_origin("Instagram / Facebook")
        if not origen_data:
            self.append_console(
                "Importación cancelada — es obligatorio declarar el origen "
                "de las cookies antes de cargarlas."
            )
            return

        import shutil
        ok, total = self._load_cookies_from_file(path)
        if ok:
            try:
                shutil.copy2(path, self._COOKIES_FILE)
                # copy2 conserva los permisos del archivo de origen, que suele
                # venir de Descargas y queda legible por cualquier usuario del
                # equipo. Como acá dentro hay tokens de sesion vivos, se
                # restringe al usuario que ejecuta el programa.
                if not restringir_a_usuario_actual(self._COOKIES_FILE):
                    self.append_console(
                        "⚠ No se pudieron restringir los permisos de la sesión importada. "
                        "Revise que el archivo no quede accesible a otros usuarios del equipo."
                    )
                    self.case.log("WARN", "AUTH",
                                  "No se pudieron restringir los permisos de session_cookies.json")
            except Exception:
                pass
            self._save_cookie_origin(origen_data)
            self.case.log("INFO", "AUTH", f"Cookies JSON importadas: {total} | archivo: {Path(path).name}")
            self._log_cookie_origin(total, origen_data)
            from PyQt6.QtCore import QUrl as _QUrl, QTimer as _QTimer
            dest_url = "https://www.facebook.com/" if origen_data["plataforma"] == "Facebook" else "https://www.instagram.com/"
            self.url_bar.setText(dest_url)
            _QTimer.singleShot(800, lambda: self.browser.setUrl(_QUrl(dest_url)))
        else:
            QMessageBox.warning(self, "Sin cookies",
                "No se importó ninguna cookie. Verificá que el archivo sea de Cookie-Editor.")

    # DETECCIÓN Y CAPTURA DE PERFIL SOCIAL

    def _on_url_changed(self, url):
        url_str = url.toString()
        self.url_bar.setText(url_str)
        self.btn_capture_profile.setVisible(self._is_social_profile_url(url_str))
        # El boton de adquirir el chat solo aparece dentro de WhatsApp Web.
        # Si la adquisicion esta corriendo se deja a la vista igualmente, para
        # que el perito siempre tenga a mano el modo de detenerla.
        en_wa = "web.whatsapp.com" in url_str.lower()
        corriendo = getattr(self, "_wa", {}).get("activo", False)
        self.btn_wa.setVisible(en_wa or corriendo)
        self.btn_wa_chat.setVisible(en_wa or corriendo)
        en_ig = "instagram.com" in url_str.lower()
        ig_corriendo = getattr(self, "_ig", {}).get("activo", False)
        self.btn_ig_perfil.setVisible(en_ig)
        # La lista de contactos sirve para Instagram y para Facebook.
        self.btn_ig_lista.setVisible(en_ig or "facebook.com" in url_str.lower()
                                     or ig_corriendo)
        # Los comentarios se relevan en Instagram y en Facebook. En Instagram
        # solo existen dentro de una publicacion; en Facebook la vista del
        # posteo se abre sobre cualquier URL del sitio, asi que ahi el boton
        # queda siempre a mano y es la funcion la que avisa si no hay nada.
        en_fb = "facebook.com" in url_str.lower()
        en_tt = "tiktok.com" in url_str.lower()
        en_post = en_ig and ("/p/" in url_str or "/reel/" in url_str or "/tv/" in url_str)
        com_corriendo = getattr(self, "_igc", {}).get("activo", False)
        self.btn_ig_com.setVisible(en_post or en_fb or en_tt or com_corriendo)

    def _is_social_profile_url(self, url: str) -> bool:
        from urllib.parse import urlparse
        try:
            p = urlparse(url)
            host = p.netloc.lower().replace("www.", "")
            path = p.path.strip("/")

            _FB_SKIP = {
                "", "home", "groups", "events", "marketplace", "watch",
                "gaming", "pages", "ads", "ad", "help", "login", "logout",
                "search", "stories", "notifications", "messages", "friends",
                "bookmarks", "saved", "fundraisers", "live", "reels",
            }
            _IG_SKIP = {
                "", "explore", "reels", "stories", "accounts",
                "p", "reel", "direct", "tv", "login", "logout",
                "challenge", "oauth", "api",
            }

            if "facebook.com" in host:
                parts = [x for x in path.split("/") if x]
                if not parts:
                    return False
                return parts[0].lower() not in _FB_SKIP

            if "instagram.com" in host:
                parts = [x for x in path.split("/") if x]
                if not parts:
                    return False
                return parts[0].lower() not in _IG_SKIP

            return False
        except Exception:
            return False

    def _capture_profile_id(self):
        from urllib.parse import urlparse, parse_qs
        url = self.url_bar.text().strip()
        ts_legible = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        try:
            p = urlparse(url)
            host = p.netloc.lower().replace("www.", "")
            path = p.path.strip("/")
            query = parse_qs(p.query)

            plataforma = ""
            profile_id = ""

            if "facebook.com" in host:
                plataforma = "Facebook"
                parts = [x for x in path.split("/") if x]
                if parts and parts[0].lower() == "profile.php":
                    profile_id = query.get("id", [""])[0]
                elif parts:
                    profile_id = parts[0]

            elif "instagram.com" in host:
                plataforma = "Instagram"
                parts = [x for x in path.split("/") if x]
                if parts:
                    profile_id = parts[0]

            if not profile_id:
                self.append_console("✗ No se pudo extraer el ID del perfil de esta URL.")
                return

            self.append_console(f"🔍 Extrayendo UID y email de {plataforma} para '{profile_id}'...")
            self.btn_capture_profile.setEnabled(False)

            # Las dos plataformas dejan el UID en el HTML cuando no hay sesion,
            # asi que el perfil se abre sin cookies y se lee del DOM con el
            # script que corresponda. 
            if plataforma == "Facebook":
                # Vanity -> facebook.com/<vanity>; numerico -> profile.php?id=<N>
                if profile_id.isdigit():
                    page_url = f"https://www.facebook.com/profile.php?id={profile_id}"
                else:
                    page_url = f"https://www.facebook.com/{profile_id}"
                js_extractor = _FB_UID_JS
            else:
                page_url = f"https://www.instagram.com/{profile_id}/"
                js_extractor = _IG_UID_JS

            self._uid_desde_pagina_sin_sesion(
                profile_id, url, ts_legible, plataforma, page_url, js_extractor)

        except Exception as e:
            self.append_console(f"✗ Error capturando perfil: {e}")
            self.case.log("ERROR", "PROFILE_CAPTURE", str(e))
            self.btn_capture_profile.setEnabled(True)

    def _uid_desde_pagina_sin_sesion(self, profile_id: str, url: str,
                                     ts_legible: str, plataforma: str,
                                     page_url: str, js_extractor: str):
        """
        Abre `page_url` sin cookies y le corre `js_extractor` para sacar el UID
        del HTML que devuelve el servidor.

        Facebook e Instagram solo mandan el UID en el HTML cuando no hay sesion.
        Va en un perfil aparte, que ademas deja intacta la sesion del perito. El
        request pasa por el interceptor, asi que queda registrado en el HAR.

        `js_extractor` devuelve un JSON con uid, email, fuente y diag. El UID se
        toma unicamente si ese script ya confirmo que la pagina es la del perfil
        pedido. Si no sale, se le ofrece reintentar al perito.
        """
        from PyQt6.QtWebEngineCore import QWebEngineProfile as _Prof
        from PyQt6.QtWebEngineCore import QWebEnginePage as _Page

        self.append_console(f"🔍 Cargando {page_url} sin sesión para leer el UID…")

        # Sin nombre de almacenamiento el perfil no persiste cookies, asi que
        # la plataforma nos responde como a un visitante anonimo.
        prof = _Prof(self)
        prof.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
        )
        # Este request forma parte de la adquisicion, asi que tiene que quedar
        # en el HAR igual que el resto. Se reutiliza el interceptor del caso,
        # que ya trabaja con lock y no tiene problema entre perfiles.
        prof.setUrlRequestInterceptor(self.interceptor)

        page = _Page(prof, self)
        # Para leer el UID alcanza con el HTML. Sin imagenes carga mas rapido y
        # no mete cientos de descargas al HAR por una pagina que se descarta.
        try:
            from PyQt6.QtWebEngineCore import QWebEngineSettings as _QWES
            page.settings().setAttribute(_QWES.WebAttribute.AutoLoadImages, False)
        except Exception:
            pass
        # Hay que guardarlos: si no, Qt los destruye y el callback nunca llega.
        self._uid_prof, self._uid_page = prof, page

        estado = {"resuelto": False}

        def _limpiar():
            try:
                page.deleteLater()
                prof.deleteLater()
            except Exception:
                pass
            self._uid_prof = self._uid_page = None

        def _fallback(motivo: str):
            if estado["resuelto"]:
                return
            estado["resuelto"] = True
            self.append_console(f"[PERFIL] No se pudo leer el UID de la página: {motivo}")
            self.case.log("INFO", "PROFILE_CAPTURE",
                          f"UID sin sesion fallido | {plataforma} | @{profile_id} | {motivo}")
            _limpiar()
            # Sin UID: no hay respaldo por API. Se ofrece reintentar al perito.
            self._finalize_profile_capture(
                plataforma=plataforma, profile_id=profile_id,
                uid_numerico="", url=url, ts_legible=ts_legible,
                error_msg=motivo, email="",
            )

        def _leer_uid(res):
            if estado["resuelto"]:
                return
            uid = fuente = email = ""
            diag = {}
            try:
                if res:
                    d      = json.loads(res)
                    uid    = str(d.get("uid", "") or "")
                    email  = str(d.get("email", "") or "")
                    fuente = str(d.get("fuente", "") or "")
                    diag   = d.get("diag", {}) or {}
            except Exception:
                pass

            if not uid:
                motivo = diag.get("motivo") or "no hallado en el HTML"
                detalles = "  ".join(f"{k}={v}" for k, v in diag.items() if k != "motivo")
                if detalles:
                    self.append_console(f"  · {detalles}")
                _fallback(motivo)
                return

            estado["resuelto"] = True
            self.append_console(f"✓ UID obtenido: {uid}")
            self.append_console(f"  Fuente: {fuente}")
            self.append_console(f"  (página anónima renderizada por {plataforma}; sin usar su API)")
            self.case.log("INFO", "PROFILE_CAPTURE",
                          f"UID sin sesion | {plataforma} | @{profile_id} | {uid} | {fuente}")
            _limpiar()
            self._finalize_profile_capture(
                plataforma=plataforma, profile_id=profile_id,
                uid_numerico=uid, url=url, ts_legible=ts_legible,
                error_msg="", email=email,
            )

        def _al_cargar(ok: bool):
            if not ok:
                _fallback("no se pudo cargar la página")
                return
            js = js_extractor.replace("__REQ__", json.dumps(profile_id))
            page.runJavaScript(js, _leer_uid)

        page.loadFinished.connect(_al_cargar)
        # Por si la carga nunca termina y la captura queda colgada.
        QTimer.singleShot(20000, lambda: _fallback("tiempo de espera agotado"))
        page.setUrl(QUrl(page_url))

    def _render_profile_card(self, entry: dict) -> Optional[str]:
        """
        Renderiza una FICHA VISUAL con los datos extraídos del perfil (usuario,
        UID, email, URL, timestamp) como imagen PNG con marca de agua forense.
        Sirve como registro visual de los datos capturados, complementario a la
        captura de pantalla del navegador. Devuelve la ruta o None si falla.
        """
        try:
            # Medidas de la ficha. El alto sale del contenido: estaba fijo en
            # 640 px, un numero calculado a mano que no dejaba margen, y el pie
            # terminaba pegado al borde con las ultimas lineas cortadas.
            W = 1000
            ALTO_CABECERA = 88
            Y_PRIMER_CAMPO = 120
            ALTO_FILA = 52
            ALTO_LINEA_PIE = 22
            N_CAMPOS = 8
            N_LINEAS_PIE = 2
            alto_campos = Y_PRIMER_CAMPO + N_CAMPOS * ALTO_FILA
            alto_pie = N_LINEAS_PIE * ALTO_LINEA_PIE + 28
            H = alto_campos + 20 + alto_pie
            img  = Image.new("RGB", (W, H), (255, 255, 255))
            draw = ImageDraw.Draw(img)

            def _font(sz, bold=False):
                for name in (("arialbd.ttf",) if bold else ("arial.ttf",)):
                    try:
                        return ImageFont.truetype(name, sz)
                    except Exception:
                        pass
                return ImageFont.load_default()

            f_title = _font(26, bold=True)
            f_sub   = _font(14)
            f_lbl   = _font(18, bold=True)
            f_val   = _font(18)
            f_foot  = _font(12)

            # Encabezado
            draw.rectangle([0, 0, W, ALTO_CABECERA], fill=(13, 27, 42))
            draw.text((28, 18), "FICHA DE PERFIL — RED SOCIAL", fill=(255, 255, 255), font=f_title)
            draw.text((30, 58), f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}",
                      fill=(125, 211, 252), font=f_sub)

            campos = [
                ("Plataforma",       entry.get("plataforma", "")),
                ("Usuario / Handle", f"@{entry.get('profile_id', '')}"),
                ("UID numérico",     entry.get("uid_numerico", "") or "No obtenido"),
                ("Email público",    entry.get("email", "") or "No encontrado / No público"),
                ("URL del perfil",   entry.get("url", "")),
                ("Timestamp",        entry.get("ts_legible", "")),
                ("Perito actuante",  entry.get("perito", "")),
                ("Case ID",          self.case.case_id),
            ]
            if len(campos) != N_CAMPOS:
                # Si algun dia se agrega o se quita un campo, el alto se ajusta
                # solo en vez de recortar en silencio.
                H = Y_PRIMER_CAMPO + len(campos) * ALTO_FILA + 20 + alto_pie
                img = Image.new("RGB", (W, H), (255, 255, 255))
                draw = ImageDraw.Draw(img)
                draw.rectangle([0, 0, W, ALTO_CABECERA], fill=(13, 27, 42))
                draw.text((28, 18), "FICHA DE PERFIL — RED SOCIAL",
                          fill=(255, 255, 255), font=f_title)
                draw.text((30, 58), f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}",
                          fill=(125, 211, 252), font=f_sub)

            y = Y_PRIMER_CAMPO
            for lbl, val in campos:
                draw.text((36, y), f"{lbl}:", fill=(27, 38, 59), font=f_lbl)
                val_str = str(val)
                if len(val_str) > 60:
                    val_str = val_str[:60] + "…"
                draw.text((330, y), val_str, fill=(20, 20, 20), font=f_val)
                draw.line([(36, y + 30), (W - 36, y + 30)], fill=(220, 226, 232), width=1)
                y += ALTO_FILA

            # Pie con marca de agua forense
            draw.rectangle([0, H - alto_pie, W, H], fill=(245, 247, 250))
            foot_lines = [
                f"Software SHA-256: {get_self_hash()[:32]}…   |   Norma: {SOFTWARE_INFO['norma']}",
                f"Generado: {datetime.datetime.now().isoformat()}   |   "
                f"Perito: {self.perito_data.get('nombre','')}",
            ]
            fy = H - alto_pie + 14
            for fl in foot_lines:
                draw.text((28, fy), fl, fill=(90, 100, 110), font=f_foot)
                fy += ALTO_LINEA_PIE

            ts_file = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_id = "".join(c for c in entry.get("profile_id", "perfil")
                              if c.isalnum() or c in ("_", "-")) or "perfil"
            plat = "".join(c for c in str(entry.get("plataforma", "perfil"))
                           if c.isalnum() or c in ("_", "-")) or "perfil"
            out = self.case.dirs["evidence_img"] / f"FichaPerfil_{plat}_{safe_id}_{ts_file}.png"
            img.save(str(out), "PNG")
            return str(out)
        except Exception as e:
            self.case.log("ERROR", "PROFILE_CARD", f"No se pudo generar ficha visual: {e}")
            return None

    def _finalize_profile_capture(self, plataforma: str, profile_id: str,
                                   uid_numerico: str, url: str, ts_legible: str,
                                   error_msg: str = "", email: str = ""):
        self.btn_capture_profile.setEnabled(True)

        uid_display   = uid_numerico if uid_numerico else f"NO OBTENIDO{' — ' + error_msg if error_msg else ''}"
        email_display = email        if email        else "No encontrado / No público"

        # DIÁLOGO DE CONFIRMACIÓN
        # NADA se registra hasta que el perito confirme.
        # Si el UID no fue obtenido se bloquea el registro y se ofrece reintentar.
        if not uid_numerico:
            dlg = QDialog(self)
            dlg.setWindowTitle(f"UID no obtenido — {plataforma}")
            dlg.setMinimumWidth(480)
            dlg.setStyleSheet("background:#1a0a0a; color:#f8d7da;")
            lay = QVBoxLayout(dlg)
            lay.setContentsMargins(20, 20, 20, 20)
            lay.setSpacing(12)

            lbl = QLabel(
                f"<b style='font-size:12pt;color:#e74c3c;'>⚠ UID numérico no obtenido</b><br><br>"
                f"<b>Plataforma:</b> {plataforma}<br>"
                f"<b>Usuario:</b> @{profile_id}<br>"
                f"<b>UID numérico:</b> <span style='color:#e74c3c;'>{uid_display}</span><br>"
                f"<b>URL:</b> {url[:80]}<br><br>"
                f"<span style='color:#f39c12;'>"
                f"No es posible registrar esta evidencia sin el UID numérico.<br>"
                f"Un registro sin UID puede generar nulidades en el proceso judicial.<br><br>"
                f"Opciones:<br>"
                f"• <b>Reintentar</b>: vuelva a hacer clic en 🪪 CAPTURAR PERFIL.<br>"
                f"• <b>Cancelar</b>: no se registra nada en el caso.</span>"
            )
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color:#f8d7da; font-size:10pt;")
            lay.addWidget(lbl)

            btn_row = QHBoxLayout()
            btn_retry  = QPushButton("🔄  Reintentar")
            btn_cancel = QPushButton("✕  Cancelar")
            btn_retry.setStyleSheet(
                "QPushButton{background:#1565C0;color:white;font-weight:bold;"
                "padding:9px 22px;border-radius:4px;font-size:10pt;}"
                "QPushButton:hover{background:#1976D2;}"
            )
            btn_cancel.setStyleSheet(
                "QPushButton{background:#4a1010;color:#f8d7da;border:1px solid #7b1a1a;"
                "border-radius:4px;padding:9px 22px;font-size:10pt;}"
                "QPushButton:hover{background:#6b1a1a;}"
            )
            btn_retry.clicked.connect(dlg.accept)
            btn_cancel.clicked.connect(dlg.reject)
            btn_row.addWidget(btn_retry)
            btn_row.addWidget(btn_cancel)
            lay.addLayout(btn_row)

            result = dlg.exec()
            if result == QDialog.DialogCode.Accepted:
                self.append_console("[PERFIL] Reintentando captura...")
                self.case.log("INFO", "PROFILE_CAPTURE",
                              f"Reintento solicitado | {plataforma} | @{profile_id}")
                # Volver a disparar la captura desde el botón
                self._capture_profile_id()
            else:
                self.append_console("[PERFIL] Captura cancelada — ningún dato registrado.")
                self.case.log("INFO", "PROFILE_CAPTURE",
                              f"Cancelado sin UID | {plataforma} | @{profile_id}")
            return

        # UID obtenido: confirmar antes de registrar
        confirm_msg = (
            f"<b>Verifique los datos antes de registrar la evidencia:</b><br><br>"
            f"<table cellspacing='4'>"
            f"<tr><td><b>Plataforma:</b></td><td>{plataforma}</td></tr>"
            f"<tr><td><b>Usuario:</b></td><td>@{profile_id}</td></tr>"
            f"<tr><td><b>UID numérico:</b></td>"
            f"<td><b style='color:#27ae60;'>{uid_numerico}</b></td></tr>"
            f"<tr><td><b>Email:</b></td><td>{email_display}</td></tr>"
            f"<tr><td><b>URL:</b></td><td>{url[:80]}</td></tr>"
            f"<tr><td><b>Timestamp:</b></td><td>{ts_legible}</td></tr>"
            f"</table><br>"
            f"<i>¿Confirma el registro de esta evidencia y la captura de pantalla?</i>"
        )
        reply = QMessageBox.question(
            self,
            f"Confirmar captura de perfil — {plataforma}",
            confirm_msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            self.append_console("[PERFIL] Captura cancelada por el perito — ningún dato registrado.")
            self.case.log("INFO", "PROFILE_CAPTURE",
                          f"Cancelado por perito | {plataforma} | @{profile_id}")
            return

        # REGISTRO: solo se ejecuta si el perito confirmó con UID presente
        ts_iso = datetime.datetime.now().isoformat()
        entry = {
            "ts":           ts_iso,
            "ts_legible":   ts_legible,
            "plataforma":   plataforma,
            "profile_id":   profile_id,
            "uid_numerico": uid_numerico,
            "email":        email,
            "url":          url,
            "perito":       self.perito_data.get("nombre", ""),
        }

        # Ficha visual con los datos extraídos (imagen PNG), registro visual
        # complementario a la captura de pantalla del navegador.
        ficha_path = self._render_profile_card(entry)
        if ficha_path:
            entry["ficha_path"] = ficha_path
            try:
                self.case.register_evidence("FICHA_PERFIL", ficha_path,
                                            source_url=url, metadata=entry)
                self.append_console(f"[PERFIL] Ficha de datos generada: {Path(ficha_path).name}")
            except Exception:
                pass

        profiles_path = self.case.dirs["network"] / "profiles_captured.json"
        try:
            existing = []
            if profiles_path.exists():
                with open(profiles_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            existing.append(entry)
            with open(profiles_path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        acta_ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        acta_path = self.case.dirs["network"] / f"Perfil_{plataforma}_{profile_id}_{acta_ts}.txt"
        sep70     = "=" * 70
        acta_lines = [
            sep70,
            "  ACTA DE CAPTURA DE PERFIL EN RED SOCIAL — TRAVERSO FORENSICS · NAVEGADOR WEB FORENSE",
            sep70, "",
            f"  PLATAFORMA      : {plataforma}",
            f"  USUARIO / HANDLE: {profile_id}",
            f"  UID NUMERICO    : {uid_numerico}",
            f"  EMAIL PUBLICO   : {email or 'No encontrado / No publico'}",
            f"  URL PERFIL      : {url}", "",
            f"  TIMESTAMP       : {ts_legible}  [{ts_iso}]",
            f"  PERITO          : {self.perito_data.get('nombre', '')}",
            f"  EMPRESA         : {self.perito_data.get('empresa', '')}",
            f"  CASE ID         : {self.case.case_id}", "",
            sep70,
        ]
        try:
            with open(acta_path, "w", encoding="utf-8") as f:
                f.write("\n".join(acta_lines))
            self.case.register_evidence("CAPTURA_PERFIL", str(acta_path),
                                        source_url=url, metadata=entry)
        except Exception:
            pass

        self.case.log("INFO", "PROFILE_CAPTURE",
                      f"REGISTRADO | {plataforma} | @{profile_id} | UID: {uid_numerico}"
                      + (f" | Email: {email}" if email else "")
                      + f" | URL: {url}")

        sep = "─" * 60
        ts_real = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{ts_real}] {sep}")
        self.console.append(f"[{ts_real}]   ✓ PERFIL REGISTRADO — {plataforma.upper()}")
        self.console.append(f"[{ts_real}]   Usuario  : @{profile_id}")
        self.console.append(f"[{ts_real}]   UID      : {uid_numerico}")
        self.console.append(f"[{ts_real}]   Email    : {email or 'no encontrado'}")
        self.console.append(f"[{ts_real}]   Acta     : {acta_path.name}")
        self.console.append(f"[{ts_real}] {sep}")

        self.capture_screenshot()

    def acquire_media(self):
        """
        Adquisición forense de media.
        Estrategia:
          1. WhatsApp .enc       → requests directo (CDN público, no necesita sesión)
          2. Instagram/Facebook  → yt-dlp (maneja DASH/HLS automáticamente)
          3. CDN directo         → requests con headers de referencia
        """
        idx = self.combo_media.currentIndex()
        url = self.combo_media.itemData(idx)
        if not url:
            self.append_console("✗ Seleccioná una URL de media en el selector antes de adquirir.")
            return

        label = self.combo_media.currentText()
        self.append_console(f"[ADQUIRIENDO] {label}")
        self.append_console(f"  URL: {url[:100]}...")
        self.btn_media.setEnabled(False)

        url_lower = url.lower()

        # Caso 1: WhatsApp .enc, NO adquirible
        # Los archivos .enc de WhatsApp están cifrados E2E (AES-256-CBC +
        # HKDF-SHA256). Sin la media_key del dispositivo origen es imposible
        # desencriptarlos. Se registra la detección pero no se descarga.
        is_wa_enc = ".enc" in url_lower and (
            "fna.whatsapp.net" in url_lower or "cdn.whatsapp.net" in url_lower
        )
        if is_wa_enc:
            self.append_console(
                "✗ No es posible adquirir archivos .enc de WhatsApp:\n"
                "  Están cifrados E2E (AES-256-CBC). Sin la media_key del\n"
                "  dispositivo origen el archivo no puede desencriptarse ni\n"
                "  reproducirse. Se registró la URL en el inventario de medios."
            )
            self.case.log("INFO", "DETECTION",
                          f"URL .enc detectada (no adquirible, E2E): {url}")
            self.btn_media.setEnabled(True)
            return

        # Caso 2: Instagram / Facebook (páginas) → yt-dlp
        is_instagram_page = any(d in url_lower for d in [
            "instagram.com/p/", "instagram.com/reel/", "instagram.com/tv/",
            "facebook.com/", "fb.watch/",
        ])
        if is_instagram_page:
            self.append_console("  Método: yt-dlp (Instagram/Facebook)")
            self._start_ytdlp_acquisition(url)
            return

        # Caso 3: CDN directo (fbcdn, otros)
        self.append_console("  Método: requests directo")
        self._start_media_acquisition(url, {})

    def _start_media_acquisition(self, url: str, headers: dict):
        """Lanza MediaAcquisition (requests externo) con los headers dados."""
        self.acq = MediaAcquisition(url, self.case, headers)
        self.acq.finished.connect(lambda ev: (
            self.append_console(f"✓ Adquisicion OK: {ev['filename']}"),
            self.btn_media.setEnabled(True)
        ))
        self.acq.progress.connect(self.append_console)
        self.acq.error.connect(lambda e: (
            self.append_console(f"✗ ERROR adquisicion: {e}"),
            self.btn_media.setEnabled(True)
        ))
        self.acq.start()

    def _ver_media(self):
        """
        Abre el reproductor forense para VERIFICAR el contenido del video.
        No registra evidencia.
          • URL de CDN (Instagram/Facebook) → intenta stream directo.
          • WhatsApp .enc (cifrado)         → avisa que hay que descargarlo primero.
          • Sin selección                   → abre el player vacío para abrir archivo.
        """
        idx = self.combo_media.currentIndex()
        url = self.combo_media.itemData(idx)
        default_dir = str(self.case.dirs["evidence_raw"])
        url_lower = (url or "").lower()
        is_wa_enc = bool(url) and ".enc" in url_lower and (
            "fna.whatsapp.net" in url_lower or "cdn.whatsapp.net" in url_lower
        )

        if is_wa_enc:
            self.append_console(
                "▶ Video WhatsApp cifrado (.enc): no se puede reproducir directo. "
                "Descargalo con el botón de descarga del chat (queda como WA_DOWNLOAD) "
                "y luego abrilo con 📂 Abrir archivo."
            )
            self.case.log("INFO", "PLAYER", "Reproductor abierto (WA .enc — requiere descarga previa)")
            MediaPlayerDialog(default_open_dir=default_dir, parent=self).exec()
            return

        if url:
            self.append_console(f"▶ Abriendo reproductor para: {url[:80]}…")
            self.case.log("INFO", "PLAYER", f"Reproductor abierto: {url}")
            MediaPlayerDialog(source_url=url, default_open_dir=default_dir, parent=self).exec()
        else:
            self.append_console("▶ Reproductor abierto. Usá 📂 Abrir archivo para elegir un video del caso.")
            self.case.log("INFO", "PLAYER", "Reproductor abierto (sin URL)")
            MediaPlayerDialog(default_open_dir=default_dir, parent=self).exec()

    def _start_ytdlp_acquisition(self, url: str):
        """Lanza YtDlpAcquisition para Instagram/Facebook."""
        cookies_path = str(self._COOKIES_FILE) if self._COOKIES_FILE.exists() else ""
        self.acq = YtDlpAcquisition(url, self.case, cookies_path)
        self.acq.finished.connect(lambda ev: (
            self.append_console(f"✓ Adquisicion yt-dlp OK: {ev['filename']}"),
            self.btn_media.setEnabled(True)
        ))
        self.acq.progress.connect(self.append_console)
        self.acq.error.connect(lambda e: (
            self.append_console(f"✗ ERROR yt-dlp: {e}"),
            self.btn_media.setEnabled(True)
        ))
        self.acq.start()


    #  ADQUISICION DEL MULTIMEDIA DE UN CHAT DE WHATSAPP WEB
    #
    #  El recorrido va del final hacia el principio de la conversacion. En cada
    #  tramo: se captura la pantalla del chat, se transcribe el texto y se pide
    #  cada archivo por el menu del mensaje. Recien despues se retrocede.
    #
    #  Los archivos se piden de a uno, esperando que cada descarga termine.
    #  Dispararlas juntas no funciona: Chromium descarta parte y esos archivos
    #  quedan en disco sin hash ni acta, o sea sin valor probatorio.

    def _wa_boton_media(self):
        """Cada boton arranca su recorrido y, mientras corre, lo detiene."""
        if getattr(self, "_wa", {}).get("activo"):
            self._wa_detener()
        else:
            self.adquirir_media_whatsapp()

    def _wa_boton_chat(self):
        if getattr(self, "_wa", {}).get("activo"):
            self._wa_detener()
        else:
            self.capturar_chat_whatsapp()

    def _wa_detener(self):
        """
        Corta el recorrido a pedido del perito.

        Lo adquirido hasta el momento se conserva: se cierra igual que si
        hubiera llegado al principio del chat, de modo que el resumen queda en
        el registro. En el acta debe constar que la adquisicion fue
        interrumpida, no que se completo.
        """
        if not getattr(self, "_wa", {}).get("activo"):
            return
        self._wa["interrumpido"] = True
        self.append_console("[WHATSAPP] Detenido por el perito.")
        self.case.log("ADVERTENCIA", "WHATSAPP",
                      f"Adquisicion detenida por el perito en el tramo "
                      f"{self._wa.get('tramo', 0)}: el chat no se recorrio entero")
        self._wa_fin()

    def _wa_modo_boton(self, corriendo: bool, cual: str = ""):
        """
        Pone en modo detener al boton del recorrido en curso y desactiva el
        otro: los dos recorridos no pueden correr a la vez sobre el mismo chat.
        """
        activo = self.btn_wa if cual == "media" else self.btn_wa_chat
        otro = self.btn_wa_chat if cual == "media" else self.btn_wa

        if corriendo:
            activo.setText("⏹ DETENER")
            activo.setToolTip("Corta el recorrido; se conserva lo adquirido hasta aqui")
            activo.setVisible(True)
            otro.setEnabled(False)
        else:
            en_wa = "web.whatsapp.com" in self.browser.url().toString().lower()
            self.btn_wa.setText("🎬 MEDIA WHATSAPP")
            self.btn_wa.setToolTip("Descarga fotos, videos, audios y documentos del chat abierto")
            self.btn_wa.setEnabled(True)
            self.btn_wa.setVisible(en_wa)
            self.btn_wa_chat.setText("📷 CAPTURAR CHAT")
            self.btn_wa_chat.setToolTip("Captura la pantalla del chat abierto, tramo por tramo")
            self.btn_wa_chat.setEnabled(True)
            self.btn_wa_chat.setVisible(en_wa)

    def adquirir_media_whatsapp(self):
        """Descarga las fotos, videos, audios y documentos del chat abierto."""
        self._wa_iniciar(
            cual="media",
            titulo="Descargar el multimedia del chat",
            detalle=("De cada tramo se descargan las fotos, videos, audios y\n"
                     "documentos. Cada archivo se pide por la opcion Descargar del\n"
                     "propio WhatsApp y se guarda con su hash SHA-256 y su acta de\n"
                     "custodia.\n\n"
                     "No se toman capturas de pantalla: eso lo hace el otro boton."))

    def capturar_chat_whatsapp(self):
        """
        Captura la pantalla del chat desde donde este la vista hasta el final.

        El punto de partida lo elige el perito: deja la conversacion donde
        quiere empezar y el recorrido avanza desde ahi hasta el ultimo
        mensaje. Es mas simple de controlar que ir hacia atras buscando una
        fecha, y ademas las capturas quedan en orden cronologico.
        """
        self._wa_iniciar(
            cual="chat",
            titulo="Capturar la pantalla del chat",
            detalle=("Se guarda una captura del panel de la conversacion por cada\n"
                     "tramo, recortada al chat y con su hash SHA-256 y su acta de\n"
                     "custodia.\n\n"
                     "No se descarga ningun archivo: eso lo hace el otro boton."))

    def _wa_iniciar(self, cual: str, titulo: str, detalle: str):
        """
        Prepara y arranca un recorrido de la conversacion.

        Los dos van por separado a proposito: descargar archivos abre menus y
        espera al servidor, y hacerlo mientras se captura la pantalla ensuciaba
        las imagenes y demoraba todo.

        Los dos arrancan donde el perito dejo la conversacion y avanzan hasta
        el ultimo mensaje. El punto de partida se elige a mano, mirando el
        chat.

        Antes el recorrido de multimedia iba hacia atras hasta una fecha que se
        indicaba en un dialogo, y eso resulto poco confiable: WhatsApp escribe
        la fecha en el orden de su idioma, de modo que 8/6/2026 es el 8 de
        junio o el 6 de agosto segun el caso. Una lectura invertida corto una
        adquisicion a los dos tramos sin que se notara. Elegir el punto en
        pantalla no admite esa confusion.
        """
        if "web.whatsapp.com" not in self.browser.url().toString().lower():
            QMessageBox.warning(self, "WhatsApp Web",
                                "Abra primero WhatsApp Web y seleccione la conversacion "
                                "que desea adquirir.")
            return
        if getattr(self, "_wa", {}).get("activo"):
            return

        resp = QMessageBox.question(
            self, titulo,
            "Se recorrera DESDE DONDE ESTA la conversacion en pantalla,\n"
            "avanzando hasta el ultimo mensaje.\n\n"
            "Antes de continuar, desplace el chat hasta el primer mensaje\n"
            "que quiera dejar registrado.\n\n"
            + detalle +
            "\n\nEn chats extensos puede demorar varios minutos. No opere el\n"
            "navegador mientras dure el recorrido.\n\n"
            "Tener presente que abrir la conversacion ya marca los mensajes\n"
            "como leidos.\n\n"
            "¿Comenzar desde aqui?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes)
        if resp != QMessageBox.StandardButton.Yes:
            self.case.log("INFO", "WHATSAPP", f"El perito no confirmo el recorrido ({cual})")
            return

        self._wa = {"activo": True, "cual": cual, "tramo": 0, "cola": [],
                    "actual": None, "bajados": 0, "sin_menu": 0, "perdidos": 0,
                    "capturas": 0, "tipos": {}, "espera": 0, "recuperos": 0,
                    "avisos": set(), "fin_seguidos": 0, "interrumpido": False,
                    "hace_media": cual == "media", "hace_capturas": cual == "chat",
                    "desde_texto": "", "hasta_texto": ""}
        self._descargas_activas = 0
        self._wa_modo_boton(True, cual)

        que = "multimedia" if cual == "media" else "capturas de pantalla"
        self.append_console("-" * 60)
        self.append_console(f"[WHATSAPP] Recorrido de {que}.")
        self.append_console("  Desde la vista actual HACIA ADELANTE, hasta el ultimo mensaje.")
        self.case.log("INFO", "WHATSAPP",
                      f"Inicio del recorrido de {que} | desde la vista elegida por el "
                      f"perito hacia el ultimo mensaje")
        self.browser.page().runJavaScript("window.__wa = null;")
        QTimer.singleShot(300, self._wa_tramo)

    def _wa_tramo(self):
        """Arranca un tramo: primero la captura, que debe mostrar el chat limpio."""
        if not self._wa.get("activo"):
            return
        self.browser.page().runJavaScript(_WA_RECT_JS, self._wa_capturar)

    def _wa_capturar(self, res):
        w = self._wa
        if not w.get("activo"):
            return
        try:
            rect = json.loads(res) if res else {}
        except Exception:
            rect = {}
        w["tramo"] += 1

        # Al llegar al principio del chat el recorrido pide varias
        # confirmaciones antes de cortar, y en esos pasos la vista ya no se
        # mueve. Sin este control quedaban cuatro o cinco capturas identicas
        # al final del caso.
        pos = rect.get("scroll", -1)
        if not w.get("hace_capturas"):
            pass                                   # este recorrido no captura
        elif pos >= 0 and pos == w.get("ultima_pos", -999):
            w["repetidas"] = w.get("repetidas", 0) + 1
        else:
            w["ultima_pos"] = pos
            n = w["capturas"] + 1
            try:
                self._capturar_region(
                    rect, f"WA_Chat_{n:03d}",
                    f"WhatsApp - vista {n} - de la vista inicial al ultimo mensaje")
                w["capturas"] = n
            except Exception as ex:
                self.case.log("ERROR", "WHATSAPP", f"No se pudo capturar: {ex}")

        QTimer.singleShot(150, lambda: self.browser.page().runJavaScript(
            _WA_ESCANEAR_JS, self._wa_escaneado))

    def _wa_escaneado(self, res):
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}

        if d.get("error"):
            # La conversacion pudo irse de pantalla por un menu o una ficha de
            # contacto que quedo abierta. Se intenta volver antes de rendirse:
            # un clic desafortunado no puede costar una adquisicion entera.
            if w["recuperos"] < 3:
                w["recuperos"] += 1
                self.append_console(f"[WHATSAPP] volviendo a la conversacion "
                                    f"({w['recuperos']} de 3)")
                w["tramo"] -= 1
                self.browser.page().runJavaScript(
                    _WA_CERRAR_JS, lambda _: QTimer.singleShot(600, self._wa_tramo))
                return
            self.append_console(f"[WHATSAPP] {d['error']}")
            registrar_fallo_critico(
                "WHATSAPP", "El recorrido se interrumpio: la conversacion salio de "
                            "pantalla y no se pudo recuperar")
            self._wa_fin()
            return

        w["recuperos"] = 0

        # Fecha del tramo, tal como la escribe WhatsApp y sin interpretarla.
        #
        # Sirve para seguir por donde va el recorrido. No se convierte a una
        # fecha real a proposito: el orden de dia y mes depende del idioma de
        # la interfaz y una lectura invertida ya costo una adquisicion cortada
        # por la mitad. Aca alcanza con mostrar lo que dice la pantalla.
        fechas = d.get("fechas") or []
        if fechas:
            if not w.get("desde_texto"):
                w["desde_texto"] = fechas[0]
            w["hasta_texto"] = fechas[-1]
            self.append_console(f"[WHATSAPP] tramo {w['tramo']}: mensajes del {fechas[0]}"
                                + (f" al {fechas[-1]}" if fechas[-1] != fechas[0] else ""))

        # Solo el recorrido de multimedia descarga archivos; el de capturas
        # recorre igual pero sin tocar nada.
        w["cola"] = list(d.get("lista") or []) if w.get("hace_media") else []
        if w["cola"]:
            cuenta = {}
            for it in w["cola"]:
                t = it.get("tipo", "?")
                cuenta[t] = cuenta.get(t, 0) + 1
                w["tipos"][t] = w["tipos"].get(t, 0) + 1
            resumen = ", ".join(f"{k} {v}" for k, v in sorted(cuenta.items()))
            self.append_console(f"[WHATSAPP] tramo {w['tramo']}: {len(w['cola'])} "
                                f"archivos ({resumen})")
        QTimer.singleShot(120, self._wa_siguiente)

    def _wa_siguiente(self):
        """Espera a que termine la descarga en curso y pide el proximo archivo."""
        w = self._wa
        if not w.get("activo"):
            return

        if getattr(self, "_descargas_activas", 0) > 0:
            w["espera"] += 1
            if w["espera"] <= 400:               # 400 sondeos de 150 ms = 60 s
                QTimer.singleShot(150, self._wa_siguiente)
                return
            self.case.log("ADVERTENCIA", "WHATSAPP",
                          "Una descarga no termino en 60 s: se sigue con la siguiente")
            self._descargas_activas = 0
        w["espera"] = 0

        if not w["cola"]:
            QTimer.singleShot(150, self._wa_retroceder)
            return

        w["actual"] = w["cola"].pop(0)
        w["esperas_traer"] = 0
        w["reintento"] = False
        w["rescatado"] = False
        w["rescate_agotado"] = False

        # Los stickers no tienen Descargar en el menu de WhatsApp: su menu
        # ofrece responder, reaccionar, reenviar y poco mas. Pasarlos por ahi
        # solo servia para que fallaran y engrosaran el aviso de archivos no
        # adquiridos. Llegan a la pagina ya descifrados, asi que se exportan
        # directamente desde su blob.
        if w["actual"].get("tipo") == "sticker":
            self.browser.page().runJavaScript(
                _WA_BLOB_JS.replace("__MSGID__", w["actual"]["id"]), self._wa_tras_blob)
            return
        # Se va derecho al menu. Su opcion Descargar se encarga tambien de
        # traer el archivo si todavia no esta: es el mismo camino que usa
        # cualquier persona y no hay que adelantarse a el.
        self._wa_hover()

    def _wa_trayendo(self, res):
        """Se pidio el archivo al servidor: hay que esperar a que llegue."""
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        if d.get("error"):
            w["perdidos"] += 1
            QTimer.singleShot(100, self._wa_siguiente)
            return
        if not d.get("traendo"):
            # No habia boton que pulsar: no queda nada por intentar
            self._wa_avisar("no se encontro como traer el archivo", None)
            w["sin_menu"] += 1
            QTimer.singleShot(100, self._wa_siguiente)
            return
        tam = d.get("etiqueta", "")
        self.append_console(f"[WHATSAPP] trayendo {(w.get('actual') or {}).get('tipo','')} "
                            f"{tam}...")
        QTimer.singleShot(1200, self._wa_ver_si_llego)

    def _wa_ver_si_llego(self):
        w = self._wa
        if not w.get("activo"):
            return
        self.browser.page().runJavaScript(
            _WA_PENDIENTE_JS.replace("__MSGID__", (w.get("actual") or {}).get("id", "")),
            self._wa_llego)

    def _wa_llego(self, res):
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        if d.get("error"):
            w["perdidos"] += 1
            QTimer.singleShot(100, self._wa_siguiente)
            return

        if not d.get("pendiente"):
            # Ya llego: se vuelve al menu, que ahora si tiene que ofrecerlo
            self._wa_hover()
            return

        # Un video de varios MB puede tardar: se espera hasta 40 s
        w["esperas_traer"] = w.get("esperas_traer", 0) + 1
        if w["esperas_traer"] <= 32:
            QTimer.singleShot(1200, self._wa_ver_si_llego)
            return
        self._wa_avisar("el archivo no termino de llegar del servidor", None)
        w["sin_menu"] += 1
        QTimer.singleShot(100, self._wa_siguiente)

    def _wa_hover(self):
        """Con el archivo ya en la pagina, se abre el menu del mensaje."""
        w = self._wa
        if not w.get("activo"):
            return
        self.browser.page().runJavaScript(
            _WA_HOVER_JS.replace("__MSGID__", (w.get("actual") or {}).get("id", "")),
            self._wa_hovereado)

    def _wa_hovereado(self, res):
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        if d.get("error"):
            w["perdidos"] += 1
            QTimer.singleShot(100, self._wa_siguiente)
            return
        # Se le da tiempo a React a dibujar el boton del menu antes de buscarlo
        QTimer.singleShot(200, lambda: self.browser.page().runJavaScript(
            _WA_CHEVRON_JS.replace("__MSGID__", (w.get("actual") or {}).get("id", "")),
            self._wa_menu_abierto))

    def _wa_menu_abierto(self, res):
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        if not d.get("ok"):
            self._wa_avisar("no aparecio el boton que abre el menu", None)
            w["sin_menu"] += 1
            QTimer.singleShot(100, self._wa_siguiente)
            return
        QTimer.singleShot(260, lambda: self.browser.page().runJavaScript(
            _WA_MENU_JS, self._wa_menu_leido))

    def _wa_menu_leido(self, res):
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}

        if d.get("pedido"):
            # Queda constancia de que opcion del menu pulso el programa: en una
            # herramienta que opera sola, eso tiene que poder auditarse.
            self.case.log("INFO", "WHATSAPP",
                          f"Menu del mensaje | opcion pulsada={d.get('pulsado', '?')} | "
                          f"tipo={(w.get('actual') or {}).get('tipo', '?')}")
            w["marca"] = getattr(self, "_descargas_iniciadas", 0)
            w["esperas_inicio"] = 0
            QTimer.singleShot(300, self._wa_esperar_entrega)
            return

        if d.get("abierto"):
            self._wa_avisar("el menu no ofrecio Descargar", d.get("items"))
        else:
            self._wa_avisar("el menu no llego a abrirse", None)
        self._wa_respaldo()

    def _wa_esperar_entrega(self):
        """
        Espera a que el archivo pedido llegue al navegador.

        Pulsar Descargar no lo produce en el acto: WhatsApp primero lo trae del
        servidor y lo descifra. Se cuenta como adquirido recien cuando el
        navegador recibe la descarga, no cuando se pulsa la opcion.

        Con video y audio no se espera a ciegas. Esta comprobado que WhatsApp
        deja el archivo descifrado en la pagina y no lo entrega nunca, asi que
        agotar la espera antes de ir a buscarlo eran dieciocho segundos
        perdidos por pieza. Ahora se lo busca apenas puede estar listo, y si
        todavia no esta se vuelve a intentar.
        """
        w = self._wa
        if not w.get("activo"):
            return
        if getattr(self, "_descargas_iniciadas", 0) > w.get("marca", 0):
            w["bajados"] += 1
            QTimer.singleShot(120, self._wa_siguiente)
            return

        w["esperas_inicio"] = w.get("esperas_inicio", 0) + 1
        tipo = (w.get("actual") or {}).get("tipo", "")

        # Video y audio: se busca en la pagina desde el primer segundo.
        # El resto sigue por su camino, que funciona y no conviene adelantar:
        # en la pagina hay muchas imagenes y se podria tomar la equivocada.
        if tipo in ("video", "audio") and w["esperas_inicio"] >= 3:
            self._wa_rescatar()
            return

        if w["esperas_inicio"] <= self._wa_tope_espera(tipo):
            QTimer.singleShot(300, self._wa_esperar_entrega)
            return

        # Se agoto la espera: ultimo intento por la pagina antes de darlo
        # por no adquirido.
        if not w.get("rescate_agotado"):
            w["rescate_agotado"] = True
            self._wa_rescatar()
            return
        self._wa_no_se_pudo()

    @staticmethod
    def _wa_tope_espera(tipo: str) -> int:
        """Sondeos de 300 ms antes de rendirse: 60 s para lo pesado, 18 s para el resto."""
        return 200 if tipo in ("video", "audio", "documento") else 60

    def _wa_rescatar(self):
        """Pide el archivo que WhatsApp haya dejado preparado en la pagina."""
        w = self._wa
        actual = w.get("actual") or {}
        tipo = actual.get("tipo", "")
        prefijo = {"video": "video", "audio": "audio",
                   "imagen": "image", "sticker": "image"}.get(tipo, "")
        import re as _re
        limpio = _re.sub(r"[^A-Za-z0-9_-]", "_", actual.get("id", ""))[-40:]
        nombre = f"WA_{tipo or 'archivo'}_{limpio}"
        js = (f"window.__nav_entregar ? window.__nav_entregar("
              f"{json.dumps(prefijo)}, {json.dumps(nombre)}) : '{{}}'")
        self.browser.page().runJavaScript(js, self._wa_tras_rescate)

    def _wa_tras_rescate(self, res):
        """Resultado de tomar el archivo que WhatsApp dejo listo en la pagina."""
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}

        if d.get("ok"):
            kb = int(d.get("size", 0)) / 1024
            self.append_console(
                f"[WHATSAPP] el archivo estaba listo en la pagina y se tomo de alli "
                f"({d.get('tipo', '?')}, {kb:.1f} KB)")
            w["de_la_pagina"] = w.get("de_la_pagina", 0) + 1
            self.case.log("INFO", "WHATSAPP",
                          f"Archivo tomado de la pagina | tipo={d.get('tipo')} | "
                          f"{d.get('size')} bytes | WhatsApp no lo entrego por si mismo")
            # Ahora si tiene que arrancar la descarga
            w["esperas_inicio"] = 0
            QTimer.singleShot(200, self._wa_esperar_entrega)
            return

        # Todavia no esta descifrado: se sigue esperando
        tipo = (w.get("actual") or {}).get("tipo", "")
        if w.get("esperas_inicio", 0) <= self._wa_tope_espera(tipo):
            QTimer.singleShot(400, self._wa_esperar_entrega)
            return
        self._wa_no_se_pudo()

    def _wa_no_se_pudo(self):
        """Se agotaron los intentos: queda constancia y se sigue con el resto."""
        w = self._wa
        w["sin_menu"] += 1
        self._wa_avisar("se pulso Descargar pero el archivo nunca quedo disponible", None)
        # Se vuelca por donde intento salir: es lo unico que permite saber que
        # camino usa WhatsApp en vez de suponerlo.
        self.browser.page().runJavaScript(
            "JSON.stringify(window.__nav_diag || {})", self._wa_volcar_diagnostico)
        QTimer.singleShot(120, self._wa_siguiente)

    def _wa_volcar_diagnostico(self, res):
        """Deja en el registro lo que hizo la pagina al pedirle el archivo."""
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        if not d:
            self.append_console("[WHATSAPP] sin datos de diagnostico de la pagina")
            return
        resumen = (f"showSaveFilePicker={d.get('picker', 0)} | "
                   f"blobs={d.get('blobs') or 'ninguno'} | "
                   f"enlaces={d.get('enlaces') or 'ninguno'} | "
                   f"errores={d.get('errores') or 'ninguno'}")
        self.append_console(f"[WHATSAPP] la pagina intento: {resumen}")
        self.case.log("ADVERTENCIA", "WHATSAPP", f"Diagnostico de entrega | {resumen}")

    def _wa_respaldo(self):
        """
        Que hacer cuando el menu no dio la descarga.

        Dos casos distintos. Los stickers no tienen opcion de descarga en
        WhatsApp (su menu ofrece responder, reaccionar, reenviar y poco mas),
        pero vienen ya descifrados y montados en la pagina: se exportan desde
        su blob. Para lo demas, lo probable es que el archivo aun no se haya
        traido del servidor, asi que se lo pide y se reintenta el menu.
        """
        w = self._wa
        if not w.get("activo"):
            return
        actual = w.get("actual") or {}

        if actual.get("tipo") in ("sticker", "imagen"):
            self.browser.page().runJavaScript(
                _WA_BLOB_JS.replace("__MSGID__", actual.get("id", "")), self._wa_tras_blob)
            return

        if w.get("reintento"):
            # Ya se trajo el archivo y el menu igual no lo ofrecio
            w["sin_menu"] += 1
            QTimer.singleShot(120, self._wa_siguiente)
            return
        w["reintento"] = True
        w["esperas_traer"] = 0
        self.browser.page().runJavaScript(
            _WA_TRAER_JS.replace("__MSGID__", actual.get("id", "")), self._wa_trayendo)

    def _wa_tras_blob(self, res):
        """Resultado de exportar un sticker o una imagen desde la pagina."""
        w = self._wa
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        if d.get("ok"):
            w["bajados"] += 1
            self.case.log("INFO", "WHATSAPP",
                          f"Exportado desde la pagina | tipo="
                          f"{(w.get('actual') or {}).get('tipo', '?')}")
        else:
            w["sin_menu"] += 1
            self._wa_avisar("tampoco estaba disponible en la pagina", None)
        QTimer.singleShot(120, self._wa_siguiente)

    def _wa_avisar(self, motivo, opciones):
        """
        Deja constancia, una sola vez por motivo y tipo, de por que no se pudo
        adquirir un archivo.

        Es la parte que permite corregir el programa cuando WhatsApp cambia su
        interfaz: sin esto solo se sabria que falto una pieza, no por que.
        """
        w = self._wa
        tipo = (w.get("actual") or {}).get("tipo", "?")
        clave = f"{tipo}|{motivo}"
        if clave in w["avisos"]:
            return
        w["avisos"].add(clave)
        detalle = ""
        if opciones:
            detalle = " Opciones vistas: " + ", ".join(str(x) for x in opciones)
        self.append_console(f"[WHATSAPP] {tipo}: {motivo}.{detalle}")
        self.case.log("ADVERTENCIA", "WHATSAPP",
                      f"No se adquirio | tipo={tipo} | motivo={motivo} |{detalle}")

    def _wa_retroceder(self):
        w = self._wa
        if not w.get("activo"):
            return
        self.browser.page().runJavaScript(_WA_AVANZAR_JS, self._wa_retrocedido)

    def _wa_retrocedido(self, res):
        w = self._wa
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}

        # Se corta cuando ya no queda chat hacia atras. Se piden varias
        # confirmaciones seguidas porque WhatsApp carga los mensajes viejos por
        # partes: un tramo sin avance no significa que sea el principio.
        w["fin_seguidos"] = w["fin_seguidos"] + 1 if d.get("fin") else 0
        if w["fin_seguidos"] >= 4 or w["tramo"] > 400:
            if w["tramo"] > 400:
                registrar_fallo_critico(
                    "WHATSAPP", "Se alcanzo el limite de tramos: la conversacion "
                                "podria no haberse recorrido entera")
            self._wa_fin()
            return
        QTimer.singleShot(500, self._wa_tramo)

    def _wa_fin(self):
        w = self._wa
        # Puede llegarse aca dos veces: por el boton de detener y por alguna
        # llamada que ya estaba en camino. El resumen se escribe una sola vez.
        if not w.get("activo"):
            return

        # Si queda una descarga en curso hay que esperarla, incluso si el
        # perito pulso detener: cerrar ahora dejaria el archivo en disco sin
        # hash ni acta, que es lo mismo que no tenerlo.
        if getattr(self, "_descargas_activas", 0) > 0 and w.get("cierres", 0) < 200:
            if not w.get("cierres"):
                self.append_console("[WHATSAPP] esperando que termine la descarga en curso...")
            w["cierres"] = w.get("cierres", 0) + 1
            QTimer.singleShot(300, self._wa_fin)
            return

        w["activo"] = False
        self._wa_modo_boton(False, w.get("cual", ""))
        que = "MULTIMEDIA" if w.get("hace_media") else "CAPTURAS DEL CHAT"
        self.append_console("-" * 60)
        if w.get("interrumpido"):
            self.append_console(f"⏹ WHATSAPP {que}: INTERRUMPIDO por el perito")
            self.append_console("  El chat NO se recorrio hasta el final del periodo")
        else:
            self.append_console(f"✓ WHATSAPP {que}: terminado")
        if w.get("hace_media"):
            detalle = ", ".join(f"{k} {v}" for k, v in sorted(w["tipos"].items())) or "ninguno"
            self.append_console(f"  Archivos descargados : {w['bajados']}")
            self.append_console(f"  Detectado por tipo   : {detalle}")
        if w.get("desde_texto"):
            self.append_console(f"  Mensajes recorridos  : del {w['desde_texto']} "
                                f"al {w['hasta_texto']}  (fechas segun WhatsApp)")
        if w["capturas"]:
            self.append_console(f"  Capturas del chat    : {w['capturas']}")
            self.append_console("     WA_Chat_001  = donde estaba la vista al comenzar")
            hasta = ("punto donde se detuvo" if w.get("interrumpido")
                     else "ultimo mensaje de la conversacion")
            self.append_console(f"     WA_Chat_{w['capturas']:03d}  = {hasta}")
        if w.get("repetidas"):
            self.append_console(f"     ({w['repetidas']} vistas repetidas no se guardaron)")
        self.append_console(f"  Tramos recorridos    : {w['tramo']}")
        if w["perdidos"]:
            self.append_console(f"  {w['perdidos']} mensajes se fueron de la vista "
                                f"antes de poder pedirlos")
        if w["sin_menu"]:
            self.append_console(f"  AVISO: {w['sin_menu']} archivos no se pudieron pedir")
            registrar_fallo_critico(
                "WHATSAPP",
                f"{w['sin_menu']} archivos no se adquirieron. Ver en el log el motivo "
                f"y las opciones que ofrecia el menu")
        self.append_console("-" * 60)
        estado = "INTERRUMPIDO por el perito" if w.get("interrumpido") else "completo"

        # Constancia para el dictamen: cada recorrido queda descripto con su
        # alcance y sus parametros, para que el informe no dependa de lo que
        # el perito recuerde despues.
        if not hasattr(self, "_wa_resumen"):
            self._wa_resumen = []
        self._wa_resumen.append({
            "tipo": "Multimedia" if w.get("hace_media") else "Capturas de pantalla",
            "estado": estado,
            "sentido": "de la vista inicial hacia el ultimo mensaje",
            "alcance": (f"del {w['desde_texto']} al {w['hasta_texto']}"
                        if w.get("desde_texto") else "sin fechas legibles en pantalla"),
            "archivos": w["bajados"],
            "capturas": w["capturas"],
            "tramos": w["tramo"],
            "no_adquiridos": w["sin_menu"],
            "de_la_pagina": w.get("de_la_pagina", 0),
        })
        if w.get("hace_media"):
            self.case.log("INFO", "WHATSAPP",
                          f"Recorrido de multimedia {estado} | {w['bajados']} archivos | "
                          f"{w['tramo']} tramos | del ultimo mensaje hacia atras")
        else:
            orden = ("de la vista inicial hacia el ultimo mensaje: WA_Chat_001 es el "
                     "punto de partida elegido por el perito y "
                     f"WA_Chat_{w['capturas']:03d} el ultimo mensaje alcanzado")
            self.case.log("INFO", "WHATSAPP",
                          f"Recorrido de capturas {estado} | {w['capturas']} capturas | "
                          f"{w['tramo']} tramos | {orden}")
        # Una adquisicion cortada a mitad de camino no cubre toda la
        # conversacion: tiene que constar como tal y no pasar por completa.
        if w.get("interrumpido"):
            registrar_fallo_critico(
                "WHATSAPP",
                f"La adquisicion se detuvo a pedido del perito en el tramo "
                f"{w['tramo']}: la conversacion no se recorrio hasta el principio")

    #  RELEVAMIENTO DE PERFILES DE INSTAGRAM
    #
    #  Lo que se registra es lo que la pagina muestra al perito con su sesion
    #  abierta. No se consultan interfaces no documentadas ni se emplean
    #  clientes de ingenieria inversa: por ese camino los datos no serian
    #  atribuibles a lo que un usuario ve, y esa atribucion es justamente lo
    #  que sostiene el resto del procedimiento.

    def relevar_perfil_instagram(self):
        """Registra los datos del perfil a la vista, su foto y sus ubicaciones."""
        if "instagram.com" not in self.browser.url().toString().lower():
            QMessageBox.warning(self, "Instagram",
                                "Abra el perfil de Instagram que desea relevar.")
            return
        self.append_console("-" * 60)
        self.append_console("[INSTAGRAM] Relevando el perfil a la vista...")
        self.browser.page().runJavaScript(_IG_DATOS_JS, self._ig_datos_leidos)

    def _ig_datos_leidos(self, res):
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        if not d:
            self.append_console("[INSTAGRAM] la pagina no devolvio datos")
            return

        usuario = d.get("usuario", "") or "perfil"
        campos = d.get("campos", {}) or {}
        ubic = d.get("ubicaciones", []) or []
        diag = d.get("diag", {}) or {}

        if not campos:
            self.append_console(
                f"[INSTAGRAM] no se hallo ningun dato en el encabezado de la pagina. "
                f"{diag.get('motivo', 'Revisar si Instagram cambio su interfaz.')}")
            self.case.log("ADVERTENCIA", "INSTAGRAM",
                          f"Sin datos en la pagina de @{usuario} | "
                          f"{diag.get('motivo', 'estructura no reconocida')}")
            return

        # Comprobacion de identidad: el texto alternativo de la foto de perfil
        # nombra a su titular. Si no coincide con la direccion, se registra
        # igual pero la salvedad queda escrita: quien lea el informe tiene que
        # saber que la atribucion no pudo confirmarse.
        atribuido = bool(diag.get("foto_nombra_al_perfil"))
        if not atribuido:
            self.append_console(
                "   AVISO: la foto de perfil no nombra a esta cuenta; "
                "la atribucion no pudo confirmarse")
            self.case.log("ADVERTENCIA", "INSTAGRAM",
                          f"@{usuario}: no se pudo confirmar la atribucion por el texto "
                          f"alternativo de la foto de perfil")

        ts = datetime.datetime.now()

        def cifra(k):
            """Muestra la cifra exacta cuando la pagina la publica."""
            v = campos.get(k, "")
            e = campos.get(k + "_exacto", "")
            return f"{e}  (en pantalla: {v})" if e and e != v else v

        etiquetas = [
            ("Usuario", "@" + usuario), ("Nombre", campos.get("nombre", "")),
            ("Biografia", campos.get("biografia", "")),
            ("Sitio web", campos.get("sitio_web", "")),
            ("Seguidores", cifra("seguidores")),
            ("Seguidos", cifra("seguidos")),
            ("Publicaciones", cifra("publicaciones")),
            ("Cuenta verificada", "si" if campos.get("verificado") else "no"),
            ("Foto de perfil", campos.get("foto_medida", "")),
            ("Atribucion", "confirmada por el texto alternativo de la foto"
                           if atribuido else "NO CONFIRMADA"),
        ]
        destino = self.case.dirs["network"] / f"Relevamiento_Instagram_{usuario}_{ts:%Y%m%d_%H%M%S}.txt"
        try:
            with open(destino, "w", encoding="utf-8") as f:
                f.write("RELEVAMIENTO DE PERFIL - Instagram\n")
                f.write(f"Caso     : {self.case.case_id}\n")
                f.write(f"Momento  : {ts.isoformat()}\n")
                f.write(f"URL      : {d.get('url', '')}\n")
                f.write("Origen   : datos publicados por la propia pagina, leidos de su\n")
                f.write("           JSON embebido. No se consulto ninguna interfaz externa.\n")
                f.write("=" * 70 + "\n\n")
                for k, v in etiquetas:
                    if str(v) != "":
                        f.write(f"{k:20}: {v}\n")
                if ubic:
                    f.write(f"\nUBICACIONES DECLARADAS EN LAS PUBLICACIONES ({len(ubic)})\n")
                    f.write("Instagram elimina los metadatos EXIF de las imagenes; estos\n")
                    f.write("lugares son los que el titular de la cuenta etiqueto al publicar.\n\n")
                    for u in ubic:
                        f.write(f"  - {u}\n")
        except Exception as e:
            registrar_fallo_critico("INSTAGRAM", f"No se pudo guardar el relevamiento: {e}")
            self.append_console(f"  x No se pudo guardar: {e}")
            return

        registrar_archivo_caso(
            self.case, destino, "RELEVAMIENTO_PERFIL",
            {"Perfil": "@" + usuario,
             "Datos hallados": ", ".join(diag.get("hallados", [])) or "ninguno",
             "Ubicaciones": str(len(ubic)),
             "Origen": "contenido mostrado por la pagina de Instagram"},
            source_url=d.get("url", ""))

        self.append_console(f"[INSTAGRAM] @{usuario}")
        for k, v in etiquetas[1:]:
            if str(v) != "":
                self.append_console(f"   {k:18}: {str(v)[:70]}")
        if ubic:
            self.append_console(f"   Ubicaciones       : {len(ubic)}  ({', '.join(ubic[:4])}"
                                + (", ..." if len(ubic) > 4 else "") + ")")
        self.append_console(f"   Registrado en     : {destino.name}")

        # La foto de perfil en su resolucion real. La que se ve en pantalla
        # esta reducida; Instagram publica la version grande en el mismo JSON.
        foto = campos.get("foto") or ""
        if foto:
            nombre = f"FotoPerfil_Instagram_{usuario}_{ts:%Y%m%d_%H%M%S}.jpg"
            self._pagina_pendiente = {
                "nombre": nombre, "url": foto, "tipo": "FOTO_PERFIL",
                "extra": {"Perfil": "@" + usuario,
                          "Resolucion": campos.get("foto_medida", "no informada"),
                          "Origen": "imagen del encabezado del perfil, tal como la "
                                    "sirve Instagram"}}
            try:
                self.browser.page().download(QUrl(foto), str(
                    self.case.dirs["evidence_img"] / nombre))
                self.append_console(f"   Foto de perfil    : descargando en resolucion completa")
            except Exception as e:
                self._pagina_pendiente = None
                self.append_console(f"   x No se pudo descargar la foto: {e}")
        else:
            self.append_console("   Foto de perfil    : no se hallo en el encabezado")
        self.append_console("-" * 60)

    #  Recorrido de la lista de seguidores o seguidos

    def listar_contactos_instagram(self):
        """Recorre la lista de contactos a la vista: seguidores o seguidos en
        Instagram, o la lista de amigos en Facebook."""
        u = self.browser.url().toString().lower()
        en_ig = "instagram.com" in u
        en_fb = "facebook.com" in u
        if not (en_ig or en_fb):
            QMessageBox.warning(self, "Lista de contactos",
                                "Abra el perfil de Instagram o de Facebook que desea relevar.")
            return
        if getattr(self, "_ig", {}).get("activo"):
            self._ig_detener()
            return

        aviso = ("Abra en Instagram la lista de SEGUIDORES o de SEGUIDOS y dejela\n"
                 "a la vista antes de continuar.\n\n"
                 if en_ig else
                 "Abra en Facebook la solapa AMIGOS del perfil y dejela a la vista\n"
                 "antes de continuar.\n\n")
        resp = QMessageBox.question(
            self, "Registrar la lista abierta",
            aviso +
            "Se recorrera esa lista de arriba a abajo, registrando cada cuenta\n"
            "y guardando una captura por tramo. Al terminar se produce un\n"
            "listado con su hash SHA-256 y su acta de custodia.\n\n"
            "En listas largas puede demorar varios minutos.\n"
            "No opere el navegador mientras dure el recorrido.\n\n"
            "¿Comenzar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes)
        if resp != QMessageBox.StandardButton.Yes:
            return

        self._ig = {"activo": True, "tramo": 0, "capturas": 0, "total": 0,
                    "interrumpido": False, "sin_avance": 0,
                    "url": self.browser.url().toString(),
                    "sitio": "Facebook" if en_fb else "Instagram"}
        self.btn_ig_lista.setText("⏹ DETENER")
        self.append_console("-" * 60)
        self.append_console("[LISTA] Recorriendo la lista abierta...")
        self.case.log("INFO", "LISTA", "Inicio del recorrido de la lista de contactos")
        self.browser.page().runJavaScript("window.__lista = null;")
        QTimer.singleShot(400, self._ig_tramo)

    def _ig_detener(self):
        if not getattr(self, "_ig", {}).get("activo"):
            return
        self._ig["interrumpido"] = True
        self.append_console("[LISTA] Detenido por el perito.")
        self.case.log("ADVERTENCIA", "LISTA",
                      f"Recorrido detenido por el perito en el tramo {self._ig['tramo']}: "
                      f"la lista no se recorrio entera")
        self._ig_fin()

    def _ig_tramo(self):
        # Se lee primero y se captura despues, con el recorte que devuelve esa
        # misma lectura: asi la imagen corresponde a lo leido.
        if not self._ig.get("activo"):
            return
        self._ig["tramo"] += 1
        self.browser.page().runJavaScript(_LISTA_JS, self._ig_leido)

    def _ig_capturar(self, rect):
        w = self._ig
        n = w["capturas"] + 1
        sitio = "FB" if w.get("sitio") == "Facebook" else "IG"
        try:
            self._capturar_region(
                rect, f"{sitio}_Lista_{n:03d}",
                f"Lista de contactos, vista {n}",
                tipo="CAPTURA_LISTA")
            w["capturas"] = n
        except Exception as e:
            self.case.log("ERROR", "LISTA", f"No se pudo capturar la vista: {e}")

    def _ig_leido(self, res):
        w = self._ig
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}

        if d.get("error"):
            self.append_console(f"[LISTA] {d['error']}")
            self._ig_fin()
            return

        nuevos = int(d.get("nuevos", 0))
        w["total"] = int(d.get("total", w["total"]))
        w["sitio"] = d.get("sitio") or w.get("sitio", "Instagram")

        r = decidir_tramo(w, d, nuevos)
        nuevos = r["nuevos"]

        if r["esperar"]:
            self.append_console(f"[LISTA] tramo {w['tramo']}: esperando a que termine "
                                f"de cargar ({w['esperas']}/5)")
            w["tramo"] -= 1
            QTimer.singleShot(900, self._ig_tramo)
            return

        self.append_console(
            f"[LISTA] tramo {w['tramo']}: {nuevos} nuevas (total {w['total']}) | "
            f"panel {'propio' if d.get('propio') else 'de la pagina'} "
            f"{r['pos']}/{r['fondo']}" + ("  <-- NO SE DESPLAZO" if r["quieto"] else ""))
        if r["quieto"] and not w.get("aviso_quieto"):
            w["aviso_quieto"] = True
            self.case.log("ADVERTENCIA", "LISTA",
                          f"El panel no se desplazo entre tramos (posicion {r['pos']} de "
                          f"{r['fondo']}): revisar si la vista quedo tapada")
        if r["parcial"] and r["capturar"]:
            w["capturas_parciales"] = w.get("capturas_parciales", 0) + 1
            self.append_console(f"[LISTA] tramo {w['tramo']}: se captura con parte de "
                                f"la lista aun cargando")
            self.case.log("ADVERTENCIA", "LISTA",
                          f"Vista {w['tramo']} capturada con marcadores de carga a la "
                          f"vista: puede mostrar espacios en blanco")

        if r["capturar"]:
            self._ig_capturar(d.get("rect") or {})

        # Se sigue mientras haya algo nuevo QUE LEER O QUE VER: contar solo las
        # cuentas nuevas cortaba a los doce tramos aunque la lista siguiera
        # desplazandose, y la mitad ya leida nunca llegaba a fotografiarse.
        if nuevos or r["movio"]:
            w["sin_avance"] = 0
        else:
            w["sin_avance"] += 1

        # El corte se decide por falta de novedad y no por haber llegado al
        # fondo. Estar al fondo es lo normal mientras la pagina trae el lote
        # siguiente: cortar ahi dejaria la lista a medias.
        if w["sin_avance"] >= 12 or w["tramo"] > 600:
            self._ig_fin(por_limite=(w["tramo"] > 600))
            return

        self._ig_rueda(d.get("centro_x", 0), d.get("centro_y", 0))
        # Con la carga en curso conviene esperar mas antes de volver a leer
        QTimer.singleShot(1100 if d.get("cargando") else 700, self._ig_tramo)

    def _ig_rueda(self, x: int, y: int):
        """
        Desplaza la lista con la rueda del mouse, como lo haria una persona.

        No se usa scrollTop. Se comprobo contra Instagram que asignar la
        posicion mueve la lista pero no dispara la carga del lote siguiente: el
        indicador de carga queda girando y no llegan mas cuentas. La rueda
        entregada por el sistema si la dispara.
        """
        destino = self.browser.focusProxy()
        if destino is None or x <= 0:
            return
        try:
            local = QPointF(float(x), float(y))
            glob = QPointF(self.browser.mapToGlobal(local.toPoint()))
            # Tres muescas hacia abajo: avanza sin saltearse filas
            ev = QWheelEvent(local, glob, QPoint(0, -120), QPoint(0, -360),
                             Qt.MouseButton.NoButton, Qt.KeyboardModifier.NoModifier,
                             Qt.ScrollPhase.NoScrollPhase, False)
            QApplication.postEvent(destino, ev)
        except Exception as e:
            self.case.log("ADVERTENCIA", "INSTAGRAM", f"No se pudo desplazar la lista: {e}")

    def _ig_fin(self, por_limite: bool = False):
        w = self._ig
        if not w.get("activo"):
            return
        w["activo"] = False
        self.btn_ig_lista.setText("👥 LISTA DE CONTACTOS")
        self.browser.page().runJavaScript(_LISTA_FINAL_JS, self._ig_guardar)
        if por_limite:
            registrar_fallo_critico(
                "INSTAGRAM",
                "Se alcanzo el limite de tramos: la lista podria no haberse recorrido entera")

    def _ig_guardar(self, res):
        w = self._ig
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        cuentas = d.get("orden") or []
        sitio = d.get("sitio") or w.get("sitio") or "Instagram"
        u_pagina = d.get("url") or ""
        u_inicio = w.get("url") or ""

        self.append_console("-" * 60)
        estado = "INTERRUMPIDO por el perito" if w.get("interrumpido") else "terminado"
        marca = "\u23f9" if w.get("interrumpido") else "\u2713"
        self.append_console(f"{marca} Lista de {sitio}: {estado}")
        self.append_console(f"  Cuentas registradas : {len(cuentas)}")
        self.append_console(f"  Capturas            : {w['capturas']}")
        self.append_console(f"  Tramos recorridos   : {w['tramo']}")

        if not cuentas:
            self.append_console("  No se registro ninguna cuenta")
            self.append_console("-" * 60)
            return

        # Igual que con los comentarios: si lo acumulado no salio de la pagina
        # donde se inicio, quedo algo en memoria de una corrida anterior y las
        # cuentas estarian atribuidas a un perfil que no es el suyo.
        if u_pagina and u_inicio and u_pagina != u_inicio:
            registrar_fallo_critico(
                "LISTA",
                f"La lista proviene de {u_pagina} y el recorrido se inicio en "
                f"{u_inicio}: no se guarda por no poder atribuirla")
            self.append_console("\u2717 LISTA: lo leido no corresponde al perfil en el que "
                                "se inicio. No se guarda.")
            self.append_console(f"  iniciado en : {u_inicio}")
            self.append_console(f"  leido de    : {u_pagina}")
            self.append_console("-" * 60)
            return

        ts = datetime.datetime.now()
        destino = self.case.dirs["network"] / f"Lista_{sitio}_{ts:%Y%m%d_%H%M%S}.txt"
        try:
            with open(destino, "w", encoding="utf-8") as f:
                f.write(f"LISTA DE CONTACTOS - {sitio}\n")
                f.write(f"Caso    : {self.case.case_id}\n")
                f.write(f"Momento : {ts.isoformat()}\n")
                f.write(f"Perfil  : {u_pagina or u_inicio}\n")
                f.write(f"Cuentas : {len(cuentas)}\n")
                estado_txt = ("recorrido interrumpido por el perito"
                              if w.get("interrumpido") else "lista recorrida hasta el final")
                f.write(f"Estado  : {estado_txt}\n")
                f.write("Origen  : enlaces de perfil publicados por la propia pagina,\n")
                f.write(f"          en el orden en que {sitio} los presenta.\n")
                f.write("=" * 70 + "\n\n")
                for i, c in enumerate(cuentas, 1):
                    if isinstance(c, dict):
                        ident, nombre = c.get("id", ""), c.get("nombre", "")
                    else:
                        ident, nombre = str(c), ""
                    if nombre and nombre != ident:
                        f.write(f"{i:5}. @{ident}   {nombre}\n")
                    else:
                        f.write(f"{i:5}. @{ident}\n")
        except Exception as e:
            registrar_fallo_critico("LISTA", f"No se pudo guardar la lista: {e}")
            return

        registrar_archivo_caso(
            self.case, destino, "LISTA_CONTACTOS",
            {"Sitio": sitio,
             "Perfil relevado": u_pagina or u_inicio,
             "Cuentas registradas": str(len(cuentas)),
             "Capturas de respaldo": str(w["capturas"]),
             "Capturas con la vista aun cargando": str(w.get("capturas_parciales", 0)),
             "Estado": ("recorrido INTERRUMPIDO por el perito"
                        if w.get("interrumpido") else "lista recorrida hasta el final"),
             "Origen": "enlaces de perfil de la pagina, sin consultar interfaces externas"},
            source_url=u_pagina or u_inicio)
        self.append_console(f"  Listado             : {destino.name}")
        self.append_console("-" * 60)
        self.case.log("INFO", "LISTA",
                      f"Lista de {sitio} {estado} | {len(cuentas)} cuentas | "
                      f"{w['capturas']} capturas | {w['tramo']} tramos")

    #  COMENTARIOS DE UNA PUBLICACION
    #
    # Mismo procedimiento que la lista de contactos, por el mismo motivo: los
    # comentarios llegan de a lotes y solo se cargan cuando el panel se
    # desplaza con la rueda de verdad. Se lee lo que la pagina ya mostro, se
    # captura cada tramo y recien al final se guarda el listado con su hash.

    def capturar_comentarios(self):
        if getattr(self, "_igc", {}).get("activo"):
            self._com_detener()
            return
        u = self.browser.url().toString().lower()
        if not any(s in u for s in ("instagram.com", "facebook.com", "tiktok.com")):
            QMessageBox.information(
                self, "Comentarios",
                "Esta funcion trabaja sobre una publicacion de Instagram, "
                "Facebook o TikTok.")
            return

        resp = QMessageBox.question(
            self, "Comentarios de la publicacion",
            "Se recorreran los comentarios de la publicacion a la vista.\n\n"
            "De cada uno se registra: autor, texto, la fecha y hora exactas que\n"
            "publica el sitio y las respuestas que deja sin desplegar.\n"
            "Cada tramo queda respaldado por una captura de pantalla.\n\n"
            "No opere el navegador mientras dure el recorrido.\n\n"
            "\u00bfComenzar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes)
        if resp != QMessageBox.StandardButton.Yes:
            return

        self._igc = {"activo": True, "tramo": 0, "capturas": 0, "total": 0,
                     "interrumpido": False, "sin_avance": 0,
                     "url": self.browser.url().toString()}
        self.btn_ig_com.setText("\u23f9 DETENER")
        self.append_console("-" * 60)
        self.append_console("[COMENTARIOS] Recorriendo los comentarios de la publicacion...")
        self.case.log("INFO", "COMENTARIOS", "Inicio del relevamiento de comentarios")
        self.browser.page().runJavaScript("window.__com = null;")
        QTimer.singleShot(400, self._com_tramo)

    def _com_detener(self):
        if not getattr(self, "_igc", {}).get("activo"):
            return
        self._igc["interrumpido"] = True
        self.append_console("[COMENTARIOS] Detenido por el perito.")
        self.case.log("ADVERTENCIA", "COMENTARIOS",
                      f"Relevamiento de comentarios detenido por el perito en el tramo "
                      f"{self._igc['tramo']}: no se recorrieron todos los comentarios")
        self._com_fin()

    def _com_tramo(self):
        # Primero se lee y despues se captura, con el recorte que devuelve esa
        # misma lectura. Al reves (capturar y despues leer) la imagen podia no
        # corresponder a lo leido, y el recorte se calculaba dos veces en dos
        # lugares distintos.
        if not self._igc.get("activo"):
            return
        self._igc["tramo"] += 1
        self.browser.page().runJavaScript(_COM_JS, self._com_leido)

    def _com_capturar(self, rect):
        w = self._igc
        n = w["capturas"] + 1
        u = w.get("url", "")
        sitio = "FB" if "facebook.com" in u else "TT" if "tiktok.com" in u else "IG"
        try:
            self._capturar_region(
                rect, f"{sitio}_Comentarios_{n:03d}",
                f"Comentarios de la publicacion, vista {n}",
                tipo="CAPTURA_COMENTARIOS")
            w["capturas"] = n
        except Exception as e:
            self.case.log("ERROR", "COMENTARIOS", f"No se pudo capturar la vista: {e}")

    def _com_leido(self, res):
        w = self._igc
        if not w.get("activo"):
            return
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}

        if d.get("error"):
            self.append_console(f"[COMENTARIOS] {d['error']}")
            self._com_fin()
            return

        nuevos = int(d.get("nuevos", 0))
        w["total"] = int(d.get("total", w["total"]))

        # Estado del desplazamiento en cada tramo. Sin esto, un recorrido que
        # no avanza no deja modo de saber si es porque ya se vio todo, porque
        # la rueda no llega, o porque la pagina no trae mas: los tres se ven
        # igual desde afuera.
        r = decidir_tramo(w, d, nuevos)
        nuevos = r["nuevos"]

        if r["esperar"]:
            self.append_console(f"[COMENTARIOS] tramo {w['tramo']}: esperando a que "
                                f"termine de cargar ({w['esperas']}/5)")
            w["tramo"] -= 1          # el reintento no cuenta como tramo nuevo
            QTimer.singleShot(900, self._com_tramo)
            return

        self.append_console(
            f"[COMENTARIOS] tramo {w['tramo']}: {nuevos} nuevos (total {w['total']}) | "
            f"panel {'propio' if d.get('propio') else 'de la pagina'} "
            f"{r['pos']}/{r['fondo']}" + ("  <-- NO SE DESPLAZO" if r["quieto"] else ""))
        if r["quieto"] and not w.get("aviso_quieto"):
            w["aviso_quieto"] = True
            self.case.log("ADVERTENCIA", "COMENTARIOS",
                          f"El panel no se desplazo entre tramos (posicion {r['pos']} de "
                          f"{r['fondo']}): revisar si la vista quedo tapada")
        if d.get("fuera_de_vista"):
            self.append_console("[COMENTARIOS]   la columna quedo fuera de la vista; "
                                "se desplaza la pagina")
        if r["parcial"] and r["capturar"]:
            w["capturas_parciales"] = w.get("capturas_parciales", 0) + 1
            self.append_console(f"[COMENTARIOS] tramo {w['tramo']}: se captura con "
                                f"parte del panel aun cargando")
            self.case.log("ADVERTENCIA", "COMENTARIOS",
                          f"Vista {w['tramo']} capturada con marcadores de carga a la "
                          f"vista: puede mostrar espacios en blanco")

        if r["capturar"]:
            self._com_capturar(d.get("rect") or {})

        # Se sigue mientras haya algo nuevo QUE LEER O QUE VER. Contar solo los
        # comentarios nuevos cortaba el recorrido a los doce tramos aunque la
        # lista siguiera desplazandose, de modo que la mitad de los comentarios
        # ya leidos nunca llegaba a fotografiarse.
        if nuevos or r["movio"]:
            w["sin_avance"] = 0
        else:
            w["sin_avance"] += 1

        # Se corta por falta de comentarios nuevos y no por haber llegado al
        # fondo del panel: estar al fondo es lo habitual mientras la pagina
        # trae el lote siguiente.
        #
        # Sin panel con barra propia no hay lotes por venir (lo que se ve es
        # todo) y esperar doce vueltas solo suma tramos. Con panel se espera,
        # porque ahi si puede estar cargando.
        tope = 12 if d.get("propio") else 2
        if w["sin_avance"] >= tope or w["tramo"] > 600:
            self._com_fin(por_limite=(w["tramo"] > 600))
            return

        self._ig_rueda(d.get("centro_x", 0), d.get("centro_y", 0))
        QTimer.singleShot(1100 if d.get("cargando") else 700, self._com_tramo)

    def _com_fin(self, por_limite: bool = False):
        w = self._igc
        if not w.get("activo"):
            return
        w["activo"] = False
        self.btn_ig_com.setText("\U0001f4ac COMENTARIOS")
        self.browser.page().runJavaScript(_COM_FINAL_JS, self._com_guardar)
        if por_limite:
            registrar_fallo_critico(
                "COMENTARIOS",
                "Se alcanzo el limite de tramos: podrian faltar comentarios por relevar")

    def _com_guardar(self, res):
        w = self._igc
        try:
            d = json.loads(res) if res else {}
        except Exception:
            d = {}
        comentarios = d.get("orden") or []
        desc = d.get("desc")
        u = w.get("url", "")

        # La pagina informa de que publicacion salio lo acumulado. Si no es la
        # misma con la que se inicio el relevamiento, quedo algo en memoria de
        # una corrida anterior y los comentarios estarian atribuidos a una
        # publicacion que no los tiene. Es el peor error posible en una prueba
        # porque no se nota mirando el listado: se corta y se deja constancia.
        u_pagina = d.get("url") or ""
        if u_pagina and u and u_pagina != u:
            registrar_fallo_critico(
                "COMENTARIOS",
                f"Los comentarios provienen de {u_pagina} y el relevamiento se "
                f"inicio en {u}: no se guardan por no poder atribuirlos")
            self.append_console("✗ COMENTARIOS: lo leido no corresponde a la "
                                "publicacion en la que se inicio. No se guarda.")
            self.append_console(f"  iniciado en : {u}")
            self.append_console(f"  leido de    : {u_pagina}")
            self.append_console("-" * 60)
            return
        sitio = d.get("sitio") or ("Facebook" if "facebook.com" in u
                                   else "TikTok" if "tiktok.com" in u
                                   else "Instagram")

        self.append_console("-" * 60)
        estado = "INTERRUMPIDO por el perito" if w.get("interrumpido") else "terminado"
        marca = "\u23f9" if w.get("interrumpido") else "\u2713"
        self.append_console(f"{marca} Comentarios de {sitio}: {estado}")
        self.append_console(f"  Comentarios registrados : {len(comentarios)}")
        self.append_console(f"  Capturas                : {w['capturas']}")
        self.append_console(f"  Tramos recorridos       : {w['tramo']}")

        if not comentarios and not desc:
            self.append_console("  No se registro ningun comentario")
            self.append_console("-" * 60)
            return

        # Respuestas que la pagina deja plegadas. No se despliegan: hacerlo
        # exigiria pulsar cada "ver respuestas", y eso ya no seria dejar
        # constancia de la publicacion tal como se presenta. Se anota cuantas
        # son, que es lo que permite a la contraparte saber que falta.
        plegadas = 0
        for c in comentarios:
            try:
                plegadas += int(c.get("respuestas") or 0)
            except Exception:
                pass

        ts = datetime.datetime.now()
        destino = (self.case.dirs["network"] /
                   f"Comentarios_{sitio}_{ts:%Y%m%d_%H%M%S}.txt")
        try:
            with open(destino, "w", encoding="utf-8") as f:
                f.write(f"COMENTARIOS DE PUBLICACION - {sitio}\n")
                f.write(f"Caso        : {self.case.case_id}\n")
                f.write(f"Momento     : {ts.isoformat()}\n")
                f.write(f"Publicacion : {u_pagina or u}\n")
                f.write(f"Comentarios : {len(comentarios)}\n")
                estado_txt = ("recorrido interrumpido por el perito"
                              if w.get("interrumpido") else "recorrido hasta el final")
                f.write(f"Estado      : {estado_txt}\n")
                if sitio == "Instagram":
                    f.write("Fechas      : tomadas del atributo datetime de la pagina (UTC\n")
                    f.write("              exacto), no del texto relativo en pantalla.\n")
                elif sitio == "Facebook":
                    f.write("Fechas      : tomadas del rotulo de accesibilidad del enlace de\n")
                    f.write("              hora, que publica la fecha y hora completas, no\n")
                    f.write("              del texto relativo en pantalla.\n")
                else:
                    f.write("Fechas      : TikTok no publica el instante exacto de cada\n")
                    f.write("              comentario en ninguna parte de la pagina. Se\n")
                    f.write("              transcribe la unica marca que expone, que es\n")
                    f.write("              parcial o relativa. La limitacion es de la\n")
                    f.write("              plataforma y no del relevamiento.\n")
                f.write("Respuestas  : las respuestas plegadas NO se desplegaron; se deja\n")
                f.write(f"              constancia de las que la pagina declaro ({plegadas}).\n")
                f.write("=" * 70 + "\n\n")

                if desc:
                    f.write("DESCRIPCION DE LA PUBLICACION\n")
                    f.write(f"  Autor : @{desc.get('autor', '')}\n")
                    f.write(f"  Fecha : {desc.get('fecha', '')}  "
                            f"({desc.get('fecha_vista', '')})\n")
                    if desc.get("marcas"):
                        f.write(f"  Marcas: {desc.get('marcas')}\n")
                    f.write(f"  Texto : {desc.get('texto', '')}\n\n")
                    f.write("=" * 70 + "\n\n")

                f.write("COMENTARIOS\n\n")
                for i, c in enumerate(comentarios, 1):
                    quien = c.get("autor", "")
                    perfil = c.get("perfil", "")
                    if perfil and perfil != quien:
                        quien = f"{quien} ({perfil})"
                    extra = []
                    if c.get("megusta"):
                        extra.append(f"{c['megusta']} me gusta")
                    if c.get("respuestas"):
                        extra.append(f"{c['respuestas']} respuestas plegadas")
                    if c.get("marcas"):
                        extra.append(c["marcas"])
                    f.write(f"{i:5}. @{quien} | {c.get('fecha', '')} | "
                            f"{'; '.join(extra)}\n")
                    f.write(f"       {c.get('texto', '')}\n\n")
        except Exception as e:
            registrar_fallo_critico("INSTAGRAM", f"No se pudieron guardar los comentarios: {e}")
            return

        registrar_archivo_caso(
            self.case, destino, "COMENTARIOS",
            {"Sitio": sitio,
             "Comentarios registrados": str(len(comentarios)),
             "Descripcion de la publicacion": ("si" if desc else "no"),
             "Respuestas plegadas sin desplegar": str(plegadas),
             "Capturas de respaldo": str(w["capturas"]),
             "Capturas con la vista aun cargando": str(w.get("capturas_parciales", 0)),
             "Estado": ("recorrido INTERRUMPIDO por el perito"
                        if w.get("interrumpido") else "recorrido hasta el final"),
             "Origen": "texto y fechas publicados por la propia pagina"},
            source_url=w.get("url", ""))
        self.append_console(f"  Listado                 : {destino.name}")
        if plegadas:
            self.append_console(f"  Respuestas plegadas     : {plegadas} "
                                f"(no desplegadas, declaradas)")
        self.append_console("-" * 60)
        self.case.log("INFO", "COMENTARIOS",
                      f"Comentarios de {sitio} {estado} | {len(comentarios)} comentarios | "
                      f"{w['capturas']} capturas | {w['tramo']} tramos | "
                      f"{plegadas} respuestas plegadas")

    def _on_download_requested(self, download: QWebEngineDownloadRequest):
        # Intercepta el boton nativo "Download" de WhatsApp Web y otros sitios
        import re as _re
        ts        = datetime.datetime.now().strftime("%H%M%S")
        # Sanitizar el nombre sugerido por el servidor para prevenir path traversal.
        # suggestedFileName() puede contener "../", componentes de directorio o
        # caracteres especiales enviados por un sitio malicioso.
        _raw      = download.suggestedFileName() or f"WhatsApp_{ts}"
        _safe     = Path(_raw).name                          # descartar directorios
        _safe     = _re.sub(r'[^\w.\-]', '_', _safe)[:80]   # solo alfanum + . -
        suggested = _safe or f"archivo_{ts}"

        # Una descarga que el programa no pidio no entra sola a la evidencia.
        # Hasta ahora se aceptaba todo lo que llegaba: una pagina podia meter
        # un archivo en la carpeta del caso sin intervencion de nadie, y el
        # archivo quedaba registrado con hash y acta como si el perito lo
        # hubiera adquirido. Ahora decide el perito, y la decision queda en el
        # log con el origen de la descarga.
        if not descarga_del_programa(getattr(self, "_pagina_pendiente", None),
                                     getattr(self, "_wa", {}).get("activo")):
            origen = download.url().toString()
            resp = QMessageBox.question(
                self, "Descarga iniciada por la pagina",
                f"La pagina pidio descargar un archivo:\n\n"
                f"   {suggested}\n   desde {origen[:110]}\n\n"
                "No es una descarga del programa. ¿Incorporarla a la evidencia?\n\n"
                "Si usted no la pidio, conviene rechazarla: una pagina puede\n"
                "iniciar descargas sin que nadie haga clic.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if resp != QMessageBox.StandardButton.Yes:
                download.cancel()
                self.case.log("ADVERTENCIA", "DOWNLOAD",
                              f"Descarga rechazada por el perito: {suggested} | origen: {origen}")
                self.append_console(f"Descarga rechazada: {suggested}")
                return
            self.case.log("INFO", "DOWNLOAD",
                          f"Descarga aceptada por el perito: {suggested} | origen: {origen}")

        # La pagina completa que archiva el programa entra por aca, porque el
        # motor la entrega como una descarga. Se la reconoce por el aviso que
        # dejo _guardar_pagina_completa, para que conserve su nombre y quede
        # registrada como pagina archivada y no como una descarga cualquiera.
        _pend = getattr(self, "_pagina_pendiente", None)
        es_pagina = bool(_pend)
        if es_pagina:
            self._pagina_pendiente = None
            dest_name = _pend["nombre"]
            suggested = dest_name
            # Cada descarga avisada dice de que tipo es. Antes todas quedaban
            # como pagina archivada, y por eso la foto de perfil no figuraba
            # como imagen ni salia reproducida en el dictamen.
            tipo_avisado = _pend.get("tipo", "PAGINA_ARCHIVADA")
            extra_avisado = _pend.get("extra", {})
        else:
            dest_name = f"WA_Download_{ts}_{suggested}"
        dest_path = str(self.case.dirs["evidence_raw"] / dest_name)
        download.setDownloadDirectory(str(self.case.dirs["evidence_raw"]))
        download.setDownloadFileName(dest_name)
        download.accept()
        self.case.log("INFO", "DOWNLOAD", f"Descarga nativa iniciada: {suggested} -> {dest_path}")
        self.append_console(f"Descarga nativa iniciada: {suggested}")

        # Se conserva una referencia al objeto de descarga y se lleva la cuenta
        # de las que estan en curso.
        #
        # Sin la referencia, Qt puede destruir el objeto antes de que emita el
        # fin: el archivo queda en disco y nunca se le calcula el hash ni se
        # levanta el acta, o sea que queda sin valor probatorio. La cuenta es
        # la que permite descargar de a un archivo por vez, que es la unica
        # forma de que no se pierdan cuando se piden varios seguidos.
        self._descargas_activas = getattr(self, "_descargas_activas", 0) + 1
        # Contador que solo sube: sirve para saber si una descarga concreta
        # llego a empezar, cosa que la cuenta de activas no permite ver.
        self._descargas_iniciadas = getattr(self, "_descargas_iniciadas", 0) + 1
        if not hasattr(self, "_descargas_ref"):
            self._descargas_ref = {}
        self._descargas_ref[id(download)] = download

        def on_finished():
            if not download.isFinished():
                return
            self._descargas_activas = max(0, getattr(self, "_descargas_activas", 1) - 1)
            self._descargas_ref.pop(id(download), None)
            if download.state() == QWebEngineDownloadRequest.DownloadState.DownloadCompleted:
                # Generar sidecar de custodia igual que todas las otras vías
                # de adquisición (cadena de custodia completa).
                # Un .enc es el archivo tal como viaja por la red de WhatsApp:
                # cifrado extremo a extremo con una clave que esta en el
                # telefono de origen. Se guarda igual, porque es lo que se
                # obtuvo, pero no puede figurar como una pieza mas: sin
                # descifrar no se abre, no se reproduce y no prueba nada.
                cifrado = suggested.lower().endswith(".enc")
                if es_pagina:
                    tipo_ev = tipo_avisado
                elif cifrado:
                    tipo_ev = "WA_DOWNLOAD_CIFRADO"
                else:
                    tipo_ev = "WA_DOWNLOAD"

                if es_pagina:
                    extra = dict(extra_avisado) if extra_avisado else {
                        "metodo": "archivado MHTML del motor del navegador",
                        "contenido": "pagina completa con sus recursos embebidos",
                        "apertura": "navegador web (Chrome, Edge)"}
                    extra["origen"] = (_pend or {}).get("url", "")
                else:
                    extra = {"metodo": "browser_native_download",
                             "archivo_sugerido": suggested}
                    if cifrado:
                        extra["ADVERTENCIA"] = ("Archivo cifrado E2E (.enc): "
                                                "no es legible ni reproducible")

                sid = write_custody_sidecar(
                    path       = dest_path,
                    tipo       = tipo_ev,
                    source_url = ((_pend or {}).get("url", "") if es_pagina else
                                  (download.url().toString() if hasattr(download, "url") else "")),
                    perito     = self.perito_data,
                    case_id    = self.case.case_id,
                    extra      = extra,
                )
                size_kb = sid["size"] / 1024
                ev = self.case.register_evidence(tipo_ev, dest_path)
                if es_pagina:
                    self.case.log("INFO", "ACREDITACION",
                        f"{tipo_ev} | {dest_name} | {size_kb:.1f} KB | "
                        f"SHA-256: {sid['sha256'][:24]}...")
                    log_signals.log_msg.emit(
                        f"  {dest_name}  ({size_kb:.1f} KB)  SHA-256 {sid['sha256'][:20]}...")
                elif cifrado:
                    self.case.log("ADVERTENCIA", "DOWNLOAD",
                        f"Descarga cifrada | {suggested} | {size_kb:.1f} KB | "
                        f"SHA-256: {sid['sha256'][:24]}...")
                    registrar_fallo_critico(
                        "DOWNLOAD",
                        f"Se descargo {suggested}, cifrado extremo a extremo. WhatsApp no "
                        f"entrego el archivo descifrado: revisar que el perfil del "
                        f"navegador tenga almacenamiento persistente")
                    log_signals.log_msg.emit(
                        f"⚠ CIFRADO (.enc): {dest_name} | {size_kb:.1f} KB | "
                        f"no es reproducible")
                else:
                    self.case.log("INFO", "DOWNLOAD",
                        f"WA_DOWNLOAD OK | {suggested} | {size_kb:.1f} KB | SHA-256: {sid['sha256'][:24]}...")
                    log_signals.log_msg.emit(
                        f"✓ WA_DOWNLOAD OK: {dest_name} | {size_kb:.1f} KB | Hash: {sid['sha256'][:20]}...")
            else:
                self.case.log("ERROR", "DOWNLOAD", f"Descarga fallida: {suggested}")
                log_signals.log_msg.emit(f"✗ FALLO descarga nativa: {suggested}")

        download.isFinishedChanged.connect(on_finished)

    def generate_report(self, zip_info: Optional[Dict] = None):
        """
        Genera el dictamen PDF forense.

        zip_info: si se provee (desde exit_and_package), agrega antes de la firma
        una leyenda con el nombre y SHA-256 del paquete ZIP del caso.
        Cuando es None se comporta igual que antes (botón GENERAR DICTAMEN).
        """
        if self.is_recording:
            self.toggle_recording()

        # Si el hilo de transcodificación (mux) todavía está corriendo,
        # esperar hasta 310s para que registre el video antes de contar evidencias.
        mux = getattr(self, "_mux_thread", None)
        if mux is not None and mux.is_alive():
            self.append_console("⏳ Esperando finalización del procesamiento de video antes de generar el informe...")
            mux.join(timeout=310)

        ts_gen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Cierre firmado del log al emitir el dictamen: el extremo de la cadena
        # que se transcribe en la seccion de logs corresponde a una firma
        # guardada, y verificar_caso.py puede comprobarla.
        self.case.flush_network_log()
        _cierre_dictamen = self.case.firmar_cabeza("al emitir el dictamen")
        h_db = sha256_file(str(self.case.db_path))
        # Guardar HAR antes de calcular su hash para que el dictamen
        # siempre certifique la totalidad del tráfico de red capturado.
        self.case.save_har()
        h_har = sha256_file(str(self.case.har_path))

        pc_name = socket.gethostname()
        try:
            pc_ip = socket.gethostbyname(pc_name)
        except Exception:
            pc_ip = "N/A"
        # os.getlogin() falla sin terminal de control (UAC, SYSTEM, etc.)
        pc_user = os.environ.get("USERNAME") or os.environ.get("USER") or "N/A"
        pc_os = get_windows_version()

        cant_img    = sum(1 for e in self.case.evidences if e["tipo"] == "CAPTURA_PANTALLA")
        cant_vid    = sum(1 for e in self.case.evidences if e["tipo"] == "VIDEO_SESION")
        _TIPOS_MEDIA = {"MEDIA_ADQUIRIDA", "DESCARGA_NATIVA", "WA_DOWNLOAD"}
        cant_media  = sum(1 for e in self.case.evidences if e["tipo"] in _TIPOS_MEDIA)
        cant_perfiles = sum(1 for e in self.case.evidences if e["tipo"] == "CAPTURA_PERFIL")
        cant_html   = sum(1 for e in self.case.evidences
                          if os.path.splitext(e.get("filename", "").lower())[1] in HTML_EXTS)

        cant_total = len(self.case.evidences)

        # Cargar perfiles capturados para sección dedicada en el PDF
        profiles_path = self.case.dirs["network"] / "profiles_captured.json"
        _perfiles_pdf: list = []
        try:
            if profiles_path.exists():
                with open(profiles_path, "r", encoding="utf-8") as _pf:
                    _perfiles_pdf = json.load(_pf)
        except Exception:
            pass

        pdf = DictamenForense()

        # Copias reducidas que se insertan en el informe; se borran al final.
        temp_thumbs: List[str] = []
        dir_temp = self.case.dirs["thumbs"]
        pdf.set_margins(10, 10, 10)
        pdf.set_auto_page_break(True, margin=15)

        pdf.cover_page(self.case.case_data, ts_gen, self.case.case_id, self.perito_data)

        pdf.add_page()
        pdf.section_title("i", "METADATOS DEL INFORME - CADENA DE CUSTODIA")
        # El manifiesto de la herramienta va dentro del paquete: permite
        # comparar archivo por archivo contra el oficial de la version.
        _conj = hash_de_la_herramienta()
        if _conj.get("manifiesto"):
            (self.case.dirs["report"] / "herramienta_archivos.sha256").write_text(
                _conj["manifiesto"], encoding="utf-8", newline="\n")
            _txt_conj = (f"{_conj['conjunto']}   ({_conj['archivos']} archivos, "
                         f"{_conj.get('modo')}; detalle en report/herramienta_archivos.sha256)")
        else:
            _txt_conj = f"NO CALCULADO: {_conj.get('error', 'causa desconocida')}"
        # Contraste del reloj con la hora firmada por la autoridad de sellado.
        # A diferencia del NTP, esa hora no se puede falsear en el camino.
        _ch = next((c["contraste_hora"] for c in (self.case.diagnostico or [])
                    if c.get("contraste_hora")), None)
        if _ch:
            _txt_reloj = (f"{_ch['desfase_s']:+.2f} s (margen {_ch['margen_s']:.2f} s), segun el "
                          f"sello de {_ch['autoridad']} del {_ch['hora_firmada']}")
            _ntp = self.case.ntp_info.get("offset_segundos")
            if _ntp is not None and abs(_ntp - _ch["desfase_s"]) > _ch["margen_s"] + 2:
                _txt_reloj += (f". AVISO: la consulta NTP informo {_ntp:+.2f} s; no coincide con "
                               f"la hora firmada, que es la que se toma como referencia")
        else:
            _txt_reloj = "no se pudo contrastar: ninguna autoridad de sellado respondio"
        meta_rows = [
            ("Herramienta", f"{SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}"),
            ("Desarrollador software", f"{AUTOR_SISTEMA['nombre']} | {AUTOR_SISTEMA['empresa']}"),
            ("Perito actuante", f"{self.perito_data.get('nombre','')} - {self.perito_data.get('titulo','')}"),
            ("Empresa / Estudio", self.perito_data.get('empresa','')),
            ("Email perito", self.perito_data.get('email','')),
            ("LinkedIn perito", self.perito_data.get('linkedin','')),
            ("Matricula", self.perito_data.get('matricula','N/A')),
            ("Licencia", "Codigo Abierto (Open Source)"),
            ("Norma", f"{SOFTWARE_INFO['norma']}"),
            ("Case ID", self.case.case_id),
            ("Equipo peritador", f"{pc_name} | Usuario: {pc_user} | IP: {pc_ip}"),
            ("Sistema operativo", pc_os),
            ("SHA-256 del ejecutable", get_self_hash()),
            ("SHA-256 del conjunto instalado", _txt_conj),
            ("Motor del navegador", version_motor()),
            ("Fecha de generacion", ts_gen),
            ("Fuente de tiempo NTP", self.case.ntp_info.get("servidor", "N/A")),
            ("Offset reloj local",   self.case.ntp_info.get("offset_legible",
                                     "No sincronizado — " + self.case.ntp_info.get("error",""))),
            ("Hora NTP UTC",         self.case.ntp_info.get("hora_ntp_utc", "N/A")),
            ("Reloj contra hora firmada", _txt_reloj),
        ]
        for i, (k, v) in enumerate(meta_rows):
            pdf.tabla_fila(k, v, i)

        # Nota de autor del sistema
        pdf.ln(3)
        pdf.set_font(FUENTE_INFORME, "I", 8)
        pdf.set_text_color(100, 100, 100)
        pdf.cuerpo_texto(
            f"NOTA: El presente software fue desarrollado por {AUTOR_SISTEMA['nombre']} "
            f"({AUTOR_SISTEMA['titulo']}), {AUTOR_SISTEMA['empresa']}. "
            f"Contacto: {AUTOR_SISTEMA['email']} | {AUTOR_SISTEMA['linkedin']}"
        )
        pdf.set_text_color(0, 0, 0)

        pdf.section_title("2", "ESTADISTICAS DE LA DILIGENCIA")
        stats = [
            ("Total evidencias", str(cant_total)),
            ("Capturas de pantalla", str(cant_img)),
            ("Videos de sesion", str(cant_vid)),
            ("Archivos media", str(cant_media)),
            ("Paginas web archivadas (HTML/MHTML)", str(cant_html)),
            ("Perfiles sociales capturados", str(cant_perfiles)),
            ("Logs de auditoria", "SQLite append-only + HAR v1.2"),
            # Un campo vacio se muestra como guion y no en blanco: en blanco
            # no se distingue de un campo que el informe se olvido de incluir.
            ("Expediente", self.case.case_data.get('exp') or '-'),
            ("Juzgado / Tribunal", self.case.case_data.get('juz') or '-'),
            ("Caratula", self.case.case_data.get('car') or '-'),
            ("Escribano / Notario", self.case.case_data.get('esc') or '-'),
            ("   Registro / Matricula", self.case.case_data.get('esc_reg') or '-'),
            ("   Colegio / Jurisdiccion", self.case.case_data.get('esc_col') or '-'),
            # El objeto de la pericia delimita el alcance de lo actuado: es lo
            # primero que se contrasta al leer un dictamen, y figuraba solo en
            # la caratula.
            ("Objeto de la pericia", self.case.case_data.get('obj') or '-'),
        ]
        for i, (k, v) in enumerate(stats):
            pdf.tabla_fila(k, v, i)

        # SECCIÓN DE PERFILES DE REDES SOCIALES
        if _perfiles_pdf:
            pdf.add_page()
            pdf.section_title("P", "PERFILES DE REDES SOCIALES IDENTIFICADOS")
            pdf.cuerpo_texto(
                "Se detallan a continuacion los perfiles de redes sociales identificados "
                "durante la diligencia mediante la funcion de captura de perfil. "
                "Cada perfil incluye el identificador publico (usuario/handle), "
                "el UID numerico interno de la plataforma, el email de contacto publico "
                "cuando esta disponible, la URL exacta visitada y el timestamp de la captura. "
                "La captura de pantalla asociada figura en el Registro de Evidencias."
            )
            for idx_p, perf in enumerate(_perfiles_pdf):
                pdf.ln(3)
                plat_label = sanitize_text(perf.get("plataforma", ""))
                usr_label  = sanitize_text(perf.get("profile_id", ""))
                pdf.set_fill_color(13, 71, 161)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font(FUENTE_INFORME, "B", 9)
                pdf.cell(
                    0, 7,
                    sanitize_text(f"  Perfil {idx_p + 1}  |  {plat_label}  |  @{usr_label}"),
                    fill=True, border=0,
                    new_x=XPos.LMARGIN, new_y=YPos.NEXT
                )
                pdf.set_text_color(0, 0, 0)

                uid   = perf.get("uid_numerico", "") or "No obtenido"
                email = perf.get("email", "")        or "No encontrado / No publico"
                filas_p = [
                    ("Plataforma",       perf.get("plataforma", "")),
                    ("Usuario / Handle", f"@{perf.get('profile_id', '')}"),
                    ("UID Numerico",     uid),
                    ("Email publico",    email),
                    ("URL del perfil",   perf.get("url", "")[:100]),
                    ("Timestamp",        perf.get("ts_legible", "")),
                    ("Perito actuante",  perf.get("perito", "")),
                ]
                for fi, (k, v) in enumerate(filas_p):
                    pdf.tabla_fila(k, sanitize_text(v), fi, w_label=50)

                # Ficha visual con los datos extraídos (imagen generada al capturar)
                ficha_p = perf.get("ficha_path", "")
                if ficha_p and os.path.exists(ficha_p):
                    pdf.ln(2)
                    pdf.set_font(FUENTE_INFORME, "B", 8)
                    pdf.set_text_color(13, 71, 161)
                    pdf.cell(0, 5, sanitize_text("  Ficha de datos capturados:"),
                             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(0, 0, 0)
                    pdf.miniatura(ficha_p,
                                  caption=f"Datos extraidos del perfil @{usr_label} en {plat_label}",
                                  max_w_mm=150, max_h_mm=95,
                                  temp_dir=dir_temp, temporales=temp_thumbs)

                # Buscar y mostrar la captura de pantalla tomada justo después de este perfil
                # (la que tiene timestamp más cercano al del perfil)
                import datetime as _dt
                try:
                    ts_perf = _dt.datetime.fromisoformat(perf.get("ts", ""))
                except Exception:
                    ts_perf = None

                cap_asociada = None
                if ts_perf:
                    candidatas = [
                        e for e in self.case.evidences
                        if e["tipo"] == "CAPTURA_PANTALLA" and os.path.exists(e["path"])
                    ]
                    mejor_delta = None
                    for cap in candidatas:
                        try:
                            ts_cap = _dt.datetime.fromisoformat(cap["ts"])
                            delta  = abs((ts_cap - ts_perf).total_seconds())
                            # Captura dentro de los 30 segundos posteriores al perfil
                            if (ts_cap >= ts_perf) and delta <= 30:
                                if mejor_delta is None or delta < mejor_delta:
                                    mejor_delta  = delta
                                    cap_asociada = cap
                        except Exception:
                            pass

                if cap_asociada:
                    pdf.ln(2)
                    pdf.set_font(FUENTE_INFORME, "B", 8)
                    pdf.set_text_color(46, 125, 50)
                    pdf.cell(0, 5,
                             sanitize_text(f"  Captura de pantalla asociada: {cap_asociada['filename']}"),
                             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(0, 0, 0)
                    pdf.miniatura(cap_asociada["path"],
                                  caption=f"Perfil @{usr_label} en {plat_label} — {perf.get('ts_legible','')}",
                                  max_w_mm=160, max_h_mm=90,
                                  temp_dir=dir_temp, temporales=temp_thumbs)

        pdf.add_page()
        pdf.section_title("F", "REGISTRO DE EVIDENCIAS Y CERTIFICACION DE INTEGRIDAD")
        pdf.cuerpo_texto(
            "Cada evidencia se registra con timestamp ISO 8601, hash SHA-256 certificado, "
            "sello de tiempo RFC 3161 (cuando disponible) y ruta de almacenamiento. "
            "Las miniaturas muestran: imagenes originales, primer cuadro de videos validos, "
            "e icono de parlante para archivos de audio. Si un video no puede leerse "
            "(archivo cifrado .enc, codec no soportado, o moov atom corrupto), "
            "se indica 'Miniatura no disponible'. "
            "Verificacion: certutil -hashfile <archivo> SHA256 (Windows) o sha256sum <archivo> (Linux)."
        )
        pdf.ln(3)

        for i, ev in enumerate(self.case.evidences):
            if pdf.get_y() > 210:
                pdf.add_page()

            pdf.set_fill_color(232, 245, 233)
            pdf.set_font(FUENTE_INFORME, "B", 9)
            pdf.cell(0, 6, sanitize_text(f"  Evidencia {i+1} | {ev['tipo']} | {ev['ts']}"), fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font(FUENTE_INFORME, "", 8)
            pdf.cell(0, 5, sanitize_text(f"  Archivo: {ev['filename']} | {ev['size_bytes']/1024:.1f} KB"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.bloque_hash("  Hash SHA-256:", ev['sha256'])
            if ev.get('source_url'):
                pdf.set_font(FUENTE_INFORME, "I", 7)
                pdf.cell(0, 4, sanitize_text(f"  URL origen: {ev['source_url'][:100]}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            thumb_path = None
            thumb_caption = ""
            is_audio_icon = False
            ev_path = ev['path']
            ev_lower = ev_path.lower()
            ext = os.path.splitext(ev_lower)[1]

            if ev['tipo'] == "CAPTURA_PANTALLA" and os.path.exists(ev_path):
                thumb_path = ev_path
                thumb_caption = "Miniatura de captura de pantalla"

            elif ev['tipo'] == "CAPTURA_PAGINA_COMPLETA" and os.path.exists(ev_path):
                thumb_path = ev_path
                thumb_caption = "Pagina completa, recorrida con scroll y unida en una imagen"

            elif ev['tipo'] == "FOTO_PERFIL" and os.path.exists(ev_path):
                thumb_path = ev_path
                thumb_caption = "Foto de perfil, en la resolucion que sirve la plataforma"

            elif ev['tipo'] == "CAPTURA_LISTA" and os.path.exists(ev_path):
                thumb_path = ev_path
                thumb_caption = "Captura de la lista de contactos"

            elif ev['tipo'] == "CAPTURA_COMENTARIOS" and os.path.exists(ev_path):
                thumb_path = ev_path
                thumb_caption = "Captura del panel de comentarios de la publicacion"

            elif ev['tipo'] == "FICHA_PERFIL" and os.path.exists(ev_path):
                thumb_path = ev_path
                thumb_caption = "Ficha visual de datos del perfil capturado"

            elif ev['tipo'] == "VIDEO_SESION" and os.path.exists(ev_path):
                if is_valid_video(ev_path):
                    frame_path = extract_video_frame(ev_path, self.case.dirs["thumbs"])
                    if frame_path:
                        thumb_path = frame_path
                        temp_thumbs.append(frame_path)
                        thumb_caption = "Primer cuadro del video de sesion"
                    else:
                        pdf.miniatura_no_disponible("Video valido pero frame no extraible")
                else:
                    pdf.miniatura_no_disponible("Video no legible (codec no soportado o archivo corrupto)")

            elif ext in HTML_EXTS and os.path.exists(ev_path):
                # Página web archivada (HTML/MHTML): no genera miniatura de imagen,
                # pero se certifica el código fuente completo preservado.
                pdf.set_font(FUENTE_INFORME, "B", 8)
                pdf.set_text_color(13, 71, 161)
                pdf.cell(0, 5, sanitize_text(
                    "  Pagina web archivada (HTML/MHTML) — codigo fuente completo preservado"),
                    new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font(FUENTE_INFORME, "I", 7)
                pdf.set_text_color(90, 90, 90)
                pdf.cell(0, 4, sanitize_text(
                    "  Apertura: navegador web (Chrome/Edge). Contenido, estructura y recursos "
                    "embebidos conservados en un unico archivo."),
                    new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)

            elif ev['tipo'] in ("MEDIA_ADQUIRIDA", "WA_DOWNLOAD") and os.path.exists(ev_path):
                if ext in AUDIO_EXTS:
                    icon_path = generate_speaker_icon(self.case.dirs["thumbs"])
                    if icon_path:
                        thumb_path = icon_path
                        temp_thumbs.append(icon_path)
                        thumb_caption = "Archivo de audio (icono representativo)"
                        is_audio_icon = True
                    else:
                        pdf.miniatura_no_disponible("Icono de audio no generable")
                elif ext in VIDEO_EXTS:
                    if is_valid_video(ev_path):
                        frame_path = extract_video_frame(ev_path, self.case.dirs["thumbs"])
                        if frame_path:
                            thumb_path = frame_path
                            temp_thumbs.append(frame_path)
                            thumb_caption = "Primer cuadro del video adquirido"
                        else:
                            pdf.miniatura_no_disponible("Video valido pero frame no extraible")
                    else:
                        pdf.miniatura_no_disponible("Video no legible (corrupto o codec no soportado)")
                elif ext in IMAGE_EXTS:
                    thumb_path = ev_path
                    thumb_caption = "Miniatura de imagen adquirida"
                else:
                    pdf.miniatura_no_disponible(f"Formato no soportado para miniatura ({ext})")

            # Evidencia Instagram

            if thumb_path and os.path.exists(thumb_path):
                if is_audio_icon:
                    # Un simbolo, no una miniatura: no muestra contenido del
                    # archivo, solo indica de que tipo es. A 40 mm ocupaba mas
                    # espacio que las capturas que si tienen algo que mostrar.
                    pdf.miniatura(thumb_path, thumb_caption, max_w_mm=18, max_h_mm=18,
                                  temp_dir=dir_temp, temporales=temp_thumbs)
                elif (ev["tipo"] in TIPOS_CON_ANEXO_DE_VISTAS
                      and thumb_path == ev_path):
                    # Ver TIPOS_CON_ANEXO_DE_VISTAS: esta imagen va entera mas
                    # adelante, asi que aca alcanza con una miniatura que
                    # permita reconocerla.
                    pdf.miniatura(thumb_path,
                                  thumb_caption + " - se reproduce completa en el anexo de vistas",
                                  max_w_mm=45, max_h_mm=32,
                                  temp_dir=dir_temp, temporales=temp_thumbs)
                else:
                    pdf.miniatura(thumb_path, thumb_caption, max_w_mm=140, max_h_mm=80,
                                  temp_dir=dir_temp, temporales=temp_thumbs)

            tsa_info = ev.get('tsa', {})
            if tsa_info and 'token_b64' in tsa_info:
                # Se consigna la autoridad que emitio el sello: con la cascada
                # puede no ser la primera de la lista, y el tribunal debe saber
                # quien certifico la fecha.
                pdf.set_font(FUENTE_INFORME, "I", 7)
                pdf.set_text_color(46, 125, 50)
                _aut = tsa_info.get('tsa_nombre') or tsa_info.get('tsa_url', '')
                _verif = ", firma verificada" if tsa_info.get("verificado") else ""
                pdf.cell(0, 4, sanitize_text(
                    f"  ✓ Sello de tiempo RFC 3161{_verif}: {tsa_info.get('timestamp_iso','OK')}"
                    f"   |   Autoridad: {_aut}"),
                    new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
            elif tsa_info and ('warning' in tsa_info or 'error' in tsa_info):
                pdf.set_font(FUENTE_INFORME, "I", 7)
                pdf.set_text_color(180, 100, 0)
                _msg = tsa_info.get('warning') or tsa_info.get('error', '')
                pdf.cell(0, 4, sanitize_text(f"  ⚠ Sin sello de tiempo: {_msg}"),
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
            pdf.ln(2)

        # SECCION: VERIFICACION DE INTEGRIDAD DEL CODIGO
        if self.case.bt_verifications:
            pdf.add_page()
            pdf.section_title("V", "VERIFICACION DE INTEGRIDAD DEL CODIGO (BINARY TRANSPARENCY)")
            pdf.cuerpo_texto(
                "Los portales de Meta publican en la propia pagina un manifiesto que contiene el "
                "hash SHA-256 de cada script autorizado de esa version del sitio, junto con un "
                "hash combinado que resume la totalidad del conjunto. De forma independiente, "
                "Cloudflare publica el hash raiz de esa misma version en su servicio de "
                "auditabilidad (api.privacy-auditability.cloudflare.com), actuando como tercero "
                "de confianza ajeno a Meta. Es el mismo mecanismo de transparencia de codigo que "
                "emplea la herramienta oficial Code Verify (Meta, licencia MIT)."
            )
            pdf.cuerpo_texto(
                "ALCANCE DE LA VERIFICACION REALIZADA: durante la presente diligencia se "
                "contrasto el hash combinado declarado por cada portal contra el hash raiz "
                "publicado por dicho tercero independiente. Un resultado VERIFICADO acredita que "
                "el inventario de codigo declarado por el sitio es autentico y corresponde a una "
                "version efectivamente publicada por Meta, no habiendo sido sustituido ni "
                "fabricado. Se deja constancia de que la presente comprobacion opera a nivel del "
                "manifiesto y no comprende la verificacion individual del contenido de cada uno "
                "de los scripts cargados contra su respectivo hash, extremo que excede el alcance "
                "de esta diligencia. Los hashes consignados a continuacion permiten a cualquier "
                "tercero reproducir y auditar esta verificacion de forma independiente."
            )
            pdf.ln(2)
            for idx_v, ver in enumerate(self.case.bt_verifications):
                res = ver.get("resultado", "")
                if res == "VERIFICADO":
                    color, etiqueta = (46, 125, 50), "VERIFICADO"
                elif res == "DISCREPANCIA":
                    color, etiqueta = (198, 40, 40), "DISCREPANCIA - ALERTA"
                else:
                    color, etiqueta = (180, 100, 0), res
                pdf.set_fill_color(*color)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font(FUENTE_INFORME, "B", 9)
                pdf.cell(0, 7, sanitize_text(
                    f"  Verificacion {idx_v + 1}  |  {ver.get('dominio','')}  |  {etiqueta}"),
                    fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
                filas_v = [
                    ("Portal verificado",        ver.get("dominio", "")),
                    ("Version del codigo",       ver.get("version", "")),
                    ("Scripts declarados",       f"{ver.get('cant_scripts', 0):,}"),
                    ("Hash segun el portal",     ver.get("hash_pagina", "")),
                    ("Hash segun Cloudflare",    ver.get("hash_cloudflare", "") or "(no disponible)"),
                    ("Fuente independiente",     ver.get("fuente_externa", "")),
                    ("Resultado",                etiqueta),
                    ("Momento de la verificacion", ver.get("ts_legible", "")),
                ]
                for fi, (k, v) in enumerate(filas_v):
                    pdf.tabla_fila(k, sanitize_text(str(v)), fi, w_label=52)
                pdf.ln(3)

            # Fuentes de la metodologia: permiten que cualquier tercero
            # compruebe de donde sale el mecanismo y lo reproduzca.
            pdf.ln(2)
            pdf.set_fill_color(13, 71, 161)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font(FUENTE_INFORME, "B", 9)
            pdf.cell(0, 7, sanitize_text("  ORIGEN DE LA METODOLOGIA APLICADA"),
                     fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
            pdf.cuerpo_texto(
                "El procedimiento de verificacion empleado no es de elaboracion propia: reproduce "
                "el mecanismo de transparencia de codigo que Meta Platforms implemento para sus "
                "portales web y documento publicamente, y que la propia empresa distribuye como "
                "software libre. Se consignan las fuentes para que cualquier tercero pueda "
                "constatar su existencia y reproducir la verificacion de manera independiente."
            )
            # Cada valor se mantiene en una sola linea: al partirse, multi_cell
            # justifica el texto y las URLs quedan con huecos entre palabras.
            fuentes = [
                ("Metodologia",            "Transparencia de codigo (binary transparency) de Meta Platforms"),
                ("Publicacion original",   "Meta Engineering, 10 de marzo de 2022"),
                ("Documentacion tecnica",  "engineering.fb.com/2022/03/10/security/code-verify/"),
                ("Codigo fuente oficial",  "github.com/facebookincubator/meta-code-verify (licencia MIT)"),
                ("Verificador de terceros", "Cloudflare - api.privacy-auditability.cloudflare.com"),
                ("Algoritmo de hash",      "SHA-256 (NIST FIPS 180-4)"),
            ]
            for fi, (k, v) in enumerate(fuentes):
                pdf.tabla_fila(k, sanitize_text(v), fi, w_label=52)

        # SECCION: ADQUISICION DE WHATSAPP WEB
        #
        # Se detalla el procedimiento porque no es evidente: la aplicacion
        # cifra el multimedia extremo a extremo y hay que dejar constancia de
        # como se obtuvo cada pieza y de que no se altero su contenido.
        resumenes = getattr(self, "_wa_resumen", [])
        if resumenes:
            pdf.add_page()
            pdf.section_title("W", "ADQUISICION DE WHATSAPP WEB")
            pdf.cuerpo_texto(
                "El multimedia de WhatsApp viaja cifrado extremo a extremo (AES-256-CBC con "
                "derivacion HKDF-SHA256) y no puede descifrarse fuera de la aplicacion: la clave "
                "reside en el dispositivo de origen. Por ese motivo NO se descargaron los archivos "
                ".enc desde los servidores, ni se intento descifrarlos por medios propios. Cada "
                "pieza se solicito a la propia aplicacion, por la opcion Descargar de su menu de "
                "mensaje, que es la via prevista para el usuario. El archivo entregado por "
                "WhatsApp se recibio en el navegador del programa, que le calculo el hash SHA-256 "
                "y levanto su acta de custodia sin intervenir en su contenido."
            )
            pdf.ln(1)
            pdf.cuerpo_texto(
                "Dos situaciones requirieron un tratamiento distinto, que se detalla por "
                "transparencia. Los archivos de video: se constato que la aplicacion los descifra "
                "y los deja disponibles en la pagina, pero no completa su entrega al navegador. En "
                "esos casos el programa tomo el archivo ya descifrado que la propia aplicacion "
                "habia preparado. Los stickers: la aplicacion no ofrece descargarlos, y se "
                "exportaron desde la pagina, donde figuran ya descifrados. En ambos casos el "
                "contenido es el que produjo WhatsApp, byte por byte; lo unico que aporto el "
                "programa fue el destino del archivo."
            )
            pdf.ln(2)

            for idx, r in enumerate(resumenes):
                pdf.set_fill_color(13, 71, 161)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font(FUENTE_INFORME, "B", 9)
                pdf.cell(0, 7, sanitize_text(f"  RECORRIDO {idx + 1}: {r['tipo'].upper()}"),
                         fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(1)
                filas = [("Resultado", r["estado"]),
                         ("Sentido del recorrido", r["sentido"]),
                         ("Mensajes alcanzados", r["alcance"]),
                         ("Tramos recorridos", str(r["tramos"]))]
                if r["archivos"]:
                    filas.append(("Archivos adquiridos", str(r["archivos"])))
                if r["de_la_pagina"]:
                    filas.append(("Tomados de la pagina",
                                  f"{r['de_la_pagina']} (la aplicacion no completo la entrega)"))
                if r["capturas"]:
                    filas.append(("Capturas de pantalla",
                                  f"{r['capturas']} (recortadas al panel de la conversacion)"))
                if r["no_adquiridos"]:
                    filas.append(("NO adquiridos", f"{r['no_adquiridos']} "
                                                   "(ver el motivo en el log de auditoria)"))
                for fi, (k, v) in enumerate(filas):
                    pdf.tabla_fila(k, sanitize_text(str(v)), fi, w_label=52)
                pdf.ln(3)

            pdf.cuerpo_texto(
                "Aclaracion sobre la lectura de fechas: WhatsApp escribe la fecha de cada mensaje "
                "en el orden propio del idioma de su interfaz, de modo que 8/6/2026 designa el 8 "
                "de junio o el 6 de agosto segun el caso. El orden aplicado se determino "
                "consultando la configuracion regional del navegador y se confirmo, cuando fue "
                "posible, con fechas cuyo dia supera el numero 12 y por lo tanto no admiten "
                "ambiguedad. El criterio empleado consta en el log de auditoria junto con el texto "
                "original de cada fecha."
            )
            pdf.ln(1)
            pdf.cuerpo_texto(
                "Se deja constancia, ademas, de que abrir una conversacion en WhatsApp Web marca "
                "sus mensajes como leidos y lo notifica al remitente si este tiene activadas las "
                "confirmaciones de lectura. Es un efecto propio de la aplicacion, inevitable al "
                "acceder a la conversacion, y ajeno al procedimiento de adquisicion."
            )

        # SECCION: ACREDITACION DEL ENTORNO
        #
        # Sostiene por escrito condiciones que de otro modo habria que creer
        # bajo palabra del perito: que el equipo no tenia el dominio
        # redirigido, quien sirvio el contenido y que codigo entrego la pagina.
        _TIPOS_ACRED = {
            "ARCHIVO_HOSTS":        "Archivo hosts del equipo",
            "CERTIFICADO_SERVIDOR": "Certificado TLS del servidor",
            "CABECERAS_HTTP":       "Cabeceras HTTP del servidor",
            "CODIGO_PAGINA":        "Codigo HTML de la pagina",
        }
        acred = [e for e in self.case.evidences if e.get("tipo") in _TIPOS_ACRED]
        if acred:
            pdf.add_page()
            pdf.section_title("A", "ACREDITACION DEL ENTORNO DE ADQUISICION")
            pdf.cuerpo_texto(
                "Junto con la evidencia se conservan los elementos que permiten verificar en que "
                "condiciones se obtuvo. No documentan el contenido adquirido sino el entorno: "
                "sirven para que un tercero pueda comprobar por su cuenta que se accedio al sitio "
                "real y no a un sustituto, y que lo mostrado se corresponde con lo que entrego el "
                "servidor. Cada uno lleva su hash SHA-256 y su acta de custodia como cualquier "
                "otra pieza del caso."
            )
            pdf.ln(1)
            explicacion = [
                ("Archivo hosts del equipo",
                 "Copia del archivo de nombres del sistema operativo. Si alguno de los dominios "
                 "visitados hubiera estado redirigido localmente a otra direccion, constaria en "
                 "el. Su ausencia de entradas acredita que no hubo desvio en el equipo."),
                ("Certificado TLS del servidor",
                 "Certificado que presento cada servidor, firmado por una autoridad de "
                 "certificacion y con el nombre de su titular. Acredita quien sirvio el contenido."),
                ("Cabeceras HTTP del servidor",
                 "Respuesta del servidor en texto plano, tal como fue enviada."),
                ("Codigo HTML de la pagina",
                 "Codigo fuente en el mismo instante de cada captura. La imagen muestra como se "
                 "veia la pagina; el codigo, de que estaba hecha, y permite examinar lo que la "
                 "imagen no registra: enlaces reales detras de un texto, atributos y contenido "
                 "fuera de la parte visible."),
            ]
            for fi, (k, v) in enumerate(explicacion):
                pdf.tabla_fila(k, sanitize_text(v), fi, w_label=46)
            pdf.ln(3)

            pdf.set_fill_color(13, 71, 161)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font(FUENTE_INFORME, "B", 9)
            pdf.cell(0, 7, sanitize_text("  ARCHIVOS INCORPORADOS"),
                     fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)
            for fi, e in enumerate(acred):
                pdf.tabla_fila(
                    _TIPOS_ACRED.get(e.get("tipo"), e.get("tipo", "")),
                    sanitize_text(f"{e.get('filename', '')}   SHA-256 {e.get('sha256', '')[:32]}..."),
                    fi, w_label=46)

        # SECCION: CONFIGURACION DEL NAVEGADOR
        #
        # Lo que el programa cambia en el navegador y en las paginas, dicho en
        # el dictamen. Hasta ahora estaba solo en el codigo: un perito de parte
        # que examinara el programa iba a encontrar que se inserta un guion en
        # cada pagina para que Instagram no detecte el navegador, y el dictamen
        # no lo mencionaba. Declararlo no debilita la prueba; callarlo si.
        pdf.add_page()
        pdf.section_title("N", "CONFIGURACION DEL NAVEGADOR DURANTE LA DILIGENCIA")
        pdf.cuerpo_texto(
            "Se declaran las modificaciones que el programa introduce en el navegador y en las "
            "paginas visitadas, para que quien lea este dictamen sepa en que condiciones se "
            "mostro el contenido adquirido. Ninguna altera el contenido que entregan los "
            "servidores: la imagen de cada captura y el codigo de cada pagina son los que el "
            "sitio envio.")
        pdf.ln(1)
        _codecs = (getattr(self, "_render_info", None) or {}).get("codecs")
        configuracion = [
            ("Motor", version_motor()),
            ("Transcripcion de texto",
             "El informe incrusta fuentes Unicode (" + FUENTES_DEL_INFORME + "), de modo que "
             "los textos adquiridos se transcriben tal como estan: tildes y eñes, alfabetos no "
             "latinos (cirilico, griego, hebreo, arabe, chino, kana) y emojis. Antes el informe "
             "usaba las fuentes base del PDF, que solo cubren el alfabeto latino, y lo demas se "
             "perdia. Es lo que exige la afirmacion CDX-CA-06 de la especificacion del NIST para "
             "herramientas de extraccion en la nube (CFTT), tomada aqui como referencia."),
            ("Reproduccion de video",
             "El motor no incluye los codecs H.264 y AAC, que son los que usan WhatsApp e "
             "Instagram, porque no vienen compilados en la version abierta de Qt WebEngine. En "
             "esas publicaciones el recuadro del video puede verse en negro, en la pantalla y en "
             "la grabacion de la sesion. El contenido no se pierde: el video se adquiere como "
             "archivo original, tal como lo sirve la plataforma, con su SHA-256 y su acta de "
             "custodia, y se reproduce en el visor del propio programa, que usa los codecs del "
             "sistema operativo. Lo que consta como prueba es ese archivo y no una regrabacion "
             "de la pantalla, que seria una copia de menor calidad de lo mismo."),
            ("Formatos que el motor declaro soportar",
             resumen_codecs(_codecs) + ". Consultado al motor con canPlayType al iniciar la "
             "diligencia; 'probably' y 'maybe' son las respuestas que preve la norma HTML."),
            ("Aislamiento de sitios",
             "Forzado (opcion --site-per-process): cada sitio se ejecuta en un proceso propio "
             "del sistema, de modo que una pagina no puede leer la memoria de otra."),
            ("SharedArrayBuffer",
             "Habilitado para todos los sitios. WhatsApp Web lo necesita para descifrar los "
             "videos: sin el se adquirian las fotos pero no los videos. Es la unica proteccion "
             "del navegador que el programa modifica, y el aislamiento de sitios forzado "
             "contiene su efecto."),
            ("Guion nav_stealth",
             "Se inserta en cada pagina al crearse. Hace que navigator.webdriver no informe "
             "automatizacion, completa el objeto window.chrome que traen los navegadores "
             "comunes y responde la consulta del permiso de notificaciones como lo hace Chrome. "
             "Motivo: Instagram y Facebook bloquean los navegadores embebidos que identifican "
             "como robots. Cambia como se presenta el navegador ante el sitio; no toca el "
             "contenido de la pagina."),
            ("Guion nav_entrega_archivos",
             "Reemplaza la funcion con que WhatsApp Web guarda los videos en disco "
             "(showSaveFilePicker), que exige confirmar a mano cada archivo, por una entrega "
             "como descarga comun hacia la carpeta del caso. Los bytes son los que produce "
             "WhatsApp; cambia solo el destino."),
            ("Recorridos automaticos",
             "Los relevamientos de comentarios y de listas leen la pagina y la desplazan con "
             "eventos de rueda del mouse, como lo haria una persona; no hacen clic ni modifican "
             "nada. El recorrido de multimedia de WhatsApp, ademas, abre el menu de cada archivo "
             "y elige Descargar."),
            ("Descargas",
             "Solo entran a la evidencia las descargas que pide el propio programa. Si una "
             "pagina inicia otra, el programa pregunta al perito y su decision queda en el "
             "log de auditoria con el origen de la descarga."),
        ]
        for fi, (k, v) in enumerate(configuracion):
            pdf.tabla_fila(k, sanitize_text(v), fi, w_label=46)

        # SECCION: URLS VISITADAS (del HAR)
        if self.case.har_entries:
            pdf.add_page()
            pdf.section_title("U", "REGISTRO DE URLS NAVEGADAS")
            pdf.cuerpo_texto(
                f"Total de requests registrados en la sesion: {len(self.case.har_entries)}. "
                "Se listan las URLs unicas con metodo HTTP y timestamp de inicio."
            )
            pdf.ln(2)
            # Encabezado de tabla
            pdf.set_font(FUENTE_INFORME, "B", 7)
            pdf.set_fill_color(46, 125, 50)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(28, 5, "  Timestamp", fill=True, border=1)
            pdf.cell(12, 5, "Metodo", fill=True, border=1)
            pdf.cell(0,  5, "  URL", fill=True, border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
            seen_urls: set = set()
            for idx_h, entry in enumerate(self.case.har_entries[:200]):  # max 200 filas
                req   = entry.get("request", {})
                url_h = req.get("url", "")
                if url_h in seen_urls:
                    continue
                seen_urls.add(url_h)
                ts_h  = entry.get("startedDateTime", "")[:19].replace("T", " ")
                meth  = req.get("method", "GET")[:6]
                fill  = idx_h % 2 == 0
                pdf.set_fill_color(*(232, 245, 233) if fill else (255, 255, 255))
                pdf.set_font(FUENTE_INFORME, "", 6)
                pdf.cell(28, 4, sanitize_text(f"  {ts_h}"), fill=fill, border=1)
                pdf.cell(12, 4, sanitize_text(meth), fill=fill, border=1)
                pdf.cell(0,  4, sanitize_text(f"  {url_h[:110]}"), fill=fill, border=1,
                         new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                if pdf.get_y() > 270:
                    pdf.add_page()
            if len(self.case.har_entries) > 200:
                pdf.set_font(FUENTE_INFORME, "I", 7)
                pdf.set_text_color(120, 120, 120)
                pdf.cell(0, 4,
                    sanitize_text(f"  ... y {len(self.case.har_entries) - 200} requests adicionales en el archivo HAR."),
                    new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)

        # SECCION: METADATOS DE SITIOS
        if self.case.site_metadata:
            pdf.add_page()
            pdf.section_title("S", "IDENTIFICACION DE SERVIDORES VISITADOS")
            pdf.cuerpo_texto(
                "Para cada dominio navegado se registran: resolucion DNS, IP del servidor, "
                "pais de origen, organizacion titular y estado HTTP. "
                "Estos datos permiten identificar la infraestructura tecnica de los sitios visitados."
            )
            pdf.ln(2)
            for idx_s, meta_s in enumerate(self.case.site_metadata):
                geo   = meta_s.get("geo", {})
                pais  = geo.get("pais",  "N/A") if isinstance(geo, dict) else "N/A"
                org   = geo.get("org",   "N/A") if isinstance(geo, dict) else "N/A"
                ciudad = geo.get("ciudad", "N/A") if isinstance(geo, dict) else "N/A"
                rows_s = [
                    ("Host",          meta_s.get("host", "N/A")),
                    ("IP Servidor",   meta_s.get("ip",   "N/A")),
                    ("DNS Inverso",   meta_s.get("rdns", "N/A")),
                    ("Pais / Ciudad", f"{pais} / {ciudad}"),
                    ("Organizacion",  org),
                    ("HTTP Status",   str(meta_s.get("http_status", "N/A"))),
                    ("Timestamp",     meta_s.get("ts", "N/A")[:19]),
                ]
                pdf.set_font(FUENTE_INFORME, "B", 8)
                pdf.set_fill_color(13, 71, 161)
                pdf.set_text_color(255, 255, 255)
                pdf.cell(0, 5, sanitize_text(f"  Sitio {idx_s+1}: {meta_s.get('host','?')}"),
                         fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
                for j_s, (k_s, v_s) in enumerate(rows_s):
                    pdf.tabla_fila(k_s, v_s, j_s, w_label=45)
                pdf.ln(2)
                if pdf.get_y() > 250:
                    pdf.add_page()

        pdf.add_page()
        pdf.section_title("L", "LOGS DE AUDITORIA")
        pdf.cuerpo_texto(
            "Base de datos SQLite de solo agregado. Cada entrada se encadena a la anterior con "
            "SHA-256, de modo que alterar, suprimir o reordenar una linea rompe la cadena desde "
            "ese punto. El extremo de la cadena se firma con una clave Ed25519 (RFC 8032) "
            "generada al abrir el caso: cada 200 entradas, al emitir este dictamen y antes de "
            "empaquetar. La clave privada existe solo en la memoria del programa, no se escribe "
            "en disco y se descarta al terminar el empaquetado, asi que despues de la diligencia "
            "nadie -tampoco el perito- puede agregar ni rehacer entradas firmadas. La clave "
            "publica figura en manifest.json desde el inicio del caso y se transcribe abajo; "
            "verificar_caso.py comprueba con ella la cadena y las firmas. Archivo HAR v1.2 de red.")
        pdf.bloque_hash("Clave publica de firma del log (Ed25519):", self.case.clave_publica_log)
        if _cierre_dictamen:
            pdf.bloque_hash(
                f"Extremo de la cadena al emitir este dictamen (entrada "
                f"{_cierre_dictamen['hasta_id']}, {_cierre_dictamen['entradas']} en total):",
                _cierre_dictamen["cabeza"])
        pdf.bloque_hash("Hash SHA-256 DB:", h_db)
        pdf.bloque_hash("Hash SHA-256 HAR:", h_har)

        # SECCION: AUTODIAGNOSTICO
        # Acredita que la herramienta se verifico a si misma antes de adquirir
        # prueba: las funciones criptograficas se contrastan contra vectores
        # publicados, y se comprueba el sellado y la escritura.
        _diag = getattr(self.case, "diagnostico", None)
        if _diag:
            pdf.add_page()
            pdf.section_title("D", "AUTODIAGNOSTICO PREVIO A LA ADQUISICION")
            pdf.cuerpo_texto(
                "Antes de iniciar la adquisicion, el software ejecuto un control de su propio "
                "funcionamiento. Las funciones criptograficas se comprueban contra vectores de "
                "prueba publicados (FIPS 180-4 para SHA-256 y RFC 8032 para Ed25519): si el "
                "resultado no coincide con el valor conocido, la herramienta no esta en "
                "condiciones de certificar integridad. Se verifica ademas el hash del propio "
                "ejecutable, la disponibilidad de una autoridad de sellado de tiempo y que el "
                "directorio del caso admita escritura. El resultado se consigna a continuacion."
            )
            pdf.ln(2)
            for idx_d, c in enumerate(_diag):
                estado = "CORRECTO" if c.get("ok") else "FALLA"
                pdf.tabla_fila(c.get("prueba", ""),
                               sanitize_text(f"{estado} - {c.get('detalle','')}"),
                               idx_d, w_label=62)

        # SECCION: INCIDENCIAS
        # Si algo fallo durante la diligencia el dictamen tiene que decirlo. Un
        # informe que calla los problemas es mas fragil ante una impugnacion
        # que uno que los declara y explica su alcance.
        if FALLOS_CRITICOS:
            pdf.add_page()
            pdf.section_title("!", "INCIDENCIAS REGISTRADAS DURANTE LA DILIGENCIA")
            pdf.cuerpo_texto(
                "Se dejan asentadas las incidencias detectadas por el software durante la "
                "adquisicion. Se consignan por transparencia y para que puedan ser valoradas "
                "al apreciar la prueba. Salvo indicacion en contrario, no afectan a la "
                "totalidad del material adquirido sino unicamente a los elementos senalados."
            )
            pdf.ln(2)
            for idx_f, f in enumerate(FALLOS_CRITICOS[:40]):
                pdf.tabla_fila(f.get("categoria", ""),
                               sanitize_text(f.get("mensaje", "")), idx_f, w_label=42)
            if len(FALLOS_CRITICOS) > 40:
                pdf.ln(1)
                pdf.set_font(FUENTE_INFORME, "I", 8)
                pdf.cell(0, 5, sanitize_text(
                    f"  (se listan las primeras 40 de {len(FALLOS_CRITICOS)} incidencias; "
                    "el detalle completo esta en el log de auditoria)"),
                    new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.ln(3)
            pdf.set_font(FUENTE_INFORME, "B", 9)
            pdf.set_text_color(27, 94, 32)
            pdf.cell(0, 6, sanitize_text(
                "  Sin incidencias: no se registraron fallos de integridad ni de "
                "sellado durante la diligencia."),
                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)

        pdf.add_page()
        pdf.section_title("8", "CERTIFICADO DE INTEGRIDAD FORENSE")
        pdf.set_font(FUENTE_INFORME, "", 10)
        w_cert = pdf.w - pdf.l_margin - pdf.r_margin
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(w_cert, 6, sanitize_text(
            f"Informe generado el {ts_gen} mediante {SOFTWARE_INFO['software']} {SOFTWARE_INFO['version']}.\n\n"
            f"Case ID: {self.case.case_id}\n"
            f"Evidencias: {cant_total} | Imagenes: {cant_img} | Videos: {cant_vid} | Media: {cant_media}\n\n"
            f"SHA-256 del software ejecutado: {get_self_hash()}\n"
            f"Hash de la base de datos de auditoria: {h_db}\n"
            f"Hash del log de red HAR: {h_har}\n\n"
            "Para verificar integridad: recalcule SHA-256 de cada archivo y compare con los valores certificados."
        ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # LEYENDA DE PAQUETE ZIP (solo cuando se genera desde Salir)
        #
        # Aca NO va el hash del paquete, y es deliberado. Este dictamen se
        # guarda dentro del ZIP: si declarara el hash del ZIP, al incorporarlo
        # el hash cambiaria y el valor impreso no podria verificarse nunca. Un
        # archivo no puede contener su propia huella.
        #
        # La huella del paquete se consigna afuera (en el sidecar .sha256, en
        # el acta de custodia y en el sello de tiempo .tsr con su cadena
        # .tsa.pem, todos al lado
        # del ZIP y no adentro) y ahi si se puede recalcular y comparar. Lo que
        # este informe certifica es cada archivo por separado, con su hash, en
        # el registro de evidencias.
        if zip_info:
            pdf.ln(8)
            pdf.set_fill_color(13, 71, 161)       # azul oscuro
            pdf.set_text_color(255, 255, 255)
            pdf.set_font(FUENTE_INFORME, "B", 10)
            pdf.cell(0, 8, "   PAQUETE DE EVIDENCIA DIGITAL CERTIFICADO",
                     fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font(FUENTE_INFORME, "", 9)
            w_full = pdf.w - pdf.l_margin - pdf.r_margin
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(w_full, 5, sanitize_text(
                f"Concluida la diligencia pericial, la totalidad de la evidencia digital "
                f"adquirida —incluido el presente dictamen— fue consolidada en un unico "
                f"archivo comprimido en formato ZIP de nombre {zip_info['nombre']}.\n\n"
                f"La huella SHA-256 de ese paquete no se transcribe en este documento, y la "
                f"razon es de metodo: este dictamen queda guardado dentro del propio paquete, "
                f"de modo que cualquier valor impreso aca dejaria de coincidir en cuanto el "
                f"archivo se incorpore. Un archivo no puede llevar impresa su propia huella.\n\n"
                f"La huella del paquete se consigna en los archivos que lo acompanan por "
                f"fuera: el sidecar {zip_info['nombre']}.sha256, el acta de custodia "
                f"correspondiente y el sello de tiempo RFC 3161 {zip_info['nombre']}.tsr, "
                f"con la cadena de certificados de la autoridad en "
                f"{zip_info['nombre']}.tsa.pem. Deben entregarse todos junto al paquete.\n\n"
                f"Con independencia de ello, cada pieza de evidencia queda certificada una "
                f"por una con su propio hash SHA-256 en el registro de evidencias de este "
                f"informe: la integridad del material es comprobable pieza por pieza aunque "
                f"el paquete se vuelva a comprimir."
            ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)
            pdf.set_font(FUENTE_INFORME, "I", 8)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(w_full, 4, sanitize_text(
                f"  Verificacion del paquete:  certutil -hashfile \"{zip_info['nombre']}\" "
                f"SHA256   (Windows)  y comparar con {zip_info['nombre']}.sha256"
            ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(4)

        # SECCION: CONTACTOS RELEVADOS
        #
        # La lista se acompaña en el cuerpo del dictamen y no solo como archivo
        # adjunto: un listado de cuentas es el resultado principal de un
        # relevamiento de perfil, y quien lee el informe tiene que poder verlo
        # sin abrir la carpeta de evidencias.
        listas = [e for e in self.case.evidences
                  if e.get("tipo") == "LISTA_CONTACTOS" and os.path.exists(e.get("path", ""))]
        if listas:
            pdf.add_page()
            pdf.section_title("R", "CONTACTOS RELEVADOS")
            pdf.cuerpo_texto(
                "Se transcriben las cuentas registradas al recorrer las listas de seguidores o "
                "seguidos, en el orden en que la plataforma las presenta. Cada cuenta se tomo del "
                "enlace de perfil que la propia pagina publica; no se consulto ninguna interfaz "
                "no documentada. El recorrido esta respaldado por las capturas de pantalla que "
                "figuran en el inventario de evidencias."
            )
            for ev in listas:
                cuentas = []
                encabezado = []
                try:
                    with open(ev["path"], "r", encoding="utf-8", errors="replace") as f:
                        for linea in f:
                            m = re.match(r"\s*\d+\.\s*@(\S+)(?:\s{2,}(.+))?", linea)
                            if m:
                                cuentas.append((m.group(1), (m.group(2) or "").strip()))
                            elif ":" in linea and len(encabezado) < 6 and not cuentas:
                                encabezado.append(linea.strip())
                except Exception:
                    continue

                pdf.ln(2)
                pdf.set_fill_color(13, 71, 161)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font(FUENTE_INFORME, "B", 9)
                pdf.cell(0, 7, sanitize_text(f"  {ev['filename']}   ({len(cuentas)} cuentas)"),
                         fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(1)
                for fi, linea in enumerate(encabezado):
                    if ":" in linea:
                        k, v = linea.split(":", 1)
                        pdf.tabla_fila(k.strip(), sanitize_text(v.strip()), fi, w_label=30)
                pdf.ln(2)

                # En columnas: un listado de a uno por linea gastaria decenas
                # de hojas sin ganar nada. Cuando las entradas traen nombre
                # (Facebook) van dos por linea, porque ahi el nombre de la
                # persona es el dato de la pericia y truncarlo a un tramo de
                # URL dejaba el listado sin valor. Sin nombre (Instagram, donde
                # el usuario ya identifica) entran tres.
                if cuentas:
                    con_nombre = any(n for _, n in cuentas)
                    cols = 2 if con_nombre else 3
                    corte = 46 if con_nombre else 26
                    pdf.set_font(FUENTE_MONO, "", 7)
                    ancho = (pdf.w - pdf.l_margin - pdf.r_margin) / cols
                    for k in range(0, len(cuentas), cols):
                        if pdf.get_y() > pdf.h - 25:
                            pdf.add_page()
                        for ident, nombre in cuentas[k:k + cols]:
                            txt = f"{nombre} (@{ident})" if nombre else f"@{ident}"
                            pdf.cell(ancho, 4, sanitize_text("  " + txt[:corte]))
                        pdf.ln(4)
                    pdf.set_font(FUENTE_INFORME, "", 9)
                    pdf.ln(2)
                    pdf.set_font(FUENTE_INFORME, "I", 7)
                    pdf.set_text_color(90, 90, 90)
                    pdf.cell(0, 4, sanitize_text(
                        f"  Total transcripto: {len(cuentas)} cuentas.   "
                        f"SHA-256 del listado: {ev.get('sha256', '')[:32]}..."),
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font(FUENTE_INFORME, "", 9)

        # SECCION: COMENTARIOS DE PUBLICACIONES
        #
        # Van transcriptos en el cuerpo del dictamen por la misma razon que las
        # listas de contactos: son el contenido que se vino a relevar, y quien
        # lee el informe tiene que poder leerlos sin abrir la carpeta de
        # evidencias. Se conserva la fecha en UTC que publica la pagina, que es
        # lo unico que fija el momento de cada comentario: el texto a la vista
        # dice "hace 4 h" y no significa nada fuera del instante de mirarlo.
        coms = [e for e in self.case.evidences
                if e.get("tipo") == "COMENTARIOS" and os.path.exists(e.get("path", ""))]
        if coms:
            pdf.add_page()
            pdf.section_title("M", "COMENTARIOS RELEVADOS")
            pdf.cuerpo_texto(
                "Se transcriben los comentarios registrados al recorrer las publicaciones, en el "
                "orden en que la plataforma los presenta. De cada uno se conserva el autor, el "
                "texto y la fecha y hora exactas publicadas por la propia pagina —no el texto "
                "relativo del tipo \"hace 18 horas\", que no fija ningun momento. Las respuestas "
                "que la plataforma muestra plegadas no fueron desplegadas: se deja constancia de "
                "cuantas declaro, de modo que pueda advertirse que material queda fuera. El "
                "recorrido esta respaldado por las capturas de pantalla del inventario."
            )
            for ev in coms:
                encabezado, desc, filas = [], [], []
                try:
                    with open(ev["path"], "r", encoding="utf-8", errors="replace") as f:
                        lineas = f.read().split("\n")
                except Exception:
                    continue
                # El listado tiene tres zonas: encabezado, descripcion de la
                # publicacion (solo en Instagram) y comentarios. La zona de
                # comentarios se reconoce por la linea que dice COMENTARIOS
                # sola, en mayusculas. Compararla con startswith no alcanza: el
                # encabezado tiene un campo "Comentarios : N" que tambien
                # empieza igual, y al descartarlo con un condicional que exigia
                # haber pasado antes por la descripcion, los listados de
                # Facebook (que no la tienen) quedaban sin una sola fila.
                zona = "cab"
                i = 0
                while i < len(lineas):
                    L = lineas[i]
                    if L.strip() == "DESCRIPCION DE LA PUBLICACION":
                        zona = "desc"
                    elif L.strip() == "COMENTARIOS":
                        zona = "com"
                    elif zona == "cab" and ":" in L:
                        encabezado.append(L.strip())
                    elif zona == "cab" and L.startswith("  ") and L.strip() and encabezado:
                        # Continuacion del campo anterior, que ocupa dos o tres
                        # renglones y no lleva dos puntos.
                        encabezado[-1] += " " + L.strip()
                    elif zona == "desc" and ":" in L and L.startswith("  "):
                        desc.append(L.strip())
                    elif zona == "com":
                        m = re.match(r"\s*(\d+)\.\s*@([^|]+?)\s*\|\s*([^|]*)\|", L)
                        if m:
                            texto = lineas[i + 1].strip() if i + 1 < len(lineas) else ""
                            filas.append((m.group(1), m.group(2), m.group(3).strip(), texto))
                            i += 1
                    i += 1

                pdf.ln(2)
                pdf.set_fill_color(13, 71, 161)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font(FUENTE_INFORME, "B", 9)
                pdf.cell(0, 7, sanitize_text(
                    f"  {ev['filename']}   ({len(filas)} comentarios)"),
                    fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(0, 0, 0)
                pdf.ln(1)
                fi = 0
                for linea in encabezado:
                    if ":" in linea:
                        k, v = linea.split(":", 1)
                        if v.strip():
                            pdf.tabla_fila(k.strip(), sanitize_text(v.strip()), fi, w_label=32)
                            fi += 1
                if desc:
                    pdf.ln(1)
                    pdf.set_font(FUENTE_INFORME, "B", 8)
                    pdf.cell(0, 5, sanitize_text("  Descripcion de la publicacion"),
                             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font(FUENTE_INFORME, "", 9)
                    for linea in desc:
                        k, v = linea.split(":", 1)
                        pdf.tabla_fila(k.strip(), sanitize_text(v.strip()), fi, w_label=32)
                        fi += 1
                pdf.ln(3)

                if filas:
                    ancho_tot = pdf.w - pdf.l_margin - pdf.r_margin
                    w_n, w_aut, w_fec = 10, 40, 42
                    w_txt = ancho_tot - w_n - w_aut - w_fec
                    def _encabezado_tabla():
                        pdf.set_font(FUENTE_INFORME, "B", 7)
                        pdf.set_fill_color(220, 230, 241)
                        for etq, an in (("N", w_n), ("Autor", w_aut),
                                        ("Fecha publicada", w_fec), ("Comentario", w_txt)):
                            pdf.cell(an, 5, sanitize_text(" " + etq), border=1, fill=True)
                        pdf.ln(5)
                        pdf.set_font(FUENTE_INFORME, "", 7)

                    _encabezado_tabla()
                    for k, (num, autor, fecha, texto) in enumerate(filas):
                        txt = sanitize_text(texto)
                        # Instagram entrega la fecha en ISO y Facebook como
                        # frase. Solo se acorta la primera, que es la que tiene
                        # una parte fija que no aporta.
                        if len(fecha) >= 19 and fecha[4] == "-" and "T" in fecha[:12]:
                            fecha = fecha[:19].replace("T", " ")
                        # Se mide antes de dibujar para que la fila no quede
                        # partida entre dos hojas, igual que en tabla_fila.
                        def _lineas(t, ancho):
                            try:
                                return len(pdf.multi_cell(ancho, 4, t, dry_run=True,
                                                          output="LINES", border=1))
                            except Exception:
                                return max(1, int(pdf.get_string_width(t) /
                                                  max(1.0, ancho - 3)) + 1)
                        n_lin = max(_lineas(txt, w_txt - 2),
                                    _lineas(sanitize_text("@" + autor), w_aut - 2),
                                    _lineas(sanitize_text(fecha), w_fec - 2))
                        alto = 4 * max(n_lin, 1) + 1
                        try:
                            salta = pdf.will_page_break(alto)
                        except Exception:
                            salta = pdf.get_y() + alto > pdf.page_break_trigger - 1
                        if salta:
                            pdf.add_page()
                            _encabezado_tabla()
                        # El recuadro de cada celda se dibuja aparte del texto.
                        # Dejar que multi_cell trace su propio borde daba filas
                        # con celdas de distinta altura (el autor ocupaba dos
                        # renglones y el comentario uno) y los marcos no
                        # cerraban entre si.
                        y0, x0 = pdf.get_y(), pdf.l_margin
                        relleno = (k % 2 == 0)
                        pdf.set_fill_color(*(pdf.C_FILA_PAR if relleno else pdf.C_FILA_IMP))
                        x = x0
                        for ancho in (w_n, w_aut, w_fec, w_txt):
                            pdf.rect(x, y0, ancho, alto, style="DF")
                            x += ancho
                        pdf.set_xy(x0, y0 + 0.5)
                        pdf.cell(w_n - 1, 4, num, align="R")
                        pdf.set_xy(x0 + w_n + 1, y0 + 0.5)
                        pdf.multi_cell(w_aut - 2, 4, sanitize_text("@" + autor),
                                       border=0, align="L", fill=False)
                        pdf.set_xy(x0 + w_n + w_aut + 1, y0 + 0.5)
                        pdf.multi_cell(w_fec - 2, 4, sanitize_text(fecha),
                                       border=0, align="L", fill=False)
                        pdf.set_xy(x0 + w_n + w_aut + w_fec + 1, y0 + 0.5)
                        pdf.multi_cell(w_txt - 2, 4, txt, border=0, align="L", fill=False)
                        pdf.set_y(y0 + alto)
                    pdf.ln(2)
                    pdf.set_font(FUENTE_INFORME, "I", 7)
                    pdf.set_text_color(90, 90, 90)
                    pdf.multi_cell(0, 4, sanitize_text(
                        f"  Total transcripto: {len(filas)} comentarios.   "
                        f"SHA-256 del listado: {ev.get('sha256', '')[:32]}..."),
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font(FUENTE_INFORME, "", 9)

        # ANEXO: VISTAS DEL CHAT
        #
        # Las capturas van reproducidas en el dictamen y no solo listadas por
        # su nombre: una tabla de archivos y hash acredita integridad pero no
        # permite leer la conversacion, y quien recibe el informe tiene que
        # poder ver de que se trata sin abrir la carpeta de evidencias.
        #
        # Van en grilla, varias por hoja. A una vista por pagina un chat
        # mediano agregaba veinte hojas al dictamen. El hash completo de cada
        # una figura en el registro de evidencias, asi que aca alcanza con el
        # comienzo para identificarlas.
        # Vale para la conversacion y para los comentarios: son dos recorridos
        # distintos pero el anexo es el mismo, asi que se recorre una lista de
        # tipos en vez de repetir la maquetacion.
        for tipo_ev, letra, titulo, explicacion in (
            ("CAPTURA_CHAT", "C", "ANEXO - VISTAS DE LA CONVERSACION",
             "Se reproducen las {n} capturas del panel de la conversacion, en el orden en "
             "que fueron tomadas. El recorrido va desde el punto elegido por el perito "
             "hacia el ultimo mensaje, de modo que la vista 001 es la mas antigua."),
            ("CAPTURA_COMENTARIOS", "K", "ANEXO - VISTAS DE LOS COMENTARIOS",
             "Se reproducen las {n} capturas del panel de comentarios, en el orden en que "
             "fueron tomadas. Cada una corresponde al tramo leido inmediatamente antes, de "
             "modo que la imagen respalda lo que figura transcripto en el listado."),
        ):
            chats = sorted(
                (e for e in self.case.evidences
                 if e.get("tipo") == tipo_ev and os.path.exists(e.get("path", ""))),
                key=lambda e: e.get("filename", ""))
            if chats:
                pdf.add_page()
                pdf.section_title(letra, titulo)
                pdf.cuerpo_texto(
                    explicacion.format(n=len(chats)) +
                    " El hash SHA-256 completo de cada imagen consta en el registro de "
                    "evidencias de este mismo informe y en el archivo que la acompaña. "
                    "Las vistas se reproducen aca redimensionadas a la medida con que se "
                    "imprimen: los archivos originales, que son los que llevan el hash "
                    "certificado, estan sin alterar en la carpeta de evidencias del paquete."
                )
                pdf.ln(2)

                # Dos vistas por pagina, de 135 mm de ancho.
                #
                # El tamaño no es arbitrario: se probo imprimiendo una captura con
                # texto del cuerpo que usa WhatsApp. A 135 mm los mensajes se leen;
                # a 73 mm, que era lo que entraba en dos columnas, el texto queda
                # en 3 puntos y no se lee. Un anexo de capturas que no pueden
                # leerse no cumple ninguna funcion, asi que la legibilidad manda
                # sobre la cantidad de hojas.
                COLS      = 1
                SEPARACION = 0.0
                ALTO_IMG  = 115.0
                ALTO_PIE  = 9.0
                usable    = pdf.w - pdf.l_margin - pdf.r_margin
                col_w     = min(135.0, usable)
                margen_x  = (usable - col_w) / 2
                alto_celda = ALTO_IMG + ALTO_PIE

                pdf.set_auto_page_break(auto=False)
                y_fila = pdf.get_y()
                for idx, ev in enumerate(chats):
                    col = idx % COLS
                    if col == 0:
                        if idx > 0:
                            y_fila += alto_celda
                        if y_fila + alto_celda > pdf.h - 20:
                            pdf.add_page()
                            y_fila = pdf.get_y()
                    x = pdf.l_margin + margen_x + col * (col_w + SEPARACION)

                    try:
                        with Image.open(ev["path"]) as im:
                            iw, ih = im.size
                        escala = min(col_w / iw, ALTO_IMG / ih)
                        w_mm, h_mm = iw * escala, ih * escala
                        # Copia al tamaño con que se va a ver. Estas vistas son
                        # las que mas pesan del informe: van 135 mm de ancho y
                        # las capturas llegan con 2560 px.
                        recorte = imagen_para_informe(ev["path"], w_mm, dir_temp)
                        if recorte != ev["path"]:
                            temp_thumbs.append(recorte)
                        pdf.image(recorte, x=x + (col_w - w_mm) / 2, y=y_fila,
                                  w=w_mm, h=h_mm)
                    except Exception:
                        pdf.set_xy(x, y_fila)
                        pdf.set_font(FUENTE_INFORME, "I", 7)
                        pdf.cell(col_w, ALTO_IMG, "imagen no disponible", align="C")

                    pdf.set_xy(x, y_fila + ALTO_IMG + 1)
                    pdf.set_font(FUENTE_INFORME, "B", 6)
                    pdf.set_text_color(46, 125, 50)
                    pdf.cell(col_w, 3, sanitize_text(
                        f"VISTA {idx + 1} de {len(chats)}   {ev.get('filename', '')}"),
                        new_x=XPos.LEFT, new_y=YPos.NEXT)
                    pdf.set_x(x)
                    pdf.set_font(FUENTE_INFORME, "", 5)
                    pdf.set_text_color(110, 110, 110)
                    pdf.cell(col_w, 3, sanitize_text(
                        f"{ev.get('ts', '')[:19].replace('T', ' ')}   "
                        f"SHA-256 {ev.get('sha256', '')[:24]}..."),
                        new_x=XPos.LEFT, new_y=YPos.NEXT)
                    pdf.set_text_color(0, 0, 0)

                pdf.set_auto_page_break(auto=True, margin=18)
                pdf.set_y(y_fila + alto_celda)

        # ANEXO: VERIFICACION INDEPENDIENTE
        #
        # Va al final, despues del cuerpo del dictamen, porque no describe lo
        # adquirido sino como comprobarlo. Su razon de ser es que la prueba no
        # dependa de la palabra del perito ni de la confianza en el programa:
        # cualquier tercero con una computadora puede rehacer las
        # comprobaciones y llegar por su cuenta al mismo resultado.
        pdf.add_page()
        pdf.section_title("V", "ANEXO - VERIFICACION INDEPENDIENTE")
        pdf.cuerpo_texto(
            "Este anexo describe como comprobar, sin intervencion del perito y sin necesidad de "
            "confiar en el programa que produjo la evidencia, que el material acompañado es el "
            "que se adquirio y que no fue alterado despues. Las comprobaciones pueden hacerlas la "
            "contraparte, un perito de control o el propio tribunal."
        )
        pdf.ln(2)

        # 1. Verificacion del caso
        pdf.set_fill_color(13, 71, 161)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(FUENTE_INFORME, "B", 9)
        pdf.cell(0, 7, sanitize_text("  1. COMO VERIFICAR ESTE CASO"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        pdf.cuerpo_texto(
            "Cada archivo del caso esta acompañado de dos documentos: uno con su hash SHA-256 y "
            "otro con su acta de custodia. Recalcular el hash de un archivo y compararlo con el "
            "declarado alcanza para saber si fue modificado. El programa incluye ademas un "
            "verificador que recorre el caso completo y contrasta todo de una vez."
        )
        pdf.ln(1)
        pasos = [
            ("Verificador incluido",
             "python verificar_caso.py <carpeta del caso>. Comprueba los hash de cada archivo, "
             "el registro de evidencias, la cadena del log de auditoria y el archivo WARC."),
            ("Sin instalar nada",
             "El verificador usa unicamente la biblioteca estandar de Python: no requiere el "
             "programa que genero la prueba ni ningun componente de terceros."),
            ("Hash de un archivo suelto",
             "certutil -hashfile <archivo> SHA256 en Windows, o sha256sum <archivo> en Linux. El "
             "valor debe coincidir con el del archivo .sha256 que lo acompaña."),
            ("Sello de tiempo del paquete",
             "openssl ts -verify -data <caso>.zip -in <caso>.zip.tsr -CAfile <caso>.zip.tsa.pem. "
             "Los dos archivos se entregan junto al paquete: la respuesta de la autoridad y su "
             "cadena de certificados. El ultimo certificado de la cadena es la raiz; su huella "
             "SHA-256 figura en el acta del paquete y puede contrastarse con la que publica la "
             "autoridad. Acredita ante un tercero que el paquete existia en esa fecha."),
            ("Trafico de red",
             "El archivo session.har se abre con las herramientas de desarrollo de cualquier "
             "navegador. El archivo .warc.gz sigue la norma ISO 28500 y se lee con herramientas "
             "de archivo web de uso general."),
            ("Inventario en formato estandar",
             "El archivo .dfxml contiene el inventario del caso en Digital Forensics XML, el "
             "formato con que la disciplina intercambia que archivos hay, de que tamano, con "
             "que hashes y en que momento se tomaron. Lo procesan utilidades independientes, "
             "sin necesidad de este programa: donde el verificador permite comprobar el caso "
             "sin la herramienta, el DFXML permite procesarlo sin ella."),
        ]
        for fi, (k, v) in enumerate(pasos):
            pdf.tabla_fila(k, sanitize_text(v), fi, w_label=46)
        pdf.ln(3)

        # 2. Verificacion de la herramienta
        pdf.set_fill_color(13, 71, 161)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(FUENTE_INFORME, "B", 9)
        pdf.cell(0, 7, sanitize_text("  2. COMO VERIFICAR LA HERRAMIENTA"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        pdf.cuerpo_texto(
            "Comprobar la evidencia no alcanza si la herramienta que la produjo no es confiable. "
            "Por eso el programa se somete a una validacion propia, siguiendo el criterio del "
            "NIST para software forense (Computer Forensics Tool Testing): cada funcion de la que "
            "depende la prueba se contrasta contra valores publicados por organismos de "
            "normalizacion, de modo que el resultado no dependa de lo que afirme el fabricante."
        )
        pdf.ln(1)
        val = [
            ("Rutina de validacion",
             "python validacion_forense.py. Ejecuta la bateria completa e informa cuantas pruebas "
             "supero, dejando constancia en un archivo aparte."),
            ("SHA-256",
             "Se contrasta contra los vectores de la norma FIPS 180-4 del NIST."),
            ("Ed25519",
             "La firma del log de auditoria se contrasta contra los vectores del RFC 8032."),
            ("Deteccion de fallos",
             "Se comprueba que un archivo inexistente o ilegible produzca un fallo registrado y "
             "no un hash falso: la herramienta no debe fallar en silencio."),
            ("Identidad del programa",
             "El dictamen consigna el SHA-256 del ejecutable y el del conjunto de archivos "
             "instalados, con el detalle archivo por archivo en report/herramienta_archivos.sha256. "
             "El hash del conjunto es el de ese manifiesto: se comprueba con certutil sobre el "
             "archivo y, comparado con el manifiesto oficial de la version, muestra si algun "
             "componente fue reemplazado."),
        ]
        for fi, (k, v) in enumerate(val):
            pdf.tabla_fila(k, sanitize_text(v), fi, w_label=46)
        pdf.ln(3)

        # 3. ISO/IEC 27037
        pdf.add_page()
        pdf.set_fill_color(13, 71, 161)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(FUENTE_INFORME, "B", 9)
        pdf.cell(0, 7, sanitize_text("  3. CORRESPONDENCIA CON LA NORMA ISO/IEC 27037"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        pdf.cuerpo_texto(
            "La norma ISO/IEC 27037 establece los lineamientos para identificar, recolectar, "
            "adquirir y preservar evidencia digital. No es una norma certificable por producto: "
            "define principios que debe satisfacer el procedimiento. Se detalla a continuacion "
            "como los satisface el empleado en esta pericia y donde consta cada uno, para que "
            "pueda contrastarse en lugar de darse por cierto."
        )
        pdf.ln(1)
        iso = [
            ("Auditabilidad",
             "Toda accion queda en un registro de auditoria con fecha, hora y detalle. Cada "
             "entrada se encadena a la anterior con SHA-256 y la cadena se firma con Ed25519, "
             "de modo que suprimir o alterar una linea rompe la cadena y se detecta. Consta en "
             "db/audit.db."),
            ("Repetibilidad",
             "El procedimiento esta descripto paso a paso en este dictamen, incluida la version "
             "de la herramienta y su hash. Un tercero con el mismo material y las mismas "
             "condiciones puede repetirlo."),
            ("Reproducibilidad",
             "El material se conserva en formatos abiertos y de uso general: SHA-256, RFC 3161, "
             "ISO 28500 (WARC), HAR 1.2, PEM, PNG, PDF. Ninguno requiere este programa para ser "
             "leido o verificado."),
            ("Justificabilidad",
             "Cada decision tecnica relevante queda explicada en el dictamen, y lo que NO se "
             "pudo adquirir se informa con su motivo. Una herramienta que solo informa sus "
             "aciertos impide juzgar la suficiencia de la prueba."),
            ("Integridad de la evidencia",
             "Hash SHA-256 por pieza en el momento de la adquisicion, acta de custodia, sello de "
             "tiempo RFC 3161 de una autoridad externa, y hash del paquete completo. Al cerrar el "
             "caso los archivos se marcan como de solo lectura."),
            ("Cadena de custodia",
             "Cada pieza tiene su acta con identificacion del caso, del perito, origen, momento "
             "de adquisicion, metodo empleado y hash. El inventario completo consta en este "
             "dictamen."),
            ("Minima alteracion del original",
             "No se modifica el sitio ni el dispositivo de origen. La adquisicion se hace por las "
             "vias que la propia aplicacion ofrece al usuario. Cuando una accion produce un "
             "efecto inevitable —como que abrir una conversacion marque los mensajes como "
             "leidos— se deja constancia expresa."),
            ("Sincronizacion horaria",
             "El reloj del equipo se contrasta contra servidores NTP publicos y la diferencia "
             "queda registrada, de modo que las horas consignadas puedan sostenerse."),
        ]
        for fi, (k, v) in enumerate(iso):
            pdf.tabla_fila(k, sanitize_text(v), fi, w_label=46)
        pdf.ln(2)
        pdf.cuerpo_texto(
            "Se deja aclarado que esta correspondencia es una declaracion tecnica del perito "
            "sobre el procedimiento aplicado, y no una certificacion de conformidad emitida por "
            "un organismo acreditado. Se expone precisamente para que pueda ser controlada."
        )
        pdf.ln(3)

        # 4. Capacidades
        pdf.set_fill_color(13, 71, 161)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(FUENTE_INFORME, "B", 9)
        pdf.cell(0, 7, sanitize_text("  4. CAPACIDADES RESPECTO DE HERRAMIENTAS COMERCIALES"),
                 fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        pdf.cuerpo_texto(
            "Las herramientas comerciales de adquisicion web de referencia producen, en lo "
            "sustancial, el mismo conjunto de elementos que se acompaña: hash por pieza, acta de "
            "custodia, sello de tiempo, captura de pantalla, codigo de la pagina, cabeceras del "
            "servidor, certificado del servidor, copia del archivo de nombres del sistema y "
            "paquete final certificado. Se detallan a continuacion las capacidades incorporadas "
            "que no son de uso corriente en esas herramientas."
        )
        pdf.ln(1)
        extra = [
            ("Verificacion del codigo de Meta",
             "Se comprueba que el codigo servido por Facebook, Instagram y WhatsApp coincida con "
             "el manifiesto de transparencia que la propia Meta Platforms publica y firma. "
             "Acredita que la pagina adquirida no fue alterada del lado del servidor. La "
             "metodologia es publica (Meta Engineering, 2022) y el codigo de referencia es libre."),
            ("Verificador independiente",
             "Se acompaña una rutina que valida el caso completo usando solo la biblioteca "
             "estandar de Python. La contraparte no necesita instalar ni confiar en el programa "
             "que produjo la prueba."),
            ("Validacion documentada",
             "La herramienta se contrasta contra vectores publicados por el NIST y el IETF, y el "
             "resultado se informa. Permite afirmar contra que fue validada y con que resultado."),
            ("Registro de lo no adquirido",
             "Lo que no pudo obtenerse se informa con su motivo, en lugar de omitirse."),
            ("Cadena criptografica del log",
             "Las entradas del registro se encadenan con SHA-256 y la cadena se firma con una "
             "clave Ed25519 que nunca se escribe en disco."),
            ("Multiples autoridades de sellado",
             "Si una autoridad de tiempo no responde se recurre a las siguientes, y queda "
             "constancia de cuales fallaron. La evidencia no queda sin sellar por una caida."),
        ]
        for fi, (k, v) in enumerate(extra):
            pdf.tabla_fila(k, sanitize_text(v), fi, w_label=46)

        # LINEA DE FIRMA
        firma_path = self.perito_data.get("firma_path", "")
        hay_firma  = bool(firma_path and os.path.exists(firma_path))

        # Evitar que el bloque de firma quede cortado al pie de la página.
        if pdf.get_y() > 235:
            pdf.add_page()

        pdf.ln(25 if hay_firma else 15)   # más espacio cuando va imagen de firma
        y_linea = pdf.get_y()

        # Firma manuscrita del perito (imagen), centrada y apoyada sobre la línea.
        if hay_firma:
            try:
                with Image.open(firma_path) as _fimg:
                    _iw, _ih = _fimg.size
                aspecto = (_iw / _ih) if _ih else 3.0
                w_mm, h_max = 50.0, 22.0            # límites en mm
                h_mm = w_mm / aspecto
                if h_mm > h_max:
                    h_mm = h_max
                    w_mm = h_mm * aspecto
                x_mm = (210 - w_mm) / 2             # A4: 210 mm de ancho → centrada
                # La firma tambien se reduce a la medida en que se ve. Es un
                # archivo que elige el perito y suele ser un escaneo grande: se
                # vieron PNG de varios MB para ocupar 50 mm al pie de una hoja.
                firma_ins = imagen_para_informe(firma_path, w_mm, dir_temp)
                if firma_ins != firma_path:
                    temp_thumbs.append(firma_ins)
                pdf.image(firma_ins, x=x_mm, y=y_linea - h_mm, w=w_mm, h=h_mm)
            except Exception as e:
                self.case.log("WARN", "REPORTE", f"No se pudo incrustar la firma: {e}")

        pdf.set_draw_color(0, 0, 0)
        pdf.set_line_width(0.5)
        pdf.line(60, y_linea, 150, y_linea)
        pdf.ln(3)
        pdf.set_font(FUENTE_INFORME, "B", 11)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 7, "FIRMA", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(FUENTE_INFORME, "", 10)
        pdf.cell(0, 6, sanitize_text(self.perito_data.get('nombre', '')), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font(FUENTE_INFORME, "I", 9)
        pdf.cell(0, 5, sanitize_text(self.perito_data.get('titulo', '')), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if self.perito_data.get('matricula'):
            pdf.set_font(FUENTE_INFORME, "I", 8)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 5, sanitize_text(f"Matricula: {self.perito_data['matricula']}"), align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf_path = str(self.case.dirs["report"] / f"DICTAMEN_{self.case.case_id}.pdf")
        pdf.output(pdf_path)

        for tp in temp_thumbs:
            try:
                if os.path.exists(tp):
                    os.remove(tp)
            except Exception:
                pass

        # Generar sidecar de custodia para el PDF (igual que cada otra evidencia).
        # El PDF ya está cerrado (pdf.output() lo finaliza), el hash es definitivo.
        sid_pdf = write_custody_sidecar(
            path       = pdf_path,
            tipo       = "DICTAMEN_PDF",
            source_url = "",
            perito     = self.perito_data,
            case_id    = self.case.case_id,
            extra      = {
                "Evidencias totales": str(cant_total),
                "Capturas":           str(cant_img),
                "Videos sesion":      str(cant_vid),
                "Archivos media":     str(cant_media),
            }
        )
        h_pdf = sid_pdf["sha256"]
        self.case.register_evidence("DICTAMEN_PDF", pdf_path, metadata={"pdf_hash": h_pdf})

        self.case.log("INFO", "REPORT", f"Dictamen generado: {pdf_path}")
        self.append_console("─" * 60)
        self.append_console(f"✓ DICTAMEN : {Path(pdf_path).name}")
        self.append_console(f"  SHA-256  : {h_pdf}")
        self.append_console(f"  Momento  : {sid_pdf['ts_legible']}")
        self.append_console(f"  Sidecar  : {Path(sid_pdf['sha256_path']).name}")
        self.append_console(f"  Acta     : {Path(sid_pdf['custodia_path']).name}")
        self.append_console("─" * 60)

        # Cuando el dictamen se genera dentro del cierre es un paso intermedio:
        # abrir la carpeta y frenar con un cartel dejaria el empaquetado a
        # medias detras de un dialogo. El cierre da su propio aviso al final.
        if zip_info:
            return

        try:
            if platform.system() == "Windows":
                os.startfile(str(self.case.root))
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(self.case.root)])
            else:
                subprocess.run(["xdg-open", str(self.case.root)])
        except Exception:
            pass

        QMessageBox.information(self, "Dictamen Generado",
            f"Reporte guardado en:\n{pdf_path}\n\nHash SHA-256 del PDF:\n{h_pdf}")

    def exit_and_package(self):
        """
        Flujo de cierre certificado:
          1. Detener grabación
          2. Guardar HAR
          3. Generar el dictamen PDF
          4. Generar el ZIP con toda la evidencia, el dictamen incluido
          5. Calcular el SHA-256 del ZIP y escribir su sidecar, su acta de
             custodia y su sello de tiempo RFC 3161 (los tres FUERA del ZIP)
          6. Proteger los archivos como solo lectura y cerrar

        El dictamen va dentro del paquete y no lleva impreso el hash del
        paquete: seria un valor imposible de verificar, porque incorporar el
        propio dictamen al ZIP cambia ese hash. La huella del paquete vive
        afuera, en el sidecar, el acta y el sello, que es donde puede
        recalcularse y compararse. Ademas, cada pieza de evidencia queda
        certificada una por una en el registro del dictamen, de modo que la
        integridad del material sigue siendo comprobable aunque el paquete se
        vuelva a comprimir.
        """
        import zipfile as _zf

        resp = QMessageBox.question(
            self, "Salir y empaquetar caso",
            "Se detendrá la grabación (si está activa), se empaquetará toda\n"
            "la evidencia en un archivo ZIP certificado, se generará el dictamen\n"
            "PDF con el hash del ZIP incorporado y se cerrará el programa.\n\n"
            "¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if resp != QMessageBox.StandardButton.Yes:
            return

        # 1. Detener grabación si está activa
        if self.is_recording:
            self.toggle_recording()

        # 2. Guardar HAR (captura toda la actividad de red de la sesión)
        self.case.save_har()

        # 2b. Incluir el verificador junto a la prueba, para que quien la
        # reciba pueda comprobarla sin este programa y sin confiar en el.
        try:
            _verif = get_app_dir() / "verificar_caso.py"
            if _verif.exists():
                shutil.copy2(_verif, self.case.root / "verificar_caso.py")
                (self.case.root / "COMO_VERIFICAR.txt").write_text(
                    "VERIFICACION INDEPENDIENTE DE ESTA PRUEBA\n"
                    "=========================================\n\n"
                    "El archivo verificar_caso.py permite comprobar la integridad de\n"
                    "este material sin utilizar el programa que lo genero. Solo\n"
                    "requiere Python 3 y su biblioteca estandar.\n\n"
                    "Ejecutar desde una terminal, en la carpeta que contiene este caso:\n\n"
                    "    python verificar_caso.py .\n\n"
                    "Comprueba:\n"
                    "  1. Que cada archivo conserve el hash SHA-256 declarado.\n"
                    "  2. Que el registro de evidencias coincida con los archivos.\n"
                    "  3. Que el log de auditoria no fue alterado (cadena SHA-256 y firma Ed25519).\n"
                    "  4. Que el archivo WARC sea legible (requiere: pip install warcio).\n\n"
                    "Si alguna comprobacion falla, el material pudo haber sido modificado\n"
                    "despues de su adquisicion.\n",
                    encoding="utf-8")
                self.case.log("INFO", "CIERRE",
                              "Verificador independiente incluido en el paquete")
        except Exception as e:
            registrar_fallo_critico("CIERRE", f"No se pudo incluir el verificador: {e}")

        # 3. Empaquetar la evidencia tambien en WARC (ISO 28500), para que
        # pueda abrirse con herramientas independientes de esta. Se genera
        # antes del ZIP para quedar incluido en el.
        self.append_console("📚 Generando archivo WARC (ISO 28500)...")
        QApplication.processEvents()
        _warc = exportar_warc(self.case)
        if _warc:
            self.case.warc_info = _warc
            self.case.log("INFO", "WARC",
                          f"WARC generado: {Path(_warc['path']).name} | "
                          f"{_warc['registros']} registros | SHA-256: {_warc['sha256'][:24]}...")
            self.append_console(f"✓ WARC      : {Path(_warc['path']).name}")
            self.append_console(f"  Registros : {_warc['registros']}")
            self.append_console(f"  SHA-256   : {_warc['sha256']}")
        else:
            self.append_console("⚠ No se pudo generar el WARC (ver incidencias)")

        # Inventario en DFXML, tambien antes del ZIP para quedar adentro. Es lo
        # que permite que otra herramienta procese el caso sin conocer este
        # programa, del mismo modo que el verificador permite comprobarlo.
        self.append_console("🗂 Generando inventario DFXML...")
        QApplication.processEvents()
        _dfx = exportar_dfxml(self.case)
        if _dfx:
            self.append_console(f"✓ DFXML     : {Path(_dfx['path']).name}")
            self.append_console(f"  Objetos   : {_dfx['objetos']}")
        else:
            self.append_console("⚠ No se pudo generar el DFXML (ver incidencias)")

        # NOTA: la protección solo-lectura de los archivos se realiza AL FINAL
        # (después de generar el ZIP y el PDF). Marcarla acá dejaría la base de
        # datos audit.db en solo-lectura y toda escritura posterior (log,
        # register_evidence, dictamen) fallaría con "readonly database".

        # 4. Dictamen primero, paquete despues.
        #
        # El orden estaba al reves: se armaba el ZIP, se calculaba su hash y
        # recien despues se generaba el dictamen con ese hash impreso. El
        # dictamen quedaba entonces FUERA del paquete (habia que entregarlo
        # aparte) y, en cuanto alguien lo metia adentro para entregar una sola
        # cosa, el hash impreso dejaba de coincidir con el ZIP.
        #
        # Ahora se genera primero el dictamen, el ZIP lo incluye y la huella
        # del paquete se consigna por fuera: en el sidecar, el acta y el sello.
        # El paquete queda autocontenido y su huella sigue siendo verificable.
        zip_name = f"{self.case.case_id}.zip"
        zip_path = str(self.case.root.parent / zip_name)

        self.append_console("─" * 60)
        self.append_console("📄 Paso 1/3 — Generando dictamen PDF...")
        self.status.showMessage("Generando dictamen PDF...")
        QApplication.processEvents()

        try:
            self.generate_report(zip_info={"nombre": zip_name})
            pdf_path = str(self.case.dirs["report"] / f"DICTAMEN_{self.case.case_id}.pdf")

            self.append_console(f"📦 Paso 2/3 — Empaquetando evidencia en: {zip_name}")
            self.status.showMessage("Empaquetando evidencia...")
            QApplication.processEvents()

            # Un archivo que no se pueda leer no puede costar el paquete
            # entero. Antes, un solo archivo bloqueado abortaba el empaquetado
            # y el caso quedaba sin ZIP y sin dictamen. Ahora se omite, se
            # cuenta y se informa: es preferible un paquete con una constancia
            # de lo que falto que ningun paquete.
            # Barrido de temporales del informe. La limpieza normal esta al
            # final de generate_report, pero si la generacion se corta antes no
            # se llega a ejecutar y los sobrantes quedarian dentro del paquete.
            try:
                for _t in (self.case.dirs["thumbs"]).glob("inf_*"):
                    _t.unlink()
            except Exception:
                pass

            # Ultimo cierre firmado del log antes de copiarlo al paquete: asi
            # el log que viaja en el ZIP queda cubierto entero por la firma.
            self.case.flush_network_log()
            self.case.firmar_cabeza("antes de empaquetar")

            n_archivos = 0
            omitidos = []
            with _zf.ZipFile(zip_path, "w", compression=_zf.ZIP_DEFLATED, compresslevel=6) as zf:
                for fp in self.case.root.rglob("*"):
                    if not fp.is_file():
                        continue
                    # Restos de perfiles de navegacion de versiones anteriores:
                    # son material de trabajo y guardan credenciales de sesion.
                    if "browser_profile" in fp.parts:
                        continue
                    try:
                        arcname = fp.relative_to(self.case.root.parent)
                        zf.write(str(fp), str(arcname))
                        n_archivos += 1
                    except (PermissionError, OSError) as _e:
                        omitidos.append(f"{fp.name}: {_e}")

            # Con el log ya dentro del paquete el programa suelta la clave:
            # desde aca nadie puede agregar entradas firmadas a este caso.
            self.case.descartar_clave_log()

            if omitidos:
                self.append_console(f"  AVISO: {len(omitidos)} archivos no se pudieron incluir")
                for _o in omitidos[:5]:
                    self.append_console(f"     {_o}")
                registrar_fallo_critico(
                    "PAQUETE",
                    f"{len(omitidos)} archivos quedaron fuera del paquete por no poder leerse: "
                    + "; ".join(omitidos[:5]))
                self.case.log("ADVERTENCIA", "PACKAGE",
                              f"Archivos omitidos del ZIP: {'; '.join(omitidos[:10])}")

            # 5. Hash y tamaño del ZIP, ya con el dictamen adentro
            zip_hash = sha256_file(zip_path)
            zip_size = os.path.getsize(zip_path)
            zip_size_mb = zip_size / (1024 * 1024)

            self.append_console(f"  Archivos incluidos : {n_archivos}")
            self.append_console(f"  SHA-256 ZIP        : {zip_hash}")
            self.append_console(f"  Tamaño             : {zip_size:,} bytes  ({zip_size_mb:.2f} MB)")

            # 6. Huella del paquete: sidecar, acta y sello, los tres AFUERA
            #    del ZIP. Es el unico lugar donde el hash puede consignarse sin
            #    invalidarse a si mismo.
            self.append_console("🔏 Paso 3/3 — Certificando el paquete (huella fuera del ZIP)...")
            self.status.showMessage("Escribiendo acta de custodia...")
            QApplication.processEvents()

            # Sello de tiempo del ZIP, antes del acta para que el acta lo
            # consigne. Junto al paquete quedan la respuesta de la autoridad y
            # su cadena de certificados: con esos dos archivos un tercero lo
            # verifica con openssl sin depender de este programa.
            _sello = None
            try:
                _sello = escribir_sello_aparte(zip_path, zip_hash)
            except Exception as _e:
                self.case.log("ERROR", "PACKAGE", f"No se pudo sellar el ZIP: {_e}")
            _sello_ok = isinstance(_sello, dict) and bool(_sello.get("token_b64"))
            if _sello_ok:
                datos_sello = {
                    "Sello RFC 3161":     f"{_sello.get('timestamp_iso')}  "
                                          f"({_sello.get('tsa_nombre')}), firma verificada",
                    "Respuesta TSA":      Path(_sello["tsr_path"]).name,
                    "Cadena TSA":         Path(_sello["pem_path"]).name,
                    "Raiz que la cierra": f"{_sello.get('raiz_cierre')}  "
                                          f"SHA-256 {_sello.get('raiz_cierre_sha256')}",
                    "Reloj al cerrar":    f"{_sello.get('desfase_reloj_s'):+.2f} s respecto de "
                                          f"la hora firmada (margen "
                                          f"{_sello.get('incertidumbre_s'):.2f} s)",
                }
            else:
                datos_sello = {"Sello RFC 3161": "NO OBTENIDO: "
                               + str((_sello or {}).get("error", "error al sellar"))}

            sid = write_custody_sidecar(
                path       = zip_path,
                tipo       = "PAQUETE_CASO_ZIP",
                source_url = "",
                perito     = self.perito_data,
                case_id    = self.case.case_id,
                extra      = {
                    "Archivos incluidos": str(n_archivos),
                    "Tamano ZIP":         f"{zip_size:,} bytes  ({zip_size_mb:.2f} MB)",
                    "Dictamen PDF":       Path(pdf_path).name + " (incluido en el paquete)",
                    "Hash PDF":           sha256_file(pdf_path) if os.path.exists(pdf_path) else "N/A",
                    **datos_sello,
                }
            )

            if _sello_ok:
                self.append_console(
                    f"  Sello RFC 3161     : {Path(_sello['tsr_path']).name}  "
                    f"({_sello.get('tsa_nombre')}, firma verificada)")
                self.append_console(f"  Cadena de la TSA   : {Path(_sello['pem_path']).name}")
                self.case.log("INFO", "PACKAGE",
                              f"Sello de tiempo del ZIP verificado | "
                              f"autoridad: {_sello.get('tsa_nombre')} | "
                              f"fecha: {_sello.get('timestamp_iso')} | "
                              f"raiz: {_sello.get('raiz')}")
            else:
                self.append_console("  AVISO: no se obtuvo sello de tiempo verificable para el ZIP")
                registrar_fallo_critico(
                    "SELLO_TIEMPO",
                    "El paquete ZIP quedo sin sello de tiempo RFC 3161 independiente")

            self.case.log("INFO", "PACKAGE",
                f"ZIP certificado: {zip_name} | SHA-256: {zip_hash} | "
                f"{n_archivos} archivos | {zip_size:,} bytes")

            self.append_console(f"✓ ZIP       : {zip_name}")
            self.append_console(f"  SHA-256   : {zip_hash}")
            self.append_console(f"  Momento   : {sid['ts_legible']}")
            self.append_console(f"  Sidecar   : {Path(sid['sha256_path']).name}")
            self.append_console(f"  Acta      : {Path(sid['custodia_path']).name}")
            self.append_console("─" * 60)

            # PROTECCIÓN FINAL: marcar archivos como solo-lectura
            # Se hace al final, cuando ya no quedan escrituras pendientes en la
            # base de datos. Se registra el evento ANTES del chmod para que el
            # log alcance a escribirse mientras la DB aún es modificable.
            self.append_console("🔒 Protegiendo evidencia — marcando archivos como solo lectura...")
            self.status.showMessage("Protegiendo archivos de evidencia...")
            QApplication.processEvents()
            n_protegidos = 0
            n_error_prot = 0
            _files = [fp for fp in self.case.root.rglob("*") if fp.is_file()]
            # La base de datos se protege última para poder registrar el cierre.
            self.case.log("INFO", "CLOSE_CASE",
                           f"Cierre de caso: protegiendo {len(_files)} archivos como solo-lectura")
            # A partir de aca los fallos de escritura en el log son esperados
            # (la base queda en solo-lectura) y no deben reportarse como problema.
            self.case.caso_cerrado = True
            for fp in _files:
                try:
                    fp.chmod(0o444)   # r--r--r-- sin escritura para nadie
                    n_protegidos += 1
                except Exception:
                    n_error_prot += 1
            self.append_console(f"  Archivos protegidos : {n_protegidos}"
                                + (f" ({n_error_prot} con error)" if n_error_prot else ""))

            # Se borra el perfil de navegacion del caso. Guarda las cookies de
            # la sesion del perito (credenciales activas de sus cuentas) y no
            # forma parte de la prueba: no hay motivo para conservarlo una vez
            # cerrado el caso, y si para eliminarlo.
            _perfil = getattr(self, "_perfil_dir", None)
            if _perfil and Path(_perfil).exists():
                try:
                    shutil.rmtree(str(_perfil), ignore_errors=False)
                    self.append_console("  Perfil de navegacion borrado (contenia credenciales)")
                    self.case.log("INFO", "CIERRE",
                                  f"Perfil de navegacion del caso eliminado: {_perfil}")
                except Exception as _e:
                    # Los archivos siguen abiertos hasta que el proceso termina
                    self.append_console(
                        f"  AVISO: no se pudo borrar el perfil de navegacion.")
                    self.append_console(f"     Contiene credenciales de sesion: {_perfil}")
                    self.case.log("ADVERTENCIA", "CIERRE",
                                  f"No se pudo eliminar el perfil de navegacion ({_e}). "
                                  f"Contiene cookies de sesion: {_perfil}")
            self.append_console("─" * 60)

            QMessageBox.information(
                self, "Caso cerrado y empaquetado",
                f"La pericia ha sido cerrada exitosamente.\n\n"
                f"ZIP  : {zip_path}\n"
                f"SHA-256 ZIP: {zip_hash}\n"
                f"Tamaño : {zip_size_mb:.2f} MB  ({n_archivos} archivos)\n\n"
                f"El dictamen PDF va incluido dentro del paquete.\n"
                f"La huella del ZIP esta en {zip_name}.sha256, en su acta de custodia\n"
                f"y en el sello de tiempo {zip_name}.tsr, con la cadena de la autoridad\n"
                f"en {zip_name}.tsa.pem: entregue esos archivos junto con el ZIP para\n"
                f"que la contraparte pueda verificar la integridad."
            )

        except Exception as e:
            self.case.log("ERROR", "PACKAGE", f"Error al empaquetar: {e}")
            QMessageBox.critical(self, "Error al empaquetar",
                f"No se pudo generar el paquete del caso:\n{e}")
            return

        QApplication.quit()

    def closeEvent(self, event):
        """
        C3: Espera a que el hilo de mux/transcodificación termine antes de
        salir. Sin este join, cerrar la ventana mientras FFmpeg transcodifica
        puede dejar el MP4 final sin el moov atom (evidencia corrupta).
        Timeout de 310s > timeout interno de subprocess.run(..., timeout=300).
        """
        if self.is_recording:
            self.toggle_recording()
        mux = getattr(self, "_mux_thread", None)
        if mux is not None and mux.is_alive():
            self.append_console("⏳ Esperando finalización del procesamiento de video antes de cerrar...")
            mux.join(timeout=310)
            if mux.is_alive():
                self.case.log("WARN", "VIDEO", "closeEvent: mux thread no terminó en 310s — cerrando de todas formas")
        super().closeEvent(event)

# DIÁLOGO DE SETUP
class ForensicSetupDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SETUP - TRAVERSO FORENSICS · NAVEGADOR WEB FORENSE v1.0")
        self.setStyleSheet("background: white; color: black;")

        screen = QApplication.primaryScreen().availableGeometry()
        dlg_w = max(680, min(760, screen.width()  - 60))
        dlg_h = min(screen.height() - 60, 920)
        self.resize(dlg_w, dlg_h)
        self.setMinimumSize(dlg_w, min(dlg_h, 820))

        _perito_defaults = _load_perito_config()

        grp_style = """
            QGroupBox { color: #0d1b2a; font-weight: bold; font-size: 11px;
                        border: 2px solid #1b263b; padding: 4px; margin-top: 6px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
        """
        fld = ("color: black; background: #f9f9f9; border: 1px solid #1c2e4a; "
               "padding: 2px 6px; font-family: 'Segoe UI'; font-size: 10pt; min-height: 24px;")
        req     = fld + " border: 1px solid #c0392b;"
        info_css = "color: #555; font-size: 8pt;"
        btn_exp_css = ("background: #1b263b; color: white; padding: 2px 10px; "
                       "border-radius: 3px; font-size: 9pt; min-height: 24px;")

        def browse_row(field, btn):
            w = QWidget()
            h = QHBoxLayout(w)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(4)
            h.addWidget(field, 1)
            h.addWidget(btn)
            return w

        layout = QVBoxLayout()
        layout.setSpacing(4)
        layout.setContentsMargins(12, 6, 12, 6)

        # Logo
        if LOGO_PATH and os.path.exists(LOGO_PATH):
            lbl_logo = QLabel()
            lbl_logo.setPixmap(QPixmap(LOGO_PATH).scaled(
                160, 160, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation))
            lbl_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl_logo.setContentsMargins(0, 6, 0, 6)
            layout.addWidget(lbl_logo)

        # DATOS DEL PERITO
        grp_perito = QGroupBox("📋 DATOS DEL PERITO")
        grp_perito.setStyleSheet(grp_style)
        frm_perito = QFormLayout(grp_perito)
        frm_perito.setVerticalSpacing(3)
        frm_perito.setContentsMargins(8, 4, 8, 4)

        self.per_nombre    = QLineEdit(_perito_defaults.get("nombre", ""))
        self.per_titulo    = QLineEdit(_perito_defaults.get("titulo", ""))
        self.per_empresa   = QLineEdit(_perito_defaults.get("empresa", ""))
        self.per_email     = QLineEdit(_perito_defaults.get("email", ""))
        self.per_linkedin  = QLineEdit(_perito_defaults.get("linkedin", ""))
        self.per_matricula = QLineEdit(_perito_defaults.get("matricula", ""))
        self.per_firma     = QLineEdit(_perito_defaults.get("firma_path", ""))

        self.per_nombre.setStyleSheet(req)
        for w in [self.per_titulo, self.per_empresa, self.per_email,
                  self.per_linkedin, self.per_matricula, self.per_firma]:
            w.setStyleSheet(fld)
        self.per_firma.setToolTip(
            "Imagen PNG/JPG de la firma manuscrita del perito. Se incrusta al "
            "final del informe, sobre la línea de firma. Recomendado: fondo "
            "transparente o blanco."
        )
        btn_firma = QPushButton("📂 Explorar")
        btn_firma.setStyleSheet(btn_exp_css)
        btn_firma.clicked.connect(self._browse_firma)

        lbl_n = QLabel("Nombre completo *:")
        lbl_n.setStyleSheet("color: #c0392b; font-weight: bold;")
        frm_perito.addRow(lbl_n,                        self.per_nombre)
        frm_perito.addRow(QLabel("Titulo / Cargo:"),    self.per_titulo)
        frm_perito.addRow(QLabel("Empresa / Estudio:"), self.per_empresa)
        frm_perito.addRow(QLabel("Email:"),             self.per_email)
        frm_perito.addRow(QLabel("LinkedIn:"),          self.per_linkedin)
        frm_perito.addRow(QLabel("Matricula:"),         self.per_matricula)
        frm_perito.addRow(QLabel("Firma (imagen):"),    browse_row(self.per_firma, btn_firma))
        layout.addWidget(grp_perito)

        # DIRECTORIO DE GUARDADO
        grp_dir = QGroupBox("💾 DIRECTORIO DONDE GUARDAR EL CASO")
        grp_dir.setStyleSheet(grp_style)
        frm_dir = QFormLayout(grp_dir)
        frm_dir.setVerticalSpacing(3)
        frm_dir.setContentsMargins(8, 4, 8, 4)

        self.dir_caso = QLineEdit(str(get_app_dir()))
        self.dir_caso.setStyleSheet(req)
        self.dir_caso.setToolTip("El caso se guardará en: <directorio> / NAV_FORENSE / TFWF_FECHA_ID")
        btn_dir = QPushButton("📂 Explorar")
        btn_dir.setStyleSheet(btn_exp_css)
        btn_dir.clicked.connect(self._browse_dir_caso)

        lbl_dir_info = QLabel("Estructura: <directorio> / NAV_FORENSE / TFWF_FECHA_HORA_ID")
        lbl_dir_info.setStyleSheet(info_css)

        lbl_dir = QLabel("Guardar en *:")
        lbl_dir.setStyleSheet("color: #c0392b; font-weight: bold;")
        frm_dir.addRow(lbl_dir, browse_row(self.dir_caso, btn_dir))
        frm_dir.addRow(lbl_dir_info)
        layout.addWidget(grp_dir)

        # DATOS DEL CASO
        grp_caso = QGroupBox("📁 DATOS DEL CASO")
        grp_caso.setStyleSheet(grp_style)
        frm_caso = QFormLayout(grp_caso)
        frm_caso.setVerticalSpacing(3)
        frm_caso.setContentsMargins(8, 4, 8, 4)

        self.exp = QLineEdit(); self.exp.setStyleSheet(req)
        self.juz = QLineEdit(); self.juz.setStyleSheet(fld)
        self.car = QLineEdit(); self.car.setStyleSheet(fld)
        self.esc = QLineEdit(); self.esc.setStyleSheet(fld)
        self.esc_reg = QLineEdit(); self.esc_reg.setStyleSheet(fld)
        self.esc_col = QLineEdit(); self.esc_col.setStyleSheet(fld)
        self.obj = QTextEdit(); self.obj.setFixedHeight(42); self.obj.setStyleSheet(fld)

        lbl_exp = QLabel("Expediente *:")
        lbl_exp.setStyleSheet("color: #c0392b; font-weight: bold;")
        frm_caso.addRow(lbl_exp,                        self.exp)
        frm_caso.addRow(QLabel("Juzgado / Tribunal:"),  self.juz)
        frm_caso.addRow(QLabel("Caratula:"),            self.car)
        # El escribano que asiste a la diligencia da fe de lo actuado: su
        # identificacion tiene que ser completa, no un nombre suelto. Sin
        # registro ni colegio, la contraparte no puede verificar quien es.
        frm_caso.addRow(QLabel("Escribano / Notario:"), self.esc)
        frm_caso.addRow(QLabel("   Registro / Matricula:"), self.esc_reg)
        frm_caso.addRow(QLabel("   Colegio / Jurisdiccion:"), self.esc_col)
        frm_caso.addRow(QLabel("Objeto:"),              self.obj)
        layout.addWidget(grp_caso)

        lbl_req_note = QLabel("* Campos obligatorios")
        lbl_req_note.setStyleSheet("color: #c0392b; font-size: 8pt; padding: 1px 0;")
        layout.addWidget(lbl_req_note)

        lbl_info = QLabel(
            "SHA-256 del ejecutable | NTP sync | Log firmado Ed25519 | RFC 3161 | "
            "HAR v1.2 | Certificado X.509 autofirmado | ZIP protegido\n"
            "v1.0 — Autor: Miguel Angel Alfredo Traverso | Traverso Forensics"
        )
        lbl_info.setWordWrap(True)
        lbl_info.setStyleSheet(info_css)
        layout.addWidget(lbl_info)

        # Contenedor con scroll solo si la pantalla es muy pequeña
        container = QWidget()
        container.setLayout(layout)
        scroll = QScrollArea()
        scroll.setWidget(container)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none;")

        btn = QPushButton("▶   INICIAR SOFTWARE")
        btn.clicked.connect(self._on_accept)
        btn.setStyleSheet(
            "background: #1565C0; color: white; font-weight: bold; "
            "padding: 12px; font-size: 12pt; border-radius: 4px; "
            "border: 2px solid #42A5F5;"
        )
        btn.setMinimumHeight(52)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(scroll, 1)
        main_layout.addWidget(btn)

    def _browse_dir_caso(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Seleccionar directorio donde guardar el caso",
            self.dir_caso.text() or str(get_app_dir()),
            QFileDialog.Option.ShowDirsOnly
        )
        if folder:
            self.dir_caso.setText(folder)

    def _browse_firma(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar imagen de la firma del perito",
            self.per_firma.text() or str(get_app_dir()),
            "Imágenes (*.png *.jpg *.jpeg *.bmp);;Todos los archivos (*.*)"
        )
        if path:
            self.per_firma.setText(path)

    def _on_accept(self):
        """Valida campos obligatorios antes de iniciar."""
        errores = []
        if not self.per_nombre.text().strip():
            errores.append("• Nombre completo del perito")
        if not self.exp.text().strip():
            errores.append("• Número de expediente")
        if not self.dir_caso.text().strip():
            errores.append("• Directorio donde guardar el caso")
        if errores:
            QMessageBox.warning(
                self, "Campos obligatorios faltantes",
                "Complete los siguientes campos antes de continuar:\n\n" +
                "\n".join(errores)
            )
            return
        # Verificar que el directorio sea accesible (o se pueda crear)
        dir_path = Path(self.dir_caso.text().strip())
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            QMessageBox.critical(
                self, "Directorio inválido",
                f"No se puede usar el directorio seleccionado:\n{dir_path}\n\nError: {e}"
            )
            return
        self.accept()

    def get_data(self):
        return {
            "exp":      self.exp.text().strip(),
            "juz":      self.juz.text().strip(),
            "car":      self.car.text().strip(),
            "esc":      self.esc.text().strip(),
            "esc_reg":  self.esc_reg.text().strip(),
            "esc_col":  self.esc_col.text().strip(),
            "obj":      self.obj.toPlainText().strip(),
            "base_dir": self.dir_caso.text().strip(),
        }

    def get_perito_data(self):
        return {
            "nombre":     self.per_nombre.text().strip(),
            "titulo":     self.per_titulo.text().strip(),
            "empresa":    self.per_empresa.text().strip(),
            "email":      self.per_email.text().strip(),
            "linkedin":   self.per_linkedin.text().strip(),
            "matricula":  self.per_matricula.text().strip(),
            "firma_path": self.per_firma.text().strip(),
        }

# VERIFICACION DE DEPENDENCIAS EXTERNAS
def _check_external_deps() -> tuple:
    """
    Verifica herramientas externas que NO se instalan con pip.
    Retorna (issues_list, ffmpeg_ok).
    N4: también verifica yt-dlp, crítico para adquisición de Instagram/Facebook.
    """
    issues = []
    ffmpeg_ok = False

    # FFmpeg
    try:
        r = subprocess.run(
            ["ffmpeg", "-version"],
            capture_output=True, timeout=6
        )
        if r.returncode == 0:
            first = r.stdout.decode("utf-8", errors="ignore").splitlines()[0]
            version = first.split("version")[-1].strip().split(" ")[0] if "version" in first else "?"
            ffmpeg_ok = True
            issues.append(("OK", f"FFmpeg {version} — grabación con audio H.264 disponible"))
    except FileNotFoundError:
        issues.append(("ERROR",
            "FFmpeg NO encontrado.\n"
            "  Sin FFmpeg: el video se graba sin audio y sin compresión H.264\n"
            "  (archivos más grandes, sin mezcla de audio).\n\n"
            "  Para instalarlo:\n"
            "  • Windows: https://ffmpeg.org/download.html  →  'Windows builds by BtbN'\n"
            "              Descomprimir y agregar la carpeta 'bin' al PATH del sistema.\n"
            "  • O instalar con Winget:  winget install ffmpeg\n"
            "  • O instalar con Chocolatey:  choco install ffmpeg"
        ))
    except Exception as e:
        issues.append(("WARN", f"FFmpeg — no se pudo verificar: {e}"))

    # yt-dlp
    try:
        r2 = subprocess.run(
            ["yt-dlp", "--version"],
            capture_output=True, timeout=6
        )
        if r2.returncode == 0:
            ver2 = r2.stdout.decode("utf-8", errors="ignore").strip().splitlines()[0]
            issues.append(("OK", f"yt-dlp {ver2} — descarga Instagram/Facebook disponible"))
        else:
            issues.append(("WARN", "yt-dlp instalado pero retornó error al verificar versión"))
    except FileNotFoundError:
        issues.append(("WARN",
            "yt-dlp NO encontrado.\n"
            "  Sin yt-dlp: la descarga de videos de Instagram y Facebook no estará disponible.\n"
            "  Instalar con:  pip install yt-dlp"
        ))
    except Exception as e:
        issues.append(("WARN", f"yt-dlp — no se pudo verificar: {e}"))

    return issues, ffmpeg_ok


def _show_deps_dialog(issues: list, ffmpeg_ok: bool):
    """Muestra diálogo informativo con estado de dependencias externas."""
    if ffmpeg_ok:
        return
    dlg = QDialog()
    dlg.setWindowTitle("Verificación de dependencias — Traverso Forensics · Navegador Web Forense")
    dlg.setMinimumWidth(600)
    dlg.setStyleSheet("background:#0d1b2a; color:#e8f0f8;")
    lay = QVBoxLayout(dlg)
    lay.setContentsMargins(20, 20, 20, 20)
    lay.setSpacing(14)
    title = QLabel("<b style='font-size:12pt;'>Estado de herramientas externas</b>")
    title.setStyleSheet("color:#7dd3fc;")
    lay.addWidget(title)
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setStyleSheet("border:1px solid #1b3a5c; border-radius:4px;")
    inner = QWidget()
    inner.setStyleSheet("background:#0a111a;")
    inner_lay = QVBoxLayout(inner)
    inner_lay.setContentsMargins(12, 12, 12, 12)
    inner_lay.setSpacing(10)
    for level, msg in issues:
        if level == "OK":
            color, icon = "#4ade80", "✓"
        elif level == "ERROR":
            color, icon = "#f87171", "✗"
        else:
            color, icon = "#fbbf24", "⚠"
        lbl = QLabel(f"<span style='color:{color};font-weight:bold;'>{icon}</span>  "
                     + msg.replace("\n", "<br>&nbsp;&nbsp;&nbsp;"))
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"color:#e8f0f8; font-size:9pt; padding:8px; "
                          f"border-left:3px solid {color}; background:#111e2e; border-radius:3px;")
        lbl.setTextFormat(Qt.TextFormat.RichText)
        inner_lay.addWidget(lbl)
    inner_lay.addStretch()
    scroll.setWidget(inner)
    lay.addWidget(scroll, 1)
    nota = QLabel(
        "<b style='color:#fbbf24;'>Sin FFmpeg</b> el programa funciona normalmente "
        "pero la grabación de sesión NO tendrá audio y el video se guardará sin "
        "compresión H.264 (archivos más grandes). Instalarlo es opcional pero recomendado."
    )
    nota.setWordWrap(True)
    nota.setStyleSheet("color:#9ca3af; font-size:9pt; padding:8px; "
                       "border:1px solid #374151; border-radius:3px; background:#111e2e;")
    lay.addWidget(nota)
    btn = QPushButton("Entendido — Continuar")
    btn.setStyleSheet(
        "QPushButton{background:#1565C0;color:white;font-weight:bold;"
        "padding:10px;border-radius:4px;font-size:10pt;}"
        "QPushButton:hover{background:#1976D2;}"
    )
    btn.clicked.connect(dlg.accept)
    lay.addWidget(btn)
    dlg.exec()


# PUNTO DE ENTRADA
if __name__ == "__main__":
    # Suprimir SetProcessDpiAwarenessContext warning de Qt en Windows.
    # Qt 6 intenta DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 pero en algunos
    # entornos Windows (UAC restringido, contenedores) el acceso es denegado.
    # QT_ENABLE_HIGHDPI_SCALING=0 fuerza el modo legacy sin necesitar privilegios.
    if platform.system() == "Windows":
        os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "0")
        os.environ.setdefault("QT_SCALE_FACTOR_ROUNDING_POLICY", "PassThrough")
        # Suprimir advertencia de SetProcessDpiAwarenessContext (acceso denegado en
        # entornos con UAC restringido). Qt ignora el error y usa DPI scaling propio.
        # QT_LOGGING_RULES ya fue configurado al inicio del módulo con todas las reglas
    app = QApplication(sys.argv)
    # Verificar dependencias externas antes del Setup
    issues, ffmpeg_ok = _check_external_deps()
    _show_deps_dialog(issues, ffmpeg_ok)
    dial = ForensicSetupDialog()
    if dial.exec():
        main = TraversoWebForensicsPro(dial.get_data(), dial.get_perito_data())
        main.showMaximized()
        sys.exit(app.exec())
