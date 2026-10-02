# -*- coding: utf-8 -*-
"""Ejecuta la seccion COMENTARIOS RELEVADOS del reporte tal como esta escrita en
el programa —se extrae del propio archivo, no se copia— contra dos listados
armados con datos medidos de Instagram y de Facebook."""
import hashlib
import io
import os
import re
import sys
import textwrap
from pathlib import Path

RUTA = r"C:\navegadorforense\navegador_forense_pro_v1_0.py"
SALIDA = Path(os.environ.get("TEMP", ".")) / "prueba_reporte_comentarios"
SALIDA.mkdir(exist_ok=True)

sys.path.insert(0, r"C:\navegadorforense")
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import navegador_forense_pro_v1_0 as app   # noqa: E402

# ------------------------------------------------------------ listados reales
ig = """COMENTARIOS DE PUBLICACION - Instagram
Caso        : TFWF_PRUEBA
Momento     : 2026-08-28T15:40:00
Publicacion : https://www.instagram.com/p/EJEMPLO00001/
Comentarios : 4
Estado      : recorrido hasta el final
Fechas      : tomadas del atributo datetime de la pagina (UTC
              exacto), no del texto relativo en pantalla.
Respuestas  : las respuestas plegadas NO se desplegaron; se deja
              constancia de las que la pagina declaro (3).
======================================================================

DESCRIPCION DE LA PUBLICACION
  Autor : @cuenta_de_ejemplo
  Marcas: Editado
  Fecha : 2026-08-27T19:09:43.000Z  (27 de agosto de 2026)
  Texto : Publicacion de ejemplo para la prueba del informe, con una mencion a @otra_cuenta_de_ejemplo y un texto de largo parecido al real.

======================================================================

COMENTARIOS

    1. @primer_usuario | 2026-08-27T19:08:32.000Z | 28 me gusta; 2 respuestas plegadas
       Primer comentario de ejemplo, de una sola linea

    2. @segundo_usuario | 2026-08-27T21:25:38.000Z | 10 me gusta
       Segundo comentario, breve

    3. @tercer_usuario | 2026-08-27T20:01:32.000Z | 9 me gusta; 1 respuestas plegadas
       Tercero, mas breve todavia

    4. @cuarto_usuario | 2026-08-27T21:40:11.000Z | 10 me gusta
       Un texto deliberadamente largo para forzar que la fila ocupe varias lineas y comprobar que el recuadro acompana al contenido en lugar de cortarlo por la mitad como pasaba antes del arreglo de la tabla.
"""

fb = """COMENTARIOS DE PUBLICACION - Facebook
Caso        : TFWF_PRUEBA
Momento     : 2026-08-28T15:41:00
Publicacion : https://www.facebook.com/pagina.de.ejemplo/posts/pfbid0EJEMPLO00001
Comentarios : 5
Estado      : recorrido hasta el final
Fechas      : tomadas del rotulo de accesibilidad del enlace de
              hora, que publica la fecha y hora completas, no
              del texto relativo en pantalla.
Respuestas  : las respuestas plegadas NO se desplegaron; se deja
              constancia de las que la pagina declaro (3).
======================================================================

COMENTARIOS

    1. @Pagina De Ejemplo (pagina.de.ejemplo) | jueves, 27 de agosto de 2026 a las 9:06 pm | Autor
       Texto de la publicacion de ejemplo, escrito por la propia pagina

    2. @Primera Persona (primera.persona.8633) | jueves, 27 de agosto de 2026 a las 9:12 pm |
       Primer comentario de ejemplo, con signos de pregunta?

    3. @Segunda Persona (segunda.persona) | jueves, 27 de agosto de 2026 a las 9:30 pm | Fan destacado
       Segundo comentario, con "comillas" adentro

    4. @Tercera Persona (tercera.persona) | jueves, 27 de agosto de 2026 a las 10:15 pm | 1 respuestas plegadas
       Tercer comentario de ejemplo, de dos oraciones. La segunda es esta.

    5. @Cuarta Persona (cuarta.persona.376) | jueves, 27 de agosto de 2026 a las 10:48 pm | 1 respuestas plegadas
       Comentario deliberadamente largo, para comprobar que una fila de varias lineas no se corta por la mitad al llegar al final de la hoja, que es lo que pasaba antes del arreglo de la tabla del informe.
"""

evidencias = []
for nombre, contenido in (("Comentarios_Instagram_20260828_154000.txt", ig),
                          ("Comentarios_Facebook_20260828_154100.txt", fb)):
    p = SALIDA / nombre
    io.open(p, "w", encoding="utf-8").write(contenido)
    evidencias.append({
        "tipo": "COMENTARIOS", "filename": nombre, "path": str(p),
        "sha256": hashlib.sha256(contenido.encode("utf-8")).hexdigest(),
    })


# ------------------------------------------- se extrae la seccion del programa
fuente = io.open(RUTA, encoding="utf-8").read()
ini = fuente.index('        # SECCION: COMENTARIOS DE PUBLICACIONES')
fin = fuente.index('        # ANEXO: VISTAS DEL CHAT')
seccion = textwrap.dedent(fuente[ini:fin])
print("Seccion extraida del programa: %d lineas" % seccion.count("\n"))


class CasoFalso:
    evidences = evidencias


class Yo:
    case = CasoFalso()


pdf = app.DictamenForense()
pdf.add_page()

entorno = {
    "self": Yo(), "pdf": pdf, "os": os, "re": re,
    "sanitize_text": app.sanitize_text, "XPos": app.XPos, "YPos": app.YPos,
}
exec(seccion, entorno)

destino = SALIDA / "prueba_comentarios.pdf"
pdf.output(str(destino))
print("PDF generado: %s (%d paginas)" % (destino, pdf.pages_count if hasattr(pdf, "pages_count") else pdf.page))
