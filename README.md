# Navegador Web Forense — Traverso Forensics

Navegador para adquirir prueba digital de sitios web y redes sociales con cadena
de custodia: cada pieza se guarda con su hash, su acta y su sello de tiempo, y
al cerrar la sesión el programa emite un dictamen y arma el paquete.

Está hecho para una pericia: lo que se adquiere tiene que poder verificarlo un
tercero —la contraparte, un perito de control, el juzgado— sin este programa y
sin creerle nada al perito.

- **Autor:** Miguel Angel Alfredo Traverso — Traverso Forensics
- **Plataforma:** Windows, Python 3.11, PyQt6 + Qt WebEngine
- **Norma de referencia:** ISO/IEC 27037:2012

---

## Qué adquiere

- Capturas de pantalla y de página completa, con recorrido automático de
  comentarios, de listas de contactos y de conversaciones de WhatsApp Web.
- Video de la sesión (FFmpeg), tráfico de red en HAR 1.2 y archivo WARC
  (ISO 28500).
- Página archivada en MHTML, código fuente, cabeceras HTTP, certificado TLS del
  servidor y archivo `hosts` del equipo: acreditan en qué condiciones se accedió.
- Multimedia original de Instagram, Facebook (yt-dlp) y WhatsApp Web, con hash
  propio: es el archivo tal como lo sirve la plataforma, no una regrabación.

## Qué garantiza

| | |
|---|---|
| **Cada archivo** | SHA-256 + acta de custodia (`.sha256` y `.custodia.txt` al lado) |
| **Sello de tiempo** | RFC 3161 con la firma **verificada** contra cuatro raíces fijadas en el programa; una respuesta que no verifica se rechaza y se deja constancia |
| **Log de auditoría** | cada entrada encadenada con SHA-256 y la cadena firmada con una clave Ed25519 que vive solo en memoria y nunca se escribe en disco |
| **La herramienta** | hash del ejecutable y del conjunto de sus 344 archivos, con el manifiesto adentro del paquete |
| **El reloj** | contrastado contra la hora firmada de la autoridad de sellado, que no se puede falsear en el camino, además de NTP |
| **El paquete** | ZIP con todo, su hash fuera del ZIP, sello RFC 3161 propio y la cadena de certificados de la autoridad |

## Verificar un caso (sin este programa)

```bash
python verificar_caso.py <carpeta del caso>
```

Solo usa la biblioteca estándar de Python: recalcula el hash de cada archivo,
contrasta el registro de evidencias, recorre el encadenamiento del log y
comprueba sus firmas Ed25519 (implementación de referencia del RFC 8032
incluida en el propio verificador).

Archivo suelto:

```bash
certutil -hashfile <archivo> SHA256
```

Sello de tiempo del paquete:

```bash
openssl ts -verify -data <caso>.zip -in <caso>.zip.tsr -CAfile <caso>.zip.tsa.pem
```

## Compilar

```bat
compilar_onedir.bat
```

Hace tres cosas: corre el control de nombres sin definir (si falla, no compila),
compila con PyInstaller desde `.venv-forense` y escribe el manifiesto oficial de
archivos de la versión. El instalador se arma aparte:

```bat
"C:\Program Files\Inno Setup 7\ISCC.exe" instalador.iss
```

Entorno de compilación fijado en `requirements-build.txt`. El entorno se arma
aparte del Python del sistema a propósito: con otros *bindings* de Qt instalados
PyInstaller aborta.

## Pruebas

En `desarrollo/`. Cada una ejecuta el código del programa, no una copia de su
lógica, y acepta la ruta de un `.py` para correrla contra un respaldo anterior y
comprobar que ahí falla.

```bat
.venv-forense\Scripts\python.exe -u desarrollo\test_sello_verificado.py
```

Las que abren el motor (listas, comentarios, rueda, descargas) **se corren de a
una**: dos procesos de QtWebEngine en paralelo se tiran abajo y parece un fallo
del programa.

## Limitación conocida

El motor no incluye los códecs H.264/AAC —no vienen compilados en la versión
abierta de Qt WebEngine, y no los traen ni los *wheels* de Riverbank ni los de la
propia Qt Company—, así que el video de WhatsApp e Instagram no se reproduce
dentro del navegador y su recuadro puede verse en negro. El contenido no se
pierde: se adquiere como archivo original con su hash y se reproduce en el visor
del programa, que usa los códecs del sistema. El dictamen lo declara y
transcribe los formatos que el motor informó en esa diligencia.
