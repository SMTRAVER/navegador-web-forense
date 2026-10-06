# Navegador Web Forense V1.0

Navegador para adquirir prueba de sitios web y redes sociales dejando cadena de custodia.
Cada archivo sale con su hash, su acta y su sello de tiempo. Al cerrar la sesión el
programa emite el dictamen y arma el paquete.

Lo que se adquiere tiene que poder comprobarlo otro sin este programa y sin creerle nada
al perito: la contraparte, el juzgado, quien sea.

Windows, Python 3.11, PyQt6 con Qt WebEngine. Referencia: ISO/IEC 27037:2012.
Autor: Miguel Angel Alfredo Traverso, Traverso Forensics.

## Qué adquiere

- Capturas de pantalla y de página completa. Los recorridos de comentarios, de listas de
  contactos y de conversaciones de WhatsApp Web se hacen solos, desplazando con la rueda
  del mouse como lo haría una persona.
- Video de la sesión con FFmpeg, en el perfil que se elija: FFV1 sin pérdida cuando la
  grabación es la prueba, H.264 cuando alcanza con que se vea. El dictamen declara con
  cuál se grabó y con qué parámetros, porque no es lo mismo.
- Tráfico de red en HAR 1.2 y archivo WARC (ISO 28500).
- La página archivada en MHTML, su código fuente, las cabeceras HTTP, el certificado TLS
  del servidor y el archivo hosts del equipo. Con eso se acredita a qué servidor se
  accedió y que el dominio no estaba desviado.
- El multimedia original de Instagram, Facebook (con yt-dlp) y WhatsApp Web, con hash
  propio. Es el archivo que sirve la plataforma, no una regrabación de la pantalla.

## Qué queda escrito

Cada archivo adquirido lleva al lado su `.sha256` y su `.custodia.txt`.

El sello de tiempo es RFC 3161, y antes de darlo por bueno el programa verifica la firma
contra cuatro raíces que trae fijadas. Si una autoridad contesta algo que no verifica, se
rechaza y queda asentado. 

El log de auditoría encadena cada entrada con la anterior usando SHA-256. La cadena se
firma con una clave Ed25519 que se genera al abrir el caso, vive en memoria y no se
escribe nunca en disco; al terminar el empaquetado se descarta. Desde ahí nadie puede
agregar entradas firmadas, el perito tampoco.

De la herramienta se declaran dos hashes: el del ejecutable y el del conjunto de sus 344
archivos, con el manifiesto adentro del paquete. Contra el manifiesto oficial de la
versión se ve enseguida si alguien reemplazó un componente, que es lo que el hash del
.exe solo no mostraba.

El reloj del equipo se contrasta con la hora firmada por la autoridad de sellado, además
del NTP de siempre. 

El paquete final es un ZIP con todo adentro. Su hash va afuera, en el sidecar, el acta y
un sello RFC 3161 propio, acompañado por la cadena de certificados de la autoridad.

Del equipo salen tres cosas: el hash a sellar, la consulta de hora y la comprobación del
código de los portales de Meta contra Cloudflare. La prueba adquirida no se sube a
ninguna parte.

## Verificar un caso sin este programa

```bash
python verificar_caso.py <carpeta del caso>
```

Usa solo la biblioteca estándar. Recalcula el hash de cada archivo, contrasta el registro
de evidencias, recorre el encadenamiento del log y comprueba sus firmas. La
implementación de referencia de Ed25519 del RFC 8032 va adentro del propio verificador,
así que no hay que instalar nada.

Un archivo suelto:

```bash
certutil -hashfile <archivo> SHA256
```

El sello del paquete:

```bash
openssl ts -verify -data <caso>.zip -in <caso>.zip.tsr -CAfile <caso>.zip.tsa.pem
```

## Lo que no hace

El motor no reproduce H.264 ni AAC. No vienen compilados en la versión abierta de Qt
WebEngine y no hay forma de agregarlos desde afuera: se probó con los wheels de Riverbank
y con los de la propia Qt Company, y ninguno los trae. El video de WhatsApp y de
Instagram no se ve dentro del navegador, y el recuadro puede quedar en negro también en
la grabación de la sesión.

El contenido igual no se pierde. Se adquiere como archivo original con su hash y se mira
en el visor del programa, que usa los códecs de Windows. El dictamen lo declara y
transcribe qué formatos informó el motor ese día.
