# Validacion de la herramienta

**Traverso Forensics · Navegador Web Forense v1.0** | commit `08cbf07` | 05/10/2026 11:07

Este informe se genera ejecutando las pruebas, no escribiendolo: cada afirmacion queda con el resultado que dio en esta corrida. Para rehacerlo:

```bash
python desarrollo/validacion_cftt.py
```

## Metodo

Se sigue la forma del programa de pruebas de herramientas forenses del NIST (Computer Forensics Tool Testing): **requisito -> afirmacion -> caso de prueba -> resultado**.

Ninguna de las once categorias del CFTT cubre la captura de sitios web o redes sociales. La mas cercana es la de extraccion de datos en la nube con credenciales (CDX), cuya especificacion v1.1 de enero de 2025 incorporo una seccion para servicios de mensajeria y redes sociales. De ahi salen los requisitos **CDX**. Los **TF** son los que la propia herramienta afirma en su dictamen: si el dictamen lo dice, hay que poder sostenerlo.

Esta validacion es propia. El NIST no probo esta herramienta ni la avala.

## Resultados

| Requisito | Origen | Afirmacion | Casos de prueba | Resultado |
|---|---|---|---|---|
| **CDX-CR-04 / CA-04** | NIST CFTT CDX v1.1 | La herramienta informa todos los artefactos extraidos, y los presenta de forma exacta y completa. | `test_cierre_paquete`: PASA<br>`test_comentarios_dos_posts`: PASA<br>`test_lista_amigos_fb`: PASA<br>`test_espera_carga`: PASA<br>`test_decision_tramo`: PASA<br>`test_sello_en_metadatos`: PASA | **PASA** |
| **CDX-CA-05** | NIST CFTT CDX v1.1 | La herramienta transcribe correctamente el texto en ingles. | `test_texto_multilingue`: PASA | **PASA** |
| **CDX-CA-06** | NIST CFTT CDX v1.1 | La herramienta transcribe correctamente el texto que no esta en ingles: acentos y diereses, alfabetos no latinos, kanji, kana y escritura de derecha a izquierda. | `test_texto_multilingue`: PASA | **PASA** |
| **TF-RQ-01** | Afirmado en el dictamen | Cada pieza de evidencia queda con su SHA-256 y su acta de custodia, y la imagen capturada no se altera al guardarla. | `test_sello_en_metadatos`: PASA<br>`test_cierre_paquete`: PASA | **PASA** |
| **TF-RQ-02** | Afirmado en el dictamen | El sello de tiempo RFC 3161 se verifica antes de aceptarlo: firma, hash sellado, numero de control y cadena hasta una raiz reconocida. Un sello que no verifica se rechaza. | `test_sello_verificado`: PASA | **PASA** |
| **TF-RQ-03** | Afirmado en el dictamen | El log de auditoria no se puede alterar sin que se note, ni siquiera teniendo el paquete completo. | `test_cadena_log`: PASA | **PASA** |
| **TF-RQ-04** | Afirmado en el dictamen | La herramienta declara su identidad: hash del ejecutable y del conjunto de sus archivos, y no se compila con nombres sin definir. | `test_hash_herramienta`: PASA<br>`test_nombres_indefinidos`: PASA | **PASA** |
| **TF-RQ-05** | Afirmado en el dictamen | El reloj del equipo se contrasta contra una hora firmada, que no se puede falsear en la red, y la discrepancia se informa. | `test_contraste_hora`: PASA | **PASA** |
| **TF-RQ-06** | Afirmado en el dictamen | Nada entra a la carpeta de evidencia sin que lo pida el programa o lo acepte el perito, y la decision queda registrada. | `test_descarga_no_pedida`: PASA | **PASA** |
| **TF-RQ-07** | ISO/IEC 27037 | Lo que la herramienta no puede hacer se declara en el dictamen, con lo que el motor informo en esa diligencia. | `test_codecs_en_dictamen`: PASA | **PASA** |
| **TF-RQ-08** | Metodo del CFTT | Las funciones criptograficas se contrastan contra vectores publicados (FIPS 180-4 y RFC 8032), no contra lo que afirme el fabricante. | `test_autodiagnostico`: PASA<br>`validacion_forense`: PASA | **PASA** |
| **TF-RQ-09** | Afirmado en el dictamen | La prueba se puede verificar sin esta herramienta: el verificador usa solo la biblioteca estandar y el sello se comprueba con openssl. | `test_cadena_log`: PASA<br>`test_sello_verificado`: PASA | **PASA** |
| **TF-RQ-10** | Afirmado en el dictamen | Se comprueba que el codigo que sirvio el sitio sea el que la plataforma publico ante un tercero (binary transparency). | `test_bt_integrado`: PASA<br>`test_seccion_bt`: PASA | **PASA** |
| **TF-RQ-11** | Ofrecido en la interfaz | La grabacion de la sesion se hace con el perfil de calidad que eligio el perito —no con otro—, el archivo se cierra completo, y el dictamen declara con que se grabo. | `test_grabacion_perfil`: PASA | **PASA** |

## Detalle de cada corrida

| Prueba | Resultado | Tiempo | Salida |
|---|---|---|---|
| `test_autodiagnostico`  | PASA | 1 s |     coinciden: True |
| `test_bt_integrado`  | PASA | 10 s | >>> RESULTADO                    : VERIFICADO |
| `test_cadena_log`  | PASA | 3 s | RESULTADO: correcto |
| `test_cierre_paquete`  | PASA | 6 s | RESULTADO: correcto |
| `test_codecs_en_dictamen`  | PASA | 4 s | RESULTADO: correcto |
| `test_comentarios_dos_posts`  | PASA | 3 s | BIEN: la segunda publicacion trae solo sus comentarios |
| `test_contraste_hora`  | PASA | 2 s | RESULTADO: correcto |
| `test_decision_tramo`  | PASA | 1 s | RESULTADO: correcto |
| `test_descarga_no_pedida`  | PASA | 9 s | RESULTADO: correcto |
| `test_espera_carga`  | PASA | 21 s | RESULTADO: correcto - nunca capturo sobre marcadores de carga |
| `test_fluidez_scroll` informativa | PASA | 21 s | CONCLUSION: el interceptor traba el scroll |
| `test_grabacion_perfil`  | PASA | 22 s | RESULTADO: correcto |
| `test_hash_herramienta`  | PASA | 1 s | RESULTADO: correcto |
| `test_lista_amigos_fb`  | PASA | 27 s | RESULTADO: correcto |
| `test_nombres_indefinidos`  | PASA | 0 s | RESULTADO: correcto - ningun nombre sin definir |
| `test_peso_dictamen` informativa | PASA | 8 s | RESULTADO: correcto |
| `test_reporte_comentarios` informativa | PASA | 1 s | PDF generado: C:\Users\MIGUE_~1\AppData\Local\Temp\prueba_reporte_comentarios\prueba_comentarios.pdf (3 pagina |
| `test_rueda_scroll` informativa | PASA | 7 s | FUNCIONAN: postEvent NoScrollPhase (actual), sendEvent NoScrollPhase, postEvent x3 seguidos |
| `test_seccion_bt`  | PASA | 1 s | PNG: C:\Users\MIGUE_~1\AppData\Local\Temp\bt_con_fuentes.png |
| `test_sello_en_metadatos`  | PASA | 1 s | RESULTADO: correcto |
| `test_sello_verificado`  | PASA | 6 s | RESULTADO: correcto |
| `test_texto_multilingue`  | PASA | 4 s | RESULTADO: correcto |
| `test_velocidad_perfil` informativa | PASA | 4 s | para separar el costo de la configuracion del de la cache fria. |
| `validacion_forense`  | PASA | 1 s | RESULTADO: 25 de 25 pruebas superadas |

## Lo que no se cumple

- **CDX-CR-02 / CA-02.** La herramienta no avisa por si misma que las credenciales son invalidas: el aviso lo da el sitio en la propia pantalla, que es lo que el perito ve y lo que queda en la captura. No se cumple como lo pide la especificacion.
- **CDX-CR-03 / CA-03.** No se presenta al usuario una lista de servicios soportados. El programa es un navegador: sirve para cualquier sitio, y tiene recorridos automaticos para Instagram, Facebook, TikTok y WhatsApp Web. Esta documentado en el README, no en la interfaz.
- **CDX-CA-06 (parcial).** Las lenguas de derecha a izquierda se componen con HarfBuzz y se ven correctamente, pero el programa no aplica el algoritmo bidireccional completo de Unicode: un parrafo que mezcle arabe y latino en la misma linea puede quedar con los tramos en otro orden. El listado .txt conserva el original.
- **Video H.264/AAC.** El motor no reproduce esos codecs y el recuadro del video puede verse en negro. El video se adquiere como archivo original con su hash. Declarado en el dictamen.
- **Perfil de grabacion sin FFmpeg.** Si el equipo no tiene FFmpeg, la sesion se graba con OpenCV en mp4v y el perfil de calidad elegido no se puede aplicar: FFV1 sin perdida no esta disponible por esa via. El desplegable queda deshabilitado y el acta de custodia lo declara, pero la limitacion existe y depende del equipo, no del programa.
- **Repeticion independiente.** Las pruebas corrieron en un solo equipo. El CFTT espera que el resultado se repita en otro, con otro operador.
- **Revision externa.** La validacion es propia. Ningun laboratorio ni organismo la reviso.

## Entorno de la corrida

| | |
|---|---|
| Codigo fuente validado | `9b378514e4d57d05bec3def002a62194b2868374fd6ec07f9c2c6a8144735699` |
| Conjunto de archivos de la version compilada | `8c6c994459ba41e56aff3b2767461605b43926f2a3b7bd757cefeb9a42a318de` |
| Instalador | `fd3733051b33a09be9888dfc7d53302b7c719167f99da9e342c7f56e9c2b2610` |
| Motor del navegador | Qt WebEngine 6.11.2 - Chromium 140.0.7339.225, parches de seguridad al nivel 151.0.7922.71 |
| Fuentes del informe | Arial y Courier New incrustadas, con respaldo de Microsoft YaHei (chino y japones) y Segoe UI Emoji, y composicion de derecha a izquierda con HarfBuzz |
| Raices de sellado reconocidas | Certum Trusted Network CA 2, DigiCert Trusted Root G4, FreeTSA Root CA, Sectigo Public Time Stamping Root R46 |
| Sistema operativo | Windows-11-26200-SP0 |
| Python | 3.11.3 |
| Equipo | EQUIPO_PERICIAS |

## Como repetir una prueba suelta

Cada prueba acepta la ruta de un `.py`, de modo que puede correrse contra un respaldo anterior para comprobar que ahi falla:

```bat
.venv-forense\Scripts\python.exe -u desarrollo\test_sello_verificado.py respaldos\navegador_forense_pro_v1_0_BACKUP_<fecha>.py
```

Las que abren el motor del navegador se corren de a una: dos procesos de QtWebEngine a la vez se tiran abajo.