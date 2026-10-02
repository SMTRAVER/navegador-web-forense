@echo off
chcp 65001 >nul
rem  El script usa rutas relativas, asi que se para en su propia carpeta:
rem  lanzado desde otro directorio no encontraba ni el entorno ni las pruebas.
cd /d "%~dp0"
echo ==========================================
echo  TRAVERSO FORENSICS - Navegador Web Forense
echo  Compilacion del ejecutable
echo ==========================================
echo.

rem  Se compila desde el entorno dedicado .venv-forense, no desde el Python
rem  del sistema. Motivos:
rem    - El entorno del sistema tiene pyOpenSSL, que exige cryptography<42 e
rem      impide actualizar a una version sin vulnerabilidades conocidas.
rem    - Tambien tiene PyQt5 y PySide6 de otros proyectos, y PyInstaller aborta
rem      cuando encuentra varios bindings de Qt.
rem    - Con un entorno acotado el ejecutable sale mas chico y la compilacion
rem      es reproducible (ver requirements-build.txt).

set VENV=.venv-forense
set PY=%VENV%\Scripts\python.exe

if not exist "%PY%" (
    echo [INFO] No existe el entorno dedicado. Creandolo...
    python -m venv %VENV%
    if errorlevel 1 (
        echo [ERROR] No se pudo crear el entorno virtual.
        pause
        exit /b 1
    )
    "%PY%" -m pip install --upgrade pip
    if exist "requirements-build.txt" (
        echo [INFO] Instalando versiones fijas de requirements-build.txt...
        "%PY%" -m pip install -r requirements-build.txt
    ) else (
        "%PY%" -m pip install PyQt6 PyQt6-WebEngine fpdf2 opencv-python pillow ^
            requests pyautogui cryptography endesive rfc3161ng ntplib qrcode ^
            warcio yt-dlp pyinstaller
    )
)

if not exist "Navegador_Forense_Icon.ico" (
    echo [ERROR] Falta Navegador_Forense_Icon.ico
    pause
    exit /b 1
)

rem  Antes de compilar: nombres usados y no definidos. py_compile no los
rem  ve porque solo fallan al ejecutarse, y en este programa buena parte
rem  del trabajo corre dentro de funciones anidadas con su propio except:
rem  ahi un nombre equivocado no rompe nada visible, solo deja de
rem  guardarse la prueba.
echo [1/3] Revisando nombres sin definir...
"%PY%" desarrollo\test_nombres_indefinidos.py navegador_forense_pro_v1_0.py
if errorlevel 1 (
    echo.
    echo [ERROR] Hay nombres sin definir. No se compila.
    pause
    exit /b 1
)
echo.
echo [2/3] Compilando... (varios minutos)
echo.

"%PY%" -m PyInstaller ^
    --noconfirm --clean ^
    --name "TraversoWebForensics" ^
    --onedir --windowed ^
    --icon=Navegador_Forense_Icon.ico ^
    --add-data "traverso_logo.png;." ^
    --hidden-import uharfbuzz ^
    --add-data "verificar_caso.py;." ^
    --exclude-module tkinter --exclude-module matplotlib --exclude-module scipy ^
    --exclude-module pandas --exclude-module IPython --exclude-module pytest ^
    --exclude-module PyQt6.QtQml --exclude-module PyQt6.QtQuick ^
    --exclude-module PyQt6.QtQuick3D --exclude-module PyQt6.QtQuickWidgets ^
    --exclude-module PyQt6.Qt3DCore --exclude-module PyQt6.Qt3DRender ^
    --exclude-module PyQt6.QtCharts --exclude-module PyQt6.QtDataVisualization ^
    --exclude-module PyQt6.QtBluetooth --exclude-module PyQt6.QtNfc ^
    --exclude-module PyQt6.QtPositioning --exclude-module PyQt6.QtSensors ^
    --exclude-module PyQt6.QtSerialPort --exclude-module PyQt6.QtSql ^
    --exclude-module PyQt6.QtTest --exclude-module PyQt6.QtDesigner ^
    --exclude-module PyQt6.QtHelp --exclude-module PyQt6.QtSpatialAudio ^
    navegador_forense_pro_v1_0.py

if errorlevel 1 (
    echo.
    echo [ERROR] La compilacion fallo.
    pause
    exit /b 1
)

echo.
echo [2/2] Quitando archivos innecesarios...

rem  La limpieza va en limpiar_dist.ps1 y no aca. Hacerla dentro del .bat
rem  fallo dos veces en silencio: primero con un for de cmd que encadenaba
rem  varios "if not" con ^, y despues con un powershell -Command inline cuyo
rem  escapado de comillas cmd no interpreta. Las dos veces el .bat anuncio
rem  COMPILACION TERMINADA y dejo 41 MB de idiomas sin usar.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0limpiar_dist.ps1"
if errorlevel 1 echo       AVISO: la limpieza no se completo

echo.
echo.
echo [3/3] Manifiesto oficial de archivos de la herramienta...
"%PY%" desarrollo\manifiesto_oficial.py
if errorlevel 1 echo       AVISO: no se pudo escribir el manifiesto oficial

echo ==========================================
echo  COMPILACION TERMINADA
echo ==========================================
echo   Carpeta   : dist\TraversoWebForensics\
echo   Ejecutable: dist\TraversoWebForensics\TraversoWebForensics.exe
echo.
echo   Siguiente paso: compilar instalador.iss con Inno Setup
echo.
pause
