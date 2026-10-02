@echo off
chcp 65001 >nul
cd /d "%~dp0"

rem  Arranca el navegador forense desde el entorno dedicado, que tiene las
rem  dependencias al dia y sin vulnerabilidades conocidas. Si ese entorno no
rem  existe, usa el Python del sistema para no dejar al perito sin herramienta.

set PY=.venv-forense\Scripts\pythonw.exe

if exist "%PY%" (
    start "" "%PY%" navegador_forense_pro_v1_0.py
) else (
    echo [AVISO] No se encontro .venv-forense. Se usara el Python del sistema,
    echo         que tiene dependencias desactualizadas.
    echo         Para crearlo: compilar_onedir.bat  ^(lo genera solo^)
    echo.
    start "" pythonw navegador_forense_pro_v1_0.py
)
