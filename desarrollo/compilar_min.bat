@echo off
chcp 65001 >nul
echo Compilando version MINIMA...
pyinstaller ^
    --noconfirm --clean ^
    --name "TraversoWebForensics" ^
    --onedir --windowed ^
    --icon=traverso_forensics.ico ^
    --add-data "traverso_logo.png;." ^
    --exclude-module PyQt5 --exclude-module PySide6 --exclude-module PySide2 ^
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
