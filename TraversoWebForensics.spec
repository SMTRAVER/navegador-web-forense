# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['navegador_forense_pro_v1_0.py'],
    pathex=[],
    binaries=[],
    datas=[('traverso_logo.png', '.'), ('verificar_caso.py', '.')],
    hiddenimports=['uharfbuzz'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy', 'pandas', 'IPython', 'pytest', 'PyQt6.QtQml', 'PyQt6.QtQuick', 'PyQt6.QtQuick3D', 'PyQt6.QtQuickWidgets', 'PyQt6.Qt3DCore', 'PyQt6.Qt3DRender', 'PyQt6.QtCharts', 'PyQt6.QtDataVisualization', 'PyQt6.QtBluetooth', 'PyQt6.QtNfc', 'PyQt6.QtPositioning', 'PyQt6.QtSensors', 'PyQt6.QtSerialPort', 'PyQt6.QtSql', 'PyQt6.QtTest', 'PyQt6.QtDesigner', 'PyQt6.QtHelp', 'PyQt6.QtSpatialAudio'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='TraversoWebForensics',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['Navegador_Forense_Icon.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='TraversoWebForensics',
)
