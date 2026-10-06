; ============================================================================
;  Instalador de Traverso Forensics - Navegador Web Forense
;  Requiere Inno Setup 6:  https://jrsoftware.org/isdl.php
;
;  Para generar el instalador:
;     - Abrir este archivo con Inno Setup Compiler y presionar F9, o
;     - ISCC.exe instalador.iss   (desde la linea de comandos)
;
;  Antes de compilar debe existir la carpeta dist\TraversoWebForensics\
;  generada por compilar_onedir.bat
; ============================================================================

#define MiNombre        "Navegador Web Forense"
#define MiVersion       "1.0"
#define MiEmpresa       "Traverso Forensics"
#define MiAutor         "Miguel Angel Alfredo Traverso"
#define MiEjecutable    "TraversoWebForensics.exe"
#define MiWeb           "https://www.linkedin.com/in/miguel-traverso"

[Setup]
; El AppId identifica al programa para futuras actualizaciones y para la
; desinstalacion. NO cambiarlo entre versiones.
AppId={{B7E4C2A1-9F3D-4E85-A6C7-1D2E3F4A5B6C}
AppName={#MiNombre}
AppVersion={#MiVersion}
AppVerName={#MiNombre} {#MiVersion}
AppPublisher={#MiEmpresa}
AppPublisherURL={#MiWeb}
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#MiEmpresa}
VersionInfoDescription={#MiNombre}
VersionInfoCopyright=Copyright (C) 2026 {#MiAutor}

; ---------------------------------------------------------------------------
;  UBICACION DE INSTALACION
;  El programa guarda archivos junto al ejecutable (session_cookies.json y,
;  por defecto, la carpeta de casos NAV_FORENSE). Por eso NO se instala en
;  Program Files, que es de solo lectura para el usuario: se instala en una
;  ubicacion escribible. El usuario puede elegir otra en el asistente.
; ---------------------------------------------------------------------------
PrivilegesRequired=lowest
DefaultDirName={autopf}\Traverso Forensics\Navegador Web Forense
DisableDirPage=no
DefaultGroupName={#MiEmpresa}
DisableProgramGroupPage=no
AllowNoIcons=yes

; ---------------------------------------------------------------------------
;  COMPRESION
;  lzma2/ultra64 con compresion solida: el mejor ratio disponible en Inno.
;  Sobre los binarios de Qt rinde cerca del 28 %.
; ---------------------------------------------------------------------------
Compression=lzma2/ultra64
SolidCompression=yes
LZMANumBlockThreads=4
InternalCompressLevel=ultra

; La compresion se delega a islzma64.exe, el compresor de 64 bits que trae
; Inno Setup. El compilador (ISCC.exe) es de 32 bits y no puede direccionar
; la memoria que pide un diccionario de 64 MB con cuatro hilos sobre una
; carpeta de 540 MB: sin esta linea la compilacion aborta con "Out of memory".
;  LZMAUseSeparateProcess ya no hace falta: se habia puesto porque el ISCC
;  de 32 bits no podia con lzma2/ultra64, y desde Inno Setup 7 la directiva
;  esta obsoleta y solo genera un aviso al compilar.

OutputDir=instalador
OutputBaseFilename=NavegadorWebForense_v{#MiVersion}_Setup
SetupIconFile=Navegador_Forense_Icon.ico
UninstallDisplayIcon={app}\{#MiEjecutable}
UninstallDisplayName={#MiNombre} {#MiVersion}
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; \
    GroupDescription: "Accesos directos:"

[Files]
; Toda la carpeta generada por PyInstaller (modo onedir)
Source: "dist\TraversoWebForensics\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs
; La licencia va adentro de la instalacion: la GPL-3.0 exige entregar su texto
; junto con el programa, y el programa usa PyQt6, que Riverbank publica bajo
; esa licencia.
Source: "LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MiNombre}"; Filename: "{app}\{#MiEjecutable}"
Name: "{group}\Desinstalar {#MiNombre}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MiNombre}"; Filename: "{app}\{#MiEjecutable}"; \
    Tasks: desktopicon

[Run]
Filename: "{app}\{#MiEjecutable}"; \
    Description: "Ejecutar {#MiNombre} ahora"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Restos que genera el programa durante su uso. La evidencia de los casos
; (NAV_FORENSE) NO se toca: es material pericial y debe conservarse.
Type: files; Name: "{app}\session_cookies.json"
Type: files; Name: "{app}\session_cookies_origen.json"
Type: dirifempty; Name: "{app}"

[Messages]
es.BeveledLabel={#MiEmpresa} - Informatica Forense

[Code]
{ Aviso si el usuario elige instalar en Program Files: ahi el programa no
  puede escribir sus archivos de sesion. }
function NextButtonClick(CurPageID: Integer): Boolean;
var
  Ruta: String;
begin
  Result := True;
  if CurPageID = wpSelectDir then
  begin
    Ruta := Uppercase(WizardDirValue);
    if (Pos('\PROGRAM FILES', Ruta) > 0) then
    begin
      if MsgBox('La carpeta elegida esta dentro de "Archivos de programa".' + #13#10 + #13#10 +
                'El programa necesita escribir archivos junto al ejecutable ' +
                '(por ejemplo la sesion importada de Chrome), y esa ubicacion ' +
                'suele ser de solo lectura. La importacion de cookies podria fallar.' + #13#10 + #13#10 +
                'Se recomienda elegir otra carpeta. Desea continuar de todos modos?',
                mbConfirmation, MB_YESNO) = IDNO then
        Result := False;
    end;
  end;
end;
