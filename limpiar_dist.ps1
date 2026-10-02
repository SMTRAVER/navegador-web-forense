# Quita de la carpeta compilada lo que no se usa en produccion.
#
# Va en un archivo aparte y no dentro del .bat a proposito: la version
# embebida fallaba en silencio. Primero por un for de cmd que encadenaba
# cuatro "if not" con ^, y despues por el escapado de comillas de un
# powershell -Command dentro de un bloque entre parentesis. En los dos casos
# el .bat anunciaba COMPILACION TERMINADA y la carpeta quedaba 41 MB mas
# grande sin que nada lo avisara.

$ErrorActionPreference = "Stop"
$base = Join-Path $PSScriptRoot "dist\TraversoWebForensics\_internal\PyQt6\Qt6"

# Recursos de depuracion de las herramientas de desarrollo de Chromium
$res = Join-Path $base "resources"
if (Test-Path $res) {
    $dbg = Get-ChildItem $res -File | Where-Object { $_.Name -like "*debug*" }
    if ($dbg) {
        $mb = [math]::Round(($dbg | Measure-Object Length -Sum).Sum / 1MB, 1)
        $dbg | Remove-Item -Force
        Write-Host "      recursos de depuracion quitados ($mb MB)"
    }
}

# Idiomas de WebEngine: vienen 53, se conservan espanol e ingles
$loc = Join-Path $base "translations\qtwebengine_locales"
if (Test-Path $loc) {
    $conservar = @("es.pak", "es-419.pak", "en-US.pak", "en-GB.pak")
    $sobran = Get-ChildItem $loc -File -Filter "*.pak" |
              Where-Object { $conservar -notcontains $_.Name }
    if ($sobran) {
        $mb = [math]::Round(($sobran | Measure-Object Length -Sum).Sum / 1MB, 1)
        $sobran | Remove-Item -Force
        Write-Host "      $($sobran.Count) idiomas quitados ($mb MB)"
    } else {
        Write-Host "      idiomas ya depurados"
    }
} else {
    Write-Host "      AVISO: no se encontro la carpeta de idiomas"
}

$c = Get-ChildItem (Join-Path $PSScriptRoot "dist\TraversoWebForensics") -Recurse -File
$tot = [math]::Round(($c | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "      carpeta final: $($c.Count) archivos, $tot MB"
