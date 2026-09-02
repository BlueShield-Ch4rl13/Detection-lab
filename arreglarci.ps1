# arreglar-ci.ps1 — deja el CI de DetectionLab en verde.
#
# El fallo: tools/build.py metia la ruta del fichero Sigma dentro del
# contenido generado usando str(Path). En Windows eso sale con barra
# invertida y en Linux con barra normal, asi que savedsearches.conf era
# distinto segun quien lo generase. El CI regenera en Linux, comparaba
# contra lo que tu commiteaste desde Windows, y no coincidian 127 lineas.
#
# El segundo fallo: el paso del CI que deberia haber cazado eso usaba el
# pathspec 'deploy/*/reglas/'. Entrecomillado, git interpreta el glob el
# mismo y la barra final exige que la ruta termine en barra, cosa que
# ningun fichero hace. No casaba nada: el paso pasaba siempre sin mirar.
#
# Ejecutar desde la raiz del repositorio:  .\arreglar-ci.ps1

$ErrorActionPreference = 'Stop'

function Leer($p) { [System.IO.File]::ReadAllText($p) }
function Escribir($p, $s) {
    # UTF-8 sin BOM a proposito: -Encoding UTF8 en PowerShell 5.1 mete BOM
    # y eso genera un diff espurio en todos los ficheros que toque.
    [System.IO.File]::WriteAllText($p, $s, (New-Object System.Text.UTF8Encoding $false))
}
function Ok($m)    { Write-Host "  [ok] $m"    -ForegroundColor Green }
function Aviso($m) { Write-Host "  [--] $m"    -ForegroundColor DarkGray }
function Error2($m){ Write-Host "  [ERROR] $m" -ForegroundColor Red }

if (-not (Test-Path 'tools/build.py') -or -not (Test-Path 'rules')) {
    Error2 "No parece la raiz de DetectionLab (no veo tools/build.py y rules/)."
    Write-Host "  Muevete a la carpeta del repositorio y vuelve a ejecutarlo."
    exit 1
}

$cambios = 0

# ---------------------------------------------------------------- build.py
Write-Host "`n1. tools/build.py — normalizar las rutas a barra normal" -ForegroundColor Cyan
$p = 'tools/build.py'
$t = Leer $p

$sustituciones = @(
    @{ de = '# Regla Sigma: {f.relative_to(RAIZ)}'
       a  = '# Regla Sigma: {f.relative_to(RAIZ).as_posix()}' },
    @{ de = 'f"// Origen: {f.relative_to(RAIZ)}\n"'
       a  = 'f"// Origen: {f.relative_to(RAIZ).as_posix()}\n"' }
)

foreach ($s in $sustituciones) {
    if ($t.Contains($s.a)) {
        Aviso "ya aplicado: $($s.a)"
    } elseif ($t.Contains($s.de)) {
        $t = $t.Replace($s.de, $s.a)
        $cambios++
        Ok $s.a
    } else {
        Error2 "no encuentro el texto a sustituir: $($s.de)"
        Write-Host "  build.py no esta como se esperaba. Parate aqui y avisa."
        exit 1
    }
}

# El comentario que explica por que, para que nadie lo revierta sin querer.
$firma = 'def generar_splunk(reglas, resultados) -> str:'
$doc = @"
$firma
    """Las rutas van con .as_posix() a proposito.

    Una Path en Windows se imprime con barra invertida y en Linux con barra
    normal. Si esa ruta acaba dentro de un fichero generado, el mismo comando
    produce ficheros distintos segun quien lo ejecute: quien genera en Windows
    y quien valida en CI nunca coinciden, y el CI falla por 127 lineas que solo
    se diferencian en el separador. Es exactamente lo que paso aqui.
    """
"@ -replace "`r`n", "`n"

if ($t.Contains('.as_posix() a proposito')) {
    Aviso "el comentario explicativo ya esta"
} elseif ($t.Contains($firma)) {
    $t = $t.Replace($firma, $doc)
    $cambios++
    Ok "anadido el comentario que explica el porque"
}

Escribir $p $t

# ------------------------------------------------------------- workflow CI
Write-Host "`n2. .github/workflows/validate.yml — arreglar el pathspec" -ForegroundColor Cyan
$w = '.github/workflows/validate.yml'
$t = Leer $w

# Se sustituye el paso entero para que quede tambien el comentario que
# explica el porque. Sin el, el pathspec entrecomillado parece correcto y
# cualquiera lo puede "arreglar" de vuelta.
$viejo = @'
      - name: Comprobar que las reglas generadas estaban al dia
        run: |
          if ! git diff --quiet -- 'deploy/*/reglas/' purple/atomic-map.md docs/fusion-de-bibliotecas.md; then
            echo "::error::Las reglas generadas no coinciden con rules/. Ejecuta 'python tools/build.py' y haz commit del resultado."
            git diff --stat -- 'deploy/*/reglas/' purple/atomic-map.md docs/fusion-de-bibliotecas.md
            exit 1
          fi
          echo "deploy/*/reglas/ esta sincronizado con rules/"
'@ -replace "`r`n", "`n"

$nuevo = @'
      # OJO con el pathspec: 'deploy/*/reglas/' entrecomillado NO casa con
      # ningun fichero. git interpreta el glob el mismo, y con la barra final
      # exige que la ruta termine en barra, cosa que ningun fichero hace. El
      # check parecia pasar y en realidad no miraba deploy/ en absoluto.
      - name: Comprobar que las reglas generadas estaban al dia
        run: |
          RUTAS="deploy purple/atomic-map.md docs/fusion-de-bibliotecas.md"
          if ! git diff --quiet -- $RUTAS; then
            echo "::error::Lo generado no coincide con rules/. Ejecuta 'python tools/build.py' y haz commit del resultado."
            git diff --stat -- $RUTAS
            exit 1
          fi
          echo "El contenido generado esta sincronizado con rules/"
'@ -replace "`r`n", "`n"

if ($t.Contains($viejo)) {
    $t = $t.Replace($viejo, $nuevo)
    Escribir $w $t
    $cambios++
    Ok "pathspec corregido: ahora compara deploy/ entero"
} elseif ($t.Contains('RUTAS="deploy purple/atomic-map.md')) {
    Aviso "ya aplicado"
} else {
    Error2 "no encuentro el paso del pathspec en el workflow. Parate aqui y avisa."
    exit 1
}

# --------------------------------------------------------------- regenerar
Write-Host "`n3. Regenerando el contenido de los cuatro SIEM" -ForegroundColor Cyan
$py = if (Get-Command python -EA SilentlyContinue) { 'python' } else { 'py' }
& $py tools/build.py
if ($LASTEXITCODE -ne 0) { Error2 "build.py fallo"; exit 1 }

# ------------------------------------------------------------ comprobacion
Write-Host "`n4. Comprobando que ya no queda ninguna barra invertida" -ForegroundColor Cyan
$sospechosas = Select-String -Path 'deploy/splunk/reglas/savedsearches.conf' `
                             -Pattern 'rules\\' -SimpleMatch -EA SilentlyContinue
if ($sospechosas) {
    Error2 "todavia hay $($sospechosas.Count) rutas con barra invertida"
    exit 1
}
Ok "savedsearches.conf sin rutas con barra invertida"

# ----------------------------------------------------------------- resumen
Write-Host "`n5. Lo que ha cambiado" -ForegroundColor Cyan
git status --short
Write-Host ""
git diff --stat | Select-Object -Last 3

Write-Host "`nListo. Para subirlo:" -ForegroundColor Cyan
Write-Host '  git add -A'
Write-Host '  git commit -m "Normalizar separadores de ruta y arreglar el pathspec del CI"'
Write-Host '  git push'
