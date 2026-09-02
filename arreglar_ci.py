#!/usr/bin/env python3
"""Deja el CI de DetectionLab en verde. Ejecutar desde la raiz del repositorio:

    python arreglar_ci.py

Arregla dos cosas.

1. tools/build.py metia la ruta del fichero Sigma dentro del contenido
   generado usando str(Path). En Windows eso se imprime con barra invertida
   y en Linux con barra normal, asi que savedsearches.conf salia distinto
   segun quien lo generase. Tu generabas en Windows, el CI regeneraba en
   Linux, y no coincidian 127 lineas que solo se diferenciaban en el
   separador. Por eso "ejecuta build.py y haz commit" no podia funcionar:
   el fichero dependia de la maquina.

2. El paso del CI que deberia haber cazado eso usaba el pathspec
   'deploy/*/reglas/'. Entrecomillado, git interpreta el glob el mismo y la
   barra final exige que la ruta termine en barra, cosa que ningun fichero
   hace. No casaba nada: el paso pasaba siempre sin mirar deploy/.

Va en Python y no en PowerShell a proposito: Windows PowerShell 5.1 y
PowerShell 7 no parsean igual, y python ya hace falta para build.py.
"""

import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent


def ok(m):
    print(f"  [ok] {m}")


def salta(m):
    print(f"  [--] {m}")


def error(m):
    print(f"  [ERROR] {m}")


def leer(ruta):
    """Devuelve (texto normalizado a \\n, tenia_crlf).

    En Windows con core.autocrlf=true el arbol de trabajo puede estar en
    CRLF aunque el repositorio guarde LF. Si escribiesemos LF a secas, git
    marcaria el fichero entero como modificado.
    """
    bruto = ruta.read_bytes().decode("utf-8")
    crlf = "\r\n" in bruto
    return bruto.replace("\r\n", "\n"), crlf


def escribir(ruta, texto, crlf):
    if crlf:
        texto = texto.replace("\n", "\r\n")
    # Bytes directamente: sin BOM y sin que Python traduzca los saltos.
    ruta.write_bytes(texto.encode("utf-8"))


# --------------------------------------------------------------- build.py
SUSTITUCIONES = [
    ("# Regla Sigma: {f.relative_to(RAIZ)}",
     "# Regla Sigma: {f.relative_to(RAIZ).as_posix()}"),
    ('f"// Origen: {f.relative_to(RAIZ)}\\n"',
     'f"// Origen: {f.relative_to(RAIZ).as_posix()}\\n"'),
]

FIRMA = "def generar_splunk(reglas, resultados) -> str:"

DOCSTRING = FIRMA + '''
    """Las rutas van con .as_posix() a proposito.

    Una Path en Windows se imprime con barra invertida y en Linux con barra
    normal. Si esa ruta acaba dentro de un fichero generado, el mismo comando
    produce ficheros distintos segun quien lo ejecute: quien genera en Windows
    y quien valida en CI nunca coinciden, y el CI falla por 127 lineas que solo
    se diferencian en el separador. Es exactamente lo que paso aqui.
    """'''

# ----------------------------------------------------------- workflow del CI
PASO_VIEJO = """      - name: Comprobar que las reglas generadas estaban al dia
        run: |
          if ! git diff --quiet -- 'deploy/*/reglas/' purple/atomic-map.md docs/fusion-de-bibliotecas.md; then
            echo "::error::Las reglas generadas no coinciden con rules/. Ejecuta 'python tools/build.py' y haz commit del resultado."
            git diff --stat -- 'deploy/*/reglas/' purple/atomic-map.md docs/fusion-de-bibliotecas.md
            exit 1
          fi
          echo "deploy/*/reglas/ esta sincronizado con rules/"
"""

PASO_NUEVO = """      # OJO con el pathspec: 'deploy/*/reglas/' entrecomillado NO casa con
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
"""


def parchear_build():
    print("\n1. tools/build.py - normalizar las rutas a barra normal")
    ruta = RAIZ / "tools" / "build.py"
    texto, crlf = leer(ruta)

    for de, a in SUSTITUCIONES:
        if a in texto:
            salta(f"ya aplicado: {a}")
        elif de in texto:
            texto = texto.replace(de, a)
            ok(a)
        else:
            error(f"no encuentro el texto a sustituir: {de}")
            print("      build.py no esta como se esperaba. Parate aqui y avisa.")
            return False

    if ".as_posix() a proposito" in texto:
        salta("el comentario explicativo ya esta")
    elif FIRMA in texto:
        texto = texto.replace(FIRMA, DOCSTRING)
        ok("anadido el comentario que explica el porque")
    else:
        error(f"no encuentro la funcion: {FIRMA}")
        return False

    escribir(ruta, texto, crlf)
    return True


def parchear_workflow():
    print("\n2. .github/workflows/validate.yml - arreglar el pathspec")
    ruta = RAIZ / ".github" / "workflows" / "validate.yml"
    texto, crlf = leer(ruta)

    if 'RUTAS="deploy purple/atomic-map.md' in texto:
        salta("ya aplicado")
        return True
    if PASO_VIEJO not in texto:
        error("no encuentro el paso del pathspec en el workflow.")
        print("      Parate aqui y avisa: el workflow no esta como se esperaba.")
        return False

    escribir(ruta, texto.replace(PASO_VIEJO, PASO_NUEVO), crlf)
    ok("pathspec corregido: ahora compara deploy/ entero")
    return True


def regenerar():
    print("\n3. Regenerando el contenido de los cuatro SIEM")
    r = subprocess.run([sys.executable, str(RAIZ / "tools" / "build.py")], cwd=RAIZ)
    if r.returncode != 0:
        error("build.py fallo")
        return False
    return True


def comprobar():
    print("\n4. Comprobando que ya no queda ninguna ruta con barra invertida")
    conf = RAIZ / "deploy" / "splunk" / "reglas" / "savedsearches.conf"
    malas = [l for l in conf.read_text(encoding="utf-8").splitlines() if "rules\\" in l]
    if malas:
        error(f"todavia hay {len(malas)} rutas con barra invertida")
        return False
    ok("savedsearches.conf sin rutas con barra invertida")
    return True


def main():
    if not (RAIZ / "tools" / "build.py").exists() or not (RAIZ / "rules").is_dir():
        error("No parece la raiz de DetectionLab (no veo tools/build.py y rules/).")
        print("      Copia este fichero a la carpeta del repositorio y ejecutalo alli.")
        return 1

    for paso in (parchear_build, parchear_workflow, regenerar, comprobar):
        if not paso():
            return 1

    print("\n5. Lo que ha cambiado")
    subprocess.run(["git", "status", "--short"], cwd=RAIZ)
    print()
    subprocess.run(["git", "diff", "--stat"], cwd=RAIZ)

    print("\nListo. Para subirlo:")
    print("  git add -A")
    print('  git commit -m "Normalizar separadores de ruta y arreglar el pathspec del CI"')
    print("  git push")
    return 0


if __name__ == "__main__":
    sys.exit(main())
