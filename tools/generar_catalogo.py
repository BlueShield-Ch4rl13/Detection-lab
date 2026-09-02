#!/usr/bin/env python3
"""
Genera la explicacion de cada regla dentro de docs/fusion-de-bibliotecas.md.

Por que se genera y no se escribe a mano
----------------------------------------
Un catalogo de 127 reglas escrito a mano se desincroniza a la tercera regla
nueva, y entonces describe detecciones que ya no existen o se calla las que si.
Aqui el texto sale de la propia regla: el titulo, la descripcion, la severidad,
las tecnicas y los falsos positivos que ya estan en el YAML. Anadir una regla
la mete en el documento; cambiarle la logica cambia lo que el documento dice.

El bloque generado va entre marcadores. Todo lo que hay fuera de ellos -el
registro de la fusion, las decisiones, las correcciones- se escribe a mano y
este script no lo toca.

Uso:
    python3 tools/generar_catalogo.py
    python3 tools/generar_catalogo.py --check   no escribe, solo informa
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

# En Windows la consola usa cp1252 y no puede imprimir ni los bloques de los
# graficos ni los simbolos de estado. Sin esto, la herramienta muere con
# UnicodeEncodeError a mitad del informe: hace el trabajo y luego revienta al
# contarlo, que es la peor forma de fallar.
for _flujo in (sys.stdout, sys.stderr):
    if hasattr(_flujo, "reconfigure"):
        try:
            _flujo.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


RAIZ = Path(__file__).resolve().parent.parent
REGLAS = RAIZ / "rules"
DOC = RAIZ / "docs" / "fusion-de-bibliotecas.md"

INI = "<!-- INICIO:CATALOGO -->"
FIN = "<!-- FIN:CATALOGO -->"

RE_TEC = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", re.I)

# Orden de presentacion y titulo de cada dominio. El orden sigue la cadena de
# ataque, no el alfabeto: se lee mejor de la entrada al impacto.
DOMINIOS = [
    ("correo", "Correo", "Proofpoint TAP y Exchange Online",
     "La entrega. Casi toda intrusion que no explota algo publicado empieza aqui."),
    ("web", "Aplicaciones web", "Registros de servidor web y WAF",
     "La otra puerta de entrada: lo que esta publicado y por tanto es alcanzable "
     "sin credenciales."),
    ("cloud", "Identidad y nube", "Entra ID, Microsoft 365, Netskope",
     "Donde el atacante ya no necesita malware: con una credencial valida entra "
     "por la puerta."),
    ("windows", "Windows y Active Directory", "Sysmon, canal Security, Defender XDR",
     "El grueso de la biblioteca. Ejecucion, persistencia, credenciales y "
     "movimiento lateral en dominio."),
    ("linux", "Linux", "auditd y Falco",
     "Servidores. Menos poblado que Windows, y por eso lo que salta suele ser "
     "mas significativo."),
    ("macos", "macOS", "Endpoint Security Framework",
     "Parque pequeno y mecanismos propios: launchd, TCC, Gatekeeper, llavero."),
    ("contenedores", "Contenedores y Kubernetes", "Auditoria del API server y runtime",
     "Superficie nueva con reglas propias: el escape del contenedor no se parece "
     "a la escalada clasica."),
    ("red", "Red", "Proxy, DNS y NetFlow",
     "Lo que se ve del trafico cuando el endpoint no dice nada."),
    ("exfiltracion", "Exfiltracion", "Endpoint, proxy y correo",
     "El final de la cadena. Cuando esto salta, los datos probablemente ya "
     "salieron: el objetivo cambia de contener a medir el alcance."),
    ("xdr", "Evasion del propio EDR", "Sysmon, registro y carga de drivers",
     "El atacante atacando la vigilancia. Si el sensor esta manipulado, la "
     "telemetria de ese equipo deja de ser fiable, incluida la que dice que "
     "todo va bien."),
    ("zta", "Arquitectura Zero Trust", "Varias, segun el pilar",
     "Desviaciones de arquitectura mas que incidentes: cosas que no deberian "
     "poder pasar si la arquitectura se cumple."),
]

ICONO_NIVEL = {"critical": "🔴", "high": "🟠", "medium": "🟡",
               "low": "🔵", "informational": "⚪"}


def tecnicas(doc) -> list[str]:
    out = []
    for t in doc.get("tags", []) or []:
        m = RE_TEC.match(str(t))
        if m:
            out.append(m.group(1).upper() + (f".{m.group(2)}" if m.group(2) else ""))
    return sorted(set(out))


def controles(doc) -> tuple[list[str], list[str]]:
    nist, iso = [], []
    for t in doc.get("tags", []) or []:
        s = str(t)
        if s.startswith("nist."):
            nist.append(s.split(".", 1)[1].upper())
        elif s.startswith("iso27001-2022.a-"):
            iso.append("A." + s.split("a-", 1)[1].replace("-", "."))
    return sorted(set(nist)), sorted(set(iso))


def parrafo(texto: str) -> str:
    """Aplana el bloque `|` de la descripcion en un parrafo."""
    return " ".join((texto or "").split())


def origen(doc, docs) -> str:
    """De donde salio la regla, para que se pueda rastrear."""
    if any("correlation" in d for d in docs):
        return "correlacion Sigma"
    return ""


def generar() -> str:
    por_dominio = defaultdict(list)
    for f in sorted(REGLAS.rglob("*.yml")):
        docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d]
        principal = next((d for d in docs if "title" in d), None)
        if not principal:
            continue
        por_dominio[f.relative_to(REGLAS).parts[0]].append((f, principal, docs))

    total = sum(len(v) for v in por_dominio.values())
    partes = [
        INI,
        "",
        f"# Las {total} reglas, una por una",
        "",
        "Generado por `tools/generar_catalogo.py` desde `rules/`. Cada entrada sale",
        "de la propia regla, asi que anadir una la mete aqui y cambiarle la logica",
        "cambia lo que este documento dice. No se edita a mano.",
        "",
        "En cada regla:",
        "",
        "- **Que detecta y por que importa** - el razonamiento, no la sintaxis.",
        "- **Que la distingue del ruido** - el primer falso positivo esperado, que es",
        "  lo que hay que descartar antes de escalar.",
        "- Severidad, tecnicas ATT&CK, origen de log y los controles NIST/ISO que",
        "  evidencia.",
        "",
        "Severidad: 🔴 critica · 🟠 alta · 🟡 media · ⚪ informativa (base de correlacion).",
        "",
    ]

    for clave, titulo, telemetria, intro in DOMINIOS:
        reglas = por_dominio.get(clave, [])
        if not reglas:
            continue
        partes += [
            "---", "",
            f"## {titulo}",
            "",
            f"**{len(reglas)} reglas** · {telemetria}",
            "",
            intro,
            "",
        ]
        for f, doc, docs in reglas:
            nivel = (doc.get("level") or "medium").lower()
            tecs = tecnicas(doc)
            nist, iso = controles(doc)
            ls = doc.get("logsource", {}) or {}
            fuente = " / ".join(x for x in (ls.get("category"), ls.get("product"),
                                            ls.get("service")) if x) or "-"
            fps = doc.get("falsepositives") or []
            corr = " · correlacion Sigma" if any("correlation" in d for d in docs) else ""

            partes.append(f"### {ICONO_NIVEL.get(nivel, '·')} {doc['title']}")
            partes.append("")
            partes.append(f"`{f.name}`{corr}")
            partes.append("")
            partes.append(parrafo(doc.get("description", "")))
            partes.append("")
            if fps:
                partes.append(f"**Lo que hay que descartar primero:** {parrafo(str(fps[0]))}")
                partes.append("")
            meta = [f"**Origen:** `{fuente}`"]
            if tecs:
                meta.append("**ATT&CK:** " + ", ".join(
                    f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/)"
                    for t in tecs))
            if nist:
                meta.append("**NIST:** " + ", ".join(nist))
            if iso:
                meta.append("**ISO 27001:** " + ", ".join(iso))
            partes.append(" · ".join(meta))
            partes.append("")

    partes.append(FIN)
    return "\n".join(partes)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    bloque = generar()
    texto = DOC.read_text(encoding="utf-8")

    if INI in texto and FIN in texto:
        nuevo = re.sub(re.escape(INI) + r".*?" + re.escape(FIN), lambda m: bloque,
                       texto, flags=re.S)
    else:
        nuevo = texto.rstrip() + "\n\n" + bloque + "\n"

    n = bloque.count("\n### ")
    if args.check:
        print(f"{n} reglas en el catalogo; "
              f"{'al dia' if nuevo == texto else 'DESFASADO, ejecuta sin --check'}")
        return 0 if nuevo == texto else 1

    DOC.write_text(nuevo, encoding="utf-8")
    print(f"{n} reglas escritas en {DOC.relative_to(RAIZ)} "
          f"({len(nuevo.splitlines())} lineas en total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
