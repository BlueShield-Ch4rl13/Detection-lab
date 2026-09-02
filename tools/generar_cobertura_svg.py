#!/usr/bin/env python3
"""
Dibuja el mapa de cobertura ATT&CK del repositorio como SVG.

Por que un SVG propio y no una captura de ATT&CK Navigator: la captura envejece
en cuanto se anade una regla y nadie se acuerda de rehacerla. Esto se regenera
con el resto del contenido y siempre dice la verdad. La capa para Navigator
sigue existiendo en navigator/coverage-layer.json para quien quiera el heatmap
completo sobre la matriz entera.

Uso: python3 tools/generar_cobertura_svg.py
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import yaml
import sys

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
SALIDA = RAIZ / "docs" / "img" / "cobertura-attack.svg"

RE_TEC = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", re.I)
TACTICAS = {
    "reconnaissance": "Reconocimiento", "resource-development": "Preparacion",
    "initial-access": "Acceso inicial", "execution": "Ejecucion",
    "persistence": "Persistencia", "privilege-escalation": "Escalada priv.",
    "defense-evasion": "Evasion", "credential-access": "Credenciales",
    "discovery": "Descubrimiento", "lateral-movement": "Mov. lateral",
    "collection": "Recoleccion", "command-and-control": "Mando/control",
    "exfiltration": "Exfiltracion", "impact": "Impacto",
}
COLOR_DOM = {
    "windows": "#2ee6f0", "cloud": "#f0a72e", "linux": "#4fd6c4",
    "macos": "#a78bfa", "contenedores": "#f472b6", "correo": "#60a5fa",
    "red": "#34d399", "zta": "#fbbf24", "web": "#fb7185", "exfiltracion": "#38bdf8",
    "xdr": "#c084fc",
}
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"


def recoger():
    por_tactica = defaultdict(dict)   # tactica -> {tecnica: set(dominios)}
    for p in sorted((RAIZ / "rules").rglob("*.yml")):
        dom = p.relative_to(RAIZ / "rules").parts[0]
        for d in yaml.safe_load_all(p.read_text(encoding="utf-8")):
            if not d or "detection" not in d:
                continue
            tags = [str(t) for t in (d.get("tags") or [])]
            tecs, tacs = [], []
            for t in tags:
                m = RE_TEC.match(t)
                if m:
                    tecs.append(m.group(1).upper() + (f".{m.group(2)}" if m.group(2) else ""))
                else:
                    n = t.split(".", 1)[1] if t.startswith("attack.") else t
                    if n in TACTICAS:
                        tacs.append(n)
            for ta in tacs:
                for te in tecs:
                    por_tactica[ta].setdefault(te, set()).add(dom)
    return por_tactica


def main() -> int:
    datos = recoger()
    cols = [t for t in TACTICAS if datos.get(t)]
    filas = max(len(v) for v in datos.values())

    cw, ch, gx, gy = 132, 26, 10, 5
    x0, y0 = 24, 128
    ancho = x0 * 2 + len(cols) * (cw + gx)
    alto = y0 + filas * (ch + gy) + 96

    s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{ancho}" height="{alto}" '
         f'viewBox="0 0 {ancho} {alto}" role="img" '
         f'aria-label="Cobertura MITRE ATT&amp;CK de detection-lab">',
         f'<rect width="{ancho}" height="{alto}" fill="#070d14"/>',
         f'<rect width="{ancho}" height="2" fill="#2ee6f0"/>',
         f'<text x="{x0}" y="42" font-family="{MONO}" font-size="15" fill="#eaf4fa" '
         f'font-weight="700" letter-spacing="2">COBERTURA MITRE ATT&amp;CK</text>',
         f'<text x="{x0}" y="66" font-family="{MONO}" font-size="11.5" fill="#6f8698">'
         f'{sum(len(v) for v in datos.values())} pares tecnica-tactica  ·  '
         f'{len({t for v in datos.values() for t in v})} tecnicas unicas  ·  '
         f'{len(cols)} tacticas  ·  color = dominio de la regla</text>']

    lx = x0
    for dom, color in COLOR_DOM.items():
        s.append(f'<rect x="{lx}" y="84" width="9" height="9" fill="{color}" rx="2"/>')
        s.append(f'<text x="{lx + 14}" y="92.5" font-family="{MONO}" font-size="10" '
                 f'fill="#8ea6bb">{dom}</text>')
        lx += 22 + len(dom) * 6.2

    for i, tac in enumerate(cols):
        x = x0 + i * (cw + gx)
        n = len(datos[tac])
        s.append(f'<rect x="{x}" y="{y0 - 34}" width="{cw}" height="26" fill="#0b141c" '
                 f'stroke="#1c2b38"/>')
        s.append(f'<text x="{x + 8}" y="{y0 - 16}" font-family="{MONO}" font-size="10.5" '
                 f'fill="#2ee6f0">{TACTICAS[tac]}</text>')
        s.append(f'<text x="{x + cw - 8}" y="{y0 - 16}" text-anchor="end" '
                 f'font-family="{MONO}" font-size="10.5" fill="#4a6275">{n}</text>')

        for j, (tec, doms) in enumerate(sorted(datos[tac].items())):
            y = y0 + j * (ch + gy)
            color = COLOR_DOM.get(sorted(doms)[0], "#2ee6f0")
            s.append(f'<rect x="{x}" y="{y}" width="{cw}" height="{ch}" fill="#0d1a22" '
                     f'stroke="{color}" stroke-opacity="0.5" rx="2"/>')
            s.append(f'<rect x="{x}" y="{y}" width="3" height="{ch}" fill="{color}"/>')
            s.append(f'<text x="{x + 11}" y="{y + 17}" font-family="{MONO}" font-size="11" '
                     f'fill="#d3e2ee">{tec}</text>')
            # varios dominios cubren la misma tecnica: se marca con un punto por dominio
            if len(doms) > 1:
                for k, d in enumerate(sorted(doms)[1:4]):
                    s.append(f'<circle cx="{x + cw - 9 - k * 8}" cy="{y + 13}" r="2.6" '
                             f'fill="{COLOR_DOM.get(d, "#2ee6f0")}"/>')

    s.append(f'<rect y="{alto - 2}" width="{ancho}" height="2" fill="#2ee6f0" opacity="0.5"/>')
    s.append(f'<text x="{x0}" y="{alto - 22}" font-family="{MONO}" font-size="10" '
             f'fill="#31485a">Generado por tools/generar_cobertura_svg.py desde rules/  ·  '
             f'la capa completa para ATT&amp;CK Navigator esta en navigator/coverage-layer.json</text>')
    s.append("</svg>")

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    SALIDA.write_text("\n".join(s), encoding="utf-8")
    print(f"{SALIDA.relative_to(RAIZ)}: {len(cols)} tacticas, "
          f"{sum(len(v) for v in datos.values())} celdas, {ancho}x{alto}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
