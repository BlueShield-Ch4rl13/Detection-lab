#!/usr/bin/env python3
"""
Valida la capa de respuesta: que los playbooks cuadren con las reglas, que el
esquema se respete y que ninguna accion peligrosa este marcada como automatica.

Lo que comprueba, y por que cada cosa
-------------------------------------

1. Cada familia que aparece en las reglas de Wazuh tiene playbook, y no hay
   playbooks huerfanos. Una alerta cuya familia no tiene playbook llega al SOAR
   y no sabe que hacer con ella: acaba en la cola generica, que es donde van a
   morir las alertas.

2. Todos los campos del esquema estan, en todos los playbooks.

3. `reversible` y `requiere_aprobacion` valen exactamente "si" o "no". Sin
   comillas, YAML convierte `no` en el booleano False y `si` se queda como
   cadena; esa asimetria hace que una comparacion contra "no" falle en silencio.

4. **Ninguna accion de radio amplio esta automatizada.** Es la comprobacion que
   de verdad importa: bloquear en el perimetro, tocar una cuenta o cambiar una
   politica de flota afecta a gente que no es el atacante, y eso no lo decide
   una maquina. El resto son comprobaciones de forma; esta es de fondo.

Uso:
    python3 tools/validar_respuesta.py
"""
from __future__ import annotations

import re
import sys
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
PLAYBOOKS = RAIZ / "respuesta" / "playbooks"
REGLAS_WAZUH = RAIZ / "deploy" / "wazuh" / "reglas"

CAMPOS = {"familia", "nombre", "descripcion", "enriquecimiento", "evidencia",
          "triaje", "cierre_automatico", "contencion", "requiere_persona",
          "escalado"}
CAMPOS_CONTENCION = {"accion", "alcance", "radio", "reversible",
                     "requiere_aprobacion", "justificacion"}

# El radio se DECLARA en cada accion, no se adivina del texto.
#
# La primera version de esta comprobacion buscaba palabras como "perimetro" en
# la prosa, y marco como peligrosa una accion cuyo alcance decia literalmente
# "no toca el perimetro". Adivinar el radio leyendo espanol es exactamente el
# tipo de comprobacion que produce falsos positivos y acaba desactivada.
RADIOS = ["proceso", "objeto", "equipo", "cuenta", "organizacion"]

# Radios que NO pueden automatizarse: afectan a personas que no son el atacante.
RADIO_REQUIERE_APROBACION = {"cuenta", "organizacion"}


def main() -> int:
    errores, avisos = [], []

    # Se leen TODOS los XML, no solo el generado: las reglas escritas a mano
    # (Zero Trust, cumplimiento, inteligencia) tambien llegan al SOAR y tambien
    # necesitan playbook.
    familias_reglas = set()
    if REGLAS_WAZUH.is_dir():
        for f in REGLAS_WAZUH.glob("*.xml"):
            familias_reglas |= set(re.findall(r"playbook=([a-z]+)",
                                              f.read_text(encoding="utf-8")))

    pbs = {}
    for f in sorted(PLAYBOOKS.glob("*.yml")):
        texto = f.read_text(encoding="utf-8")
        try:
            d = yaml.safe_load(texto)
        except Exception as e:
            errores.append((f.name, f"YAML invalido: {e}"))
            continue
        pbs[d.get("familia", f.stem)] = d

        if set(d) != CAMPOS:
            errores.append((f.name, f"campos: falta={CAMPOS - set(d)} "
                                    f"sobra={set(d) - CAMPOS}"))
        if d.get("familia") != f.stem:
            errores.append((f.name, f"familia '{d.get('familia')}' != nombre de fichero"))
        if any(c in texto for c in "aeiou".translate(str.maketrans(
                "aeiou", "aeiou")) ) and any(c in texto for c in "áéíóúñÁÉÍÓÚÑ"):
            errores.append((f.name, "lleva tildes; el resto del repositorio no las usa en YAML"))

        for i, c in enumerate(d.get("contencion") or [], 1):
            faltan = CAMPOS_CONTENCION - set(c)
            if faltan:
                errores.append((f.name, f"contencion #{i}: falta {faltan}"))
                continue
            rev, apr = c["reversible"], c["requiere_aprobacion"]
            if rev not in ("si", "no") or apr not in ("si", "no"):
                errores.append((f.name, f"contencion #{i}: reversible={rev!r} "
                                        f"requiere_aprobacion={apr!r}; "
                                        f"deben ir entrecomillados como \"si\" o \"no\""))
                continue
            radio = c["radio"]
            if radio not in RADIOS:
                errores.append((f.name, f"contencion #{i}: radio '{radio}' no valido; "
                                        f"usa uno de {RADIOS}"))
                continue
            if radio in RADIO_REQUIERE_APROBACION and apr == "no":
                errores.append((f.name,
                    f"contencion #{i} tiene radio '{radio}' y esta automatizada. "
                    f"Lo que afecta a una cuenta o a la organizacion no lo decide "
                    f"una maquina: '{c['accion'][:55]}'"))
            if rev == "no" and radio != "proceso":
                errores.append((f.name,
                    f"contencion #{i} es irreversible con radio '{radio}'. Solo se "
                    f"admite irreversible cuando el objetivo es un proceso "
                    f"identificado sin ambiguedad: '{c['accion'][:55]}'"))

        if not (d.get("requiere_persona") or []):
            avisos.append((f.name, "no declara nada que requiera persona; "
                                   "revisa si es realista"))

    # Ninguna regla puede quedarse sin el grupo que la lleva al SOAR: si falta,
    # dispara en Wazuh y no abre caso, que es donde las detecciones se pierden
    # pareciendo que funcionan.
    if REGLAS_WAZUH.is_dir():
        for f in sorted(REGLAS_WAZUH.glob("*.xml")):
            texto = f.read_text(encoding="utf-8")
            n_reglas = len(re.findall(r"<rule id=", texto))
            n_grupo = len(re.findall(r"<group>[^<]*detectionlab", texto))
            if n_reglas and n_grupo < n_reglas:
                errores.append((f.name, f"{n_reglas - n_grupo} de {n_reglas} reglas "
                                        f"sin el grupo 'detectionlab': no llegarian "
                                        f"al SOAR"))

    sin_pb = familias_reglas - set(pbs)
    huerfanos = set(pbs) - familias_reglas
    for x in sorted(sin_pb):
        errores.append(("(reglas)", f"familia '{x}' aparece en las reglas y no tiene playbook"))
    for x in sorted(huerfanos):
        avisos.append(("(playbooks)", f"playbook '{x}' no lo usa ninguna regla"))

    print(f"Playbooks: {len(pbs)}   familias en las reglas: {len(familias_reglas)}")
    auto = sum(1 for d in pbs.values() for c in (d.get("contencion") or [])
               if c.get("requiere_aprobacion") == "no")
    apr = sum(1 for d in pbs.values() for c in (d.get("contencion") or [])
              if c.get("requiere_aprobacion") == "si")
    vacios = [k for k, v in pbs.items() if not (v.get("cierre_automatico") or [])]
    print(f"Contencion: {auto} automaticas, {apr} con aprobacion")
    print(f"Sin cierre automatico ({len(vacios)}): {', '.join(sorted(vacios))}")

    print(f"\n{len(errores)} error(es), {len(avisos)} aviso(s)")
    for n, e in errores:
        print(f"  x {n}: {e}")
    for n, a in avisos:
        print(f"  ! {n}: {a}")
    if not errores:
        print("\nCapa de respuesta coherente.")
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
