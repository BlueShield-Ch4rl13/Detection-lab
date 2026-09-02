#!/usr/bin/env python3
"""
Compila los playbooks en una tabla de decision y genera el nodo de Shuffle que
la usa.

Por que hay un paso de compilacion
----------------------------------
Un nodo "Execute Python" de Shuffle no lee ficheros del disco ni tiene acceso al
repositorio: recibe el cuerpo del webhook y poco mas. Asi que la tabla se
embebe en el propio nodo en tiempo de generacion. La consecuencia practica es
que **tocar un playbook obliga a regenerar el nodo y volver a pegarlo en
Shuffle**, y por eso el nodo lleva la fecha y el numero de playbooks en la
cabecera: si no cuadran con el repositorio, esta desfasado.

Salidas:
    respuesta/tabla_decision.json       la tabla, legible y diffeable
    integracion/shuffle/enrutador.py    el nodo listo para pegar en Shuffle

Uso:
    python3 tools/generar_enrutador.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
PLAYBOOKS = RAIZ / "respuesta" / "playbooks"
TABLA = RAIZ / "respuesta" / "tabla_decision.json"
NODO = RAIZ / "integracion" / "shuffle" / "enrutador.py"

PLANTILLA = '''# ============================================================
#  Nodo "ENRUTADOR" - Shuffle (accion Execute Python)
#
#  Decide que hacer con una alerta de Detection-lab: a que
#  playbook pertenece, si va al LLM, si se puede cerrar sola y
#  que contencion esta autorizada sin persona.
#
#  GENERADO por tools/generar_enrutador.py el {sello}
#  {n_playbooks} playbooks, {n_acciones} acciones de contencion.
#  Si el repositorio tiene mas playbooks que estos, este nodo
#  esta desfasado: regeneralo y vuelve a pegarlo.
# ------------------------------------------------------------
#  REGLAS DE ORO de Shuffle (las mismas que en IOC PYTHON):
#   - Terminar SIEMPRE con print(json.dumps({{...}})).
#     NO usar return ni exit(json.dumps(...)).
#   - El nombre del nodo debe ser exactamente "ENRUTADOR"
#     para que aguas abajo resuelva como $enrutador.*
#   - Leer el cuerpo como string entre triples comillas.
#
#  Entrada:  la salida de custom-detectionlab.py
#  Salida:   decision estructurada para el resto del flujo
# ============================================================
import json

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


raw = """$exec"""

try:
    a = json.loads(raw)
except Exception:
    a = {{}}

TABLA = {tabla}

familia = a.get("playbook", "generico")
clase = a.get("clase_automatizacion", "auto_analisis")
severidad = int(a.get("severidad", 2) or 2)
pb = TABLA.get(familia, TABLA.get("_generico", {{}}))

# ¿Va al LLM? Solo las clases que lo justifican. Ollama es CPU-bound y el
# README del SOC ya avisa de que se satura; mandarle todo lo convierte en el
# cuello de botella del pipeline.
usar_llm = clase in ("auto_analisis", "auto_contener")

# Contencion autorizada sin persona: la que el playbook marca sin aprobacion.
# El resto se PREPARA y se deja en el caso para que alguien decida.
acciones_auto, acciones_espera = [], []
if clase == "auto_contener":
    for c in pb.get("contencion", []):
        (acciones_auto if c.get("aprobacion") == "no" else acciones_espera).append(c)

decision = {{
    "familia": familia,
    "playbook": pb.get("nombre", "Generico"),
    "clase": clase,
    "severidad": severidad,
    "usar_llm": usar_llm,
    "crear_caso": clase in ("auto_analisis", "auto_contener"),
    "notificar": clase == "auto_contener" or severidad >= 3,
    "enriquecer_con": pb.get("enriquecimiento", []),
    "evidencia": pb.get("evidencia", []),
    "puede_cerrarse_solo": bool(pb.get("cierre_automatico")),
    "condiciones_cierre": pb.get("cierre_automatico", []),
    "contencion_automatica": acciones_auto,
    "contencion_en_espera": acciones_espera,
    "requiere_persona": pb.get("requiere_persona", []),
    "escalar_a": pb.get("escalado", {{}}).get("a", "L2"),
    "plazo_min": pb.get("escalado", {{}}).get("plazo_min", 30),
    # Se arrastra para que los nodos de aguas abajo no tengan que releer $exec
    "agente": a.get("agente", ""),
    "observables": a.get("observables", {{}}),
    "descripcion": a.get("descripcion", ""),
    "mitre": a.get("mitre", []),
    "regla_sigma": a.get("regla_sigma", ""),
    "wazuh_id": a.get("wazuh_id", ""),
}}

print(json.dumps(decision))
'''


def compilar() -> dict:
    tabla = {}
    for f in sorted(PLAYBOOKS.glob("*.yml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        tabla[d["familia"]] = {
            "nombre": d["nombre"],
            "enriquecimiento": [e["fuente"] for e in d.get("enriquecimiento") or []],
            "evidencia": [e["descripcion"] for e in d.get("evidencia") or []],
            "cierre_automatico": [c["condicion"] for c in d.get("cierre_automatico") or []],
            "contencion": [
                {"accion": c["accion"], "radio": c["radio"],
                 "aprobacion": c["requiere_aprobacion"],
                 "reversible": c["reversible"]}
                for c in d.get("contencion") or []
            ],
            "requiere_persona": [r["situacion"] for r in d.get("requiere_persona") or []],
            "escalado": d.get("escalado", {}),
        }
    # Red de seguridad: una familia nueva sin playbook no se pierde, va a
    # analisis con escalado a L2. Perder una alerta por un fichero que falta
    # seria cambiar un descuido por un incidente.
    tabla["_generico"] = {
        "nombre": "Generico (familia sin playbook)",
        "enriquecimiento": ["cti_local", "inventario"],
        "evidencia": [], "cierre_automatico": [], "contencion": [],
        "requiere_persona": ["Toda la alerta: no hay playbook para esta familia"],
        "escalado": {"a": "L2", "plazo_min": 30},
    }
    return tabla


def main() -> int:
    tabla = compilar()
    TABLA.write_text(json.dumps(tabla, indent=2, ensure_ascii=False), encoding="utf-8")

    n_acc = sum(len(v["contencion"]) for v in tabla.values())
    NODO.parent.mkdir(parents=True, exist_ok=True)
    NODO.write_text(PLANTILLA.format(
        sello=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        n_playbooks=len(tabla) - 1,
        n_acciones=n_acc,
        tabla=json.dumps(tabla, ensure_ascii=False, separators=(",", ":")),
    ), encoding="utf-8")

    print(f"{len(tabla) - 1} playbooks compilados, {n_acc} acciones de contencion")
    print(f"  {TABLA.relative_to(RAIZ)}  ({TABLA.stat().st_size // 1024} KB)")
    print(f"  {NODO.relative_to(RAIZ)}  ({NODO.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
