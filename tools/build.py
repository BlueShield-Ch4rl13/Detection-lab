#!/usr/bin/env python3
"""
Genera, desde una unica biblioteca Sigma, el contenido desplegable de cuatro
SIEM: Splunk, Microsoft Sentinel, Wazuh y Elastic.

    rules/*.yml
        |
        +-- deploy/splunk/reglas/savedsearches.conf   busquedas con cadencia
        +-- deploy/sentinel/reglas/*.kql              consultas KQL por dominio
        +-- deploy/wazuh/reglas/*.xml                 reglas nativas
        +-- deploy/elastic/reglas/*.txt               Lucene y ES|QL

Cada carpeta de SIEM lleva ademas, escritas a mano y no regeneradas:
    consultas/    caza sobre lo ya indexado, con su ventana y su umbral
    listas/       indicadores de News CTI (los genera tools/sync_cti.py)
    INSTALAR.md   como se carga todo eso en ese SIEM concreto

La regla se escribe una vez. Si hay que cambiar un indice, un sourcetype o una
tabla, se cambia en tools/pipelines/ y todo el contenido se regenera. Ninguna
consulta se edita a mano en deploy/: se sobrescribe en cada ejecucion.

Que NO hace este script, y por que
----------------------------------
No inventa lo que un backend no soporta. Tres reglas son correlaciones Sigma
(cuentan cardinalidad de un campo en una ventana) y el backend de Kusto no las
convierte; sus consultas KQL estan escritas a mano en deploy/sentinel/
consultas/correlaciones.kql y este script las respeta. Wazuh tampoco puede expresarlas, y
sigma_to_wazuh.py lo declara en sus avisos en vez de generar una regla que
parezca equivalente sin serlo.

Uso:
    python3 tools/build.py              genera todo
    python3 tools/build.py --check      no escribe, solo informa de diferencias
    python3 tools/build.py --solo splunk,sentinel
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from sigma.processing.resolver import ProcessingPipelineResolver

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


_PLUGINS = InstalledSigmaPlugins.autodiscover()
_RESOLVER = ProcessingPipelineResolver(_PLUGINS.pipelines)

RAIZ = Path(__file__).resolve().parent.parent
REGLAS = RAIZ / "rules"
PIPES = RAIZ / "tools" / "pipelines"
DEPLOY = RAIZ / "deploy"

MARCA = "# Generado por tools/build.py — no editar a mano"

# ---------------------------------------------------------------------------
# Perfiles de conversion
#
# Cada dominio de reglas necesita sus propios pipelines. Los pipelines
# comunitarios (sysmon, splunk_windows, ecs_*, sentinel_asim) resuelven el caso
# general; los de tools/pipelines/ anaden lo que falta.
# ---------------------------------------------------------------------------
PERFILES: dict[str, dict] = {
    "splunk": {
        "backend": "splunk",
        "ext": "conf",
        "pipelines": {
            "*": ["sysmon", "splunk_windows", str(PIPES / "splunk.yml")],
        },
    },
    "sentinel": {
        "backend": "kusto",
        "ext": "kql",
        "pipelines": {
            "*": [str(PIPES / "sentinel.yml"), "sentinel_asim", str(PIPES / "sentinel-post.yml")],
        },
    },
    "elastic": {
        "backend": "lucene",
        "ext": "txt",
        "pipelines": {
            "windows": ["ecs_windows"],
            "macos": ["ecs_macos_esf"],
            "contenedores": ["ecs_kubernetes"],
            "*": ["ecs_windows"],
        },
    },
    "elastic-esql": {
        "backend": "esql",
        "ext": "txt",
        "pipelines": {"*": ["sysmon"]},
    },
}

# Cadencia, ventana de busqueda y severidad de Splunk segun el nivel Sigma.
# Lo critico se mira cada pocos minutos; lo que necesita acumular, cada hora.
PERFIL_SPLUNK = {
    "critical": ("*/5 * * * *", "-10m", 6),
    "high": ("*/15 * * * *", "-20m", 5),
    "medium": ("*/30 * * * *", "-35m", 4),
    "low": ("15 * * * *", "-1h", 3),
    "informational": ("30 * * * *", "-1h", 2),
}


# ---------------------------------------------------------------------------
def dominio(fichero: Path) -> str:
    return fichero.relative_to(REGLAS).parts[0]


def leer(fichero: Path) -> dict:
    """Primer documento de la regla: el que lleva titulo, nivel y etiquetas."""
    for doc in yaml.safe_load_all(fichero.read_text(encoding="utf-8")):
        if doc and "title" in doc:
            return doc
    return {}


def tecnicas(doc: dict) -> list[str]:
    out = []
    for t in doc.get("tags", []) or []:
        m = re.match(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", str(t), re.I)
        if m:
            out.append(m.group(1).upper() + (f".{m.group(2)}" if m.group(2) else ""))
    return sorted(set(out))


def convertir(fichero: Path, perfil: dict) -> tuple[str | None, str | None]:
    """Devuelve (consulta, error). Nunca lanza: que un backend falle en una
    regla no debe abortar la generacion de las otras 78.

    El pipeline se resuelve DE NUEVO para cada regla, a proposito. La
    transformacion set_state escribe la tabla de destino en el estado del
    pipeline, y ese estado sobrevive de una conversion a la siguiente: si una
    regla de Entra ID fija SigninLogs y la siguiente no fija ninguna tabla, la
    heredaria en silencio. Una consulta valida contra la tabla equivocada es el
    peor fallo posible en una deteccion, asi que se paga el coste de resolver
    otra vez (unas centesimas de segundo por regla).
    """
    pipes = perfil["pipelines"].get(dominio(fichero)) or perfil["pipelines"]["*"]
    try:
        pipeline = _RESOLVER.resolve(pipes)
        backend = _PLUGINS.backends[perfil["backend"]](pipeline)
        consultas = backend.convert(SigmaCollection.load_ruleset([str(fichero)]))
    except Exception as exc:
        return None, " ".join(str(exc).split())[:220]

    # En las correlaciones el backend emite varios bloques que son partes de UNA
    # sola consulta (la busqueda base, el bin/stats y el filtro por el contador).
    # Se unen, no se separan.
    texto = "\n".join(str(c) for c in consultas).strip()
    return texto or None, None if texto else "sin salida"


# ---------------------------------------------------------------------------
def escapar_conf(spl: str) -> str:
    """Splunk .conf continua una linea con barra invertida al final."""
    return " \\\n".join(spl.splitlines())


def generar_splunk(reglas, resultados) -> str:
    partes = [
        MARCA,
        "# Fuente: rules/  ·  pipeline: tools/pipelines/splunk.yml",
        "#",
        "# Los indices no estan escritos en las reglas Sigma: salen del pipeline.",
        "# Para adaptar a otro entorno se edita el pipeline y se regenera.",
        "",
    ]
    for f, doc, consulta in resultados:
        nivel = (doc.get("level") or "medium").lower()
        cron, ventana, sev = PERFIL_SPLUNK.get(nivel, PERFIL_SPLUNK["medium"])
        tec = ",".join(tecnicas(doc)) or "-"
        desc = " ".join((doc.get("description") or "").split())[:400]
        partes.append(f"""[DL - {doc.get('title', f.stem)}]
description = {desc}
search = {escapar_conf(consulta)}
cron_schedule = {cron}
dispatch.earliest_time = {ventana}
dispatch.latest_time = now
enableSched = 1
alert.severity = {sev}
alert.track = 1
alert.suppress = 1
alert.suppress.period = 60m
alert.digest_mode = 1
counttype = number of events
relation = greater than
quantity = 0
action.notable = 1
action.notable.param.rule_title = {doc.get('title', f.stem)}
action.notable.param.security_domain = threat
action.notable.param.severity = {nivel}
action.notable.param.drilldown_name = Ver eventos de la deteccion
# MITRE ATT&CK: {tec}
# Regla Sigma: {f.relative_to(RAIZ)}
# UUID: {doc.get('id', '-')}
""")
    return "\n".join(partes)


def generar_kql(reglas, resultados, fallos) -> dict[str, str]:
    """Un fichero .kql por dominio, con la cabecera de preparacion cuando la
    tabla de destino la necesita."""
    PRELUDIO = {
        "contenedores": (
            "// AKS: el evento de auditoria viaja dentro de log_s. Antepon esto\n"
            "// a cada consulta de este fichero si tu origen es AzureDiagnostics:\n"
            "//   AzureDiagnostics\n"
            "//   | where Category == 'kube-audit'\n"
            "//   | extend e = parse_json(log_s)\n"
            "//   | extend verb = tostring(e.verb), username = tostring(e.user.username),\n"
            "//            namespace = tostring(e.objectRef.namespace),\n"
            "//            resource = tostring(e.objectRef.resource),\n"
            "//            subresource = tostring(e.objectRef.subresource),\n"
            "//            apiGroup = tostring(e.objectRef.apiGroup)\n"
        ),
        "windows": (
            "// Las consultas sobre DeviceEvents (process_access, pipe_created,\n"
            "// create_remote_thread) necesitan expandir AdditionalFields:\n"
            "//   | extend af = parse_json(AdditionalFields)\n"
            "//   | extend PipeName = tostring(af.PipeName),\n"
            "//            GrantedAccess = tostring(af.DesiredAccess),\n"
            "//            CallTrace = tostring(af.CallTrace)\n"
        ),
        "cloud": (
            "// SigninLogs: DeviceDetail es dynamic. Antepon:\n"
            "//   | extend DeviceIsCompliant = tostring(DeviceDetail.isCompliant),\n"
            "//            DeviceTrustType   = tostring(DeviceDetail.trustType)\n"
        ),
    }
    salidas = {}
    por_dominio = defaultdict(list)
    for f, doc, consulta in resultados:
        por_dominio[dominio(f)].append((f, doc, consulta))

    for dom, items in sorted(por_dominio.items()):
        bloques = [
            f"// {MARCA[2:]}",
            f"// Dominio: {dom}  ·  pipeline: tools/pipelines/sentinel.yml + sentinel_asim",
            "",
        ]
        if dom in PRELUDIO:
            bloques += [PRELUDIO[dom], ""]
        for f, doc, consulta in items:
            tec = ", ".join(tecnicas(doc)) or "-"
            bloques.append(
                f"// ─────────────────────────────────────────────────────────\n"
                f"// {doc.get('title', f.stem)}\n"
                f"// Severidad: {doc.get('level', 'medium')}  ·  ATT&CK: {tec}\n"
                f"// Origen: {f.relative_to(RAIZ)}\n"
                f"{consulta}\n"
            )
        # los fallos de este dominio se declaran en el propio fichero
        propios = [(f, m) for f, m in fallos if dominio(f) == dom]
        if propios:
            bloques.append("// ── Sin conversion automatica a KQL ──")
            for f, m in propios:
                bloques.append(f"//   {f.name}: {m}")
            bloques.append("// Ver deploy/sentinel/consultas/correlaciones.kql\n")
        salidas[dom] = "\n".join(bloques)
    return salidas


def generar_texto(resultados, cabecera: str) -> dict[str, str]:
    por_dominio = defaultdict(list)
    for f, doc, consulta in resultados:
        por_dominio[dominio(f)].append((f, doc, consulta))
    salidas = {}
    for dom, items in sorted(por_dominio.items()):
        bloques = [MARCA, f"# Dominio: {dom}  ·  {cabecera}", ""]
        for f, doc, consulta in items:
            bloques.append(f"# {doc.get('title', f.stem)}  [{doc.get('level','medium')}]")
            bloques.append(consulta)
            bloques.append("")
        salidas[dom] = "\n".join(bloques)
    return salidas


# ---------------------------------------------------------------------------
# Mapa purple team
#
# Se genera, no se mantiene a mano. La version escrita a mano citaba trece
# reglas que ya no existen tras la fusion de bibliotecas: un mapa purple team
# que apunta a reglas retiradas hace perder el tiempo al que lo sigue, porque
# emula una tecnica y luego busca una deteccion que nadie va a disparar.
# ---------------------------------------------------------------------------
TELEMETRIA = {
    ("process_creation", "windows"): "Sysmon EID 1",
    ("process_creation", "linux"): "execve (auditd / Falco)",
    ("process_creation", "macos"): "ESF exec",
    ("network_connection", "windows"): "Sysmon EID 3",
    ("file_event", "windows"): "Sysmon EID 11",
    ("file_event", "macos"): "ESF create",
    ("registry_event", "windows"): "Sysmon EID 12/13/14",
    ("process_access", None): "Sysmon EID 10",
    ("pipe_created", None): "Sysmon EID 17/18",
    ("create_remote_thread", None): "Sysmon EID 8",
    ("image_load", "windows"): "Sysmon EID 7",
    ("dns", None): "Suricata eve / DNS del resolutor",
    ("proxy", None): "Registro del proxy",
    ("webserver", None): "Acceso de nginx / apache",
    (None, "windows"): "Canal Security / System de Windows",
    (None, "azure"): "Entra ID (SigninLogs / AuditLogs)",
    (None, "m365"): "Registro de auditoria de M365",
    (None, "proofpoint"): "Proofpoint TAP",
    (None, "netskope"): "Alertas de Netskope",
    (None, "kubernetes"): "Auditoria del API server",
}

# Tecnicas sin prueba en Atomic Red Team: emularlas necesita otra herramienta o
# una accion manual. Decirlo evita que alguien busque un atomic que no existe.
SIN_ATOMIC = {
    "T1110.003": "Rociado de contrasenas contra el IdP: usar una prueba controlada del propio tenant",
    "T1539": "Robo de token de sesion: requiere un proxy AitM tipo Evilginx en laboratorio aislado",
    "T1534": "Envio interno masivo: se emula desde el propio buzon, no con Atomic",
    "T1566.001": "Entrega de phishing: se emula enviando un correo de prueba al tenant",
}


def telemetria_de(doc) -> str:
    ls = doc.get("logsource", {}) or {}
    cat, prod = ls.get("category"), ls.get("product")
    for clave in ((cat, prod), (cat, None), (None, prod)):
        if clave in TELEMETRIA:
            return TELEMETRIA[clave]
    return " / ".join(x for x in (cat, prod, ls.get("service")) if x) or "-"


def generar_atomic_map(resultados_por_regla) -> str:
    """Construye purple/atomic-map.md desde las reglas: tecnica -> reglas que
    la cubren -> prueba de Atomic Red Team -> telemetria donde se ve."""
    por_tecnica: dict[str, list] = defaultdict(list)
    for f, doc in resultados_por_regla:
        for t in tecnicas(doc):
            por_tecnica[t].append((f, doc))

    partes = [
        "# 🟣 Mapeo Purple Team — Atomic Red Team ↔ Detecciones",
        "",
        f"<!-- {MARCA[2:]} · fuente: rules/ -->",
        "",
        "El bucle: **emular** una técnica con Atomic Red Team → comprobar que **salta**",
        "la regla en el SIEM → si no salta, **afinar** la regla → volver a medir la",
        "cobertura.",
        "",
        "Este fichero **se genera** desde `rules/` con `python tools/build.py`. No se",
        "edita a mano: un mapa que cita reglas que ya no existen manda a emular una",
        "técnica y luego a buscar una detección que nadie va a disparar.",
        "",
        "> Ejecuta las pruebas **solo en el laboratorio aislado**. Limpia siempre con",
        "> `-Cleanup`.",
        "",
        "```powershell",
        "Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser",
        "Import-Module Invoke-AtomicRedTeam",
        "Invoke-AtomicTest T1003.001                 # ejecuta la tecnica",
        "Invoke-AtomicTest T1003.001 -Cleanup        # revierte",
        "```",
        "",
    ]

    ORDEN = ["windows", "linux", "macos", "contenedores", "cloud", "correo", "red", "zta"]
    TITULOS = {
        "windows": "Windows — Sysmon y canal Security",
        "linux": "Linux — auditd / Falco",
        "macos": "macOS — Endpoint Security Framework",
        "contenedores": "Contenedores — auditoría de Kubernetes y runtime",
        "cloud": "Nube e identidad — Entra ID, M365, CASB",
        "correo": "Correo — Proofpoint TAP y Exchange Online",
        "red": "Red — proxy, DNS y servidor web",
        "zta": "Arquitectura Zero Trust",
    }

    for dom in ORDEN:
        filas = []
        for tec in sorted(por_tecnica):
            enDom = [(f, d) for f, d in por_tecnica[tec] if dominio(f) == dom]
            if not enDom:
                continue
            reglas = " · ".join(f"`{f.stem}`" for f, _ in enDom[:3])
            if len(enDom) > 3:
                reglas += f" · y {len(enDom) - 3} mas"
            base = tec.split(".")[0]
            if tec in SIN_ATOMIC or base in SIN_ATOMIC:
                prueba = "— " + SIN_ATOMIC.get(tec, SIN_ATOMIC.get(base, ""))
            else:
                prueba = f"`Invoke-AtomicTest {tec}`"
            filas.append(f"| {tec} | {prueba} | {reglas} | {telemetria_de(enDom[0][1])} |")
        if filas:
            partes += [f"## {TITULOS[dom]}", "",
                       "| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |",
                       "|---|---|---|---|", *filas, ""]

    partes += [
        "## Registro de resultados",
        "",
        "Rellena una fila por ronda de validación. Es lo que convierte la cobertura",
        "declarada en cobertura comprobada: una regla sin probar no es cobertura, es",
        "una hipótesis.",
        "",
        "| Fecha | Técnica | ¿Detectó? | Regla | Notas |",
        "|---|---|---|---|---|",
        "|  |  | ⬜ |  |  |",
        "|  |  | ⬜ |  |  |",
        "|  |  | ⬜ |  |  |",
        "",
        "Tras cada ronda: actualiza el registro, ajusta las reglas con falsos",
        "positivos y vuelve a correr `python tools/validate.py` para regenerar el",
        "mapa de cobertura.",
        "",
    ]
    return "\n".join(partes)


# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="no escribe nada")
    ap.add_argument("--solo", default="", help="lista separada por comas de destinos")
    args = ap.parse_args()

    solo = {s.strip() for s in args.solo.split(",") if s.strip()}
    destinos = [d for d in PERFILES if not solo or d in solo]

    ficheros = sorted(REGLAS.rglob("*.yml"))
    if not ficheros:
        print("No hay reglas en rules/", file=sys.stderr)
        return 1
    print(f"{len(ficheros)} reglas Sigma en rules/\n")

    resumen = {}
    for destino in destinos:
        perfil = PERFILES[destino]
        resultados, fallos = [], []
        for f in ficheros:
            consulta, err = convertir(f, perfil)
            (resultados.append((f, leer(f), consulta)) if consulta
             else fallos.append((f, err or "sin salida")))

        if destino == "splunk":
            escrituras = {"savedsearches.conf": generar_splunk(ficheros, resultados)}
            carpeta = DEPLOY / "splunk" / "reglas"
        elif destino == "sentinel":
            escrituras = {f"{k}.kql": v for k, v in
                          generar_kql(ficheros, resultados, fallos).items()}
            carpeta = DEPLOY / "sentinel" / "reglas"
        elif destino == "elastic":
            escrituras = {f"{k}-lucene.txt": v for k, v in
                          generar_texto(resultados, "Lucene (indexador Wazuh / OpenSearch)").items()}
            carpeta = DEPLOY / "elastic" / "reglas"
        else:  # elastic-esql
            escrituras = {f"{k}-esql.txt": v for k, v in
                          generar_texto(resultados, "ES|QL (Elastic)").items()}
            carpeta = DEPLOY / "elastic" / "reglas"

        if not args.check:
            carpeta.mkdir(parents=True, exist_ok=True)
            for nombre, contenido in escrituras.items():
                (carpeta / nombre).write_text(contenido, encoding="utf-8")

        resumen[destino] = (len(resultados), fallos)
        estado = "" if args.check else f" -> {carpeta.relative_to(RAIZ)}/"
        print(f"{destino:14} {len(resultados):3} convertidas, "
              f"{len(fallos):2} sin conversion{estado}")
        for f, m in fallos:
            print(f"                 · {f.name}: {m[:100]}")

    # El catalogo de reglas se genera de las reglas: un catalogo escrito a mano
    # se desincroniza a la tercera regla nueva y entonces describe detecciones
    # que ya no existen.
    if not args.check and (RAIZ / "docs" / "fusion-de-bibliotecas.md").exists():
        r = subprocess.run([sys.executable, str(RAIZ / "tools" / "generar_catalogo.py")],
                           capture_output=True, text=True)
        print("\n" + (r.stdout.strip() or r.stderr.strip()))

    # La capa de respuesta se compila de los playbooks: el nodo de Shuffle no
    # puede leer ficheros, asi que la tabla va embebida y hay que regenerarla
    # cada vez que cambia un playbook.
    if not args.check and (RAIZ / "respuesta" / "playbooks").is_dir():
        r = subprocess.run([sys.executable, str(RAIZ / "tools" / "generar_enrutador.py")],
                           capture_output=True, text=True)
        print("\n" + (r.stdout.strip() or r.stderr.strip()))

    # El mapa purple team se genera de las reglas, no se mantiene a mano.
    if not args.check:
        mapa = RAIZ / "purple" / "atomic-map.md"
        mapa.parent.mkdir(parents=True, exist_ok=True)
        mapa.write_text(generar_atomic_map([(f, leer(f)) for f in ficheros]),
                        encoding="utf-8")
        print(f"\n{'purple/atomic-map.md':14} regenerado desde rules/")

    # Wazuh se delega al backend propio: pySigma no tiene uno oficial.
    if not solo or "wazuh" in solo:
        print()
        r = subprocess.run(
            [sys.executable, str(RAIZ / "tools" / "sigma_to_wazuh.py")]
            + (["--check"] if args.check else []),
            capture_output=True, text=True,
        )
        print(r.stdout.strip() or r.stderr.strip())

    total_fallos = sum(len(f) for _, f in resumen.values())
    print(f"\n{'Comprobacion' if args.check else 'Generacion'} terminada. "
          f"{total_fallos} conversiones sin salida automatica "
          f"(declaradas en cada fichero de destino).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
