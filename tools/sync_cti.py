#!/usr/bin/env python3
"""
Convierte el feed de News CTI en listas de indicadores que cada SIEM sabe leer.

    ScriptNewsCTI/data/iocs_latest.json
              |
              +-- intel/listas/wazuh/*.cdb        listas CDB para <list lookup=...>
              +-- intel/listas/splunk/*.csv       lookups para |inputlookup
              +-- intel/listas/sentinel/*.csv     watchlists
              +-- intel/listas/elastic/*.ndjson   indicadores para el motor de reglas
              +-- intel/listas/RESUMEN.md         que hay en cada lista y de cuando

Tres decisiones que conviene entender antes de tocar nada
--------------------------------------------------------

1. **Se filtra por puntuacion, no se vuelca todo.** El feed trae ~700 IOCs por
   ejecucion; la mayoria son de nivel bajo y con vida util de horas. Alertar
   sobre todos convierte el SIEM en un generador de ruido. Por defecto solo
   entran los de nivel alto y medio, y los hashes entran siempre porque un hash
   no caduca como caduca una IP.

2. **Las IP y dominios generan CAZA, no ALERTA.** Un indicador de reputacion
   coincide muchas veces por motivos aburridos: sinkholes, CDN compartidas,
   dominios reciclados. Lo que se genera para IP y dominio son consultas de caza
   programadas con umbral; el unico indicador que se despliega como alerta
   directa es el hash de fichero, porque un hash coincide o no coincide.

3. **Cada indicador lleva su fecha.** Sin fecha no se puede caducar la lista, y
   una lista de reputacion que no caduca acaba disparando por una IP que hoy es
   de un servicio legitimo. El campo `visto` va en todas las salidas y
   `--max-dias` descarta lo viejo.

Uso:
    python3 tools/sync_cti.py                 descarga y genera
    python3 tools/sync_cti.py --local RUTA    usa un json ya descargado
    python3 tools/sync_cti.py --min-nivel media --max-dias 30
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

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
SALIDA = RAIZ / "intel" / "listas"

FUENTE = ("https://raw.githubusercontent.com/BlueShield-Ch4rl13/"
          "ScriptNewsCTI/main/data/iocs_latest.json")

# Orden de severidad del feed de News CTI.
NIVELES = {"baja": 0, "media": 1, "alta": 2}

# Tipos del feed agrupados por como los consume un SIEM. El feed emite
# 'ip:port' con el puerto pegado, que hay que partir antes de comparar contra
# un campo de direccion.
GRUPOS = {
    "ip": {"ipv4", "ip:port"},
    "dominio": {"domain", "hostname"},
    "url": {"url"},
    "hash": {"filehash-sha256", "filehash-sha1", "filehash-md5"},
}

MARCA = "Generado por tools/sync_cti.py desde ScriptNewsCTI - no editar a mano"


def descargar(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "detection-lab-intel"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read())


def normalizar(ioc: dict) -> tuple[str, str] | None:
    """Devuelve (grupo, valor_limpio) o None si el tipo no se usa."""
    tipo = (ioc.get("type") or "").lower()
    valor = (ioc.get("value") or "").strip()
    if not valor:
        return None
    for grupo, tipos in GRUPOS.items():
        if tipo in tipos:
            # 'ip:port' -> solo la IP. El puerto se conserva aparte en el CSV,
            # pero la comparacion contra un campo de destino es por direccion.
            if tipo == "ip:port" and ":" in valor:
                valor = valor.rsplit(":", 1)[0]
            return grupo, valor
    return None


def edad_dias(ioc: dict, ahora: datetime) -> int | None:
    for campo, formato in (("first_seen", "%Y-%m-%d %H:%M:%S UTC"),
                           ("first_seen_local", "%Y-%m-%dT%H:%M:%SZ")):
        crudo = ioc.get(campo)
        if not crudo:
            continue
        try:
            d = datetime.strptime(crudo, formato).replace(tzinfo=timezone.utc)
            return (ahora - d).days
        except ValueError:
            continue
    return ioc.get("age_days")


def seleccionar(datos: dict, min_nivel: str, max_dias: int):
    ahora = datetime.now(timezone.utc)
    umbral = NIVELES[min_nivel]
    por_grupo: dict[str, list[dict]] = defaultdict(list)
    descartes = Counter()

    for ioc in datos.get("iocs", []):
        norm = normalizar(ioc)
        if not norm:
            descartes["tipo no usado"] += 1
            continue
        grupo, valor = norm

        edad = edad_dias(ioc, ahora)
        if edad is not None and edad > max_dias:
            descartes["caducado"] += 1
            continue

        # Los hashes entran siempre: no caducan como una IP y no comparten
        # infraestructura con nada legitimo.
        if grupo != "hash" and NIVELES.get(ioc.get("level"), 0) < umbral:
            descartes["nivel bajo"] += 1
            continue

        por_grupo[grupo].append({
            "valor": valor,
            "tipo": ioc.get("type", ""),
            "amenaza": (ioc.get("threat") or "desconocida").replace(",", " "),
            "nivel": ioc.get("level", ""),
            "score": ioc.get("score", ""),
            "confianza": ioc.get("confidence", ""),
            "pais": ioc.get("country", ""),
            "fuente": ioc.get("source", ""),
            "visto": ioc.get("first_seen", ""),
            "edad_dias": edad if edad is not None else "",
        })

    for g in por_grupo:
        vistos, unicos = set(), []
        for x in por_grupo[g]:
            if x["valor"] not in vistos:
                vistos.add(x["valor"])
                unicos.append(x)
        por_grupo[g] = sorted(unicos, key=lambda x: -(x["score"] or 0))
    return por_grupo, descartes


# ---------------------------------------------------------------------------
# Una salida por SIEM
# ---------------------------------------------------------------------------
def escribir_wazuh(por_grupo, kev, sello):
    """Listas CDB: 'clave:valor' por linea, una lista por tipo de indicador.

    Wazuh compila estos ficheros con ossec-makelists y los consulta con
    <list field="..." lookup="match_key">. El valor de la derecha sale en la
    alerta, asi que ahi va la amenaza: el analista ve 'Mirai' sin abrir nada.
    """
    d = SALIDA / "wazuh"
    d.mkdir(parents=True, exist_ok=True)
    nombres = {"ip": "cti_ip", "dominio": "cti_dominio",
               "url": "cti_url", "hash": "cti_hash"}
    escritos = {}
    for grupo, nombre in nombres.items():
        filas = por_grupo.get(grupo, [])
        # Sin cabecera de comentario: ossec-makelists trata cada linea como
        # entrada y una linea de comentario se convertiria en un indicador.
        cuerpo = "\n".join(f"{x['valor']}:{x['amenaza']}|{x['nivel']}" for x in filas)
        (d / f"{nombre}.cdb").write_text(cuerpo + ("\n" if cuerpo else ""), encoding="utf-8")
        escritos[nombre] = len(filas)
    (d / "cti_cve_kev.cdb").write_text(
        "\n".join(f"{v['cve']}:{v.get('vendor','')} {v.get('product','')}".strip()
                  for v in kev) + "\n", encoding="utf-8")
    escritos["cti_cve_kev"] = len(kev)
    return escritos


def escribir_splunk(por_grupo, kev, sello):
    """Lookups CSV. Splunk los indexa por la primera columna."""
    d = SALIDA / "splunk"
    d.mkdir(parents=True, exist_ok=True)
    cols = ["valor", "tipo", "amenaza", "nivel", "score", "confianza",
            "pais", "fuente", "visto", "edad_dias"]
    escritos = {}
    for grupo in ("ip", "dominio", "url", "hash"):
        filas = por_grupo.get(grupo, [])
        ruta = d / f"cti_{grupo}.csv"
        with ruta.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(filas)
        escritos[ruta.name] = len(filas)
    ruta = d / "cti_cve_kev.csv"
    with ruta.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve", "vendor", "product", "name",
                                          "date_added", "ransomware"],
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(kev)
    escritos[ruta.name] = len(kev)
    return escritos


def escribir_sentinel(por_grupo, kev, sello):
    """Watchlists. Sentinel las importa por CSV y las consulta con _GetWatchlist()."""
    d = SALIDA / "sentinel"
    d.mkdir(parents=True, exist_ok=True)
    cols = ["valor", "tipo", "amenaza", "nivel", "score", "confianza",
            "pais", "fuente", "visto"]
    escritos = {}
    for grupo in ("ip", "dominio", "url", "hash"):
        filas = por_grupo.get(grupo, [])
        ruta = d / f"CTI_{grupo.capitalize()}.csv"
        with ruta.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(filas)
        escritos[ruta.name] = len(filas)
    return escritos


def escribir_elastic(por_grupo, kev, sello):
    """NDJSON con el esquema ECS de amenazas, para el indice de indicadores."""
    d = SALIDA / "elastic"
    d.mkdir(parents=True, exist_ok=True)
    ECS = {"ip": "ipv4-addr", "dominio": "domain-name",
           "url": "url", "hash": "file"}
    escritos = {}
    for grupo, tipo_ecs in ECS.items():
        filas = por_grupo.get(grupo, [])
        lineas = []
        for x in filas:
            doc = {
                "@timestamp": sello,
                "event": {"kind": "enrichment", "category": "threat",
                          "type": "indicator", "dataset": "newscti"},
                "threat": {
                    "indicator": {
                        "type": tipo_ecs,
                        "description": x["amenaza"],
                        "confidence": x["nivel"],
                        "provider": x["fuente"],
                        "first_seen": x["visto"],
                    }
                },
            }
            ind = doc["threat"]["indicator"]
            if grupo == "ip":
                ind["ip"] = x["valor"]
            elif grupo == "dominio":
                ind["url"] = {"domain": x["valor"]}
            elif grupo == "url":
                ind["url"] = {"original": x["valor"]}
            else:
                algo = {"filehash-sha256": "sha256", "filehash-sha1": "sha1",
                        "filehash-md5": "md5"}.get(x["tipo"], "sha256")
                ind["file"] = {"hash": {algo: x["valor"]}}
            lineas.append(json.dumps(doc, ensure_ascii=False))
        ruta = d / f"cti_{grupo}.ndjson"
        ruta.write_text("\n".join(lineas) + ("\n" if lineas else ""), encoding="utf-8")
        escritos[ruta.name] = len(filas)
    return escritos


def escribir_resumen(por_grupo, kev, datos, descartes, sello, args, escrituras):
    filas_amenaza = Counter()
    for g in por_grupo.values():
        for x in g:
            filas_amenaza[x["amenaza"]] += 1

    lineas = [
        "# Listas de inteligencia",
        "",
        f"<!-- {MARCA} -->",
        "",
        f"**Origen:** [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)  ",
        f"**Feed generado:** {datos.get('generated_utc', '?')} UTC  ",
        f"**Listas generadas:** {sello}  ",
        f"**Filtro aplicado:** nivel minimo `{args.min_nivel}`, "
        f"maximo `{args.max_dias}` dias de antiguedad",
        "",
        "## Que hay en cada lista",
        "",
        "| Indicador | Entradas | Uso previsto |",
        "|---|---:|---|",
        f"| IP | {len(por_grupo.get('ip', []))} | Caza programada, no alerta directa |",
        f"| Dominio | {len(por_grupo.get('dominio', []))} | Caza programada, no alerta directa |",
        f"| URL | {len(por_grupo.get('url', []))} | Caza programada, no alerta directa |",
        f"| Hash | {len(por_grupo.get('hash', []))} | **Alerta directa**: un hash coincide o no |",
        f"| CVE en KEV | {len(kev)} | Priorizacion de parcheo y caza de explotacion |",
        "",
        "## Por que las IP y los dominios no alertan",
        "",
        "Un indicador de reputacion coincide muchas veces por motivos aburridos:",
        "sinkholes de investigadores, CDN compartidas, dominios reciclados, rangos",
        "de proveedores de nube. Desplegarlos como alerta directa llena la cola de",
        "eventos que se cierran sin accion, y eso entrena al turno a cerrar sin",
        "mirar. Se despliegan como **consultas de caza programadas con umbral**, en",
        "`deploy/<siem>/consultas/`.",
        "",
        "El hash es distinto: no comparte infraestructura con nada legitimo, asi que",
        "va como alerta y ademas sin caducidad.",
        "",
        f"## Que se descarto del feed ({sum(descartes.values())} de "
        f"{datos.get('ioc_count', 0)})",
        "",
        "| Motivo | Descartados |",
        "|---|---:|",
    ]
    for motivo, n in descartes.most_common():
        lineas.append(f"| {motivo} | {n} |")

    lineas += ["", "## Familias mas presentes", "",
               "| Amenaza | Indicadores |", "|---|---:|"]
    for amenaza, n in filas_amenaza.most_common(12):
        lineas.append(f"| {amenaza} | {n} |")

    lineas += ["", "## Ficheros generados", "", "| Fichero | Entradas |", "|---|---:|"]
    for siem, escritos in escrituras.items():
        for nombre, n in escritos.items():
            lineas.append(f"| `{siem}/{nombre}` | {n} |")

    lineas += [
        "",
        "## Como se instala cada una",
        "",
        "Ver `deploy/<siem>/INSTALAR.md`. En resumen:",
        "",
        "```bash",
        "# Wazuh: copiar, declarar en ossec.conf y compilar",
        "sudo cp intel/listas/wazuh/*.cdb /var/ossec/etc/lists/",
        "sudo /var/ossec/bin/ossec-makelists",
        "",
        "# Splunk: como lookups de la app",
        "cp intel/listas/splunk/*.csv $SPLUNK_HOME/etc/apps/TA-detection-lab/lookups/",
        "",
        "# Sentinel: Watchlists > New > importar el CSV, alias sin el prefijo CTI_",
        "# Elastic: bulk al indice de indicadores",
        "curl -XPOST 'localhost:9200/logs-ti_newscti-default/_bulk' \\",
        "     -H 'Content-Type: application/x-ndjson' \\",
        "     --data-binary @intel/listas/elastic/cti_ip.ndjson",
        "```",
        "",
    ]
    (SALIDA / "RESUMEN.md").write_text("\n".join(lineas), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", type=Path, help="usa un iocs_latest.json ya descargado")
    ap.add_argument("--min-nivel", choices=list(NIVELES), default="media",
                    help="nivel minimo para IP, dominio y URL (los hashes entran siempre)")
    ap.add_argument("--max-dias", type=int, default=30,
                    help="descarta indicadores mas antiguos que esto")
    args = ap.parse_args()

    if args.local:
        datos = json.loads(args.local.read_text(encoding="utf-8"))
        print(f"Feed local: {args.local}")
    else:
        try:
            datos = descargar(FUENTE)
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"No se pudo descargar el feed: {e}\n"
                  f"Usa --local con una copia de data/iocs_latest.json.", file=sys.stderr)
            return 1
        print(f"Feed descargado de News CTI")

    print(f"  generado {datos.get('generated_utc')} UTC, "
          f"{datos.get('ioc_count')} IOCs, {datos.get('kev_count')} CVEs KEV")

    por_grupo, descartes = seleccionar(datos, args.min_nivel, args.max_dias)
    kev = datos.get("cisa_kev_recent", [])
    sello = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    escrituras = {
        "wazuh": escribir_wazuh(por_grupo, kev, sello),
        "splunk": escribir_splunk(por_grupo, kev, sello),
        "sentinel": escribir_sentinel(por_grupo, kev, sello),
        "elastic": escribir_elastic(por_grupo, kev, sello),
    }
    escribir_resumen(por_grupo, kev, datos, descartes, sello, args, escrituras)

    total = sum(len(v) for v in por_grupo.values())
    print(f"\n  seleccionados {total} indicadores "
          f"({', '.join(f'{k}: {len(v)}' for k, v in sorted(por_grupo.items()))})")
    print(f"  descartados  {sum(descartes.values())} "
          f"({', '.join(f'{k}: {v}' for k, v in descartes.most_common())})")
    print(f"  + {len(kev)} CVEs de CISA KEV")
    print(f"\n  listas en {SALIDA.relative_to(RAIZ)}/ para wazuh, splunk, sentinel y elastic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
