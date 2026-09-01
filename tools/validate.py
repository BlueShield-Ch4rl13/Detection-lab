#!/usr/bin/env python3
"""detection-as-code: valida la biblioteca Sigma y mide la cobertura ATT&CK.

Comprobaciones, en orden:

  1. Cada regla parsea con pySigma y no tiene errores de estructura.
  2. Ningun fichero YAML tiene claves duplicadas. Es un fallo silencioso: la
     segunda sobrescribe a la primera y la deteccion se estrecha sin avisar.
  3. Las etiquetas de tactica ATT&CK usan la forma canonica con guion
     (attack.credential-access), que es la del campo x_mitre_shortname de MITRE
     y la unica que acepta el validador de pySigma.
  4. Las referencias a attack.mitre.org apuntan a una tecnica real.
  5. Los identificadores UUID existen y son unicos.
  6. Si existe deploy/, cada regla tiene su consulta generada, y las consultas
     de SecurityEvent y Event conservan su EventID (el porque, en
     tools/pipelines/sentinel-post.yml).
  7. Las tres correlaciones escritas a mano en KQL siguen sincronizadas con los
     umbrales de su regla Sigma de origen.

Ademas genera la capa de cobertura para ATT&CK Navigator y un informe por
dominio, tactica y severidad.

Uso:
  python tools/validate.py                 valida, informa y genera la capa
  python tools/validate.py --rules rules   ruta alternativa de reglas
  python tools/validate.py --estricto      falla tambien con las incidencias de deploy/
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

# Tacticas ATT&CK en la forma canonica (x_mitre_shortname), con guion.
TACTICAS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}
# Formas antiguas con guion bajo, que el validador de pySigma rechaza.
TACTICAS_ANTIGUAS = {t.replace("-", "_") for t in TACTICAS if "-" in t}

RE_TECNICA = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", re.I)
RE_REF_ATTACK = re.compile(r"attack\.mitre\.org/techniques/(\S*)")

ORDEN_TACTICAS = [
    "reconnaissance", "resource-development",
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]

# Correlaciones sin conversion automatica a KQL: la consulta esta escrita a mano
# en deploy/sentinel/correlaciones.kql. El umbral y la ventana se leen de LOS DOS
# lados y se comparan, para que cambiar solo uno no pase desapercibido.
#
#   fichero Sigma -> (patron que captura el umbral en el KQL,
#                     patron que captura la ventana en el KQL)
CORRELACIONES_MANUALES = {
    "soc_cld_003_password_spraying.yml": (
        re.compile(r"umbral_usuarios\s*=\s*(\d+)"),
        re.compile(r"let ventana\s*=\s*(\S+?);"),
    ),
    "soc_cld_004_token_robado.yml": (
        re.compile(r"RedesDistintas\s*>=\s*(\d+)"),
        re.compile(r"let ventana_sesion\s*=\s*(\S+?);"),
    ),
    "soc_mail_007_envio_masivo_interno.yml": (
        re.compile(r"umbral_destinatarios\s*=\s*(\d+)"),
        re.compile(r"let ventana_correo\s*=\s*(\S+?);"),
    ),
}
RE_SIGMA_GTE = re.compile(r"^\s*gte:\s*(\d+)", re.M)
RE_SIGMA_TIMESPAN = re.compile(r"^\s*timespan:\s*(\S+)", re.M)


# ---------------------------------------------------------------------------
def claves_duplicadas(texto: str) -> list[str]:
    """Detecta claves repetidas dentro de un mismo bloque de indentacion.

    PyYAML acepta el duplicado en silencio y se queda con el ultimo valor. En
    una regla eso significa perder media deteccion sin ningun error visible.
    """
    vistas: dict[tuple[int, str], int] = {}
    duplicadas: list[str] = []
    for n, linea in enumerate(texto.split("\n"), 1):
        if not linea.strip() or linea.lstrip().startswith("#"):
            continue
        if linea.startswith("---"):
            vistas.clear()
            continue
        m = re.match(r"^(\s*)([\w|.\-]+):", linea)
        if not m:
            continue
        sangria, clave = len(m.group(1)), m.group(2)
        # al cerrar un bloque, olvidar las claves mas profundas
        for (s, c) in [k for k in vistas if k[0] > sangria]:
            del vistas[(s, c)]
        if (sangria, clave) in vistas:
            duplicadas.append(f"'{clave}' repetida (lineas {vistas[(sangria, clave)]} y {n})")
        else:
            vistas[(sangria, clave)] = n
    return duplicadas


def cargar(dir_reglas: Path):
    import yaml

    ficheros = sorted(dir_reglas.rglob("*.yml"))
    ok, errores, avisos = [], [], []
    try:
        from sigma.collection import SigmaCollection
        con_pysigma = True
    except ImportError:
        con_pysigma = False
        avisos.append("pySigma no instalado: la validacion se queda en el nivel YAML")

    for f in ficheros:
        texto = f.read_text(encoding="utf-8")
        rel = f.relative_to(RAIZ)

        for d in claves_duplicadas(texto):
            errores.append((rel, f"clave YAML duplicada: {d}"))

        try:
            docs = [d for d in yaml.safe_load_all(texto) if d]
        except Exception as exc:
            errores.append((rel, f"YAML invalido: {str(exc)[:150]}"))
            continue

        principal = next((d for d in docs if "title" in d), None)
        if principal is None:
            errores.append((rel, "ningun documento tiene titulo"))
            continue

        for d in docs:
            for t in d.get("tags", []) or []:
                nombre = str(t).split(".", 1)[1] if str(t).startswith("attack.") else str(t)
                if nombre in TACTICAS_ANTIGUAS:
                    errores.append((rel, f"tactica en forma antigua '{t}': usa "
                                         f"attack.{nombre.replace('_', '-')}"))
            for r in d.get("references", []) or []:
                m = RE_REF_ATTACK.search(str(r))
                if m and not re.match(r"^T\d{4}", m.group(1)):
                    errores.append((rel, f"referencia ATT&CK rota: {r}"))

        if con_pysigma:
            try:
                # Una coleccion, no una regla suelta: hay ficheros con regla base
                # mas correlacion, y leer solo el primer documento los rompe.
                SigmaCollection.load_ruleset([str(f)])
            except Exception as exc:
                errores.append((rel, f"pySigma: {' '.join(str(exc).split())[:170]}"))

        etiquetas: list[str] = []
        for d in docs:
            etiquetas += [str(t) for t in (d.get("tags", []) or [])]
        ls = principal.get("logsource", {}) or {}
        ok.append({
            "file": f, "rel": rel,
            "title": principal.get("title", f.stem),
            "level": (principal.get("level") or "medium").lower(),
            "tags": etiquetas,
            "id": principal.get("id"),
            "dominio": f.relative_to(dir_reglas).parts[0],
            "product": ls.get("product"), "category": ls.get("category"),
            "correlacion": any("correlation" in d for d in docs),
        })

    ids = Counter(r["id"] for r in ok if r["id"])
    for uuid, n in ids.items():
        if n > 1:
            errores.append((Path("rules"), f"UUID repetido en {n} reglas: {uuid}"))
    for r in ok:
        if not r["id"]:
            errores.append((r["rel"], "sin UUID (ejecuta tools/stamp_sigma_ids.py)"))

    return ok, errores, avisos


def tecnicas(tags):
    out = []
    for t in tags:
        m = RE_TECNICA.match(str(t))
        if m:
            out.append(m.group(1).upper() + (f".{m.group(2)}" if m.group(2) else ""))
    return out


def tacticas(tags):
    out = []
    for t in tags:
        n = str(t).split(".", 1)[1] if str(t).startswith("attack.") else str(t)
        if n in TACTICAS:
            out.append(n)
    return out


# ---------------------------------------------------------------------------
def revisar_deploy(reglas) -> list[str]:
    """Comprueba la coherencia de lo generado en deploy/."""
    problemas: list[str] = []
    deploy = RAIZ / "deploy"
    if not deploy.exists():
        return ["deploy/ no existe: ejecuta tools/build.py"]

    conf = deploy / "splunk" / "reglas" / "savedsearches.conf"
    if conf.exists():
        texto = conf.read_text(encoding="utf-8")
        faltan = [r["title"] for r in reglas if f"[DL - {r['title']}]" not in texto]
        if faltan:
            problemas.append(f"savedsearches.conf: faltan {len(faltan)} reglas "
                             f"(la primera: {faltan[0]})")
    else:
        problemas.append("falta deploy/splunk/reglas/savedsearches.conf")

    # EventID conservado alli donde es una columna real y no un implicito de la tabla.
    for r in reglas:
        if not re.search(r"^\s+EventID:", r["file"].read_text(encoding="utf-8"), re.M):
            continue
        kql = deploy / "sentinel" / "reglas" / f"{r['dominio']}.kql"
        if not kql.exists():
            continue
        cuerpo = kql.read_text(encoding="utf-8")
        i = cuerpo.find(r["title"])
        if i < 0:
            continue
        if "EventID" not in cuerpo[i:].split("// ─────")[0]:
            problemas.append(f"{r['rel']}: la consulta KQL perdio la condicion EventID "
                             f"(ver tools/pipelines/sentinel-post.yml)")

    # Las correlaciones manuales siguen sincronizadas con su regla Sigma.
    # Se lee el valor de los dos lados y se comparan: cambiar solo uno es
    # exactamente el fallo que esta comprobacion existe para atrapar.
    manual = deploy / "sentinel" / "consultas" / "correlaciones.kql"
    if manual.exists():
        kql = manual.read_text(encoding="utf-8")
        for nombre, (re_umbral, re_ventana) in CORRELACIONES_MANUALES.items():
            origen = list((RAIZ / "rules").rglob(nombre))
            if not origen:
                problemas.append(f"correlaciones.kql cita {nombre}, que ya no existe en rules/")
                continue
            sigma = origen[0].read_text(encoding="utf-8")

            for etiqueta, re_kql, re_sig in (
                ("umbral", re_umbral, RE_SIGMA_GTE),
                ("ventana temporal", re_ventana, RE_SIGMA_TIMESPAN),
            ):
                en_kql = re_kql.search(kql)
                en_sigma = re_sig.search(sigma)
                if not en_kql:
                    problemas.append(f"correlaciones.kql: no encuentro el {etiqueta} "
                                     f"de {nombre}")
                elif not en_sigma:
                    problemas.append(f"{nombre}: no encuentro el {etiqueta} en la correlacion Sigma")
                elif en_kql.group(1) != en_sigma.group(1):
                    problemas.append(
                        f"{nombre}: {etiqueta} descuadrado — Sigma dice "
                        f"{en_sigma.group(1)} y correlaciones.kql dice {en_kql.group(1)}")
    else:
        problemas.append("falta deploy/sentinel/consultas/correlaciones.kql")

    # Cada SIEM tiene que tener su guia y su carpeta de consultas: sin ellas el
    # contenido esta pero nadie sabe como cargarlo, que en la practica es lo
    # mismo que no tenerlo.
    for siem in ("wazuh", "splunk", "sentinel", "elastic"):
        base = deploy / siem
        if not (base / "INSTALAR.md").exists():
            problemas.append(f"falta deploy/{siem}/INSTALAR.md")
        if not (base / "consultas").is_dir() or not any((base / "consultas").iterdir()):
            problemas.append(f"deploy/{siem}/consultas/ vacia o inexistente")

    # La capa de respuesta: que exista, y que el nodo compilado no este viejo.
    pbs = RAIZ / "respuesta" / "playbooks"
    if pbs.is_dir():
        nodo = RAIZ / "integracion" / "shuffle" / "enrutador.py"
        if not nodo.exists():
            problemas.append("falta integracion/shuffle/enrutador.py "
                             "(ejecuta tools/generar_enrutador.py)")
        else:
            mas_nuevo = max(f.stat().st_mtime for f in pbs.glob("*.yml"))
            if mas_nuevo > nodo.stat().st_mtime:
                problemas.append("el nodo de Shuffle es mas viejo que los playbooks: "
                                 "regeneralo con tools/generar_enrutador.py y "
                                 "vuelve a pegarlo en Shuffle")

    # Las listas de inteligencia caducan; si estan, se avisa de su antiguedad.
    resumen = RAIZ / "intel" / "listas" / "RESUMEN.md"
    if resumen.exists():
        m = re.search(r"\*\*Listas generadas:\*\* (\S+)", resumen.read_text(encoding="utf-8"))
        if m:
            from datetime import datetime, timezone
            try:
                gen = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)
                dias = (datetime.now(timezone.utc) - gen).days
                if dias > 7:
                    problemas.append(
                        f"las listas de inteligencia tienen {dias} dias: "
                        f"ejecuta tools/sync_cti.py (los indicadores caducan)")
            except ValueError:
                pass

    return problemas


def capa_navigator(por_tecnica, reglas_de_tecnica):
    capa = []
    maximo = max(por_tecnica.values()) if por_tecnica else 1
    for tec, n in sorted(por_tecnica.items()):
        titulos = reglas_de_tecnica[tec][:4]
        comentario = f"{n} regla(s): " + "; ".join(titulos)
        if n > 4:
            comentario += f"; y {n - 4} mas"
        capa.append({"techniqueID": tec, "score": n, "color": "",
                     "comment": comentario, "enabled": True})
    return {
        "name": "Cobertura de deteccion - detection-lab",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Tecnicas cubiertas por la biblioteca Sigma de detection-lab. "
                        "Cada regla se despliega en Splunk, Microsoft Sentinel, Wazuh y "
                        "Elastic desde una unica definicion."),
        "sorting": 3,
        "techniques": capa,
        "gradient": {"colors": ["#12171F", "#4FD6C4"], "minValue": 0, "maxValue": maximo},
        "legendItems": [{"label": "Nº de reglas que cubren la tecnica", "color": "#4FD6C4"}],
        "hideDisabled": False,
    }


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=RAIZ / "rules")
    ap.add_argument("--out", type=Path, default=RAIZ / "navigator" / "coverage-layer.json")
    ap.add_argument("--estricto", action="store_true",
                    help="devuelve error tambien si deploy/ tiene incidencias")
    args = ap.parse_args(argv)

    reglas, errores, avisos = cargar(args.rules)
    for a in avisos:
        print(f"  aviso: {a}")
    print(f"Reglas Sigma: {len(reglas)} validadas, {len(errores)} con error")
    for f, e in errores:
        print(f"  ✗ {f}: {e}")

    por_tecnica, por_tactica, por_nivel, por_dominio = Counter(), Counter(), Counter(), Counter()
    reglas_de_tecnica = defaultdict(list)
    for r in reglas:
        por_nivel[r["level"]] += 1
        por_dominio[r["dominio"]] += 1
        for t in set(tecnicas(r["tags"])):
            por_tecnica[t] += 1
            reglas_de_tecnica[t].append(r["title"])
        for t in set(tacticas(r["tags"])):
            por_tactica[t] += 1

    base = {t.split(".")[0] for t in por_tecnica}
    print(f"\nCobertura ATT&CK: {len(base)} tecnicas base, "
          f"{len(por_tecnica)} contando subtecnicas, {len(por_tactica)} tacticas")

    print("\nPor dominio:")
    for d, n in sorted(por_dominio.items(), key=lambda x: -x[1]):
        print(f"  {d:16} {n:3}")

    print("\nPor tactica (cadena de ataque):")
    for t in ORDEN_TACTICAS:
        if por_tactica.get(t):
            print(f"  {t:22} {por_tactica[t]:3}  {'█' * min(por_tactica[t], 40)}")

    print("\nPor severidad:")
    for lvl in ["critical", "high", "medium", "low", "informational"]:
        if por_nivel.get(lvl):
            print(f"  {lvl:14} {por_nivel[lvl]:3}")

    correl = [r["title"] for r in reglas if r["correlacion"]]
    if correl:
        print(f"\nCorrelaciones Sigma: {len(correl)}")
        for t in correl:
            print(f"  · {t}")

    problemas = revisar_deploy(reglas)
    print(f"\nContenido desplegable: {len(problemas)} incidencia(s)")
    for p in problemas:
        print(f"  ! {p}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(capa_navigator(por_tecnica, reglas_de_tecnica),
                                   indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nCapa ATT&CK Navigator: {args.out.relative_to(RAIZ)} "
          f"({len(por_tecnica)} tecnicas)")

    if errores:
        print("\n✗ Hay reglas con errores de validacion.")
        return 1
    if problemas and args.estricto:
        print("\n✗ Modo estricto: las incidencias de deploy/ cuentan como error.")
        return 1
    print("\n✓ Biblioteca valida.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
