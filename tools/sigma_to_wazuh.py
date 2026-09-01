#!/usr/bin/env python3
"""
Backend de Sigma a Wazuh.

pySigma tiene backends oficiales para Splunk, Sentinel, Elastic o Chronicle, pero
no para Wazuh. Este script cubre ese hueco: lee las reglas Sigma de sigma/ y
genera el XML de reglas custom de Wazuh.

CÓMO FUNCIONA
-------------
El problema de fondo es que una regla de Wazuh conjuga con AND todas sus
condiciones: no existe el OR dentro de una regla. Sigma, en cambio, permite
expresiones booleanas arbitrarias. La solución es convertir la condición Sigma a
forma normal disyuntiva (una OR de ANDs) y emitir una regla de Wazuh por cada
término de la disyunción, todas con el mismo identificador SOC y los mismos
grupos, de modo que en el SIEM se comportan como una sola detección.

Las negaciones se propagan a los literales con las leyes de De Morgan. Un
literal negado se convierte en <field negate="yes">, y como el valor de un
literal con lista es una alternancia (a|b|c), negarlo equivale exactamente a
"ninguno de", que es lo que se busca en los bloques filter de Sigma.

LIMITACIONES CONOCIDAS, y son importantes
-----------------------------------------
1. Las reglas de correlación de Sigma (type: value_count, event_count) NO se
   convierten. Wazuh cuenta con <frequency> y <timeframe>, pero solo sobre el
   número de veces que dispara una regla, no sobre la cardinalidad de un campo
   arbitrario. Esas detecciones se quedan solo en Splunk y el script lo dice.
2. Los modificadores |lt, |gt, |lte, |gte y |base64 no se convierten.
3. La regla generada es una traducción mecánica: hay que revisarla con
   wazuh-logtest antes de darla por buena, sobre todo el nombre de los campos
   decodificados, que dependen del decoder que uses.

Uso:
    python3 scripts/sigma_to_wazuh.py            # genera el XML
    python3 scripts/sigma_to_wazuh.py --check    # no escribe, solo informa
"""
from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
SIGMA = RAIZ / "rules"
SALIDA = RAIZ / "deploy" / "wazuh" / "reglas" / "0970-detection_lab_sigma.xml"

ID_BASE = 101000          # rango reservado a las reglas generadas
ID_TOPE = 101999

# ---------------------------------------------------------------------------
# Nivel de automatizacion (contrato con Infra-SocAnalyst)
#
# El pipeline SOAR del SOC decide que hace con una alerta segun este grupo. Va
# en el XML porque el script de integracion solo ve la alerta de Wazuh: no
# puede volver a leer la regla Sigma para saber su severidad original.
#
# El mapeo NO es "severidad alta = mas automatizacion". Es al reves de lo que
# parece: cuanto mas grave es la deteccion, mas cara es una accion automatica
# equivocada. Por eso lo critico contiene solo lo reversible y despierta a una
# persona, en vez de actuar por su cuenta.
#
#   auto_cierre  -> se registra y se cierra. Sin analista, sin LLM.
#   auto_enriq   -> se enriquece y se encola. Sin LLM, sin notificacion.
#   auto_analisis-> pipeline completo con Ollama y caso en TheHive.
#   auto_contener-> lo anterior mas contencion reversible y aviso inmediato.
AUTOMATIZACION = {
    "informational": "auto_cierre",
    "low": "auto_enriq",
    "medium": "auto_analisis",
    "high": "auto_analisis",
    "critical": "auto_contener",
}

# Severidad de TheHive (1-4) derivada del nivel SIGMA, no del nivel Wazuh.
#
# Por que hace falta: el pipeline del SOC mapea nivel de Wazuh a severidad, y
# su umbral superior es >=12. Como aqui high tambien es 12, el 75% de estas
# reglas aterrizaria como severidad 4 y la cola dejaria de estar priorizada.
# Llevando la severidad ya calculada en la alerta, cada regla cae donde debe.
SEVERIDAD_THEHIVE = {
    "informational": 1, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def familia_playbook(ruta) -> str:
    """Familia de playbook de una regla, para que el SOAR sepa que hacer.

    Sale de la CARPETA, no del nombre del fichero. Derivarla del nombre
    funcionaba mientras todas las reglas se llamaban soc_XX_NNN, y se rompio en
    cuanto entraron web_001, cred_001 o mac_tcc: producia familias como '001',
    'osascript' o 'usuario', y el enrutador de respuesta no encontraba playbook.
    La carpeta es estable y significa algo.
    """
    dominio = ruta.parent.name
    if dominio != "windows":
        return dominio
    # rules/windows/ mezcla tres familias con playbooks muy distintos.
    n = ruta.stem
    if n.startswith(("soc_ad_", "ad_")):
        return "ad"
    if n.startswith("cred_"):
        return "credenciales"
    return "endpoint"

NIVEL = {                 # nivel Sigma -> nivel Wazuh
    # Nivel 0 en Wazuh significa "no generes alerta". Es lo correcto para las
    # reglas base de una correlacion Sigma: existen para que otra regla las
    # referencie, no para llegar al analista.
    "informational": 0,
    "low": 5,
    "medium": 8,
    "high": 12,
    "critical": 14,
}

# Sysmon: categoría genérica de Sigma -> EventID
CATEGORIA_EVENTID = {
    "process_creation": ["1"],
    "network_connection": ["3"],
    "image_load": ["7"],
    "create_remote_thread": ["8"],
    "process_access": ["10"],
    "file_event": ["11", "23"],
    "registry_event": ["12", "13", "14"],
    "registry_set": ["13"],
    "pipe_created": ["17", "18"],
    "dns_query": ["22"],
}

# Fuentes no Windows: se ingieren como JSON, así que los campos van bajo data.
FUENTES_JSON = {
    ("azure", "signinlogs"): "entra_signin",
    ("azure", "auditlogs"): "entra_audit",
    ("m365", "exchange"): "m365_exchange",
    ("proofpoint", "tap"): "proofpoint",
    ("netskope", "alerts"): "netskope",
}
CATEGORIAS_JSON = {"proxy", "dns", "webserver", "firewall"}


# ─────────────────────────────────────────────────────────────────────
# Parser de la condición Sigma
# ─────────────────────────────────────────────────────────────────────
TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[\w*]+")


def tokenizar(cond: str) -> list[str]:
    cond = cond.replace("1 of", "1_of").replace("all of", "all_of")
    return re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|1_of|all_of|[\w*]+", cond)


def parsear(tokens: list[str]):
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def consumir():
        nonlocal pos
        t = tokens[pos]
        pos += 1
        return t

    def primario():
        nonlocal pos
        t = peek()
        if t == "(":
            consumir()
            n = expr_or()
            if peek() == ")":
                consumir()
            return n
        if t == "not":
            consumir()
            return ("not", primario())
        if t in ("1_of", "all_of"):
            op = consumir()
            patron = consumir()
            return ("oneof" if op == "1_of" else "allof", patron)
        return ("id", consumir())

    def expr_and():
        n = primario()
        while peek() == "and":
            consumir()
            n = ("and", [n, primario()])
        return n

    def expr_or():
        n = expr_and()
        while peek() == "or":
            consumir()
            n = ("or", [n, expr_and()])
        return n

    return expr_or()


# ─────────────────────────────────────────────────────────────────────
# Traducción de un campo Sigma a un literal (campo, regex)
# ─────────────────────────────────────────────────────────────────────
def valor_a_regex(valor, modificadores: list[str]) -> str:
    """Convierte un valor Sigma y sus modificadores en un fragmento PCRE2."""
    if "re" in modificadores:
        return str(valor)

    v = re.escape(str(valor))
    # Sigma usa * y ? como comodines; re.escape los ha neutralizado
    v = v.replace(r"\*", ".*").replace(r"\?", ".")

    if "contains" in modificadores:
        return v
    if "startswith" in modificadores:
        return "^" + v
    if "endswith" in modificadores:
        return v + "$"
    return "^" + v + "$"


def literal(campo_spec: str, valor, mapear) -> tuple[str, str] | None:
    partes = campo_spec.split("|")
    campo, modificadores = partes[0], partes[1:]

    no_soportados = {"lt", "gt", "lte", "gte", "base64", "base64offset", "cidr"}
    usados = no_soportados & set(modificadores)
    if usados:
        raise ValueError(
            f"el campo '{campo}' usa el modificador |{sorted(usados)[0]}, que Wazuh no "
            f"puede expresar (comparacion numerica o decodificacion)"
        )

    valores = valor if isinstance(valor, list) else [valor]
    if any(v is None for v in valores):
        raise ValueError(
            f"el campo '{campo}' compara contra null (campo ausente); Wazuh no tiene "
            f"forma directa de comprobar la ausencia de un campo decodificado"
        )

    if "all" in modificadores:
        # AND sobre el mismo campo: se resuelve con lookaheads de PCRE2
        mods = [m for m in modificadores if m != "all"]
        partes_re = [valor_a_regex(v, mods).lstrip("^").rstrip("$") for v in valores]
        return mapear(campo), "(?i)" + "".join(f"(?=.*{p})" for p in partes_re)

    alternativas = [valor_a_regex(v, modificadores) for v in valores]
    if len(alternativas) == 1:
        return mapear(campo), "(?i)" + alternativas[0]
    # Alternancia: al negarla, Wazuh excluye todas a la vez, que es lo que quieren
    # los bloques filter de Sigma
    limpias = [a.lstrip("^").rstrip("$") for a in alternativas]
    anclas = all(a.startswith("^") for a in alternativas), all(a.endswith("$") for a in alternativas)
    patron = "(" + "|".join(limpias) + ")"
    if anclas[0]:
        patron = "^" + patron
    if anclas[1]:
        patron = patron + "$"
    return mapear(campo), "(?i)" + patron


def bloque_a_ast(bloque, mapear):
    """Un bloque de detection es un dict (AND) o una lista de dicts (OR de ANDs)."""
    if isinstance(bloque, list):
        hijos = []
        for sub in bloque:
            if isinstance(sub, dict):
                hijos.append(bloque_a_ast(sub, mapear))
            else:  # keyword suelto: busqueda en el log completo
                hijos.append(("lit", ("full_log", "(?i)" + re.escape(str(sub)))))
        return ("or", hijos)

    literales = []
    for k, v in bloque.items():
        literales.append(("lit", literal(k, v, mapear)))
    if len(literales) == 1:
        return literales[0]
    return ("and", literales)


# ─────────────────────────────────────────────────────────────────────
# Álgebra booleana: De Morgan y forma normal disyuntiva
# ─────────────────────────────────────────────────────────────────────
def empujar_not(nodo, negado=False):
    tipo = nodo[0]
    if tipo == "lit":
        campo, patron = nodo[1]
        return ("lit", (campo, patron, negado))
    if tipo == "not":
        return empujar_not(nodo[1], not negado)
    if tipo in ("and", "or"):
        nuevo = "or" if (tipo == "and" and negado) else ("and" if (tipo == "or" and negado) else tipo)
        return (nuevo, [empujar_not(h, negado) for h in nodo[1]])
    raise ValueError(f"nodo inesperado: {tipo}")


def a_dnf(nodo) -> list[list[tuple]]:
    """Devuelve una lista de términos; cada término es una lista de literales en AND."""
    tipo = nodo[0]
    if tipo == "lit":
        return [[nodo[1]]]
    if tipo == "or":
        terminos = []
        for h in nodo[1]:
            terminos.extend(a_dnf(h))
        return terminos
    if tipo == "and":
        resultado = [[]]
        for h in nodo[1]:
            nuevos = []
            for parcial in resultado:
                for termino in a_dnf(h):
                    nuevos.append(parcial + termino)
            resultado = nuevos
        return resultado
    raise ValueError(f"nodo inesperado en DNF: {tipo}")


# ─────────────────────────────────────────────────────────────────────
# Generación del XML
# ─────────────────────────────────────────────────────────────────────
def mapeador(logsource):
    producto = logsource.get("product")
    servicio = logsource.get("service")
    categoria = logsource.get("category")

    es_json = (producto, servicio) in FUENTES_JSON or categoria in CATEGORIAS_JSON

    if es_json:
        return lambda c: "data." + c.replace(".", "_"), True

    def mapear_windows(c: str) -> str:
        if c in ("EventID", "Provider_Name", "Channel", "Computer"):
            return "win.system." + {"EventID": "eventID", "Provider_Name": "providerName",
                                    "Channel": "channel", "Computer": "computer"}[c]
        return "win.eventdata." + c[0].lower() + c[1:]

    return mapear_windows, False


def condiciones_base(logsource) -> tuple[list[str], list[tuple[str, str, bool]]]:
    """Devuelve (elementos XML previos, literales extra a añadir a cada término)."""
    producto = logsource.get("product")
    servicio = logsource.get("service")
    categoria = logsource.get("category")
    previos, extra = [], []

    if categoria in CATEGORIA_EVENTID and producto == "windows":
        previos.append("<if_group>windows</if_group>")
        eids = CATEGORIA_EVENTID[categoria]
        extra.append(("win.system.eventID", "^(" + "|".join(eids) + ")$", False))
    elif producto == "windows":
        previos.append("<if_group>windows</if_group>")
    elif (producto, servicio) in FUENTES_JSON or categoria in CATEGORIAS_JSON:
        previos.append("<decoded_as>json</decoded_as>")
    else:
        previos.append("<decoded_as>json</decoded_as>")

    return previos, extra


def escapar(t: str) -> str:
    return html.escape(t, quote=False)


def convertir(ruta: Path, ident: int) -> tuple[list[str], int, list[str]]:
    """Devuelve (bloques XML, siguiente id libre, avisos)."""
    docs = [d for d in yaml.safe_load_all(ruta.read_text(encoding="utf-8")) if d]
    xml, avisos = [], []

    for doc in docs:
        titulo = doc.get("title", "sin titulo")

        if "correlation" in doc:
            avisos.append(
                f"{ruta.name}: '{titulo}' es una correlacion Sigma "
                f"({doc['correlation'].get('type')}); Wazuh no puede contar cardinalidad "
                f"de un campo, se queda solo en Splunk"
            )
            continue
        if "detection" not in doc:
            continue

        logsource = doc.get("logsource", {})
        mapear, _ = mapeador(logsource)
        deteccion = dict(doc["detection"])
        condicion = deteccion.pop("condition")
        if isinstance(condicion, list):
            condicion = " or ".join(f"({c})" for c in condicion)

        # bloques -> AST
        try:
            bloques = {k: bloque_a_ast(v, mapear) for k, v in deteccion.items()}
        except ValueError as e:
            avisos.append(f"{ruta.name}: '{titulo}' no convertible: {e}")
            continue

        def sustituir(nodo):
            t = nodo[0]
            if t == "id":
                nombre = nodo[1]
                if nombre not in bloques:
                    raise ValueError(f"la condicion referencia '{nombre}', que no existe")
                return bloques[nombre]
            if t in ("oneof", "allof"):
                patron = nodo[1].replace("*", ".*")
                coincidencias = [bloques[k] for k in bloques if re.fullmatch(patron, k)]
                if not coincidencias:
                    raise ValueError(f"'{nodo[1]}' no coincide con ningun bloque")
                return ("or" if t == "oneof" else "and", coincidencias)
            if t == "not":
                return ("not", sustituir(nodo[1]))
            return (t, [sustituir(h) for h in nodo[1]])

        try:
            ast = sustituir(parsear(tokenizar(condicion)))
            terminos = a_dnf(empujar_not(ast))
        except ValueError as e:
            avisos.append(f"{ruta.name}: '{titulo}' no convertible: {e}")
            continue

        previos, extra = condiciones_base(logsource)
        soc_id = ruta.stem.upper().replace("_", "-")
        soc_id = "-".join(soc_id.split("-")[:3])   # SOC-AD-001
        nivel = NIVEL.get(doc.get("level", "medium"), 8)
        tecnicas = [t.split(".", 1)[1].upper() for t in doc.get("tags", [])
                    if t.startswith("attack.t")]

        for n, termino in enumerate(terminos, 1):
            if ident > ID_TOPE:
                avisos.append("se ha agotado el rango de IDs reservado (101000-101999)")
                return xml, ident, avisos

            sufijo = f" [{n}/{len(terminos)}]" if len(terminos) > 1 else ""
            partes = [f'  <rule id="{ident}" level="{nivel}">']
            for p in previos:
                partes.append(f"    {p}")
            for campo, patron, negado in extra + termino:
                neg = ' negate="yes"' if negado else ""
                partes.append(
                    f'    <field name="{campo}"{neg} type="pcre2">{escapar(patron)}</field>'
                )
            partes.append(f"    <description>{escapar(soc_id)}: {escapar(titulo)}{sufijo}</description>")
            if tecnicas:
                partes.append("    <mitre>")
                for t in sorted(set(tecnicas)):
                    partes.append(f"      <id>{t}</id>")
                partes.append("    </mitre>")
            grupo = soc_id.lower().replace("-", "_")
            familia = familia_playbook(ruta)
            sev_sigma = doc.get("level", "medium")
            # 'detectionlab' es el grupo por el que filtra la integracion del SOC.
            # Sin el, estas reglas disparan en Wazuh y no llegan al SOAR: se ven
            # en el dashboard y no abren caso, que es el peor sitio donde estar.
            grupos = ["detectionlab", "soc_sigma", f"soc_{familia}", grupo,
                      AUTOMATIZACION.get(sev_sigma, "auto_analisis"),
                      f"sev_{sev_sigma}"]
            partes.append(f"    <group>{','.join(grupos)},</group>")
            # El campo de informacion viaja en la alerta y es lo que lee el
            # enrutador de respuesta para elegir playbook.
            partes.append(f'    <info type="text">playbook={familia}; '
                          f'severidad_thehive={SEVERIDAD_THEHIVE.get(sev_sigma, 2)}; '
                          f'origen={ruta.name}</info>')
            partes.append("  </rule>")
            xml.append("\n".join(partes))
            ident += 1

    return xml, ident, avisos


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true", help="no escribe, solo informa")
    args = p.parse_args()

    ficheros = sorted(SIGMA.rglob("*.yml"))
    if not ficheros:
        print("No hay reglas Sigma en sigma/")
        return 1

    bloques, avisos, ident = [], [], ID_BASE
    for f in ficheros:
        x, ident, a = convertir(f, ident)
        bloques.extend(x)
        avisos.extend(a)

    cabecera = f"""<!--
  Reglas de Wazuh GENERADAS AUTOMATICAMENTE desde las reglas Sigma de sigma/.

  NO EDITAR A MANO: cualquier cambio se pierde en la siguiente ejecucion de
      python3 scripts/sigma_to_wazuh.py
  Para cambiar una deteccion, edita su fichero .yml en sigma/ y regenera.

  Rango de IDs: {ID_BASE}-{ID_TOPE}. Las reglas escritas a mano ocupan
  100100-100799, asi que no hay colision posible entre ambos conjuntos.

  Una regla Sigma puede producir varias reglas de Wazuh: Wazuh conjuga con AND
  todas las condiciones de una regla, de modo que un OR de Sigma se convierte en
  varias reglas que comparten identificador SOC y grupos.

  Reglas generadas: {len(bloques)}  |  desde {len(ficheros)} ficheros Sigma
-->
<group name="soc,soc_sigma,detectionlab,">

"""
    contenido = cabecera + "\n\n".join(bloques) + "\n\n</group>\n"

    if not args.check:
        SALIDA.parent.mkdir(parents=True, exist_ok=True)
        SALIDA.write_text(contenido, encoding="utf-8")

    print(f"{len(ficheros)} ficheros Sigma -> {len(bloques)} reglas de Wazuh "
          f"(ids {ID_BASE}-{ident - 1})")
    if not args.check:
        print(f"escrito en {SALIDA.relative_to(RAIZ)}")
    if avisos:
        print(f"\n{len(avisos)} avisos:")
        for a in avisos:
            print(f"  {a}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
