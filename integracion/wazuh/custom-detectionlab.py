#!/usr/bin/env python3
"""
Integracion Wazuh -> Shuffle para las reglas de Detection-lab.

Sustituye a custom-shuffle.py de Infra-SocAnalyst para las alertas de esta
biblioteca, y convive con el: aquel sigue atendiendo a falco, tetragon,
suricata e ids.

Tres problemas que resuelve, y que solo se ven mirando los dos repositorios
a la vez
-------------------------------------------------------------------------

1. **El filtro de grupos dejaba fuera estas reglas.** custom-shuffle.py filtra
   por los grupos `falco,tetragon,suricata,ids`. Las 340 reglas de Wazuh que
   genera Detection-lab llevan `detectionlab,soc_sigma,...`, asi que
   disparaban en Wazuh y NO llegaban al SOAR: visibles en el dashboard, sin
   caso abierto. Es el peor sitio donde puede quedarse una deteccion, porque
   parece que funciona.

2. **La severidad se aplastaba.** El pipeline mapea nivel de Wazuh a severidad
   de TheHive con umbral superior en >=12. Como aqui `high` tambien es nivel
   12, 219 de 260 reglas aterrizaban como severidad 4 y la cola dejaba de
   estar priorizada. Este script lee la severidad ya calculada del campo
   `<info>` de la regla, que viene del nivel Sigma original.

3. **Ollama se ahogaba.** El README del SOC ya avisa de que un umbral bajo
   satura Ollama, que es CPU-bound. Con 127 detecciones activas eso deja de
   ser un riesgo teorico. Aqui solo las clases `auto_analisis` y
   `auto_contener` van al LLM; el resto se enriquece y se encola sin pasar por
   el, y hay un limitador por regla y agente para que una sola deteccion en
   bucle no consuma el turno entero.

Instalacion
-----------
    sudo cp custom-detectionlab.py /var/ossec/integrations/
    sudo cp custom-detectionlab    /var/ossec/integrations/
    sudo chmod 750 /var/ossec/integrations/custom-detectionlab*
    sudo chown root:wazuh /var/ossec/integrations/custom-detectionlab*

En ossec.conf, junto al bloque de custom-shuffle que ya existe:

    <integration>
      <name>custom-detectionlab</name>
      <hook_url>https://HOST_SOC:3443/api/v1/hooks/webhook_XXXX</hook_url>
      <group>detectionlab</group>
      <level>5</level>
      <alert_format>json</alert_format>
    </integration>

El `<level>5</level>` NO significa que todo lo de nivel 5 despierte a alguien:
significa que llega aqui, y este script decide. Las de `auto_cierre` se
registran y se descartan sin salir a la red.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

# Ventana y tope del limitador. Una deteccion en bucle (un proceso que
# rearranca cada segundo) genera cientos de alertas identicas; sin esto,
# todas irian al LLM.
VENTANA_S = 300
TOPE_POR_CLAVE = 5
ESTADO = Path("/var/ossec/var/run/detectionlab_rate.json")

RE_INFO = re.compile(r"playbook=(\S+);\s*severidad_thehive=(\d);\s*origen=(\S+)")

# Observables que el nodo de enriquecimiento sabe resolver. Se extraen aqui
# para que el nodo de Shuffle no tenga que conocer el esquema de Wazuh.
CAMPOS_IOC = {
    "ip": ["srcip", "dstip", "data.srcip", "data.dstip",
           "data.win.eventdata.destinationIp"],
    "hash": ["data.win.eventdata.hashes", "syscheck.sha256_after",
             "data.sha256"],
    "dominio": ["data.win.eventdata.queryName", "data.dns.rrname", "data.hostname"],
    "url": ["data.url", "data.http.url"],
    "usuario": ["data.win.eventdata.user", "data.srcuser", "data.dstuser",
                "data.win.eventdata.targetUserName"],
}


def buscar(d: dict, ruta: str):
    """Lee 'data.win.eventdata.image' de un dict anidado."""
    actual = d
    for parte in ruta.split("."):
        if not isinstance(actual, dict):
            return None
        actual = actual.get(parte)
    return actual if isinstance(actual, str) and actual.strip() else None


def limitado(clave: str) -> bool:
    """True si esta clave ya ha pasado el tope en la ventana.

    El estado va a disco porque cada alerta arranca un proceso nuevo: no hay
    memoria entre ejecuciones. Si el fichero no se puede leer o escribir, se
    deja pasar la alerta: perder una deteccion por un problema de disco seria
    cambiar un fallo pequeno por uno grande.
    """
    ahora = time.time()
    try:
        estado = json.loads(ESTADO.read_text()) if ESTADO.exists() else {}
    except Exception:
        estado = {}

    estado = {k: [t for t in v if ahora - t < VENTANA_S]
              for k, v in estado.items()}
    estado = {k: v for k, v in estado.items() if v}

    marcas = estado.setdefault(clave, [])
    pasado = len(marcas) >= TOPE_POR_CLAVE
    if not pasado:
        marcas.append(ahora)

    try:
        ESTADO.parent.mkdir(parents=True, exist_ok=True)
        ESTADO.write_text(json.dumps(estado))
    except Exception:
        pass
    return pasado


def construir(alerta: dict) -> dict | None:
    regla = alerta.get("rule", {}) or {}
    grupos = regla.get("groups", []) or []

    if "detectionlab" not in grupos:
        return None

    clase = next((g for g in grupos if g.startswith("auto_")), "auto_analisis")

    # auto_cierre: se registra en Wazuh y no sale a la red. Son las reglas base
    # de correlacion (nivel informational), que existen para que otra regla las
    # referencie, no para llegar a nadie.
    if clase == "auto_cierre":
        return None

    playbook, severidad, origen = "generico", 2, ""
    m = RE_INFO.search(str(regla.get("info", "")))
    if m:
        playbook, severidad, origen = m.group(1), int(m.group(2)), m.group(3)

    datos = alerta.get("data", {}) or {}
    observables = {}
    for tipo, rutas in CAMPOS_IOC.items():
        for ruta in rutas:
            v = buscar(alerta, ruta) or buscar({"data": datos}, ruta)
            if v:
                observables[tipo] = v
                break

    agente = (alerta.get("agent", {}) or {}).get("name", "desconocido")

    # El limitador agrupa por regla y agente: la misma deteccion en dos equipos
    # distintos son dos incidentes, no una repeticion.
    if limitado(f"{regla.get('id')}::{agente}"):
        return None

    return {
        "origen": "detection-lab",
        "clase_automatizacion": clase,
        "playbook": playbook,
        "severidad": severidad,
        "regla_sigma": origen,
        "wazuh_id": alerta.get("id", ""),
        "regla_id": regla.get("id", ""),
        "nivel_wazuh": regla.get("level", 0),
        "descripcion": regla.get("description", ""),
        "mitre": (regla.get("mitre", {}) or {}).get("id", []),
        "agente": agente,
        "agente_ip": (alerta.get("agent", {}) or {}).get("ip", ""),
        "observables": observables,
        "ioc_list": ", ".join(observables.values()) or "N/A",
        "marca_tiempo": alerta.get("timestamp", ""),
        "full_log": (alerta.get("full_log", "") or "")[:2000],
    }


def main(argv) -> int:
    # Wazuh llama: custom-detectionlab <fichero_alerta> <api_key> <hook_url>
    if len(argv) < 4:
        print("uso: custom-detectionlab.py <alerta.json> <api_key> <hook_url>",
              file=sys.stderr)
        return 1

    try:
        alerta = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"alerta ilegible: {e}", file=sys.stderr)
        return 1

    carga = construir(alerta)
    if carga is None:
        return 0          # no es nuestra, o es auto_cierre, o esta limitada

    hook = argv[3]
    cuerpo = json.dumps(carga).encode("utf-8")

    import urllib.request
    req = urllib.request.Request(
        hook, data=cuerpo,
        headers={"Content-Type": "application/json",
                 "User-Agent": "wazuh-detectionlab"},
    )
    try:
        import ssl
        ctx = ssl.create_default_context()
        # El Shuffle del laboratorio usa certificado propio. En produccion esto
        # se quita y se instala la CA en el manager.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            r.read()
    except Exception as e:
        print(f"no se pudo entregar al SOAR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
