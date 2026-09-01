#!/usr/bin/env python3
"""
Mapea cada regla Sigma a los controles de NIST SP 800-53 Rev 5 e ISO/IEC
27001:2022 que evidencia, y escribe el resultado como etiquetas en la propia
regla mas una matriz en marcos/matriz_controles.csv.

Por que se genera y no se etiqueta a mano
-----------------------------------------
Un mapeo a mano de 127 reglas se desincroniza a la tercera regla nueva, y un
mapeo desincronizado es peor que ninguno: en una auditoria se presenta como
evidencia de una cobertura que ya no existe. Aqui el mapeo se DERIVA de la
tecnica ATT&CK y del origen de log de cada regla, asi que una regla nueva queda
mapeada sola y una regla que cambia de tecnica cambia de control.

Que NO hace
-----------
No afirma cumplimiento. Una deteccion es evidencia de la parte de DETECCION de
un control, no del control entero: AC-2 exige tambien procedimientos de alta y
baja de cuentas, revision periodica y titularidad, y nada de eso lo demuestra
una regla Sigma. La matriz dice "esta regla aporta evidencia a este control",
que es una afirmacion mucho mas pequena y la unica que se sostiene.

Uso:
    python3 tools/mapear_marcos.py            escribe etiquetas y matriz
    python3 tools/mapear_marcos.py --check    no escribe, solo informa
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

RAIZ = Path(__file__).resolve().parent.parent
REGLAS = RAIZ / "rules"
MATRIZ = RAIZ / "marcos" / "matriz_controles.csv"

RE_TEC = re.compile(r"^attack\.(t\d{4})(?:\.(\d{3}))?$", re.I)

# ---------------------------------------------------------------------------
# Controles que aplican a TODA la biblioteca por construccion
#
# No se etiquetan en cada regla: seria repetir cuatro lineas 127 veces sin
# aportar informacion. Se declaran aqui y se documentan en docs/marcos-*.md.
# ---------------------------------------------------------------------------
TRANSVERSALES = {
    "nist.au-6": "Audit Record Review, Analysis, and Reporting",
    "nist.au-12": "Audit Record Generation",
    "nist.si-4": "System Monitoring",
    "iso27001-2022.a-8-15": "Logging",
    "iso27001-2022.a-8-16": "Monitoring activities",
}

# ---------------------------------------------------------------------------
# Mapeo por tecnica base ATT&CK
#
# Cada entrada dice: esta familia de tecnicas evidencia estos controles. La
# justificacion va en el comentario porque en una auditoria la pregunta
# siguiente siempre es "por que".
# ---------------------------------------------------------------------------
POR_TECNICA: dict[str, tuple[list[str], str]] = {
    # ── Credenciales ────────────────────────────────────────────────────
    # IA-5 es gestion de autenticadores: si alguien vuelca credenciales, el
    # control de proteccion del autenticador ha fallado o esta a prueba.
    "T1003": (["nist.ia-5", "nist.ac-6", "iso27001-2022.a-8-5", "iso27001-2022.a-5-17"],
              "volcado de credenciales: proteccion del autenticador"),
    "T1555": (["nist.ia-5", "iso27001-2022.a-5-17", "iso27001-2022.a-8-5"],
              "credenciales almacenadas"),
    "T1552": (["nist.ia-5", "nist.sc-28", "iso27001-2022.a-5-17"],
              "credenciales en fichero o configuracion"),
    "T1558": (["nist.ia-5", "nist.ia-2", "iso27001-2022.a-8-5"],
              "abuso de tiquetes Kerberos"),
    "T1550": (["nist.ia-2", "nist.ac-3", "iso27001-2022.a-8-5"],
              "uso de material de autenticacion alternativo"),
    "T1539": (["nist.ia-2", "nist.sc-23", "iso27001-2022.a-8-5"],
              "robo de sesion"),
    "T1110": (["nist.ac-7", "nist.ia-2", "iso27001-2022.a-8-5"],
              "intentos fallidos de autenticacion"),
    "T1187": (["nist.ia-2", "nist.sc-8", "iso27001-2022.a-8-5"],
              "coercion de autenticacion"),
    "T1557": (["nist.sc-8", "nist.ia-2", "iso27001-2022.a-8-24"],
              "interceptacion de la autenticacion"),
    "T1040": (["nist.sc-8", "iso27001-2022.a-8-24", "iso27001-2022.a-8-20"],
              "trafico sin cifrar"),

    # ── Cuentas y privilegios ───────────────────────────────────────────
    "T1078": (["nist.ac-2", "nist.ac-6", "iso27001-2022.a-5-15", "iso27001-2022.a-8-2"],
              "uso de cuenta valida"),
    "T1098": (["nist.ac-2", "nist.ac-6", "iso27001-2022.a-5-16", "iso27001-2022.a-5-18"],
              "manipulacion de cuenta"),
    "T1136": (["nist.ac-2", "iso27001-2022.a-5-16"],
              "alta de cuenta"),
    "T1484": (["nist.cm-5", "nist.ac-6", "iso27001-2022.a-8-9"],
              "modificacion de la politica del dominio"),
    "T1134": (["nist.ac-6", "nist.ac-3", "iso27001-2022.a-8-2"],
              "manipulacion de tokens de acceso"),
    "T1207": (["nist.ac-6", "nist.cm-5", "iso27001-2022.a-8-2"],
              "controlador de dominio no autorizado"),
    "T1222": (["nist.ac-3", "iso27001-2022.a-8-3"],
              "modificacion de permisos"),
    "T1069": (["nist.ac-2", "iso27001-2022.a-5-18"],
              "descubrimiento de grupos de permisos"),
    "T1087": (["nist.ac-2", "iso27001-2022.a-5-16"],
              "enumeracion de cuentas"),

    # ── Registro y evasion ──────────────────────────────────────────────
    # AU-9 es proteccion de la informacion de auditoria: borrar el registro
    # ataca directamente ese control.
    "T1070": (["nist.au-9", "nist.au-11", "iso27001-2022.a-8-15"],
              "borrado de rastro en el registro"),
    "T1562": (["nist.si-3", "nist.au-9", "nist.cm-7", "iso27001-2022.a-8-7"],
              "deterioro de las defensas"),
    "T1564": (["nist.au-9", "iso27001-2022.a-8-15"],
              "ocultacion de artefactos"),
    "T1027": (["nist.si-3", "iso27001-2022.a-8-7"],
              "ofuscacion"),
    "T1140": (["nist.si-3", "iso27001-2022.a-8-7"],
              "desofuscacion de carga util"),
    "T1553": (["nist.si-7", "nist.cm-14", "iso27001-2022.a-8-7"],
              "subversion del control de confianza"),
    "T1548": (["nist.ac-6", "iso27001-2022.a-8-2"],
              "elusion del mecanismo de elevacion"),
    "T1068": (["nist.si-2", "nist.ra-5", "iso27001-2022.a-8-8"],
              "explotacion para elevar privilegios"),

    # ── Codigo malicioso y ejecucion ────────────────────────────────────
    "T1204": (["nist.si-3", "nist.at-2", "iso27001-2022.a-8-7"],
              "ejecucion inducida al usuario"),
    "T1059": (["nist.si-3", "nist.cm-7", "iso27001-2022.a-8-7"],
              "interprete de comandos"),
    "T1218": (["nist.cm-7", "nist.si-3", "iso27001-2022.a-8-7"],
              "binario firmado usado como proxy"),
    "T1105": (["nist.sc-7", "nist.si-3", "iso27001-2022.a-8-7"],
              "transferencia de herramientas al interior"),
    "T1055": (["nist.si-3", "nist.si-7", "iso27001-2022.a-8-7"],
              "inyeccion en procesos"),
    "T1197": (["nist.cm-7", "iso27001-2022.a-8-7"],
              "transferencia por servicio del sistema"),
    "T1106": (["nist.si-3", "iso27001-2022.a-8-7"],
              "uso directo de la API nativa"),

    # ── Persistencia y configuracion ────────────────────────────────────
    "T1543": (["nist.cm-5", "nist.cm-6", "iso27001-2022.a-8-9"],
              "creacion o modificacion de servicio"),
    "T1547": (["nist.cm-5", "nist.cm-6", "iso27001-2022.a-8-9"],
              "ejecucion automatica en el arranque"),
    "T1053": (["nist.cm-5", "nist.cm-7", "iso27001-2022.a-8-9"],
              "tarea programada"),
    "T1112": (["nist.cm-5", "nist.cm-6", "iso27001-2022.a-8-9"],
              "modificacion del registro"),
    "T1505": (["nist.cm-5", "nist.si-7", "iso27001-2022.a-8-9"],
              "componente de software del servidor"),
    "T1546": (["nist.cm-5", "iso27001-2022.a-8-9"],
              "ejecucion disparada por evento"),
    "T1136.001": (["nist.ac-2", "iso27001-2022.a-5-16"], "alta de cuenta local"),

    # ── Red y mando y control ───────────────────────────────────────────
    "T1071": (["nist.sc-7", "nist.si-4", "iso27001-2022.a-8-20", "iso27001-2022.a-8-23"],
              "canal de mando y control"),
    "T1090": (["nist.sc-7", "iso27001-2022.a-8-20", "iso27001-2022.a-8-22"],
              "proxy de conexion"),
    "T1102": (["nist.sc-7", "iso27001-2022.a-8-23"],
              "servicio web como canal"),
    "T1572": (["nist.sc-7", "iso27001-2022.a-8-20"],
              "tunelizacion de protocolo"),
    "T1568": (["nist.sc-7", "iso27001-2022.a-8-20"],
              "resolucion dinamica"),

    # ── Exfiltracion ────────────────────────────────────────────────────
    "T1041": (["nist.ac-4", "nist.sc-7", "iso27001-2022.a-8-12"],
              "exfiltracion por el canal de mando"),
    "T1048": (["nist.ac-4", "nist.sc-7", "iso27001-2022.a-8-12"],
              "exfiltracion por protocolo alternativo"),
    "T1567": (["nist.ac-4", "nist.sc-7", "iso27001-2022.a-8-12", "iso27001-2022.a-8-23"],
              "exfiltracion por servicio web"),
    "T1052": (["nist.mp-7", "nist.ac-19", "iso27001-2022.a-7-10", "iso27001-2022.a-8-12"],
              "exfiltracion por medio fisico"),
    "T1020": (["nist.ac-4", "iso27001-2022.a-8-12"],
              "exfiltracion automatizada"),
    "T1030": (["nist.ac-4", "iso27001-2022.a-8-12"],
              "limite de tamano en la transferencia"),
    "T1091": (["nist.mp-7", "nist.ac-19", "iso27001-2022.a-7-10"],
              "propagacion por medio extraible"),
    "T1005": (["nist.ac-3", "iso27001-2022.a-8-3", "iso27001-2022.a-8-12"],
              "recoleccion de datos del sistema local"),
    "T1074": (["nist.ac-4", "iso27001-2022.a-8-12"],
              "preparacion de datos para la salida"),
    "T1560": (["nist.ac-4", "iso27001-2022.a-8-12"],
              "archivado de datos recogidos"),
    "T1114": (["nist.ac-3", "iso27001-2022.a-8-3", "iso27001-2022.a-8-12"],
              "recoleccion de correo"),
    "T1113": (["nist.ac-3", "iso27001-2022.a-8-3"],
              "captura de pantalla"),

    # ── Acceso inicial y aplicaciones ───────────────────────────────────
    "T1190": (["nist.si-10", "nist.ra-5", "nist.sc-7", "iso27001-2022.a-8-28",
               "iso27001-2022.a-8-8"],
              "explotacion de aplicacion publicada"),
    "T1189": (["nist.si-3", "nist.sc-18", "iso27001-2022.a-8-23"],
              "compromiso desde el navegador"),
    "T1566": (["nist.si-8", "nist.at-2", "iso27001-2022.a-6-3", "iso27001-2022.a-8-23"],
              "phishing"),
    "T1534": (["nist.si-8", "iso27001-2022.a-6-3"],
              "suplantacion interna"),
    "T1606": (["nist.ia-5", "nist.sc-23", "iso27001-2022.a-8-5"],
              "falsificacion de credencial web"),
    "T1595": (["nist.sc-7", "nist.ra-5", "iso27001-2022.a-8-8"],
              "escaneo activo"),
    "T1083": (["nist.ac-3", "iso27001-2022.a-8-3"],
              "descubrimiento de ficheros y directorios"),

    # ── Cadena de suministro ────────────────────────────────────────────
    "T1195": (["nist.sr-3", "nist.sr-11", "nist.cm-14", "iso27001-2022.a-5-19",
               "iso27001-2022.a-8-30"],
              "compromiso de la cadena de suministro"),
    "T1574": (["nist.si-7", "nist.cm-5", "iso27001-2022.a-8-9"],
              "secuestro del flujo de ejecucion"),

    # ── Impacto ─────────────────────────────────────────────────────────
    "T1486": (["nist.cp-9", "nist.cp-10", "nist.ir-4", "iso27001-2022.a-8-13",
               "iso27001-2022.a-5-26"],
              "cifrado con fines de impacto"),
    "T1490": (["nist.cp-9", "nist.cp-10", "iso27001-2022.a-8-13"],
              "inhibicion de la recuperacion"),
    "T1489": (["nist.cp-10", "nist.ir-4", "iso27001-2022.a-5-29"],
              "parada de servicio"),
    "T1485": (["nist.cp-9", "iso27001-2022.a-8-13"],
              "destruccion de datos"),

    # ── Contenedores y nube ─────────────────────────────────────────────
    "T1610": (["nist.cm-7", "nist.ac-6", "iso27001-2022.a-8-9"],
              "despliegue de contenedor"),
    "T1611": (["nist.ac-6", "nist.sc-39", "iso27001-2022.a-8-2"],
              "escape del contenedor"),
    "T1609": (["nist.ac-6", "nist.au-12", "iso27001-2022.a-8-2"],
              "comando en el administrador de contenedores"),
    "T1613": (["nist.ac-2", "iso27001-2022.a-5-15"],
              "descubrimiento de recursos de contenedor"),
    "T1526": (["nist.ac-2", "iso27001-2022.a-5-15"],
              "descubrimiento de servicios de nube"),
    "T1556": (["nist.ia-2", "nist.ac-2", "iso27001-2022.a-8-5"],
              "modificacion del proceso de autenticacion"),
    "T1569": (["nist.cm-7", "iso27001-2022.a-8-9"],
              "ejecucion por servicio del sistema"),
    "T1021": (["nist.ac-17", "nist.sc-7", "iso27001-2022.a-8-20", "iso27001-2022.a-6-7"],
              "servicio remoto"),
    "T1047": (["nist.ac-17", "nist.cm-7", "iso27001-2022.a-8-20"],
              "instrumental de gestion de Windows"),
    "T1649": (["nist.ia-5", "nist.sc-12", "iso27001-2022.a-8-24"],
              "robo de certificados"),
}

TITULOS = {
    "nist.ac-2": "Account Management", "nist.ac-3": "Access Enforcement",
    "nist.ac-4": "Information Flow Enforcement", "nist.ac-6": "Least Privilege",
    "nist.ac-7": "Unsuccessful Logon Attempts", "nist.ac-17": "Remote Access",
    "nist.ac-19": "Access Control for Mobile Devices",
    "nist.at-2": "Literacy Training and Awareness",
    "nist.au-6": "Audit Record Review, Analysis, and Reporting",
    "nist.au-9": "Protection of Audit Information",
    "nist.au-11": "Audit Record Retention", "nist.au-12": "Audit Record Generation",
    "nist.cm-5": "Access Restrictions for Change",
    "nist.cm-6": "Configuration Settings", "nist.cm-7": "Least Functionality",
    "nist.cm-14": "Signed Components", "nist.cp-9": "System Backup",
    "nist.cp-10": "System Recovery and Reconstitution",
    "nist.ia-2": "Identification and Authentication (Organizational Users)",
    "nist.ia-5": "Authenticator Management", "nist.ir-4": "Incident Handling",
    "nist.mp-7": "Media Use", "nist.ra-5": "Vulnerability Monitoring and Scanning",
    "nist.sc-7": "Boundary Protection",
    "nist.sc-8": "Transmission Confidentiality and Integrity",
    "nist.sc-12": "Cryptographic Key Establishment and Management",
    "nist.sc-18": "Mobile Code", "nist.sc-23": "Session Authenticity",
    "nist.sc-28": "Protection of Information at Rest",
    "nist.sc-39": "Process Isolation", "nist.si-2": "Flaw Remediation",
    "nist.si-3": "Malicious Code Protection", "nist.si-4": "System Monitoring",
    "nist.si-7": "Software, Firmware, and Information Integrity",
    "nist.si-8": "Spam Protection", "nist.si-10": "Information Input Validation",
    "nist.sr-3": "Supply Chain Controls and Processes",
    "nist.sr-11": "Component Authenticity",
    "iso27001-2022.a-5-15": "Access control",
    "iso27001-2022.a-5-16": "Identity management",
    "iso27001-2022.a-5-17": "Authentication information",
    "iso27001-2022.a-5-18": "Access rights",
    "iso27001-2022.a-5-19": "Information security in supplier relationships",
    "iso27001-2022.a-5-26": "Response to information security incidents",
    "iso27001-2022.a-5-29": "Information security during disruption",
    "iso27001-2022.a-6-3": "Information security awareness, education and training",
    "iso27001-2022.a-6-7": "Remote working",
    "iso27001-2022.a-7-10": "Storage media",
    "iso27001-2022.a-8-2": "Privileged access rights",
    "iso27001-2022.a-8-3": "Information access restriction",
    "iso27001-2022.a-8-5": "Secure authentication",
    "iso27001-2022.a-8-7": "Protection against malware",
    "iso27001-2022.a-8-8": "Management of technical vulnerabilities",
    "iso27001-2022.a-8-9": "Configuration management",
    "iso27001-2022.a-8-12": "Data leakage prevention",
    "iso27001-2022.a-8-13": "Information backup",
    "iso27001-2022.a-8-15": "Logging",
    "iso27001-2022.a-8-16": "Monitoring activities",
    "iso27001-2022.a-8-20": "Networks security",
    "iso27001-2022.a-8-22": "Segregation of networks",
    "iso27001-2022.a-8-23": "Web filtering",
    "iso27001-2022.a-8-24": "Use of cryptography",
    "iso27001-2022.a-8-28": "Secure coding",
    "iso27001-2022.a-8-30": "Outsourced development",
}


def tecnicas(doc) -> list[str]:
    out = []
    for t in doc.get("tags", []) or []:
        m = RE_TEC.match(str(t))
        if m:
            out.append(m.group(1).upper())
    return sorted(set(out))


def controles_de(doc) -> tuple[list[str], list[str]]:
    """Devuelve (controles, justificaciones) para una regla."""
    ctrl, razon = [], []
    for t in tecnicas(doc):
        if t in POR_TECNICA:
            c, r = POR_TECNICA[t]
            ctrl += c
            razon.append(f"{t}: {r}")
    return sorted(set(ctrl)), razon


def escribir_etiquetas(fichero: Path, controles: list[str]) -> bool:
    """Inserta las etiquetas de control tras la ultima etiqueta attack.*"""
    lineas = fichero.read_text(encoding="utf-8").split("\n")
    # quitar las de una pasada anterior para que la operacion sea idempotente
    lineas = [l for l in lineas
              if not re.match(r'^\s*-\s*(nist|iso27001-2022)\.', l)]
    ultima, sangria = None, "    "
    for i, l in enumerate(lineas):
        m = re.match(r'^(\s*)-\s*attack\.', l)
        if m:
            ultima, sangria = i, m.group(1)
    if ultima is None or not controles:
        fichero.write_text("\n".join(lineas), encoding="utf-8")
        return False
    nuevas = [f"{sangria}- {c}" for c in controles]
    lineas[ultima + 1:ultima + 1] = nuevas
    fichero.write_text("\n".join(lineas), encoding="utf-8")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    filas, sin_mapeo = [], []
    por_control = Counter()
    tecnicas_huerfanas = Counter()

    for f in sorted(REGLAS.rglob("*.yml")):
        docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if d]
        doc = next((d for d in docs if "title" in d), None)
        if not doc:
            continue
        ctrl, razon = controles_de(doc)
        for t in tecnicas(doc):
            if t not in POR_TECNICA:
                tecnicas_huerfanas[t] += 1
        if not ctrl:
            sin_mapeo.append(f.relative_to(RAIZ))
        for c in ctrl:
            por_control[c] += 1
        if not args.check:
            escribir_etiquetas(f, ctrl)
        filas.append({
            "regla": f.stem,
            "dominio": f.relative_to(REGLAS).parts[0],
            "titulo": doc.get("title", ""),
            "severidad": doc.get("level", "medium"),
            "mitre": ",".join(tecnicas(doc)),
            "nist_800_53": ",".join(c.split(".", 1)[1].upper()
                                    for c in ctrl if c.startswith("nist.")),
            "iso_27001_2022": ",".join(
                "A." + c.split(".", 1)[1].removeprefix("a-").replace("-", ".")
                for c in ctrl if c.startswith("iso27001")),
            "justificacion": " | ".join(razon),
        })

    if not args.check:
        MATRIZ.parent.mkdir(parents=True, exist_ok=True)
        with MATRIZ.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(filas[0].keys()))
            w.writeheader()
            w.writerows(filas)

    print(f"{len(filas)} reglas procesadas")
    print(f"  controles distintos referenciados: {len(por_control)}")
    print(f"    NIST 800-53: {sum(1 for c in por_control if c.startswith('nist.'))}")
    print(f"    ISO 27001:2022: {sum(1 for c in por_control if c.startswith('iso'))}")
    print(f"  reglas sin control asignado: {len(sin_mapeo)}")
    for r in sin_mapeo[:10]:
        print(f"    · {r}")
    if tecnicas_huerfanas:
        print(f"  tecnicas sin entrada en POR_TECNICA: {len(tecnicas_huerfanas)}")
        for t, n in tecnicas_huerfanas.most_common(15):
            print(f"    · {t} ({n} regla/s)")
    print(f"\n  controles con mas reglas de respaldo:")
    for c, n in por_control.most_common(10):
        print(f"    {c:26} {n:3}  {TITULOS.get(c, '?')}")
    if not args.check:
        print(f"\n  matriz en {MATRIZ.relative_to(RAIZ)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
