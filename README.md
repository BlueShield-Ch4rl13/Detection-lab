# 🛡️ Detection-lab — detección como código, multi-SIEM

![Sigma](https://img.shields.io/badge/reglas-127%20Sigma-4FD6C4)
![ATT&CK](https://img.shields.io/badge/ATT%26CK-71%20t%C3%A9cnicas%20%C2%B7%2013%20t%C3%A1cticas-E0A34A)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20%C2%B7%20Sentinel%20%C2%B7%20Wazuh%20%C2%B7%20Elastic-2ee6f0)
![Marcos](https://img.shields.io/badge/marcos-NIST%20800--53%20%C2%B7%20ISO%2027001%3A2022-a78bfa)
![SOAR](https://img.shields.io/badge/respuesta-15%20playbooks%20%C2%B7%2055%20acciones-34d399)
![CI](https://github.com/BlueShield-Ch4rl13/Detection-lab/actions/workflows/validate.yml/badge.svg)
![License](https://img.shields.io/badge/licencia-MIT-blue)

**Una regla se escribe una vez y se despliega en cuatro SIEM.** 127 reglas Sigma
que el CI valida y convierte a Splunk, Microsoft Sentinel, Wazuh y Elastic en
cada commit, mapeadas a NIST SP 800-53 e ISO 27001:2022, con la inteligencia de
[News CTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI) integrada en los
cuatro.

Se acopla a **[Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst)**:
aquel es la *plataforma* SOC (Wazuh, sensores, Shuffle, TheHive, Ollama); éste
es el **contenido de detección y la lógica de respuesta** que corre encima. La
integración entre los dos está en
[`docs/integracion-soc.md`](docs/integracion-soc.md).

![Cobertura MITRE ATT&CK](docs/img/cobertura-attack.svg)

<sub>Este mapa **se regenera** con `python tools/generar_cobertura_svg.py`. Una
captura de ATT&CK Navigator envejece en cuanto se añade una regla y nadie se
acuerda de rehacerla; ésta siempre dice la verdad. La capa completa para
Navigator sigue en `navigator/coverage-layer.json`.</sub>

---

## 🎯 Las decisiones, y el porqué

**Una fuente, cuatro destinos.** La regla vive en Sigma y `tools/build.py` la
convierte. Los índices, sourcetypes y tablas no están escritos en las reglas:
están en `tools/pipelines/`. Cambiar de entorno es editar un fichero y
regenerar, no reescribir 127 reglas.

**Lo que un backend no soporta se dice, no se disimula.** Tres reglas son
correlaciones Sigma que cuentan cardinalidad en una ventana. El backend de Kusto
no las convierte y Wazuh no puede expresarlas. En vez de convertir sólo la regla
base y llamarlo cobertura —esa regla base tiene nivel `informational` a
propósito, por sí sola no es una señal— hay KQL escrito a mano en
`deploy/sentinel/consultas/correlaciones.kql`, y el validador comprueba que sus
umbrales sigan cuadrando con los de Sigma. Los cinco casos que Wazuh no puede
expresar salen como avisos con su motivo.

**Reglas nativas de Wazuh, no consultas Lucene.** Una consulta Lucene sirve para
buscar en el indexador *después*; no alerta. `tools/sigma_to_wazuh.py` genera
reglas XML reales: como Wazuh combina con AND todas las condiciones de una
regla, el conversor pasa la condición Sigma a forma normal disyuntiva aplicando
De Morgan y emite una regla por cada término. 127 reglas Sigma → **260 reglas de
Wazuh**, más 80 escritas a mano.

**La inteligencia alerta donde tiene sentido y caza donde no.** Sólo los hashes
se despliegan como alerta directa: un hash coincide o no coincide. Las IP y los
dominios coinciden muchas veces por sinkholes, CDN compartidas y dominios
reciclados, así que van como caza con umbral. Desplegarlos como alerta llena la
cola de eventos que se cierran sin acción, y eso entrena al turno a cerrar sin
mirar.

**El mapeo a marcos se genera, no se etiqueta a mano.** Un mapeo mantenido a
mano se desincroniza a la tercera regla nueva, y entonces es peor que ninguno:
en una auditoría se presenta como evidencia de una cobertura que ya no existe.

**La respuesta se decide por radio de impacto, no por gravedad.** Cada acción
de contención declara a qué llega: un proceso, un objeto, un equipo, una cuenta
o la organización. Lo que toca un proceso o un equipo se automatiza; lo que toca
una cuenta o el perímetro se prepara y espera a una persona. Es contraintuitivo
—cuanto más grave la detección, menos actúa sola la máquina— y es lo correcto:
el coste de una acción automática equivocada crece con el radio, no con la
severidad.

**El CI comprueba que lo generado está al día.** Regenera todo y falla si no
coincide con lo commiteado. Sin eso, una regla se modifica, sus consultas se
quedan viejas, y lo que está desplegado deja de ser lo que dice el repositorio.

---

## 📊 Qué cubre

| Dominio | Reglas | Telemetría |
|---|---:|---|
| `rules/windows/` | 43 | Sysmon, canal Security, Defender XDR |
| `rules/web/` | 13 | Servidor web y WAF: OWASP y explotación |
| `rules/cloud/` | 10 | Entra ID (SigninLogs, AuditLogs), M365, Netskope |
| `rules/linux/` | 10 | auditd, Falco |
| `rules/contenedores/` | 8 | Auditoría de Kubernetes, runtime |
| `rules/correo/` | 8 | Proofpoint TAP, Exchange Online |
| `rules/exfiltracion/` | 8 | Nube personal, USB, correo, repositorios, BD |
| `rules/macos/` | 8 | Endpoint Security Framework |
| `rules/zta/` | 8 | Arquitectura Zero Trust |
| `rules/xdr/` | 6 | Manipulación del sensor, ASR, BYOVD, ETW |
| `rules/red/` | 5 | Proxy, DNS, NetFlow |

**71 técnicas ATT&CK base** (124 contando subtécnicas) en **13 tácticas**.
31 críticas · 65 altas · 28 medias · 3 informativas (bases de correlación).

Por familia de ataque: 19 de **Active Directory**, 10 de **volcado de
credenciales**, 13 de **ataques web**, 8 de **exfiltración**, 6 de **evasión de
XDR**, 8 de **contenedores**.

---

## 🗂️ Una carpeta por SIEM

Cada SIEM tiene todo lo suyo junto, y su propia guía de instalación:

```
deploy/
├── wazuh/      reglas/ (340 XML)  listas/ (CDB)      consultas/  INSTALAR.md
├── splunk/     reglas/ (127)      lookups/ (CSV)     consultas/  INSTALAR.md
├── sentinel/   reglas/ (124 KQL)  watchlists/ (CSV)  consultas/  INSTALAR.md
└── elastic/    reglas/ (Lucene+ES|QL)  indicadores/ (NDJSON)  consultas/  INSTALAR.md
```

| Subcarpeta | Qué es | Se regenera |
|---|---|---|
| `reglas/` | Lo que **alerta**, generado desde `rules/` | Sí, `tools/build.py` |
| `listas/` `lookups/` `watchlists/` `indicadores/` | Indicadores de News CTI | Sí, `tools/sync_cti.py` |
| `consultas/` | Lo que **caza** sobre lo ya indexado | No, escritas a mano |
| `INSTALAR.md` | Cómo se carga todo eso en ese SIEM | No |

**Regla y consulta no son lo mismo.** Una regla alerta en tiempo real, evento a
evento. Una consulta busca hacia atrás sobre lo indexado. Confundirlas es el
error que este repositorio ya cometió una vez, cuando los `*-wazuh-lucene.txt`
se presentaban como si fueran detecciones.

---

## 🤖 Respuesta automática

Cada alerta llega al SOAR con su clase ya decidida, escrita en la propia regla
de Wazuh:

| Clase | Se dispara con | Qué pasa sin persona |
|---|---|---|
| `auto_cierre` | Sigma `informational` | Se registra y se descarta. No sale del manager. |
| `auto_enriq` | `low` | Se enriquece y se encola. Sin LLM, sin aviso. |
| `auto_analisis` | `medium`, `high` | Enriquecimiento, Ollama, caso en TheHive, aviso. |
| `auto_contener` | `critical` | Lo anterior más contención reversible y aviso inmediato. |

**15 playbooks, 55 acciones de contención**: 43 automáticas y 12 que esperan
aprobación. Cuatro familias —AD, credenciales, exfiltración y XDR— no tienen
ninguna condición de cierre automático, y el playbook explica por qué en cada
caso.

`tools/validar_respuesta.py` impide que una acción de radio `cuenta` u
`organizacion` se marque como automática, y que algo irreversible que no sea un
proceso identificado lo esté.

Detalle en **[respuesta/ESQUEMA.md](respuesta/ESQUEMA.md)** y
**[docs/integracion-soc.md](docs/integracion-soc.md)**.

---

## 🧠 Inteligencia desde News CTI

```
ThreatFox ┐
URLhaus   ├─► News CTI ─► iocs_latest.json ─► tools/sync_cti.py ─► los 4 SIEM
OTX       ┘   (scoring)
CISA KEV  ─────────────────────────────────────────────────────►
```

De 716 indicadores del último feed entraron **575**: 98 IP, 192 dominios, 181
URL y 104 hashes, más 20 CVE del catálogo KEV. Los 96 descartados eran de nivel
bajo, con vida útil de horas.

| Indicador | Despliegue | Por qué |
|---|---|---|
| Hash | **Alerta directa** | No comparte infraestructura con nada legítimo |
| IP, dominio, URL | Caza con umbral | Sinkholes, CDN compartidas, dominios reciclados |
| CVE (KEV) | Caza y priorización | No detecta la vulnerabilidad: detecta el intento |

`.github/workflows/inteligencia.yml` refresca a diario y hace commit sólo si algo
cambió. Los indicadores caducan a los 30 días por defecto, y `validate.py` avisa
si las listas llevan más de 7 días sin refrescar.

Detalle completo en **[docs/inteligencia.md](docs/inteligencia.md)**.

---

## 📐 Marcos regulatorios

Cada regla lleva, además de sus etiquetas ATT&CK, los controles que **evidencia**:

```yaml
tags:
    - attack.credential-access
    - attack.t1003.002
    - iso27001-2022.a-5-17     # Authentication information
    - iso27001-2022.a-8-5      # Secure authentication
    - nist.ac-6                # Least Privilege
    - nist.ia-5                # Authenticator Management
```

**62 controles distintos**: 37 de NIST SP 800-53 Rev 5 y 25 del Anexo A de ISO/IEC
27001:2022. `marcos/matriz_controles.csv` lleva una fila por regla con la columna
`justificacion`, que es la que hace la matriz defendible: en una auditoría, la
pregunta siguiente a «¿esto cubre AU-9?» siempre es «¿por qué?».

Más los catálogos previos: Zero Trust (NIST SP 800-207, CISA ZTMM 2.0) y
cumplimiento (ENS, NIS2, DORA, RGPD, ISO 22301).

> El mapeo dice **«esta regla aporta evidencia a este control»**, no «este
> control está cumplido». AC-2 exige además procedimientos de alta y baja,
> revisión periódica y titularidad; nada de eso lo demuestra una regla Sigma.

---

## 🚀 Uso

```bash
pip install -r requirements.txt

python tools/validate.py          # validar y medir la cobertura ATT&CK
python tools/build.py             # generar los cuatro SIEM (unos 8 segundos)
python tools/sync_cti.py          # refrescar los indicadores desde News CTI
python tools/mapear_marcos.py     # remapear a NIST e ISO
python tools/validar_respuesta.py # comprobar la capa de respuesta

# Convertir una regla suelta, para ver la salida
sigma convert -t splunk -p sysmon -p splunk_windows -p tools/pipelines/splunk.yml \
              rules/windows/cred_001_volcado_colmenas_registro.yml

sigma convert -t kusto  -p tools/pipelines/sentinel.yml -p sentinel_asim \
              -p tools/pipelines/sentinel-post.yml \
              rules/web/web_008_inyeccion_jndi_log4shell.yml
```

Después, la guía del SIEM que toque: `deploy/<siem>/INSTALAR.md`.

---

## 📂 Qué hay dentro

| Ruta | Contenido |
|---|---|
| `rules/` | Las 127 reglas Sigma, por dominio |
| `deploy/<siem>/` | Reglas, listas, consultas y guía de cada SIEM |
| `intel/listas/` | Indicadores de News CTI en los cuatro formatos |
| `marcos/` | Catálogos Zero Trust y cumplimiento, y la matriz de controles |
| `tools/build.py` | El generador multi-SIEM |
| `tools/sync_cti.py` | News CTI → listas de indicadores |
| `tools/mapear_marcos.py` | Reglas → controles NIST e ISO |
| `respuesta/playbooks/` | 15 playbooks: qué se automatiza y qué no, y por qué |
| `integracion/wazuh/` | Script de integración Wazuh → Shuffle |
| `integracion/shuffle/` | Nodo enrutador, con la tabla de playbooks compilada |
| `tools/validate.py` | Validación, cobertura y coherencia de lo generado |
| `tools/validar_respuesta.py` | Coherencia de la capa de respuesta |
| `tools/generar_enrutador.py` | Playbooks → nodo de Shuffle |
| `tools/sigma_to_wazuh.py` | Backend propio Sigma → XML de Wazuh (DNF + De Morgan) |
| `tools/pipelines/` | Índices, sourcetypes y tablas. **El único sitio donde tocar el entorno** |
| `purple/atomic-map.md` | Técnica ↔ Atomic Red Team ↔ regla ↔ telemetría (generado) |
| `docs/` | Fusión de bibliotecas, marcos, inteligencia |
| `LAB.md` | Cómo montar el bucle purple team sobre tu Wazuh |

---

## 🧩 Cómo se ve una regla en los cuatro SIEM

Origen — `rules/windows/soc_edr_003_borrado_copias_sombra.yml`:

```yaml
title: Destruccion de copias de seguridad y puntos de restauracion
tags: [attack.impact, attack.t1490, nist.cp-9, iso27001-2022.a-8-13]
logsource: {category: process_creation, product: windows}
detection:
  selection_vssadmin:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains|all: ['delete', 'shadows']
  # ... wmic, wbadmin, bcdedit, powershell
  condition: 1 of selection_*
level: critical
```

```spl
# Splunk
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*") OR ...
```

```kusto
// Microsoft Sentinel
imProcessCreate
| where (TargetProcessName endswith "\\vssadmin.exe" and ...) or ...
```

```xml
<!-- Wazuh: una regla por termino de la forma normal disyuntiva, 5 en total -->
<rule id="101104" level="14">
  <if_group>windows</if_group>
  <field name="win.system.eventID" type="pcre2">^(1)$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\vssadmin\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(?=.*delete)(?=.*shadows)</field>
  <description>SOC-EDR-003: Destruccion de copias de seguridad [1/5]</description>
  <mitre><id>T1490</id></mitre>
</rule>
```

---

## 🔗 El ecosistema

```
News CTI          Detection-lab              Infra-SocAnalyst           ftriage
(IOCs)      ─────► (reglas + respuesta) ────► (Wazuh + SOAR + IA)  ────► (DFIR)
                         │                            │
                         └── playbooks ───────────────┘
```

- **[News CTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)** — inteligencia de amenazas. Alimenta `intel/listas/`.
- **[Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst)** — la plataforma donde corren las detecciones y los playbooks.

---

## 📖 Documentación

- **[Integración con el SOC](docs/integracion-soc.md)** — cómo se acopla a Infra-SocAnalyst, y las tres cosas que estaban rotas entre los dos repositorios.
- **[Esquema de respuesta](respuesta/ESQUEMA.md)** — qué se automatiza, qué no, y la regla de radio de impacto.
- **[Inteligencia](docs/inteligencia.md)** — cómo el feed de News CTI acaba en los cuatro SIEM, y por qué las IP no alertan.
- **[Marcos y cumplimiento](docs/marcos-y-cumplimiento.md)** — Zero Trust, cumplimiento, y el mapeo a NIST 800-53 e ISO 27001:2022.
- **[Fusión de bibliotecas](docs/fusion-de-bibliotecas.md)** — qué reglas se retiraron al unir catálogos y por qué, incluidas las pérdidas de cobertura asumidas.
- **[LAB.md](LAB.md)** — montar el bucle purple team sobre Wazuh.
- **[APLICAR.md](APLICAR.md)** — cómo llevar esto a tu repositorio.

---

## 🔒 Seguridad

Las pruebas de Atomic Red Team se ejecutan **sólo en el laboratorio aislado** y
se revierten con `-Cleanup`. Las reglas son de detección (defensivas). Uso
académico y de respuesta a incidentes.

## 📄 Licencia

MIT.
