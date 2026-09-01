# Fusión de bibliotecas — qué se conservó, qué se retiró y por qué

Este repositorio nació con **28 reglas Sigma** propias. Se le ha incorporado una
segunda biblioteca de **48 reglas** procedente del paquete de detecciones
ZTA/SOC, más reglas nuevas de macOS, contenedores y marcos regulatorios.

Sumar `28 + 48` habría dado 76 reglas con **13 pares que disparan a la vez sobre
el mismo evento**. Eso no es cobertura: es ruido con dos identificadores. Este
documento es el registro de las decisiones de fusión, para que cualquiera pueda
auditar por qué falta una regla que antes estaba.

## Criterio

Para cada par solapado se comparó la **lógica de detección**, no el título:

| Situación | Decisión |
|---|---|
| La regla A es un subconjunto estricto de B | Se conserva **B**. A se retira y sus etiquetas ATT&CK se trasladan a B. |
| A y B miran el mismo evento desde ángulos distintos (origen/destino, telemetrías distintas) | **Se conservan las dos**. |
| A es más amplia pero con peor fidelidad | Se conserva la de mayor fidelidad y se anota la pérdida de amplitud abajo. |

---

## Reglas retiradas (13)

Todas eran de `rules/windows/`. En los 13 casos la regla superviviente contiene
la lógica de la retirada **de forma literal o más amplia**.

| Regla retirada | Superviviente | Por qué |
|---|---|---|
| `proc_lsass_comsvcs_minidump` | `soc_edr_001_volcado_lsass` | La retirada **es** la primera selección de la superviviente, carácter por carácter. La superviviente añade procdump, dumpert, nanodump y `MiniDumpWriteDump` vía rundll32. |
| `proc_vssadmin_delete_shadows` | `soc_edr_003_borrado_copias_sombra` | La superviviente cubre vssadmin, wmic, wbadmin, bcdedit y PowerShell, y **ancla en `Image`** en vez de buscar la cadena en cualquier línea de comandos. |
| `proc_powershell_encoded` | `soc_edr_006_powershell_ofuscado` | La retirada buscaba `-enc` sin delimitar, lo que casa también con `-Encoding` y `-EncodedArguments`: falso positivo garantizado. La superviviente delimita con espacios y añade 8 patrones de ofuscación más, incluido `pwsh.exe`. |
| `proc_certutil_download_decode` | `soc_edr_005_lolbins_descarga` | Selección `selection_certutil` equivalente. |
| `proc_bitsadmin_transfer` | `soc_edr_005_lolbins_descarga` | Selección `selection_bitsadmin` idéntica. |
| `proc_mshta_execution` | `soc_edr_005_lolbins_descarga` | Selección `selection_mshta` idéntica. |
| `proc_regsvr32_scriptlet` | `soc_edr_005_lolbins_descarga` | Selección `selection_regsvr32` idéntica. |
| `proc_powershell_download_cradle` | `soc_edr_005_lolbins_descarga` | Selección `selection_ps_metodo` equivalente. |
| `proc_defender_tamper` | `soc_edr_004_defensas_deshabilitadas` | La superviviente cubre además firewall, parada de servicios (WinDefend, Sense, wazuh) y `auditpol`. |
| `proc_wevtutil_clear_logs` | `soc_edr_004_defensas_deshabilitadas` | `wevtutil cl` y `wevtutil sl` están en `selection_auditoria`. Se trasladó la etiqueta `attack.t1070.001`. |
| `proc_mimikatz_cmdline` | `soc_ad_005_herramientas_kerberos` | La superviviente cubre los mismos argumentos **y** el nombre de imagen / `OriginalFileName`, que sobrevive al renombrado del binario. |
| `proc_scheduled_task_create` | `soc_edr_008_persistencia_tarea` | Ver «pérdidas conocidas». |
| `reg_run_key_persistence` | `soc_edr_009_persistencia_registro` | Ver «pérdidas conocidas». |

### Pérdidas conocidas de amplitud

Dos retiradas **sí reducen** lo que se ve, y conviene decirlo:

- `proc_scheduled_task_create` alertaba de **cualquier** `schtasks /create`.
  `soc_edr_008` exige además intérprete, ruta escribible, URL o `/ru system`.
  Una tarea programada creada para lanzar un `.exe` legítimo desde
  `C:\Program Files\` ya no alerta.
- `reg_run_key_persistence` alertaba de **cualquier** escritura en `Run`/`RunOnce`.
  `soc_edr_009` exige además que el valor apunte a un intérprete o a una ruta
  escribible por el usuario.

La decisión es deliberada: ambas versiones amplias generan decenas de eventos
diarios por instalaciones y actualizaciones legítimas, y en un turno de 24×7 eso
se traduce en cierre por fatiga. La amplitud sigue disponible como **consulta de
caza** — no como alerta — en `deploy/*/`, filtrando por técnica T1053.005 y
T1547.001 sin la condición de sospecha.

---

## Reglas conservadas pese a compartir técnica (5)

| Regla | Coincide en | Se conserva porque |
|---|---|---|
| `proc_wmic_process_call_create` | T1047 con `soc_ad_009_wmi_winrm_remoto` | Miran **lados opuestos** del movimiento lateral: la primera ve el `wmic` que lanza el atacante en el equipo origen; la segunda ve a `WmiPrvSE.exe` pariendo una shell en el equipo destino. En un incidente real quieres las dos, y correlacionarlas da el par origen-destino. |
| `proc_net_user_add` | T1136 con `soc_ad_011_cuenta_equipo_creada` | Telemetría distinta: línea de comandos local frente a evento 4741 del controlador de dominio. Y técnicas distintas: cuenta local frente a cuenta de equipo. |
| `proc_office_spawning_shell` | T1204/T1566 con las reglas de correo | Las de correo detectan la **entrega**; ésta detecta la **ejecución**. Son dos puntos distintos de la cadena. |
| `net_rare_process_external_conn` | T1071 con `soc_net_001_beaconing` | Una mira el proceso que abre la conexión (endpoint); la otra el patrón temporal del tráfico (red). |
| `proc_service_create_scexe` | T1543.003, sin equivalente | Sin solapamiento real. |

---

## Correcciones aplicadas a las 28 reglas originales

Durante la fusión se validaron las reglas originales contra pySigma y aparecieron
dos defectos que ya estaban en `main`:

1. **Etiquetas de táctica no canónicas.** Las 28 reglas usaban la forma antigua
   con guion bajo (`attack.credential-access`). La taxonomía oficial de ATT&CK
   —el campo `x_mitre_shortname` del STIX de MITRE, que es de donde pySigma saca
   la lista de valores válidos— usa **guion**: `attack.credential-access`.
   `ATTACKTagValidator` rechaza la forma con guion bajo. Normalizadas las 14
   tácticas en los 7 ficheros afectados.

2. **Referencias ATT&CK rotas en las 14 reglas que las llevaban.** Todas
   apuntaban a `https://attack.mitre.org/techniques/T1562/001`, `/002`, `/003`…
   El generador original había hecho `tag.split(".")[-1]` sobre
   `attack.t1003.001`, quedándose con el sufijo de subtécnica y perdiendo la
   técnica base. La URL correcta de una subtécnica es
   `https://attack.mitre.org/techniques/T1003/001/`. Regeneradas desde las
   etiquetas de cada regla.

Ninguna de las dos afectaba a la detección, pero la primera habría hecho fallar
el CI en cuanto se activara el validador de etiquetas, y la segunda mandaba al
analista a una página inexistente justo cuando está triando.

---

## Resultado

| | Antes | Después |
|---|---|---|
| Reglas Sigma | 28 | **87** |
| Pares que disparaban a la vez | 13 | 0 |
| Técnicas ATT&CK base | 20 | **55** |
| Tácticas cubiertas | 7 | **12** |
| Plataformas | Windows, Linux | Windows, Linux, macOS, contenedores, nube, correo, red |
| SIEM de destino | Lucene, Splunk, ES\|QL | Splunk, Sentinel, **Wazuh nativo**, Elastic |
| Reglas con etiquetas inválidas | 28 | 0 |
| Referencias rotas | 14 | 0 |

Desglose del recorrido: 28 originales − 13 retiradas = 15, + 48 del paquete
ZTA/SOC + 8 de macOS + 8 de contenedores + 8 de arquitectura Zero Trust = **87**.
