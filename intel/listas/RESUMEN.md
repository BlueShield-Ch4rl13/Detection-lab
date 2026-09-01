# Listas de inteligencia

<!-- Generado por tools/sync_cti.py desde ScriptNewsCTI - no editar a mano -->

**Origen:** [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)  
**Feed generado:** 2026-08-31 13:27 UTC  
**Listas generadas:** 2026-08-31T17:34:46Z  
**Filtro aplicado:** nivel minimo `media`, maximo `30` dias de antiguedad

## Que hay en cada lista

| Indicador | Entradas | Uso previsto |
|---|---:|---|
| IP | 98 | Caza programada, no alerta directa |
| Dominio | 192 | Caza programada, no alerta directa |
| URL | 181 | Caza programada, no alerta directa |
| Hash | 104 | **Alerta directa**: un hash coincide o no |
| CVE en KEV | 20 | Priorizacion de parcheo y caza de explotacion |

## Por que las IP y los dominios no alertan

Un indicador de reputacion coincide muchas veces por motivos aburridos:
sinkholes de investigadores, CDN compartidas, dominios reciclados, rangos
de proveedores de nube. Desplegarlos como alerta directa llena la cola de
eventos que se cierran sin accion, y eso entrena al turno a cerrar sin
mirar. Se despliegan como **consultas de caza programadas con umbral**, en
`deploy/<siem>/consultas/`.

El hash es distinto: no comparte infraestructura con nada legitimo, asi que
va como alerta y ademas sin caducidad.

## Que se descarto del feed (96 de 716)

| Motivo | Descartados |
|---|---:|
| nivel bajo | 96 |

## Familias mas presentes

| Amenaza | Indicadores |
|---|---:|
| php.shin_webshell | 103 |
| malware_download | 99 |
| Vidar | 93 |
| ClearFake | 52 |
| 11 Malicious NuGet Tools Pose as Game Cheats to Drop a Windows Host-Surveillance Payload | 32 |
| Toy Ghouls’ new toy: the GenieLocker ransomware | 24 |
| Remus | 23 |
| Campaign deploys a reverse tunnel through multistage intrusion | 23 |
| Real-time Open Source Software Supply Chain Security | 21 |
| Unknown malware | 11 |
| Cobalt Strike | 11 |
| Remcos | 11 |

## Ficheros generados

| Fichero | Entradas |
|---|---:|
| `wazuh/cti_ip` | 98 |
| `wazuh/cti_dominio` | 192 |
| `wazuh/cti_url` | 181 |
| `wazuh/cti_hash` | 104 |
| `wazuh/cti_cve_kev` | 20 |
| `splunk/cti_ip.csv` | 98 |
| `splunk/cti_dominio.csv` | 192 |
| `splunk/cti_url.csv` | 181 |
| `splunk/cti_hash.csv` | 104 |
| `splunk/cti_cve_kev.csv` | 20 |
| `sentinel/CTI_Ip.csv` | 98 |
| `sentinel/CTI_Dominio.csv` | 192 |
| `sentinel/CTI_Url.csv` | 181 |
| `sentinel/CTI_Hash.csv` | 104 |
| `elastic/cti_ip.ndjson` | 98 |
| `elastic/cti_dominio.ndjson` | 192 |
| `elastic/cti_url.ndjson` | 181 |
| `elastic/cti_hash.ndjson` | 104 |

## Como se instala cada una

Ver `deploy/<siem>/INSTALAR.md`. En resumen:

```bash
# Wazuh: copiar, declarar en ossec.conf y compilar
sudo cp intel/listas/wazuh/*.cdb /var/ossec/etc/lists/
sudo /var/ossec/bin/ossec-makelists

# Splunk: como lookups de la app
cp intel/listas/splunk/*.csv $SPLUNK_HOME/etc/apps/TA-detection-lab/lookups/

# Sentinel: Watchlists > New > importar el CSV, alias sin el prefijo CTI_
# Elastic: bulk al indice de indicadores
curl -XPOST 'localhost:9200/logs-ti_newscti-default/_bulk' \
     -H 'Content-Type: application/x-ndjson' \
     --data-binary @intel/listas/elastic/cti_ip.ndjson
```
