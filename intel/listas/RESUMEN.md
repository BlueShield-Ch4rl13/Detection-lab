# Listas de inteligencia

<!-- Generado por tools/sync_cti.py desde ScriptNewsCTI - no editar a mano -->

**Origen:** [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)  
**Feed generado:** 2026-09-05 04:05 UTC  
**Listas generadas:** 2026-09-05T09:44:48Z  
**Filtro aplicado:** nivel minimo `media`, maximo `30` dias de antiguedad

## Que hay en cada lista

| Indicador | Entradas | Uso previsto |
|---|---:|---|
| IP | 2156 | Caza programada, no alerta directa |
| Dominio | 141 | Caza programada, no alerta directa |
| URL | 161 | Caza programada, no alerta directa |
| Hash | 106 | **Alerta directa**: un hash coincide o no |
| CVE en KEV | 21 | Priorizacion de parcheo y caza de explotacion |

## Por que las IP y los dominios no alertan

Un indicador de reputacion coincide muchas veces por motivos aburridos:
sinkholes de investigadores, CDN compartidas, dominios reciclados, rangos
de proveedores de nube. Desplegarlos como alerta directa llena la cola de
eventos que se cierran sin accion, y eso entrena al turno a cerrar sin
mirar. Se despliegan como **consultas de caza programadas con umbral**, en
`deploy/<siem>/consultas/`.

El hash es distinto: no comparte infraestructura con nada legitimo, asi que
va como alerta y ademas sin caducidad.

## Que se descarto del feed (146 de 7350)

| Motivo | Descartados |
|---|---:|
| nivel bajo | 92 |
| tipo no usado | 54 |

## Familias mas presentes

| Amenaza | Indicadores |
|---|---:|
| Unknown malware | 2020 |
| malware_download | 99 |
| VShell | 88 |
| ClearFake | 78 |
| TA416 resumes European government espionage campaigns | 40 |
| Contagious Interview steps outside the developer workflow | 28 |
| php.shin_webshell | 27 |
| ENDLESSDOORS Is Phoning Home. Pick Up. | 27 |
| KongTuke | 19 |
| Mozi | 14 |
| Unknown Stealer | 13 |
| PureRAT | 12 |

## Ficheros generados

| Fichero | Entradas |
|---|---:|
| `wazuh/cti_ip` | 2156 |
| `wazuh/cti_dominio` | 141 |
| `wazuh/cti_url` | 161 |
| `wazuh/cti_hash` | 106 |
| `wazuh/cti_cve_kev` | 21 |
| `splunk/cti_ip.csv` | 2156 |
| `splunk/cti_dominio.csv` | 141 |
| `splunk/cti_url.csv` | 161 |
| `splunk/cti_hash.csv` | 106 |
| `splunk/cti_cve_kev.csv` | 21 |
| `sentinel/CTI_Ip.csv` | 2156 |
| `sentinel/CTI_Dominio.csv` | 141 |
| `sentinel/CTI_Url.csv` | 161 |
| `sentinel/CTI_Hash.csv` | 106 |
| `elastic/cti_ip.ndjson` | 2156 |
| `elastic/cti_dominio.ndjson` | 141 |
| `elastic/cti_url.ndjson` | 161 |
| `elastic/cti_hash.ndjson` | 106 |

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
