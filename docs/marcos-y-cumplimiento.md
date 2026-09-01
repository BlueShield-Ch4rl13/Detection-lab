# Marcos: Zero Trust y cumplimiento

El repositorio tiene **dos vias de deteccion**, y mezclarlas seria un error. Este
documento explica cual es cual, por que no se han unificado y como se relacionan.

## Via 1 — Biblioteca Sigma (`rules/`)

Deteccion basada en eventos: llega un evento, se compara con un patron, salta o
no salta. Es lo que Sigma expresa, y por eso todo lo que cabe aqui se escribe
aqui: una regla, cuatro SIEM.

## Via 2 — Detecciones de marco (`marcos/`)

57 detecciones derivadas de los marcos regulatorios y de arquitectura. **No
todas caben en Sigma**, y forzarlas seria vender cobertura que no existe. Se
dividen en tres clases:

| Clase | Ejemplo | Por que no es Sigma |
|---|---|---|
| **Dependen de telemetria propia de Wazuh** | Fallo de comprobacion SCA del baseline, CVE critico en el inventario de syscollector, cambio en syscheck | Sigma no tiene un `logsource` para los modulos de Wazuh. Son alertas del propio SIEM, no eventos del endpoint. |
| **Dependen de un dato de la organizacion** | Equipo no inventariado generando eventos, proveedor fuera de ventana autorizada, acceso sin pasar por el PEP | Necesitan un *lookup*: inventario de activos, lista de proveedores, mapa de segmentos. Sigma no cruza contra fuentes externas. |
| **Detectan una ausencia** | Copia de seguridad no ejecutada dentro del RPO, notificacion NIS2 de 72 h pendiente, retencion por debajo del minimo | Sigma detecta que algo **pasa**. Estas detectan que algo **no ha pasado** dentro de un plazo, que es una busqueda programada sobre un registro, no una coincidencia de evento. |

Las detecciones de esta via viven como **reglas nativas de Wazuh** en
`deploy/wazuh/09[0-6]*.xml` y como **busquedas programadas de Splunk**. El
catalogo declara para cada una si esta en los dos SIEM o solo en Splunk, y en
qué estado está.

### Lo que sí se ha llevado a Sigma

Ocho detecciones de marco eran expresables como coincidencia de evento y no
estaban ya cubiertas por la biblioteca. Estan en `rules/zta/` y salen por los
cuatro SIEM como cualquier otra regla:

| Regla | Pilar | Principio que sostiene |
|---|---|---|
| `zta_sup_001_libreria_ruta_no_estandar` | Cadena de suministro | Sideloading de DLL: el binario esta firmado, la libreria no |
| `zta_sup_002_paquete_repositorio_no_aprobado` | Cadena de suministro | Saltarse el repositorio interno es saltarse el escaneo y el inventario |
| `zta_sup_003_fichero_dependencias_modificado` | Cadena de suministro | El lockfile es lo que hace reproducible lo auditado |
| `zta_id_001_autenticacion_heredada` | Identidad | Los protocolos heredados no pasan por MFA ni acceso condicional |
| `zta_id_002_cuenta_servicio_interactiva` | Identidad | Una cuenta de servicio la usa un proceso, no una persona |
| `zta_dev_001_almacenamiento_extraible` | Dispositivos | Entrada de codigo y salida de datos en el mismo evento |
| `zta_net_001_protocolo_en_claro` | Redes | Cifrado extremo a extremo: la red interna tampoco es de confianza |
| `zta_vis_001_borrado_registro_auditoria` | Visibilidad | Sin registro no hay deteccion |

Las que se quedaron fuera por estar ya cubiertas: tunel DNS, explotacion web,
webshell, contenedor privilegiado, volumen de subida anomalo y borrado de
registros — todas tienen su equivalente en `rules/red/`, `rules/contenedores/`
o `rules/windows/`.

## Los catalogos

| Fichero | Filas | Que contiene |
|---|---|---|
| `marcos/zta_detections.csv` | 37 | Detecciones Zero Trust, con pilar CISA, principio NIST SP 800-207, etapa de madurez y estado |
| `marcos/cmp_detections.csv` | 20 | Detecciones de cumplimiento, con marcos aplicables, obligacion y plazo |
| `marcos/zta_controls.csv` | 25 | Las 25 funciones CISA cruzadas con NIST 800-53, ISO 27001, ENS, NIS2, DORA, ISO 22301 y RGPD |
| `marcos/marcos_obligaciones.csv` | 19 | Obligaciones con su plazo y la autoridad competente en Espana |
| `marcos/soc_detections.csv` | 48 | Indice de la biblioteca Sigma original del paquete |

El de mas valor es **`zta_controls.csv`**: es la matriz que traduce una funcion
de arquitectura a un articulo concreto de cada marco. Es lo que permite
responder a un auditor "esta funcion la cubre esta deteccion, y responde a este
articulo" sin reconstruirlo cada vez.

### Estado de las detecciones de marco

De las 57, **28 estan listas** para desplegar tal cual. Las otras 29 declaran lo
que les falta en vez de fingir que funcionan:

- `requiere-lookup` (25): funcionan en cuanto se carga el fichero de contexto
  que necesitan — inventario de activos, lista de proveedores, mapa de
  segmentos, registro de incidentes.
- `requiere-fuente` (4): necesitan una telemetria que no todos los entornos
  tienen — geolocalizacion del IdP, eventos de MFA, carga de modulos.

Una deteccion que necesita un dato que no esta cargado **no detecta nada**. Se
declara en el catalogo en lugar de contarla como cobertura.

## Marcos verificados

Cada referencia se comprobo contra la fuente primaria, no contra memoria:

| Marco | Version / referencia |
|---|---|
| NIST SP 800-207 | 7 principios, arquitectura PE / PA / PEP |
| CISA ZTMM | 2.0 — 5 pilares, 3 capacidades transversales, 4 etapas de madurez |
| ENS | RD 311/2022 — `op.exp.8` registro de actividad, `op.exp.10` proteccion de los registros, `mp.info.9` copias de seguridad |
| NIS2 | Art. 23 — alerta temprana 24 h, notificacion 72 h, informe final 1 mes |
| DORA | RTS art. 5 — notificacion inicial 4 h, intermedia 24 h/72 h, final 1 mes |
| RGPD | Art. 33 y 34 (notificacion), 44 a 49 (transferencias internacionales) |
| ISO/IEC 27001 | 2022 |
| ISO 22301 | 2019 |

> Una correccion que salio de esa verificacion: `mp.info.9` es *Copias de
> seguridad* en el Anexo II del RD 311/2022. `mp.info.6` es *Limpieza de
> documentos*, que es otra cosa. Estaba mal en una version anterior del
> catalogo.

## Despliegue

Las detecciones de marco no las genera `tools/build.py`: son artefactos escritos
a mano y se despliegan tal cual.

```bash
# Wazuh: reglas de marco (series 100100-100799)
sudo cp deploy/wazuh/09[0-6]*.xml /var/ossec/etc/rules/
sudo systemctl restart wazuh-manager

# Wazuh: reglas generadas desde Sigma (serie 101000+)
sudo cp deploy/wazuh/0970-detection_lab_sigma.xml /var/ossec/etc/rules/
```

Las series de identificadores no se solapan, asi que las dos vias pueden
convivir en el mismo manager:

| Serie | Origen |
|---|---|
| 100100 – 100699 | Detecciones Zero Trust escritas a mano |
| 100700 – 100799 | Detecciones de cumplimiento escritas a mano |
| 101000 – 101999 | Generadas desde `rules/` por `tools/sigma_to_wazuh.py` |
