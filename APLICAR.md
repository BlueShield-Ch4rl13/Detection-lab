# Cómo aplicar esto sobre tu repositorio

Este paquete es la evolución de
[Detection-lab](https://github.com/BlueShield-Ch4rl13/Detection-lab), no un
repositorio nuevo. Está pensado para reemplazar el contenido y conservar el
historial.

## Antes de nada: lee esto

**Se retiran 13 de tus 28 reglas.** No es una limpieza arbitraria: en los 13
casos la regla que se queda contiene la lógica de la retirada, literal o más
amplia. El razonamiento de cada una está en
[`docs/fusion-de-bibliotecas.md`](docs/fusion-de-bibliotecas.md), con las dos
pérdidas de cobertura que se asumen a propósito. Si alguna decisión no te
convence, esa es la lista que hay que discutir antes de aplicar nada.

## Orden

```bash
git clone https://github.com/BlueShield-Ch4rl13/Detection-lab.git
cd Detection-lab
git checkout -b fusion-multi-siem        # nunca directamente sobre main

# 1) Sustituir el contenido por el de este paquete
rm -rf rules deploy tools docs purple navigator
cp -r /ruta/al/paquete/{rules,deploy,tools,docs,purple,navigator,marcos,intel} .
cp /ruta/al/paquete/{README.md,LAB.md,APLICAR.md,requirements.txt} .
cp /ruta/al/paquete/.github/workflows/*.yml .github/workflows/

# 2) Comprobar que todo cuadra antes de commitear
pip install -r requirements.txt
python tools/validate.py             # 127 reglas, 0 errores, 0 incidencias
python tools/build.py                # regenera deploy/*/reglas/ y el mapa purple
python tools/mapear_marcos.py        # remapea a NIST e ISO
python tools/sync_cti.py             # refresca los indicadores desde News CTI

git diff --stat -- 'deploy/*/reglas/' # debe salir vacio: ya estaba al dia

# 3) Commit
git add -A
git commit -m "127 reglas Sigma a cuatro SIEM, con inteligencia CTI y mapeo NIST/ISO"
git push -u origin fusion-multi-siem
```

Abre el pull request y deja que corra el CI antes de fusionar. El workflow
regenera `deploy/` y falla si no coincide con lo commiteado, así que si el paso
2 salió limpio el CI pasará.

## Qué comprobar en el pull request

| Comprobación | Cómo |
|---|---|
| Las 127 reglas validan | `python tools/validate.py` |
| Lo generado está al día | `git diff --stat -- 'deploy/*/reglas/'` vacío tras `build.py` |
| Los IDs de Wazuh no chocan con Infra-SocAnalyst | Series 100xxx a 101399 aquí; las tuyas son 110xxx |
| El mapa purple no cita reglas muertas | Se genera desde `rules/`, no puede |
| El mapeo a NIST/ISO cuadra | `python tools/mapear_marcos.py` y `git diff` vacío |

## Lo que hay que ajustar a tu entorno

Todo lo dependiente del despliegue está en tres ficheros. Ninguna regla Sigma
lleva un índice o una tabla escrita a mano.

| Fichero | Qué ajustar |
|---|---|
| `tools/pipelines/splunk.yml` | Índices y sourcetypes: `endpoint`, `idp`, `email`, `casb`, `k8s`, `proxy`, `web`, `network` |
| `tools/pipelines/sentinel.yml` | Tablas de Proofpoint, Netskope y Kubernetes, marcadas con `AJUSTAR` |
| `deploy/sentinel/consultas/correlaciones.kql` | La tabla de correo y los buzones a excluir |

### Y en el SOC

Este repositorio y **Infra-SocAnalyst** se acoplan por tres puntos. Los tres
están en [`docs/integracion-soc.md`](docs/integracion-soc.md); el resumen:

```bash
# 1) El script de integración, junto al custom-shuffle que ya tienes
sudo cp integracion/wazuh/custom-detectionlab* /var/ossec/integrations/
sudo chmod 750 /var/ossec/integrations/custom-detectionlab*
sudo chown root:wazuh /var/ossec/integrations/custom-detectionlab*

# 2) El bloque <integration> en ossec.conf, con <group>detectionlab</group>

# 3) El nodo ENRUTADOR en Shuffle: pegar integracion/shuffle/enrutador.py
#    en un nodo Execute Python llamado exactamente ENRUTADOR
```

**Sin el paso 1 y 2, las 340 reglas disparan en Wazuh y no abren caso.** Es
justo el fallo que este acoplamiento existe para evitar, y desde el dashboard
de Wazuh parece que todo funciona.

Y después, la guía de cada SIEM: `deploy/wazuh/INSTALAR.md`,
`deploy/splunk/INSTALAR.md`, `deploy/sentinel/INSTALAR.md`,
`deploy/elastic/INSTALAR.md`. Cada una lleva lo suyo, incluidos los bloques
`extend` de Sentinel, que son lo que más se olvida y lo que peor falla: sin
ellos la consulta es válida y **no casa nunca**.

Además, cuatro reglas llevan `midominio.local` como marcador del dominio propio:

```bash
grep -rl "midominio.local" rules/
# rules/correo/soc_mail_002_suplantacion_directivo.yml
# rules/correo/soc_mail_003_fallo_dmarc.yml
# rules/red/soc_net_006_exfiltracion_volumen.yml
# rules/zta/zta_sup_002_paquete_repositorio_no_aprobado.yml
```

## Despliegue en cada SIEM

```bash
# Wazuh
sudo cp deploy/wazuh/*.xml /var/ossec/etc/rules/
sudo /var/ossec/bin/wazuh-logtest -t          # valida sintaxis
sudo systemctl restart wazuh-manager

# Splunk: como app propia, no en search
cp deploy/splunk/savedsearches.conf $SPLUNK_HOME/etc/apps/TA-detection-lab/local/
$SPLUNK_HOME/bin/splunk btool savedsearches list --debug | grep TA-detection-lab
$SPLUNK_HOME/bin/splunk restart

# Sentinel: cada consulta de deploy/sentinel/*.kql es el cuerpo de una regla de
# analitica. Copia primero el bloque `extend` de la cabecera del fichero cuando
# lo haya: sin el, la consulta es valida pero no casa nunca.

# Elastic / indexador de Wazuh: deploy/elastic/*-lucene.txt van al Discover;
# los *-esql.txt, a Elastic con ES|QL.
```

## Los cinco casos que Wazuh no puede expresar

`tools/build.py` los avisa en cada ejecución. Están disponibles en Splunk, y
tres de ellos en Sentinel como KQL escrito a mano. No se han convertido a Wazuh
porque no hay forma honesta de hacerlo: `<frequency>` cuenta disparos de regla,
no valores distintos de un campo.
