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
cp -r /ruta/al/paquete/{rules,deploy,tools,docs,purple,navigator,marcos} .
cp /ruta/al/paquete/{README.md,LAB.md,requirements.txt} .
cp /ruta/al/paquete/.github/workflows/validate.yml .github/workflows/

# 2) Comprobar que todo cuadra antes de commitear
pip install -r requirements.txt
python tools/validate.py          # 87 reglas, 0 errores, 0 incidencias
python tools/build.py             # regenera deploy/ y purple/atomic-map.md
git diff --stat -- deploy/        # debe salir vacio: ya estaba al dia

# 3) Commit
git add -A
git commit -m "Fusion multi-SIEM: 87 reglas Sigma a Splunk, Sentinel, Wazuh y Elastic"
git push -u origin fusion-multi-siem
```

Abre el pull request y deja que corra el CI antes de fusionar. El workflow
regenera `deploy/` y falla si no coincide con lo commiteado, así que si el paso
2 salió limpio el CI pasará.

## Qué comprobar en el pull request

| Comprobación | Cómo |
|---|---|
| Las 87 reglas validan | `python tools/validate.py` |
| `deploy/` está al día | `git diff --stat -- deploy/` vacío tras `build.py` |
| Los IDs de Wazuh no chocan con Infra-SocAnalyst | Series 100xxx y 101xxx aquí; las tuyas son 110xxx |
| El mapa purple no cita reglas muertas | Se genera desde `rules/`, no puede |

## Lo que hay que ajustar a tu entorno

Todo lo dependiente del despliegue está en tres ficheros. Ninguna regla Sigma
lleva un índice o una tabla escrita a mano.

| Fichero | Qué ajustar |
|---|---|
| `tools/pipelines/splunk.yml` | Índices y sourcetypes: `endpoint`, `idp`, `email`, `casb`, `k8s`, `proxy`, `web`, `network` |
| `tools/pipelines/sentinel.yml` | Tablas de Proofpoint, Netskope y Kubernetes, marcadas con `AJUSTAR` |
| `deploy/sentinel/correlaciones.kql` | La tabla de correo y los buzones a excluir |

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
