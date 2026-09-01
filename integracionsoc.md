# Integración con el SOC

Este repositorio produce **contenido de detección**. El SOC que lo ejecuta es
[Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst):
Wazuh, sensores, Shuffle, TheHive, Ollama y Discord sobre Proxmox.

```
Detection-lab                          Infra-SocAnalyst
─────────────                          ────────────────
rules/*.yml                            Wazuh Manager (VLAN 30)
    │  build.py                             │
    ▼                                       │ alerta nivel >= 5
deploy/wazuh/reglas/*.xml ─────────────────►│ grupo "detectionlab"
                                            │
respuesta/playbooks/*.yml                   ▼
    │  generar_enrutador.py         custom-detectionlab.py
    ▼                                       │
integracion/shuffle/enrutador.py ──────────►│ Shuffle
                                            ├─► ENRUTADOR (decide)
intel/listas/ ─────────────────────────────►├─► enriquecimiento (MISP, CTI local)
                                            ├─► Ollama (solo si la clase lo pide)
                                            ├─► TheHive (caso, severidad correcta)
                                            └─► Discord
```

---

## Tres cosas que estaban rotas entre los dos repositorios

No se ven mirando uno solo. Salieron al poner los dos delante.

### 1. El 99 % de las detecciones no llegaba al SOAR

`custom-shuffle.py` de Infra-SocAnalyst filtra por los grupos
`falco,tetragon,suricata,ids`. Las 340 reglas de Wazuh que genera este
repositorio llevan `soc_sigma`, `soc_edr`, `zta_*`… **336 de ellas no
coincidían con ninguno de esos cuatro grupos.**

El efecto no era que fallaran: era que **disparaban en Wazuh y no abrían caso**.
Visibles en el dashboard, sin llegar a nadie. Es el peor sitio donde puede
quedarse una detección, porque desde el dashboard parece que funciona.

**Arreglo:** todas las reglas generadas llevan ahora el grupo `detectionlab`, y
hay un script de integración propio que filtra por él. Convive con el
existente: aquel sigue atendiendo a Falco, Tetragon y Suricata.

### 2. La severidad se aplastaba en TheHive

El nodo `IOC PYTHON` mapea nivel de Wazuh a severidad de TheHive con el umbral
superior en `>= 12`. En este repositorio, `high` **también** es nivel 12 —lo fija
el conversor de Sigma a Wazuh— así que 219 de 260 reglas habrían aterrizado como
severidad 4.

Una cola donde el 84 % es crítico no está priorizada: está desordenada con más
pasos.

**Arreglo:** la severidad se calcula del nivel **Sigma** original, no del nivel
Wazuh, y viaja en el campo `<info>` de cada regla:

| Sigma | Wazuh | TheHive |
|---|---|---|
| `critical` | 14 | 4 |
| `high` | 12 | **3** |
| `medium` | 8 | 2 |
| `low` | 5 | 1 |
| `informational` | 0 | no sale |

### 3. Ollama se habría ahogado

El README del SOC ya avisa: *«Un umbral demasiado bajo satura Ollama (CPU-bound)
y genera backlog en Shuffle»*. Con 127 detecciones activas eso deja de ser un
riesgo teórico y pasa a ser aritmética.

**Arreglo, en dos partes:**

- **Sólo las clases `auto_analisis` y `auto_contener` van al LLM.** Las de
  `auto_cierre` no salen del manager; las de `auto_enriq` se enriquecen y se
  encolan sin pasar por Ollama.
- **Limitador por regla y agente**: 5 alertas por ventana de 5 minutos. Un
  proceso en bucle genera cientos de alertas idénticas; sin esto, todas irían al
  LLM. La misma regla en otro equipo cuenta aparte, porque son dos incidentes.

---

## Instalación en el manager de Wazuh

```bash
sudo cp integracion/wazuh/custom-detectionlab.py /var/ossec/integrations/
sudo cp integracion/wazuh/custom-detectionlab    /var/ossec/integrations/
sudo chmod 750 /var/ossec/integrations/custom-detectionlab*
sudo chown root:wazuh /var/ossec/integrations/custom-detectionlab*
```

En `ossec.conf`, **junto al bloque de `custom-shuffle` que ya existe**, sin
tocarlo:

```xml
<integration>
  <name>custom-detectionlab</name>
  <hook_url>https://HOST_SOC:3443/api/v1/hooks/webhook_XXXX</hook_url>
  <group>detectionlab</group>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

`<level>5</level>` no significa que todo lo de nivel 5 despierte a alguien:
significa que llega al script, y el script decide. Las de `auto_cierre` se
registran y se descartan sin salir a la red.

## En Shuffle

1. Crear un workflow nuevo (o clonar el existente) con su propio webhook.
2. Primer nodo: **Execute Python**, nombre exactamente `ENRUTADOR`, y pegar
   `integracion/shuffle/enrutador.py`.
3. Los nodos siguientes leen `$enrutador.*`:

| Campo | Para qué |
|---|---|
| `$enrutador.usar_llm` | Condición del nodo de Ollama |
| `$enrutador.severidad` | Severidad de la alerta en TheHive |
| `$enrutador.crear_caso` | Condición del nodo de TheHive |
| `$enrutador.notificar` | Condición del nodo de Discord |
| `$enrutador.contencion_automatica` | Acciones a ejecutar sin preguntar |
| `$enrutador.contencion_en_espera` | Acciones a escribir en el caso, sin ejecutar |
| `$enrutador.escalar_a` / `plazo_min` | A quién y en cuánto tiempo |

> **El nodo lleva la tabla de playbooks embebida.** Un nodo Python de Shuffle no
> lee ficheros del repositorio. Cuando cambies un playbook, `tools/build.py`
> regenera el nodo, pero hay que **volver a pegarlo en Shuffle**.
> `tools/validate.py` avisa si el nodo es más viejo que los playbooks.

## Convivencia de las series de reglas

| Serie | Origen |
|---|---|
| 100100 – 100799 | Zero Trust y cumplimiento, escritas a mano aquí |
| 101000 – 101299 | Generadas desde `rules/` |
| 101300 – 101399 | Inteligencia de News CTI |
| **110xxx** | **Reglas propias de Infra-SocAnalyst — no se tocan** |

Sin solape. Comprobación antes de desplegar:

```bash
grep -ho 'rule id="[0-9]*"' /var/ossec/etc/rules/*.xml \
  | grep -o '[0-9]*' | sort -n | uniq -d
```

## Lo que este repositorio no aporta al SOC

- **La plataforma.** Wazuh, Shuffle, TheHive, MISP y Ollama los monta el otro.
- **Los sensores.** Falco, Tetragon y Suricata son suyos, y sus reglas
  (`110xxx`) siguen funcionando igual.
- **El bloqueo en kernel.** Las TracingPolicy de eBPF son del otro repositorio.
  Aquí la contención llega hasta aislar el equipo o matar el proceso; matar en
  el kernel antes de que el `execve` termine es otra capa.
