# Consultas de caza — Wazuh / OpenSearch

Escritas a mano; `tools/build.py` no las regenera.

**Distincion importante en Wazuh.** Este SIEM tiene dos superficies y no hacen
lo mismo:

| Superficie | Que es | Donde vive |
|---|---|---|
| **Reglas** (`deploy/wazuh/reglas/`) | Lo que **alerta** en tiempo real, evento a evento | `/var/ossec/etc/rules/` |
| **Consultas** (este fichero) | Lo que **caza** sobre lo ya indexado | Discover del dashboard |

Una consulta Lucene no detecta nada: busca hacia atras. Confundirlas es el error
que este repositorio ya cometio una vez, cuando `deploy/*-wazuh-lucene.txt` se
presentaba como si fueran detecciones.

---

## Inteligencia: las coincidencias que dejaron las reglas 1013xx

Las reglas de `0980-cti_indicadores.xml` registran las coincidencias con las
listas de News CTI en nivel 4 —por debajo del umbral de notificacion— para que
queden indexadas sin llenar la cola. Estas consultas son las que las explotan.

### Todo lo que ha tocado la inteligencia en 24 h

```
rule.groups:cti AND @timestamp:[now-24h TO now]
```

Agrupa en el Discover por `agent.name` y ordena por recuento. Un equipo con
varias coincidencias distintas no es una casualidad de CDN.

### Solo lo que alerto de verdad (hash)

```
rule.id:(101300 OR 101301)
```

### Las correlaciones que si despertaron a alguien

```
rule.id:(101320 OR 101321) AND @timestamp:[now-7d TO now]
```

### Equipos ordenados por numero de indicadores distintos

En el Discover no se puede agregar por cardinalidad; esto va en la consola de
desarrollo del indexador:

```json
POST wazuh-alerts-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term": { "rule.groups": "cti" } },
    { "range": { "@timestamp": { "gte": "now-24h" } } }
  ]}},
  "aggs": {
    "por_equipo": {
      "terms": { "field": "agent.name", "size": 30, "order": { "distintos": "desc" } },
      "aggs": {
        "distintos": { "cardinality": { "field": "rule.id" } },
        "amenazas": { "terms": { "field": "data.amenaza", "size": 10 } }
      }
    }
  }
}
```

---

## Caza sin inteligencia externa

### Binarios poco frecuentes en el parque

```json
POST wazuh-alerts-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term": { "rule.groups": "sysmon_event1" } },
    { "range": { "@timestamp": { "gte": "now-30d" } } }
  ]}},
  "aggs": {
    "binarios": {
      "terms": { "field": "data.win.eventdata.image", "size": 500,
                 "order": { "equipos": "asc" } },
      "aggs": { "equipos": { "cardinality": { "field": "agent.name" } } }
    }
  }
}
```

Filtra despues los que tengan `equipos <= 2`. En un parque homogeneo, un
ejecutable que solo ha visto un equipo en treinta dias merece una mirada.

### Agentes que han dejado de reportar

El silencio de una fuente es una senal, no una ausencia de senal: un agente
detenido es lo primero que hace quien no quiere que le vean.

```
rule.id:503 OR rule.id:502
```

Y para los que simplemente callaron sin desconectarse limpiamente:

```json
POST wazuh-alerts-*/_search
{
  "size": 0,
  "aggs": {
    "agentes": {
      "terms": { "field": "agent.name", "size": 1000 },
      "aggs": { "ultimo": { "max": { "field": "@timestamp" } } }
    }
  }
}
```

Cualquier agente cuyo `ultimo` sea de hace mas de 2 horas esta callado.

### Procesos padre-hijo inusuales

```
rule.groups:sysmon_event1 AND data.win.eventdata.parentImage:(*\\w3wp.exe OR *\\httpd.exe OR *\\nginx.exe OR *\\sqlservr.exe)
```

Un servidor web o de base de datos pariendo un interprete es explotacion en
curso, casi sin excepcion.

### Ejecucion desde rutas escribibles por el usuario

```
rule.groups:sysmon_event1 AND data.win.eventdata.image:(*\\AppData\\Local\\Temp\\* OR *\\Users\\Public\\* OR *\\ProgramData\\*) AND NOT data.win.eventdata.parentImage:*\\msiexec.exe
```

### Autenticaciones fuera de horario

```
rule.groups:authentication_success AND NOT data.win.eventdata.targetUserName:*$ AND @timestamp:[now-7d TO now]
```

Filtra en el Discover por hora del dia. Lo interesante no es el evento suelto,
sino la cuenta que **solo** aparece fuera de horario.

---

## Consultas Lucene de las 127 reglas

Las conversiones a Lucene de toda la biblioteca estan en
`deploy/elastic/reglas/*-lucene.txt`. Sirven igual en el indexador de Wazuh, que
es OpenSearch: pegalas en el Discover para cazar hacia atras una deteccion
concreta antes de desplegarla como regla, que es la forma barata de estimar
cuanto ruido va a generar.
