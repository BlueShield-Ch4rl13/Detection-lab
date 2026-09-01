# Esquema de los playbooks de respuesta

Un playbook por familia de regla. El SOAR lo lee, no lo interpreta una persona:
el campo `playbook=` que viaja en la alerta de Wazuh es el que selecciona el
fichero.

## La idea de fondo

**No se puede automatizar la gestión de cualquier alerta.** Lo que sí se puede
es partir cada alerta en pasos, y automatizar sólo los pasos cuyo peor
resultado sea aceptable.

El coste de equivocarse no es simétrico:

| Acción | Peor caso si se equivoca |
|---|---|
| Enriquecer con inteligencia | Se gasta una consulta a la API |
| Recoger evidencia | Se ocupa disco |
| Cerrar como benigno | **Se pierde un incidente real** |
| Aislar un endpoint | Alguien se queda sin trabajar 20 minutos |
| Deshabilitar una cuenta | **Se corta el acceso a quien no debía** |
| Bloquear una IP en el perímetro | **Se corta un servicio a los clientes** |

Por eso los cuatro primeros se automatizan y los dos últimos no, aunque
técnicamente el SOAR pueda hacerlos igual de fácil.

## Los cuatro niveles

Cada regla declara el suyo. Va en el grupo de la regla de Wazuh y el script de
integración lo lee.

| Nivel | Se dispara con | Qué pasa sin persona |
|---|---|---|
| `auto_cierre` | Sigma `informational` | Se registra en Wazuh y se descarta. No sale a la red. |
| `auto_enriq` | Sigma `low` | Se enriquece, se escribe la alerta en TheHive y se cierra si cumple `cierre_automatico`. Sin LLM, sin aviso. |
| `auto_analisis` | Sigma `medium` y `high` | Enriquecimiento, análisis con Ollama, caso en TheHive, aviso en Discord. |
| `auto_contener` | Sigma `critical` | Lo anterior, más las acciones de `contencion` y aviso inmediato. |

## Estructura del fichero

```yaml
familia: ad                     # coincide con el campo playbook= de la alerta
nombre: Active Directory
descripcion: |
    Qué cubre esta familia y qué la distingue en el triaje.

enriquecimiento:                # siempre, en cualquier nivel
  - fuente: cti_local           # las listas de intel/listas/
    sobre: [ip, dominio, hash]
  - fuente: inventario
    sobre: [agente]

evidencia:                      # lo que se recoge solo, antes de que llegue nadie
  - descripcion: Qué se recoge
    comando: El comando concreto
    donde: agente | manager | siem

triaje:                         # preguntas que decide el SOAR, no una persona
  - pregunta: ¿El origen está en la lista de administración?
    fuente: lookup
    si_afirmativo: bajar_severidad

cierre_automatico:              # condiciones para cerrar sin analista
  - condicion: Descripción exacta
    justificacion: Por qué es seguro cerrar aquí

contencion:                     # sólo en auto_contener
  - accion: Qué se hace
    alcance: Qué toca y qué no
    reversible: si | no
    requiere_aprobacion: si | no
    justificacion: Por qué es aceptable hacerlo solo

requiere_persona:               # lo que NO se automatiza, y el motivo
  - situacion: Cuándo
    motivo: Por qué no puede decidirlo una máquina

escalado:
  a: L2 | L3 | guardia
  plazo_min: 15
```

## Regla de oro

Lo que decide si una acción se automatiza no es sólo si se puede deshacer:
es **radio de impacto × reversibilidad**.

|  | Reversible | Irreversible |
|---|---|---|
| **Radio de un proceso o un equipo** | Automática | Automática si el objetivo está identificado sin ambigüedad |
| **Radio de una cuenta, un servicio o el perímetro** | Aprobación | Aprobación, siempre |

El caso que obliga a decirlo así es **matar un proceso**. Técnicamente es
irreversible —no se des-mata— y aun así seis playbooks lo automatizan. La razón
es que el objetivo va identificado por `ProcessGuid`, o por PID *más hora de
arranque*: no hay forma de que la acción caiga sobre otra cosa, y si la
detección era un falso positivo el daño es un proceso que hay que relanzar.

Frente a eso, bloquear una IP en el cortafuegos perimetral **sí** es reversible
y aun así lleva aprobación: el radio es toda la organización, y una IP mal
bloqueada corta un servicio a clientes que no se enteran de por qué.

`tools/validar_respuesta.py` comprueba que ninguna acción con radio amplio esté
marcada como automática. Es la línea que separa un SOC automatizado de uno que
se pega un tiro en el pie, y conviene que la vigile un script y no la memoria.

## Unos detalles de los ficheros YAML

`reversible: no` sin comillas **no es la cadena "no": es el booleano `False`**.
`si` sin comillas sí se queda como cadena. Esa asimetría hace que un enrutador
que compare contra `"no"` trate todo como si necesitara aprobación, o al revés
según cómo esté escrita la comparación, y en los dos casos falla en silencio.

Por eso los valores van entrecomillados en los playbooks y el enrutador
normaliza antes de comparar.
