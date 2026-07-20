# 🛡️ detection-lab — Detection Engineering + Purple Team

Catálogo de detecciones **como código** (Sigma) con validación automática,
conversión multi-SIEM y un bucle **purple team** (Atomic Red Team) que mide la
cobertura **MITRE ATT&CK**. Complementa a
[Infra-SocAnalyst](https://github.com/BlueShield-Ch4rl13/Infra-SocAnalyst): aquel
es la *plataforma* SOC (Wazuh, sensores, SOAR); **este es el contenido de
detección y su validación**.

## Por qué existe (y qué NO repite)

`Infra-SocAnalyst` ya aporta la infraestructura (Proxmox, pfSense, Wazuh XDR,
Tetragon/Falco/Suricata, SOAR) y una cadena de ataque Linux. Su "trabajo futuro"
pedía **emulación de adversario (Atomic Red Team)**. Este proyecto lo entrega y
además:

- Escribe las detecciones en **Sigma** (portable, no atado a un SIEM) en vez de
  reglas Wazuh sueltas.
- Amplía la cobertura a **Windows/Sysmon** (la demo actual es solo Linux).
- Añade **medición de cobertura ATT&CK** (heatmap en Navigator).
- Formaliza el ciclo **detection-as-code**: validar → convertir → emular → afinar.

## Qué hay dentro

| Carpeta | Contenido |
|---|---|
| `rules/windows/` | Reglas Sigma para telemetría **Sysmon** (18) |
| `rules/linux/` | Reglas Sigma para **auditd/Falco** (10) |
| `tools/validate.py` | Valida las reglas, mide cobertura y genera la capa Navigator |
| `navigator/` | Capa JSON de cobertura para **ATT&CK Navigator** |
| `deploy/` | Reglas ya convertidas a **Wazuh(Lucene)/Splunk/ES\|QL** |
| `purple/atomic-map.md` | Mapeo técnica ↔ **Atomic Red Team** ↔ regla ↔ telemetría |
| `LAB.md` | Cómo montar el bucle purple team sobre tu Wazuh |

**Cobertura actual**: 28 reglas → **25 técnicas ATT&CK** en 7 tácticas
(ejecución, persistencia, evasión, acceso a credenciales, C2, impacto, acceso inicial).

## Uso

```bash
pip install -r requirements.txt          # sigma-cli + pySigma + backends

# 1) Validar reglas y medir cobertura (genera la capa Navigator)
python tools/validate.py

# 2) Convertir a tu SIEM
sigma convert -t lucene -p sysmon rules/windows/    # Wazuh / OpenSearch
sigma convert -t splunk -p sysmon rules/windows/    # Splunk
sigma convert -t esql   -p sysmon rules/windows/    # Elastic ES|QL

# 3) Emular y validar (en el lab): ver purple/atomic-map.md y LAB.md
Invoke-AtomicTest T1059.001
```

Sube `navigator/coverage-layer.json` a
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) para ver el heatmap.

## Formato de una regla (ejemplo)

```yaml
title: PowerShell con comando codificado
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ['-enc', '-EncodedCommand']
  condition: selection
level: high
```

## El ciclo completo del portfolio

```
News CTI (IOCs) → detection-lab (detecciones) → Infra-SocAnalyst (Wazuh+SOAR) → ftriage (DFIR)
```

## Seguridad

Las pruebas de Atomic Red Team se ejecutan **solo en el laboratorio aislado** y se
revierten con `-Cleanup`. Las reglas son de detección (defensivas). Uso académico
y de respuesta a incidentes.

## Licencia

MIT.
