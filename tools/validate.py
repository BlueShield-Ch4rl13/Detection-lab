#!/usr/bin/env python3
"""detection-as-code: valida las reglas Sigma y mide la cobertura ATT&CK.

- Valida cada regla con pySigma (estructura correcta, campos, condicion).
- Extrae las tecnicas MITRE ATT&CK de las etiquetas.
- Genera una capa para ATT&CK Navigator (heatmap de lo que detectamos).
- Imprime un informe de cobertura por tactica y por nivel de severidad.

Uso:
  python tools/validate.py                 # valida + informe + capa navigator
  python tools/validate.py --rules rules   # ruta alternativa de reglas
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

TACTIC_NAMES = {
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
}


def load_rules(rules_dir: Path):
    """Devuelve (reglas_ok, errores) validando con pySigma si esta disponible."""
    files = sorted(rules_dir.rglob("*.yml"))
    ok, errors = [], []
    try:
        from sigma.rule import SigmaRule
        use_sigma = True
    except ImportError:
        import yaml
        use_sigma = False

    for f in files:
        try:
            if use_sigma:
                from sigma.rule import SigmaRule
                rule = SigmaRule.from_yaml(f.read_text(encoding="utf-8"))
                if rule.errors:
                    raise ValueError(rule.errors)
                tags = [f"{t.namespace}.{t.name}" for t in rule.tags]
                ok.append({"file": f, "title": str(rule.title),
                           "level": str(rule.level).lower() if rule.level else "medium",
                           "tags": tags,
                           "product": rule.logsource.product, "category": rule.logsource.category})
            else:
                import yaml
                d = yaml.safe_load(f.read_text(encoding="utf-8"))
                assert "detection" in d and "condition" in d["detection"], "falta detection/condition"
                ls = d.get("logsource", {})
                ok.append({"file": f, "title": d.get("title", f.stem),
                           "level": (d.get("level") or "medium").lower(),
                           "tags": d.get("tags", []),
                           "product": ls.get("product"), "category": ls.get("category")})
        except Exception as exc:
            errors.append((f, str(exc)[:200]))
    return ok, errors


def techniques_from_tags(tags):
    """IDs de tecnica ATT&CK (Txxxx / Txxxx.yyy) a partir de las etiquetas."""
    out = []
    for t in tags:
        name = t.split(".", 1)[1] if t.startswith("attack.") else t
        # subtecnica: t1059.001 -> partes ['t1059','001']
        base = name.split(".")[0]
        if base.startswith("t") and base[1:].isdigit():
            out.append(name.upper())
    return out


def tactics_from_tags(tags):
    out = []
    for t in tags:
        name = t.split(".", 1)[1] if t.startswith("attack.") else t
        if name in TACTIC_NAMES:
            out.append(name)
    return out


def build_navigator(rules, per_tech):
    techniques = []
    maxn = max(per_tech.values()) if per_tech else 1
    for tech, n in sorted(per_tech.items()):
        techniques.append({
            "techniqueID": tech,
            "score": n,
            "color": "",
            "comment": f"{n} regla(s) Sigma",
            "enabled": True,
        })
    return {
        "name": "Cobertura de deteccion - detection-lab",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Tecnicas cubiertas por el catalogo de reglas Sigma de detection-lab (complemento de Infra-SocAnalyst).",
        "sorting": 3,
        "techniques": techniques,
        "gradient": {"colors": ["#12171F", "#4FD6C4"], "minValue": 0, "maxValue": maxn},
        "legendItems": [{"label": "Nº de reglas que cubren la tecnica", "color": "#4FD6C4"}],
        "hideDisabled": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", type=Path, default=Path("rules"))
    ap.add_argument("--out", type=Path, default=Path("navigator/coverage-layer.json"))
    args = ap.parse_args(argv)

    rules, errors = load_rules(args.rules)
    print(f"Reglas validadas: {len(rules)} OK, {len(errors)} con error")
    for f, e in errors:
        print(f"  ✗ {f.name}: {e}")

    per_tech, per_tactic, per_level = Counter(), Counter(), Counter()
    tech_rules = defaultdict(list)
    for r in rules:
        per_level[r["level"]] += 1
        for tech in set(techniques_from_tags(r["tags"])):
            per_tech[tech] += 1
            tech_rules[tech].append(r["title"])
        for tac in set(tactics_from_tags(r["tags"])):
            per_tactic[tac] += 1

    print(f"\nCobertura: {len(per_tech)} tecnicas ATT&CK unicas, {len(per_tactic)} tacticas")
    print("\nPor tactica (kill chain):")
    order = ["initial_access","execution","persistence","privilege_escalation","defense_evasion",
             "credential_access","discovery","lateral_movement","collection","command_and_control",
             "exfiltration","impact"]
    for tac in order:
        if per_tactic.get(tac):
            bar = "█" * per_tactic[tac]
            print(f"  {tac:22} {per_tactic[tac]:2}  {bar}")
    print("\nPor severidad:")
    for lvl in ["critical", "high", "medium", "low"]:
        if per_level.get(lvl):
            print(f"  {lvl:10} {per_level[lvl]}")

    if errors:
        print("\n⚠ Hay reglas con errores de validacion.")

    layer = build_navigator(rules, per_tech)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nCapa ATT&CK Navigator: {args.out} ({len(per_tech)} tecnicas)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
