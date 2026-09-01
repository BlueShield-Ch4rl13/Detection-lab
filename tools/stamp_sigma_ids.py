#!/usr/bin/env python3
"""
Asigna un identificador UUID estable a cada regla Sigma que no lo tenga.

Sigma exige un campo 'id' unico por regla. Generarlo al azar haria que cada
ejecucion produjese un fichero distinto y ensuciaria el historial de git, asi
que aqui se usa UUIDv5: un hash determinista de la ruta de la regla dentro de
un espacio de nombres propio del proyecto. La misma regla produce siempre el
mismo identificador, y dos reglas distintas nunca colisionan.

Uso: python3 tools/stamp_sigma_ids.py [--check]
"""
import argparse
import sys
import uuid
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SIGMA = RAIZ / "rules"

# Espacio de nombres propio del paquete, derivado a su vez de forma determinista
NS = uuid.uuid5(uuid.NAMESPACE_DNS, "detection-lab.blueshield.local")


def id_para(ruta_relativa: str) -> str:
    return str(uuid.uuid5(NS, ruta_relativa))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true", help="no escribe, solo comprueba")
    args = p.parse_args()

    ficheros = sorted(SIGMA.rglob("*.yml"))
    if not ficheros:
        print("No hay reglas Sigma en sigma/")
        return 1

    sin_id, vistos, colisiones = [], {}, []

    for f in ficheros:
        rel = f.relative_to(RAIZ).as_posix()
        # Un fichero puede contener varios documentos: una regla base y su
        # correlacion. Cada documento necesita su propio id.
        docs = f.read_text(encoding="utf-8").split("\n---\n")
        modificado = False

        for n, doc in enumerate(docs):
            lineas = doc.splitlines(keepends=True)
            idx_id = next((i for i, l in enumerate(lineas) if l.startswith("id:")), None)
            clave = rel if n == 0 else f"{rel}#{n}"
            esperado = id_para(clave)

            if idx_id is None:
                sin_id.append(clave)
                idx_title = next((i for i, l in enumerate(lineas) if l.startswith("title:")), None)
                if idx_title is None:
                    print(f"  SIN TITLE {clave}: no es una regla Sigma valida")
                    return 1
                if not args.check:
                    lineas.insert(idx_title + 1, f"id: {esperado}\n")
                    docs[n] = "".join(lineas)
                    modificado = True
                actual = esperado
            else:
                actual = lineas[idx_id].split(":", 1)[1].strip()

            if actual in vistos:
                colisiones.append((clave, vistos[actual]))
            vistos[actual] = clave

        if modificado:
            f.write_text("\n---\n".join(docs), encoding="utf-8")

    if colisiones:
        for a, b in colisiones:
            print(f"  COLISION de id entre {a} y {b}")
        return 1

    if args.check:
        if sin_id:
            print(f"{len(sin_id)} reglas sin id:")
            for r in sin_id:
                print(f"  {r}")
            return 1
        print(f"{len(ficheros)} reglas Sigma, todas con id unico.")
        return 0

    print(f"{len(ficheros)} reglas Sigma procesadas, {len(sin_id)} ids anadidos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
