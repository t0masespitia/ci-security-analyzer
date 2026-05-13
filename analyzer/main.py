"""
Este archivo es el punto de entrada principal del proyecto.
Se hizo para que el usuario pueda ejecutar el analizador desde la terminal indicando
la ruta de un archivo YAML de GitHub Actions. El programa carga el YAML, ejecuta las reglas
de seguridad, muestra los hallazgos encontrados y genera un reporte SARIF en la carpeta reports.
"""

import argparse
import os
from pathlib import Path

from analyzer.parser import load_yaml_file
from analyzer.rules import run_all_rules
from analyzer.sarif import generate_sarif

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def collect_yaml_files(path_str):
    p = Path(path_str)
    if p.is_file():
        return [p]
    if p.is_dir():
        return list(p.rglob("*.yml")) + list(p.rglob("*.yaml"))
    raise FileNotFoundError(f"No existe la ruta: {path_str}")


def print_findings(findings):
    if not findings:
        print("No se encontraron vulnerabilidades en el workflow analizado.")
        return

    print("Hallazgos encontrados:")
    print("-" * 60)

    for finding in findings:
        print(f"Regla: {finding['rule_id']}")
        print(f"Severidad: {finding['severity']}")
        print(f"Título: {finding['title']}")
        print(f"Descripción: {finding['description']}")
        print(f"Recomendación: {finding['recommendation']}")
        print("-" * 60)


def print_summary(all_findings_by_file):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for findings in all_findings_by_file.values():
        for f in findings:
            sev = f.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1

    print("\nResumen de hallazgos:")
    print("-" * 40)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"{sev}: {counts[sev]}")
    print(f"TOTAL: {sum(counts.values())}")


def save_text_report(findings, output_path):
    with open(output_path, "w", encoding="utf-8") as file:
        if not findings:
            file.write("No se encontraron vulnerabilidades en el workflow analizado.\n")
            return

        file.write("Hallazgos encontrados:\n")
        file.write("-" * 60 + "\n")

        for finding in findings:
            file.write(f"Regla: {finding['rule_id']}\n")
            file.write(f"Severidad: {finding['severity']}\n")
            file.write(f"Título: {finding['title']}\n")
            file.write(f"Descripción: {finding['description']}\n")
            file.write(f"Recomendación: {finding['recommendation']}\n")
            file.write("-" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Analizador de seguridad para workflows de GitHub Actions."
    )

    parser.add_argument(
        "path",
        help="Ruta de un archivo YAML o directorio a analizar."
    )

    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Nivel mínimo de severidad que hace fallar el pipeline."
    )

    args = parser.parse_args()

    yaml_files = collect_yaml_files(args.path)
    all_findings_by_file = {}
    all_findings = []

    os.makedirs("reports", exist_ok=True)

    for yaml_file in yaml_files:
        data, raw_text = load_yaml_file(str(yaml_file))
        findings = run_all_rules(data, raw_text)
        all_findings_by_file[str(yaml_file)] = findings
        all_findings.extend(findings)

        print(f"\nArchivo: {yaml_file}")
        print_findings(findings)

    save_text_report(all_findings, "reports/scan-output.txt")
    generate_sarif(all_findings, "reports/results.sarif", workflow_path=str(yaml_files[0]) if yaml_files else None)

    print_summary(all_findings_by_file)

    if args.fail_on == "none":
        exit(0)

    fail_threshold = SEVERITY_ORDER.get(args.fail_on.upper(), 1)
    should_fail = any(
        SEVERITY_ORDER.get(f["severity"], 3) <= fail_threshold
        for findings in all_findings_by_file.values()
        for f in findings
    )

    exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
