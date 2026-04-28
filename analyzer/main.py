"""
Este archivo es el punto de entrada principal del proyecto.
Se hizo para que el usuario pueda ejecutar el analizador desde la terminal indicando
la ruta de un archivo YAML de GitHub Actions. El programa carga el YAML, ejecuta las reglas
de seguridad, muestra los hallazgos encontrados y genera un reporte SARIF en la carpeta reports.
"""

import argparse
import os

from parser import load_yaml_file
from rules import run_all_rules
from sarif import generate_sarif


def print_findings(findings):
    """
    Imprime los hallazgos en la terminal de forma clara.
    """
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


def save_text_report(findings, output_path):
    """
    Guarda un reporte de texto para dejar evidencia de ejecución.
    """
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
        "file",
        help="Ruta del archivo YAML que se quiere analizar."
    )

    args = parser.parse_args()

    data = load_yaml_file(args.file)
    findings = run_all_rules(data)

    os.makedirs("reports", exist_ok=True)

    print_findings(findings)
    save_text_report(findings, "reports/scan-output.txt")
    generate_sarif(findings, "reports/results.sarif")

    if findings:
        exit(1)

    exit(0)


if __name__ == "__main__":
    main()