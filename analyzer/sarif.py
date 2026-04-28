"""
Este archivo genera un reporte en formato SARIF.
Se hizo porque SARIF es un formato usado por herramientas de análisis estático
y permite presentar los hallazgos de forma más técnica y compatible con plataformas como GitHub.
En este proyecto se usa para demostrar que el analizador no solo imprime resultados,
sino que también puede producir evidencia estructurada.
"""

import json


def generate_sarif(findings, output_path):
    """
    Genera un archivo SARIF básico con los hallazgos encontrados.
    """
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CI Security Analyzer",
                        "informationUri": "https://github.com/t0masespitia/ci-security-analyzer",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    added_rules = set()

    for finding in findings:
        rule_id = finding["rule_id"]

        if rule_id not in added_rules:
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "name": finding["title"],
                "shortDescription": {
                    "text": finding["title"]
                },
                "fullDescription": {
                    "text": finding["description"]
                },
                "help": {
                    "text": finding["recommendation"]
                }
            })

            added_rules.add(rule_id)

        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": map_severity_to_sarif_level(finding["severity"]),
            "message": {
                "text": f"{finding['title']}: {finding['description']}"
            }
        })

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(sarif, file, indent=2, ensure_ascii=False)


def map_severity_to_sarif_level(severity):
    """
    Convierte la severidad interna del proyecto a niveles compatibles con SARIF.
    """
    if severity == "CRITICAL":
        return "error"

    if severity == "HIGH":
        return "error"

    if severity == "MEDIUM":
        return "warning"

    return "note"