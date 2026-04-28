"""
Este archivo contiene pruebas básicas del motor de reglas.
Se hizo para comprobar que el analizador detecta vulnerabilidades conocidas
y también para dejar evidencia de que el proyecto fue probado.
Las pruebas ayudan a demostrar que las reglas no están solo escritas,
sino que realmente funcionan sobre estructuras YAML simuladas.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "analyzer")))

from rules import run_all_rules


def test_detects_write_all_permissions():
    data = {
        "permissions": "write-all",
        "jobs": {}
    }

    findings = run_all_rules(data)

    assert any(finding["rule_id"] == "CICD-PERM-001" for finding in findings)


def test_detects_pull_request_target():
    data = {
        "on": "pull_request_target",
        "jobs": {}
    }

    findings = run_all_rules(data)

    assert any(finding["rule_id"] == "CICD-TRIGGER-001" for finding in findings)


def test_detects_unpinned_action():
    data = {
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3"
                    }
                ]
            }
        }
    }

    findings = run_all_rules(data)

    assert any(finding["rule_id"] == "CICD-ACTION-001" for finding in findings)


def test_detects_plaintext_secret():
    data = {
        "env": {
            "API_KEY": "123456"
        },
        "jobs": {}
    }

    findings = run_all_rules(data)

    assert any(finding["rule_id"] == "CICD-SECRET-001" for finding in findings)


def test_secure_workflow_has_no_findings():
    data = {
        "on": "pull_request",
        "permissions": {
            "contents": "read"
        },
        "env": {
            "API_KEY": "${{ secrets.API_KEY }}"
        },
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744"
                    }
                ]
            }
        }
    }

    findings = run_all_rules(data)

    assert len(findings) == 0