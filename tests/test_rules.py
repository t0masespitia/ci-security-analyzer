"""
Este archivo contiene pruebas básicas del motor de reglas.
Se hizo para comprobar que el analizador detecta vulnerabilidades conocidas
y también para dejar evidencia de que el proyecto fue probado.
Las pruebas ayudan a demostrar que las reglas no están solo escritas,
sino que realmente funcionan sobre estructuras YAML simuladas.
"""

from analyzer.rules import run_all_rules


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

    rule_ids = [f["rule_id"] for f in findings]
    assert "CICD-TRIGGER-001" in rule_ids
    assert "CICD-TRIGGER-002" not in rule_ids


def test_detects_poisoned_pipeline_execution():
    data = {
        "on": "pull_request_target",
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@v3",
                        "with": {
                            "ref": "${{ github.event.pull_request.head.sha }}"
                        }
                    }
                ]
            }
        }
    }

    findings = run_all_rules(data)

    rule_ids = [f["rule_id"] for f in findings]
    assert "CICD-TRIGGER-002" in rule_ids
    assert "CICD-TRIGGER-001" not in rule_ids
    ppe = next(f for f in findings if f["rule_id"] == "CICD-TRIGGER-002")
    assert ppe["severity"] == "CRITICAL"


def test_detects_poisoned_pipeline_execution_with_head_ref():
    data = {
        "on": {"pull_request_target": None},
        "jobs": {
            "build": {
                "steps": [
                    {
                        "uses": "actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744",
                        "with": {
                            "ref": "${{ github.head_ref }}"
                        }
                    }
                ]
            }
        }
    }

    findings = run_all_rules(data)

    assert any(f["rule_id"] == "CICD-TRIGGER-002" for f in findings)


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


def test_detects_secret_in_run_script():
    data = {"jobs": {"deploy": {"steps": [{"run": "export TOKEN=supersecretvalue123"}]}}}
    findings = run_all_rules(data)
    assert any(f["rule_id"] == "CICD-SECRET-002" for f in findings)


def test_safe_run_script_not_flagged():
    data = {"jobs": {"deploy": {"steps": [{"run": "echo $TOKEN"}]}}}
    findings = run_all_rules(data)
    assert not any(f["rule_id"] == "CICD-SECRET-002" for f in findings)


def test_local_action_not_flagged():
    data = {"jobs": {"build": {"steps": [{"uses": "./my-local-action"}]}}}
    findings = run_all_rules(data)
    assert not any(f["rule_id"] == "CICD-ACTION-001" for f in findings)


def test_detects_container_image_without_digest():
    data = {"jobs": {"build": {"container": "ubuntu:22.04", "steps": []}}}
    findings = run_all_rules(data)
    assert any(f["rule_id"] == "CICD-IMAGE-001" for f in findings)


def test_container_image_with_digest_not_flagged():
    data = {"jobs": {"build": {"container": {"image": "ubuntu@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456ab12"}, "steps": []}}}
    findings = run_all_rules(data)
    assert not any(f["rule_id"] == "CICD-IMAGE-001" for f in findings)


def test_detects_self_hosted_runner_without_isolation():
    data = {"jobs": {"build": {"runs-on": ["self-hosted", "linux"], "steps": []}}}
    findings = run_all_rules(data)
    assert any(f["rule_id"] == "CICD-RUNNER-001" for f in findings)


def test_self_hosted_runner_with_isolation_not_flagged():
    data = {"jobs": {"build": {"runs-on": ["self-hosted", "ephemeral", "linux"], "steps": []}}}
    findings = run_all_rules(data)
    assert not any(f["rule_id"] == "CICD-RUNNER-001" for f in findings)


def test_github_hosted_runner_not_flagged():
    data = {"jobs": {"build": {"runs-on": "ubuntu-latest", "steps": []}}}
    findings = run_all_rules(data)
    assert not any(f["rule_id"] == "CICD-RUNNER-001" for f in findings)
