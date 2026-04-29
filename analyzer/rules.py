"""
Este archivo contiene las reglas de seguridad del analizador.
Se hizo para identificar configuraciones inseguras dentro de pipelines de GitHub Actions.
Cada regla revisa una parte del YAML y devuelve hallazgos con severidad, descripción y recomendación.
Estas reglas están relacionadas con riesgos como permisos excesivos, uso inseguro de acciones,
eventos peligrosos y exposición de secretos.
"""

import re


def create_finding(rule_id, severity, title, description, recommendation, line=None):
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation
    }
    if line is not None:
        finding["line"] = line
    return finding


def find_line(raw_text, search_string):
    for i, line in enumerate(raw_text.splitlines(), start=1):
        if search_string in line:
            return i
    return None


def check_permissions_write_all(data, raw_text=None):
    findings = []
    permissions = data.get("permissions")

    if permissions == "write-all":
        findings.append(create_finding(
            "CICD-PERM-001",
            "HIGH",
            "Permisos write-all detectados",
            "El workflow usa permissions: write-all, lo cual entrega permisos amplios al pipeline.",
            "Usar permisos mínimos, por ejemplo contents: read.",
            line=find_line(raw_text, "write-all") if raw_text else None
        ))

    if isinstance(permissions, dict):
        for permission_name, permission_value in permissions.items():
            if permission_value == "write":
                findings.append(create_finding(
                    "CICD-PERM-002",
                    "HIGH",
                    "Permiso write detectado",
                    f"El permiso '{permission_name}' está configurado con acceso write.",
                    "Revisar si realmente se necesita write. Si no, cambiarlo a read.",
                    line=find_line(raw_text, f"{permission_name}: write") if raw_text else None
                ))

    return findings


def _has_pull_request_target(trigger):
    if trigger == "pull_request_target":
        return True
    if isinstance(trigger, list) and "pull_request_target" in trigger:
        return True
    if isinstance(trigger, dict) and "pull_request_target" in trigger:
        return True
    return False


def _find_unsafe_pr_ref(data):
    """Returns the dangerous ref string if found, otherwise None."""
    dangerous_refs = ("github.event.pull_request", "github.head_ref")

    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return None

    for job_config in jobs.values():
        for step in job_config.get("steps", []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if not isinstance(uses, str) or not uses.startswith("actions/checkout"):
                continue
            ref = str(step.get("with", {}).get("ref", ""))
            for dangerous in dangerous_refs:
                if dangerous in ref:
                    return dangerous
    return None


def check_pull_request_target(data, raw_text=None):
    findings = []

    if not _has_pull_request_target(data.get("on")):
        return findings

    dangerous_ref = _find_unsafe_pr_ref(data)

    if dangerous_ref:
        findings.append(create_finding(
            "CICD-TRIGGER-002",
            "CRITICAL",
            "Poisoned Pipeline Execution: pull_request_target con checkout inseguro",
            "El workflow usa pull_request_target y hace checkout del código del PR con "
            "github.event.pull_request o github.head_ref, permitiendo que código no confiable "
            "se ejecute con los permisos del repositorio base.",
            "Eliminar el ref al código del PR en el checkout, o reemplazar pull_request_target "
            "por pull_request.",
            line=find_line(raw_text, dangerous_ref) if raw_text else None
        ))
    else:
        findings.append(create_finding(
            "CICD-TRIGGER-001",
            "HIGH",
            "Uso de pull_request_target",
            "El workflow usa pull_request_target, un evento que se ejecuta con los permisos "
            "del repositorio base y puede ser peligroso si se combina con código externo.",
            "Usar pull_request cuando sea posible o asegurarse de no hacer checkout del "
            "código de la rama del PR.",
            line=find_line(raw_text, "pull_request_target") if raw_text else None
        ))

    return findings


def check_unpinned_actions(data, raw_text=None):
    findings = []
    jobs = data.get("jobs", {})

    if not isinstance(jobs, dict):
        return findings

    for job_name, job_config in jobs.items():
        for step in job_config.get("steps", []):
            if not isinstance(step, dict):
                continue

            uses = step.get("uses")
            if not uses:
                continue

            parts = uses.split("@")
            if len(parts) == 2:
                is_sha = bool(re.fullmatch(r"[a-fA-F0-9]{40}", parts[1]))
                if not is_sha:
                    findings.append(create_finding(
                        "CICD-ACTION-001",
                        "HIGH",
                        "Action sin hash fijo",
                        f"La acción '{uses}' en el job '{job_name}' no está fijada a un commit SHA.",
                        "Usar un hash de commit completo para reducir riesgos de manipulación.",
                        line=find_line(raw_text, uses) if raw_text else None
                    ))

    return findings


def check_plaintext_secrets(data, raw_text=None):
    findings = []
    risky_words = ["TOKEN", "SECRET", "PASSWORD", "API_KEY", "ACCESS_KEY"]

    def scan_env(env_data, location):
        if not isinstance(env_data, dict):
            return
        for key, value in env_data.items():
            key_upper = str(key).upper()
            value_text = str(value)
            if any(word in key_upper for word in risky_words):
                if "${{ secrets." not in value_text:
                    findings.append(create_finding(
                        "CICD-SECRET-001",
                        "CRITICAL",
                        "Posible secreto en texto plano",
                        f"La variable '{key}' en '{location}' parece contener un secreto sin usar GitHub Secrets.",
                        "Guardar valores sensibles en GitHub Secrets y referenciarlos con ${{ secrets.NOMBRE }}.",
                        line=find_line(raw_text, str(key)) if raw_text else None
                    ))

    scan_env(data.get("env"), "nivel global")

    jobs = data.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job_config in jobs.items():
            scan_env(job_config.get("env"), f"job {job_name}")
            for index, step in enumerate(job_config.get("steps", [])):
                if isinstance(step, dict):
                    scan_env(step.get("env"), f"job {job_name}, step {index + 1}")

    return findings


def run_all_rules(data, raw_text=None):
    findings = []
    findings.extend(check_permissions_write_all(data, raw_text))
    findings.extend(check_pull_request_target(data, raw_text))
    findings.extend(check_unpinned_actions(data, raw_text))
    findings.extend(check_plaintext_secrets(data, raw_text))
    return findings