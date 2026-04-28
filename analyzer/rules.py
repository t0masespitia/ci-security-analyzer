"""
Este archivo contiene las reglas de seguridad del analizador.
Se hizo para identificar configuraciones inseguras dentro de pipelines de GitHub Actions.
Cada regla revisa una parte del YAML y devuelve hallazgos con severidad, descripción y recomendación.
Estas reglas están relacionadas con riesgos como permisos excesivos, uso inseguro de acciones,
eventos peligrosos y exposición de secretos.
"""

import re


def create_finding(rule_id, severity, title, description, recommendation):
    """
    Crea un hallazgo con una estructura uniforme.
    """
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation
    }


def check_permissions_write_all(data):
    """
    Detecta si el pipeline usa permissions: write-all.
    Esto es riesgoso porque otorga permisos amplios al token del pipeline.
    """
    findings = []

    permissions = data.get("permissions")

    if permissions == "write-all":
        findings.append(create_finding(
            "CICD-PERM-001",
            "HIGH",
            "Permisos write-all detectados",
            "El workflow usa permissions: write-all, lo cual entrega permisos amplios al pipeline.",
            "Usar permisos mínimos, por ejemplo contents: read."
        ))

    if isinstance(permissions, dict):
        for permission_name, permission_value in permissions.items():
            if permission_value == "write":
                findings.append(create_finding(
                    "CICD-PERM-002",
                    "HIGH",
                    "Permiso write detectado",
                    f"El permiso '{permission_name}' está configurado con acceso write.",
                    "Revisar si realmente se necesita write. Si no, cambiarlo a read."
                ))

    return findings


def check_pull_request_target(data):
    """
    Detecta el uso del evento pull_request_target.
    Este evento puede ser peligroso si se combina con código externo o checkout inseguro.
    """
    findings = []

    trigger = data.get("on")

    if trigger == "pull_request_target":
        findings.append(create_finding(
            "CICD-TRIGGER-001",
            "CRITICAL",
            "Uso de pull_request_target",
            "El workflow se ejecuta con pull_request_target, un evento sensible en GitHub Actions.",
            "Usar pull_request cuando sea posible o restringir cuidadosamente el workflow."
        ))

    if isinstance(trigger, list) and "pull_request_target" in trigger:
        findings.append(create_finding(
            "CICD-TRIGGER-001",
            "CRITICAL",
            "Uso de pull_request_target",
            "El workflow incluye pull_request_target dentro de sus eventos.",
            "Evitar este evento si el pipeline ejecuta código de contribuciones externas."
        ))

    if isinstance(trigger, dict) and "pull_request_target" in trigger:
        findings.append(create_finding(
            "CICD-TRIGGER-001",
            "CRITICAL",
            "Uso de pull_request_target",
            "El workflow tiene configurado pull_request_target.",
            "Validar estrictamente qué código se ejecuta y evitar checkout de ramas no confiables."
        ))

    return findings


def check_unpinned_actions(data):
    """
    Detecta acciones usadas con tags o ramas en vez de hashes de commit.
    Usar actions/checkout@v3 es menos seguro que fijar la acción a un commit SHA.
    """
    findings = []
    jobs = data.get("jobs", {})

    if not isinstance(jobs, dict):
        return findings

    for job_name, job_config in jobs.items():
        steps = job_config.get("steps", [])

        for step in steps:
            if not isinstance(step, dict):
                continue

            uses = step.get("uses")

            if uses:
                parts = uses.split("@")

                if len(parts) == 2:
                    version = parts[1]

                    is_sha = bool(re.fullmatch(r"[a-fA-F0-9]{40}", version))

                    if not is_sha:
                        findings.append(create_finding(
                            "CICD-ACTION-001",
                            "HIGH",
                            "Action sin hash fijo",
                            f"La acción '{uses}' en el job '{job_name}' no está fijada a un commit SHA.",
                            "Usar un hash de commit completo para reducir riesgos de manipulación."
                        ))

    return findings


def check_plaintext_secrets(data):
    """
    Detecta posibles secretos escritos directamente en variables env.
    No es una detección perfecta, pero ayuda a encontrar malas prácticas evidentes.
    """
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
                        "Guardar valores sensibles en GitHub Secrets y referenciarlos con ${{ secrets.NOMBRE }}."
                    ))

    scan_env(data.get("env"), "nivel global")

    jobs = data.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job_config in jobs.items():
            scan_env(job_config.get("env"), f"job {job_name}")

            steps = job_config.get("steps", [])
            for index, step in enumerate(steps):
                if isinstance(step, dict):
                    scan_env(step.get("env"), f"job {job_name}, step {index + 1}")

    return findings


def run_all_rules(data):
    """
    Ejecuta todas las reglas de seguridad sobre el YAML cargado.
    """
    findings = []

    findings.extend(check_permissions_write_all(data))
    findings.extend(check_pull_request_target(data))
    findings.extend(check_unpinned_actions(data))
    findings.extend(check_plaintext_secrets(data))

    return findings