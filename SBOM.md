<!--
Este archivo funciona como un SBOM básico del proyecto.
Se hizo para cumplir con el requisito de inventario tecnológico y control de versiones.
Aquí se documentan las tecnologías, dependencias, versiones y riesgos asociados.
-->

# SBOM - CI Security Analyzer

## 1. Información general

Nombre del proyecto: CI Security Analyzer  
Tipo de proyecto: Analizador estático de seguridad para workflows de GitHub Actions  
Lenguaje principal: Python  
Formato analizado: YAML  
Salida generada: Reporte en terminal, reporte TXT y reporte SARIF  

## 2. Inventario tecnológico

| Componente | Versión | Uso dentro del proyecto | Riesgo asociado |
|---|---:|---|---|
| Python | 3.12 | Lenguaje principal del analizador | Riesgos si se usan versiones sin soporte |
| PyYAML | 6.0.2 | Lectura y parseo de archivos YAML | Riesgos de parseo inseguro si no se usa safe_load |
| pytest | 8.3.3 | Ejecución de pruebas unitarias | Riesgo bajo, se usa solo en desarrollo |
| GitHub Actions | N/A | Integración del analizador en CI | Configuración insegura puede exponer el pipeline |
| SARIF | 2.1.0 | Formato de salida de hallazgos | Riesgo bajo, usado para interoperabilidad |

## 3. Dependencias directas

| Dependencia | Versión | Motivo de uso |
|---|---:|---|
| PyYAML | 6.0.2 | Convertir workflows YAML en estructuras de Python |
| pytest | 8.3.3 | Validar automáticamente las reglas implementadas |

## 4. Controles aplicados

- Uso de versiones exactas en `requirements.txt`.
- Uso de `yaml.safe_load` para evitar carga insegura de objetos.
- Separación del código en módulos.
- Workflow de CI con permisos mínimos `contents: read`.
- Actions fijadas a commit SHA.
- Evidencia de análisis mediante `reports/scan-output.txt` y `reports/results.sarif`.

## 5. Riesgos identificados

| Riesgo | Impacto | Mitigación |
|---|---|---|
| Dependencia vulnerable | Medio | Ejecutar SCA con herramientas como pip-audit |
| Configuración insegura del workflow | Alto | Revisar permisos, triggers y actions externas |
| Secretos expuestos | Crítico | Usar GitHub Secrets y escaneo de secretos |
| Actions sin hash fijo | Alto | Fijar actions a commit SHA |

## 6. Conclusión

El proyecto mantiene un inventario tecnológico básico y controlado.
Las dependencias son pocas, tienen versión definida y cumplen una función clara dentro del analizador.