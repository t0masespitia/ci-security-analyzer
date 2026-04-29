# CI Security Analyzer

CI Security Analyzer es una herramienta académica de análisis estático para workflows de GitHub Actions. Revisa archivos `.yml` de pipelines CI/CD y detecta configuraciones inseguras antes de que el pipeline se ejecute.

---

## Requisitos

- Python 3.12 o superior
- pip

---

## Instalación

```bash
git clone https://github.com/t0masespitia/ci-security-analyzer.git
cd ci-security-analyzer
pip install -r requirements.txt
```

---

## Uso

### Analizar el workflow vulnerable

```bash
python -m analyzer.main examples/vulnerable-workflow.yml
```

### Analizar el workflow corregido

```bash
python -m analyzer.main examples/fixed-workflow.yml
```

El workflow corregido no debe producir hallazgos y el programa termina con código de salida `0`.

---

## Cómo interpretar los hallazgos

Cuando el analizador detecta problemas, muestra un bloque por cada hallazgo:

```
Hallazgos encontrados:
------------------------------------------------------------
Regla: CICD-PERM-001
Severidad: HIGH
Título: Permisos write-all detectados
Descripción: El workflow usa permissions: write-all, lo cual entrega permisos amplios al pipeline.
Recomendación: Usar permisos mínimos, por ejemplo contents: read.
------------------------------------------------------------
Regla: CICD-ACTION-001
Severidad: HIGH
Título: Action sin hash fijo
Descripción: La acción 'actions/checkout@v3' en el job 'build' no está fijada a un commit SHA.
Recomendación: Usar un hash de commit completo para reducir riesgos de manipulación.
------------------------------------------------------------
Regla: CICD-SECRET-001
Severidad: CRITICAL
Título: Posible secreto en texto plano
Descripción: La variable 'API_KEY' en 'nivel global' parece contener un secreto sin usar GitHub Secrets.
Recomendación: Guardar valores sensibles en GitHub Secrets y referenciarlos con ${{ secrets.NOMBRE }}.
------------------------------------------------------------
```

Cada hallazgo indica:

- **Regla**: identificador de la regla activada.
- **Severidad**: `CRITICAL`, `HIGH`, `MEDIUM` o `LOW`.
- **Título**: nombre corto del problema.
- **Descripción**: explicación del riesgo detectado.
- **Recomendación**: acción correctiva sugerida.

Además, se generan dos reportes en la carpeta `reports/`:

| Archivo | Descripción |
|---|---|
| `reports/scan-output.txt` | Hallazgos en texto plano |
| `reports/results.sarif` | Hallazgos en formato SARIF (compatible con herramientas de análisis estático) |

El programa termina con código `1` si se encontraron hallazgos, o `0` si el workflow está limpio.

---

## Ejecutar los tests

```bash
pytest
```

---

## Estructura del proyecto

```
ci-security-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── main.py        # Punto de entrada principal
│   ├── parser.py      # Carga y parsea el archivo YAML
│   ├── rules.py       # Reglas de seguridad
│   └── sarif.py       # Generación del reporte SARIF
├── examples/
│   ├── vulnerable-workflow.yml   # Workflow con configuraciones inseguras
│   └── fixed-workflow.yml        # Workflow corregido
├── reports/
│   ├── scan-output.txt
│   └── results.sarif
├── tests/
│   └── test_rules.py
├── requirements.txt
└── README.md
```
