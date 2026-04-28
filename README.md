# ci-security-analyzer

## Cómo se usa

El uso principal del proyecto es analizar un archivo YAML de GitHub Actions para identificar configuraciones inseguras.

1. Clonar el repositorio

```bash
git clone https://github.com/t0masespitia/ci-security-analyzer.git
cd ci-security-analyzer
2. Instalar dependencias
pip install -r requirements.txt
3. Analizar un workflow vulnerable
python analyzer/main.py examples/vulnerable-workflow.yml

Este comando ejecuta el analizador sobre un archivo de ejemplo que contiene configuraciones inseguras.

4. Interpretar el resultado

Si el workflow tiene problemas, la herramienta muestra hallazgos como:

Regla: CICD-PERM-001
Severidad: HIGH
Título: Permisos write-all detectados
Descripción: El workflow usa permissions: write-all.
Recomendación: Usar permisos mínimos, por ejemplo contents: read.

Cada hallazgo indica:

La regla detectada.
La severidad del problema.
Una explicación del riesgo.
Una recomendación de corrección.
5. Analizar el workflow corregido
python analyzer/main.py examples/fixed-workflow.yml

Este segundo comando sirve para validar que las configuraciones inseguras fueron corregidas.

6. Revisar los reportes generados

Después de ejecutar el analizador, se generan reportes en la carpeta:

reports/

Los archivos principales son:

reports/scan-output.txt
reports/results.sarif

scan-output.txt muestra los hallazgos en texto plano.

results.sarif guarda los hallazgos en formato SARIF, que es usado por herramientas de análisis estático.

7. Ejecutar pruebas
pytest

Este comando ejecuta las pruebas unitarias para verificar que las reglas del analizador funcionan correctamente.


Y en el inicio del README pon esto:

```markdown
# CI Security Analyzer

CI Security Analyzer es una herramienta académica de análisis estático para workflows de GitHub Actions.

Su uso principal es revisar archivos `.yml` de pipelines CI/CD y detectar configuraciones inseguras antes de que el pipeline se ejecute.