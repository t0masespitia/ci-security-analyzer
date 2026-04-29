"""
Este archivo se encarga de leer archivos YAML de pipelines CI/CD.
Se hizo para separar la lectura del archivo de la lógica de seguridad.
Así el proyecto queda más ordenado: este archivo solo abre, valida y convierte el YAML
en una estructura de Python que después puede ser revisada por las reglas.
"""

import yaml


def load_yaml_file(file_path):
    """
    Lee un archivo YAML y devuelve (contenido_parseado, texto_crudo).
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            raw_text = file.read()

        content = yaml.safe_load(raw_text)

        if content is None:
            return {}, ""

        return content, raw_text

    except FileNotFoundError:
        raise FileNotFoundError(f"No se encontró el archivo: {file_path}")

    except yaml.YAMLError as error:
        raise ValueError(f"El archivo YAML tiene errores de sintaxis: {error}")