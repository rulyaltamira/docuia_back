# docpilot-backend/test_special_chars.py
"""
Script para probar la subida de archivos con caracteres especiales.

Uso: python test_special_chars.py --tenant_id TENANT_ID [--api_url API_URL]
"""

import argparse
import requests
import json
import time
import logging
from datetime import datetime

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger()

# Colores para la terminal
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log_success(message):
    logger.info(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")

def log_failure(message):
    logger.error(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")

def log_section(message):
    logger.info(f"\n{Colors.HEADER}{Colors.BOLD}=== {message} ==={Colors.ENDC}")

def test_upload_special_chars_file(api_url, tenant_id, filename, content):
    """
    Prueba la subida de un archivo con caracteres especiales
    
    Args:
        api_url (str): URL base de la API
        tenant_id (str): ID del tenant
        filename (str): Nombre del archivo con caracteres especiales
        content (str): Contenido del archivo
        
    Returns:
        dict: Resultado de la prueba
    """
    result = {
        "success": False,
        "steps": {}
    }
    
    try:
        # Paso 1: Generar URL para subida
        logger.info(f"Generando URL para subir: {filename}")
        gen_url_response = requests.get(
            f"{api_url}/generate-url",
            params={
                "tenant_id": tenant_id,
                "filename": filename,
                "contentType": "text/plain"
            }
        )
        
        if gen_url_response.status_code != 200:
            logger.error(f"Error generando URL: {gen_url_response.status_code} - {gen_url_response.text}")
            result["steps"]["generate_url"] = {
                "success": False,
                "error": f"Error {gen_url_response.status_code}: {gen_url_response.text}"
            }
            return result
        
        url_data = gen_url_response.json()
        upload_url = url_data.get('upload_url')
        file_id = url_data.get('file_id')
        
        result["steps"]["generate_url"] = {
            "success": True,
            "file_id": file_id
        }
        
        logger.info(f"URL generada con éxito. File ID: {file_id}")
        
        # Paso 2: Subir el archivo
        logger.info(f"Subiendo archivo: {filename}")
        upload_response = requests.put(
            upload_url,
            data=content,
            headers={"Content-Type": "text/plain"}
        )
        
        if upload_response.status_code != 200:
            logger.error(f"Error subiendo archivo: {upload_response.status_code} - {upload_response.text}")
            result["steps"]["upload_file"] = {
                "success": False,
                "error": f"Error {upload_response.status_code}: {upload_response.text}"
            }
            return result
        
        result["steps"]["upload_file"] = {
            "success": True
        }
        
        logger.info("Archivo subido con éxito")
        
        # Paso 3: Confirmar la subida
        logger.info(f"Confirmando subida para file ID: {file_id}")
        confirm_response = requests.post(
            f"{api_url}/confirm-upload",
            json={"file_id": file_id}
        )
        
        if confirm_response.status_code != 200:
            logger.error(f"Error confirmando subida: {confirm_response.status_code} - {confirm_response.text}")
            result["steps"]["confirm_upload"] = {
                "success": False,
                "error": f"Error {confirm_response.status_code}: {confirm_response.text}"
            }
            return result
        
        result["steps"]["confirm_upload"] = {
            "success": True,
            "response": confirm_response.json()
        }
        
        logger.info("Subida confirmada con éxito")
        
        # Dar tiempo para procesamiento
        time.sleep(2)
        
        # Paso 4: Verificar el documento
        logger.info(f"Obteniendo detalles del documento: {file_id}")
        details_response = requests.get(
            f"{api_url}/documents/{file_id}",
            params={"tenant_id": tenant_id}
        )
        
        if details_response.status_code != 200:
            logger.error(f"Error obteniendo detalles: {details_response.status_code} - {details_response.text}")
            result["steps"]["get_details"] = {
                "success": False,
                "error": f"Error {details_response.status_code}: {details_response.text}"
            }
            return result
        
        document = details_response.json().get('document', {})
        stored_filename = document.get('filename')
        
        result["steps"]["get_details"] = {
            "success": True,
            "stored_filename": stored_filename,
            "document": document
        }
        
        logger.info(f"Documento obtenido. Nombre almacenado: {stored_filename}")
        
        # Paso 5: Generar URL de visualización
        logger.info(f"Generando URL de visualización para: {file_id}")
        view_response = requests.get(
            f"{api_url}/documents/{file_id}/view",
            params={"tenant_id": tenant_id}
        )
        
        if view_response.status_code != 200:
            logger.error(f"Error generando URL de visualización: {view_response.status_code} - {view_response.text}")
            result["steps"]["view_url"] = {
                "success": False,
                "error": f"Error {view_response.status_code}: {view_response.text}"
            }
            return result
        
        view_data = view_response.json()
        view_url = view_data.get('view_url')
        
        # Intentar acceder a la URL
        logger.info(f"Accediendo a URL de visualización")
        view_content_response = requests.get(view_url)
        
        if view_content_response.status_code != 200:
            logger.error(f"Error accediendo a URL: {view_content_response.status_code}")
            result["steps"]["access_url"] = {
                "success": False,
                "error": f"Error {view_content_response.status_code}"
            }
            return result
        
        result["steps"]["access_url"] = {
            "success": True,
            "content_length": len(view_content_response.content)
        }
        
        logger.info("URL de visualización accedida con éxito")
        
        # Todo ha sido exitoso
        result["success"] = True
        result["file_id"] = file_id
        
        return result
    
    except Exception as e:
        logger.error(f"Error inesperado: {str(e)}")
        result["error"] = str(e)
        return result

def main():
    parser = argparse.ArgumentParser(description='Prueba la subida de archivos con caracteres especiales')
    parser.add_argument('--tenant_id', required=True, help='ID del tenant para las pruebas')
    parser.add_argument('--api_url', default='https://49b3724c7h.execute-api.eu-west-1.amazonaws.com/dev', 
                        help='URL base de la API')
    parser.add_argument('--filename', default='prueba_año_2023_@#.txt', help='Nombre del archivo con caracteres especiales')
    
    args = parser.parse_args()
    
    log_section("PRUEBA DE MANEJO DE CARACTERES ESPECIALES")
    
    # Lista de archivos con caracteres especiales para probar
    test_files = [
        {"name": args.filename, "content": "Este es un archivo de prueba con caracteres especiales."},
        {"name": "archivo con espacios.txt", "content": "Este archivo tiene espacios en el nombre."},
        {"name": "documento_ñandú.txt", "content": "Documento con letra ñ en el nombre."},
        {"name": "contrato@empresa.txt", "content": "Documento con símbolo @ en el nombre."},
        {"name": "100%_completo.txt", "content": "Documento con símbolo % en el nombre."}
    ]
    
    successful = 0
    failed = 0
    results = []
    
    for test_file in test_files:
        logger.info(f"\nProbando archivo: {test_file['name']}")
        result = test_upload_special_chars_file(
            args.api_url, 
            args.tenant_id, 
            test_file['name'], 
            test_file['content']
        )
        
        results.append({
            "filename": test_file['name'],
            "result": result
        })
        
        if result["success"]:
            log_success(f"Prueba exitosa para {test_file['name']}")
            successful += 1
        else:
            log_failure(f"Prueba fallida para {test_file['name']}")
            failed += 1
    
    # Mostrar resumen
    log_section("RESUMEN")
    logger.info(f"Total de pruebas: {len(test_files)}")
    logger.info(f"Exitosas: {successful}")
    logger.info(f"Fallidas: {failed}")
    
    # Guardar resultados en archivo
    filename = f"special_chars_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Resultados guardados en: {filename}")

if __name__ == "__main__":
    main()