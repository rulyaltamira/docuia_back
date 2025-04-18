# docpilot-backend/test_duplicates.py
"""
Script para probar la detección y manejo de documentos duplicados.

Uso: python test_duplicates.py --tenant_id TENANT_ID [--api_url API_URL]
"""

import argparse
import requests
import json
import time
import logging
import hashlib
import base64
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

def test_check_duplicate_by_hash(api_url, tenant_id, content):
    """Prueba la verificación de duplicados mediante hash"""
    logger.info("Verificando duplicado por hash")
    
    # Calcular hash del contenido
    content_bytes = content.encode('utf-8')
    file_hash = hashlib.sha256(content_bytes).hexdigest()
    
    # Verificar si el hash ya existe
    response = requests.post(
        f"{api_url}/documents/check-duplicate",
        json={
            "tenant_id": tenant_id,
            "hash": file_hash
        }
    )
    
    if response.status_code != 200:
        log_failure(f"Error verificando duplicado por hash: {response.status_code} - {response.text}")
        return {
            "success": False,
            "error": f"Error {response.status_code}: {response.text}"
        }
    
    result = response.json()
    logger.info(f"Resultado de verificación de hash {file_hash}: {result}")
    
    return {
        "success": True,
        "is_duplicate": result.get('is_duplicate', False),
        "hash": file_hash,
        "result": result
    }

def test_check_duplicate_by_content(api_url, tenant_id, content):
    """Prueba la verificación de duplicados mediante contenido base64"""
    logger.info("Verificando duplicado por contenido base64")
    
    # Codificar contenido en base64
    content_base64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    
    # Verificar si el contenido ya existe
    response = requests.post(
        f"{api_url}/documents/check-duplicate",
        json={
            "tenant_id": tenant_id,
            "file_content": content_base64
        }
    )
    
    if response.status_code != 200:
        log_failure(f"Error verificando duplicado por contenido: {response.status_code} - {response.text}")
        return {
            "success": False,
            "error": f"Error {response.status_code}: {response.text}"
        }
    
    result = response.json()
    logger.info(f"Resultado de verificación por contenido: {result}")
    
    return {
        "success": True,
        "is_duplicate": result.get('is_duplicate', False),
        "hash": result.get('hash'),
        "result": result
    }

def upload_file(api_url, tenant_id, filename, content):
    """Sube un archivo y devuelve su ID"""
    logger.info(f"Subiendo archivo: {filename}")
    
    # Generar URL para subida
    gen_url_response = requests.get(
        f"{api_url}/generate-url",
        params={
            "tenant_id": tenant_id,
            "filename": filename,
            "contentType": "text/plain"
        }
    )
    
    if gen_url_response.status_code != 200:
        log_failure(f"Error generando URL: {gen_url_response.status_code} - {gen_url_response.text}")
        return {
            "success": False,
            "error": f"Error {gen_url_response.status_code}: {gen_url_response.text}"
        }
    
    url_data = gen_url_response.json()
    upload_url = url_data.get('upload_url')
    file_id = url_data.get('file_id')
    
    # Subir el archivo
    upload_response = requests.put(
        upload_url,
        data=content,
        headers={"Content-Type": "text/plain"}
    )
    
    if upload_response.status_code != 200:
        log_failure(f"Error subiendo archivo: {upload_response.status_code}")
        return {
            "success": False,
            "error": f"Error {upload_response.status_code}"
        }
    
    # Confirmar la subida
    confirm_response = requests.post(
        f"{api_url}/confirm-upload",
        json={"file_id": file_id}
    )
    
    if confirm_response.status_code != 200:
        log_failure(f"Error confirmando subida: {confirm_response.status_code} - {confirm_response.text}")
        return {
            "success": False,
            "error": f"Error {confirm_response.status_code}: {confirm_response.text}"
        }
    
    # Verificar si la respuesta indica que es un duplicado
    is_duplicate = confirm_response.json().get('is_duplicate', False)
    original_doc_id = confirm_response.json().get('original_doc_id')
    
    logger.info(f"Archivo subido con éxito. ID: {file_id}")
    if is_duplicate:
        logger.info(f"El archivo es un duplicado del documento: {original_doc_id}")
    
    return {
        "success": True,
        "file_id": file_id,
        "is_duplicate": is_duplicate,
        "original_doc_id": original_doc_id
    }

def test_handle_duplicate(api_url, tenant_id, duplicate_id, original_id, action="ignore"):
    """Prueba el manejo de un duplicado"""
    logger.info(f"Manejando duplicado: {duplicate_id}, acción: {action}")
    
    # Llamar al endpoint para manejar duplicados
    response = requests.post(
        f"{api_url}/documents/handle-duplicate",
        json={
            "document_id": duplicate_id,
            "original_doc_id": original_id,
            "action": action
        }
    )
    
    if response.status_code != 200:
        log_failure(f"Error manejando duplicado: {response.status_code} - {response.text}")
        return {
            "success": False,
            "error": f"Error {response.status_code}: {response.text}"
        }
    
    result = response.json()
    logger.info(f"Resultado de manejo de duplicado: {result}")
    
    # Verificar estado del documento
    details_response = requests.get(
        f"{api_url}/documents/{duplicate_id}",
        params={"tenant_id": tenant_id}
    )
    
    if details_response.status_code != 200:
        log_failure(f"Error verificando estado del documento: {details_response.status_code}")
        return {
            "success": False,
            "error": f"Error {details_response.status_code}"
        }
    
    document = details_response.json().get('document', {})
    
    return {
        "success": True,
        "action": action,
        "result": result,
        "document": document
    }

def test_verify_document_status(api_url, tenant_id, document_id):
    """Verifica el estado de un documento"""
    logger.info(f"Verificando estado del documento: {document_id}")
    
    # Obtener detalles del documento
    response = requests.get(
        f"{api_url}/documents/{document_id}",
        params={"tenant_id": tenant_id}
    )
    
    if response.status_code != 200:
        log_failure(f"Error obteniendo detalles del documento: {response.status_code} - {response.text}")
        return {
            "success": False,
            "error": f"Error {response.status_code}: {response.text}"
        }
    
    document = response.json().get('document', {})
    logger.info(f"Estado del documento: {document.get('status')}")
    
    return {
        "success": True,
        "document": document
    }

def test_check_stats(api_url, tenant_id):
    """Verifica las estadísticas que incluyen duplicados"""
    logger.info("Verificando estadísticas")
    
    # Obtener estadísticas
    response = requests.get(
        f"{api_url}/stats",
        params={"tenant_id": tenant_id}
    )
    
    if response.status_code != 200:
        log_failure(f"Error obteniendo estadísticas: {response.status_code} - {response.text}")
        return {
            "success": False,
            "error": f"Error {response.status_code}: {response.text}"
        }
    
    stats = response.json()
    
    # Verificar que las estadísticas incluyen duplicados
    if 'duplicateDocuments' in stats:
        log_success("Las estadísticas incluyen información sobre duplicados")
        duplicate_count = stats.get('duplicateDocuments', 0)
        logger.info(f"Número de documentos duplicados: {duplicate_count}")
    else:
        log_failure("Las estadísticas no incluyen información sobre duplicados")
    
    return {
        "success": 'duplicateDocuments' in stats,
        "stats": stats
    }

def main():
    parser = argparse.ArgumentParser(description='Prueba la detección y manejo de documentos duplicados')
    parser.add_argument('--tenant_id', required=True, help='ID del tenant para las pruebas')
    parser.add_argument('--api_url', default='https://49b3724c7h.execute-api.eu-west-1.amazonaws.com/dev', 
                        help='URL base de la API')
    
    args = parser.parse_args()
    
    results = {}
    
    log_section("PRUEBA DE DETECCIÓN DE DUPLICADOS")
    
    # Contenido de prueba único para este test
    test_content = f"Este es un contenido de prueba para detectar duplicados. Timestamp: {datetime.now()}"
    
    # Fase 1: Verificar que el hash no existe (no debería ser duplicado)
    results["check_hash_new"] = test_check_duplicate_by_hash(args.api_url, args.tenant_id, test_content)
    
    # Fase 2: Verificar que el contenido no existe
    results["check_content_new"] = test_check_duplicate_by_content(args.api_url, args.tenant_id, test_content)
    
    # Fase 3: Subir el archivo (debe ser un archivo nuevo)
    upload_result = upload_file(args.api_url, args.tenant_id, "test_duplicado_original.txt", test_content)
    results["upload_original"] = upload_result
    
    if not upload_result["success"]:
        log_failure("No se pudo continuar con las pruebas por error en la subida del archivo original")
        return
    
    original_id = upload_result["file_id"]
    
    # Dar tiempo para que se procese
    time.sleep(2)
    
    # Fase 4: Verificar nuevamente el hash (ahora debería ser duplicado)
    results["check_hash_existing"] = test_check_duplicate_by_hash(args.api_url, args.tenant_id, test_content)
    
    # Fase 5: Verificar nuevamente el contenido (ahora debería ser duplicado)
    results["check_content_existing"] = test_check_duplicate_by_content(args.api_url, args.tenant_id, test_content)
    
    # Fase 6: Subir un duplicado
    duplicate_upload_result = upload_file(args.api_url, args.tenant_id, "test_duplicado_copia.txt", test_content)
    results["upload_duplicate"] = duplicate_upload_result
    
    if not duplicate_upload_result["success"]:
        log_failure("No se pudo continuar con las pruebas por error en la subida del duplicado")
        return
    
    duplicate_id = duplicate_upload_result["file_id"]
    
    # Fase 7: Manejar el duplicado
    if duplicate_upload_result.get("is_duplicate", False):
        handle_result = test_handle_duplicate(
            args.api_url, 
            args.tenant_id, 
            duplicate_id, 
            duplicate_upload_result.get("original_doc_id") or original_id,
            "ignore"
        )
        results["handle_duplicate"] = handle_result
    
    # Fase 8: Verificar que las estadísticas incluyen duplicados
    time.sleep(2)  # Dar tiempo para que se actualicen
    stats_result = test_check_stats(args.api_url, args.tenant_id)
    results["check_stats"] = stats_result
    
    # Fase 9: Subir versión modificada para prueba de manejo como nueva versión
    modified_content = test_content + "\nEsta es una versión actualizada del documento."
    modified_upload_result = upload_file(args.api_url, args.tenant_id, "test_duplicado_version2.txt", modified_content)
    results["upload_modified"] = modified_upload_result
    
    # Mostrar resumen
    log_section("RESUMEN DE PRUEBAS DE DUPLICADOS")
    
    success_count = sum(1 for result in results.values() if result.get("success", False))
    total_count = len(results)
    
    logger.info(f"Total de pruebas: {total_count}")
    logger.info(f"Pruebas exitosas: {success_count}")
    logger.info(f"Pruebas fallidas: {total_count - success_count}")
    
    # Guardar resultados en archivo
    filename = f"duplicate_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Resultados guardados en: {filename}")

if __name__ == "__main__":
    main()