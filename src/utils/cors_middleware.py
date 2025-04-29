# docpilot-backend/src/utils/cors_middleware.py
"""
Middleware para asegurar encabezados CORS en todas las respuestas API.
Proporciona funciones de utilidad para aplicar encabezados CORS consistentes.
"""

import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def add_cors_headers(headers=None):
    """
    Añade encabezados CORS a un diccionario de cabeceras existente o nuevo.
    
    Args:
        headers (dict, optional): Diccionario de cabeceras existente
        
    Returns:
        dict: Diccionario con encabezados CORS añadidos
    """
    if headers is None:
        headers = {}
    
    # Añadir encabezados CORS estándar con x-tenant-id incluido
    cors_headers = {
        'Access-Control-Allow-Origin': '*',  # Permite cualquier origen - ajustar en producción
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Requested-With,x-tenant-id',
        'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,PATCH,DELETE'
    }
    
    # Combinar con encabezados existentes
    return {**headers, **cors_headers}

def cors_wrapper(func):
    """
    Decorador para añadir encabezados CORS a respuestas de funciones Lambda.
    
    Args:
        func (function): Función Lambda a envolver
        
    Returns:
        function: Función Lambda con soporte CORS añadido
    """
    def wrapper(event, context):
        # Verificar si es una solicitud OPTIONS (preflight request)
        if event.get('httpMethod') == 'OPTIONS':
            logger.info("Manejando solicitud preflight OPTIONS")
            return {
                'statusCode': 200,
                'headers': add_cors_headers(),
                'body': ''
            }
        
        # Ejecutar la función original
        response = func(event, context)
        
        # Verificar que la respuesta tenga la estructura esperada
        if isinstance(response, dict) and 'headers' in response:
            # Añadir encabezados CORS a la respuesta existente
            response['headers'] = add_cors_headers(response['headers'])
        elif isinstance(response, dict) and 'statusCode' in response:
            # La respuesta no tiene headers, añadirlos
            response['headers'] = add_cors_headers()
        
        return response
    
    return wrapper

def create_cors_response(status_code, body=None):
    """
    Crea una respuesta con encabezados CORS.
    
    Args:
        status_code (int): Código de estado HTTP
        body (dict, optional): Cuerpo de la respuesta
        
    Returns:
        dict: Respuesta formateada con encabezados CORS
    """
    response = {
        'statusCode': status_code,
        'headers': add_cors_headers(),
    }
    
    if body is not None:
        if isinstance(body, dict):
            response['body'] = json.dumps(body)
        else:
            response['body'] = body
    
    return response