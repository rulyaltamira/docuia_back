import json
import base64
import logging

logger = logging.getLogger()

def parse_api_gateway_event(event):
    """
    Parsea un evento de API Gateway para extraer el body en formato JSON.
    Maneja tanto la codificación base64 como otros formatos comunes.
    
    Args:
        event (dict): Evento de API Gateway
        
    Returns:
        dict: Payload JSON extraído del body
    """
    # Validar que tenemos un evento
    if not event:
        logger.error("Evento vacío o None")
        return {}
        
    # Extraer información básica para logs
    http_method = event.get('httpMethod', 'UNKNOWN')
    path = event.get('path', 'UNKNOWN')
    query_params = event.get('queryStringParameters', {})
    headers = event.get('headers', {})
    
    logger.info(f"Procesando solicitud: {http_method} {path}")
    logger.debug(f"Headers: {headers}")
    
    # Obtener el body
    body_raw = event.get('body', '{}')
    is_base64 = event.get('isBase64Encoded', False)
    
    # Extraer y parsear el body
    body_json = {}
    
    try:
        # 1. Manejar None o string vacío
        if body_raw is None or (isinstance(body_raw, str) and not body_raw.strip()):
            logger.debug("Body vacío o None, usando diccionario vacío")
            return {}
            
        # 2. Si ya es un diccionario
        if isinstance(body_raw, dict):
            logger.debug("Body ya es un diccionario")
            return body_raw
            
        # 3. Decodificar Base64 si es necesario
        if is_base64 and isinstance(body_raw, str):
            logger.debug("Decodificando body desde Base64")
            try:
                body_decoded = base64.b64decode(body_raw).decode('utf-8')
                logger.debug(f"Body decodificado (primeros 100 chars): {body_decoded[:100]}")
                body_raw = body_decoded
            except Exception as e:
                logger.error(f"Error decodificando Base64: {str(e)}")
                # Continuar con el body original
        
        # 4. Parsear JSON
        if isinstance(body_raw, str):
            logger.debug("Parseando body JSON desde string")
            body_json = json.loads(body_raw)
            logger.debug(f"Body parseado exitosamente: {len(body_json)} campos")
        
    except json.JSONDecodeError as e:
        logger.error(f"Error parseando JSON: {str(e)}")
        logger.error(f"Body problemático (primeros 100 chars): '{body_raw[:100]}'")
        # Devolver diccionario vacío en caso de error
        return {}
    except Exception as e:
        logger.error(f"Error inesperado procesando body: {str(e)}")
        return {}
    
    return body_json

def format_api_gateway_response(status_code, body, headers=None):
    """
    Formatea una respuesta para API Gateway
    
    Args:
        status_code (int): Código de estado HTTP
        body (dict): Cuerpo de la respuesta
        headers (dict, optional): Headers adicionales
        
    Returns:
        dict: Respuesta formateada para API Gateway
    """
    # Encabezados por defecto
    default_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Requested-With',
        'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'
    }
    
    # Combinar con headers personalizados
    merged_headers = {**default_headers, **(headers or {})}
    
    # Construir respuesta
    response = {
        'statusCode': status_code,
        'headers': merged_headers
    }
    
    # Añadir body si se proporciona
    if body is not None:
        if isinstance(body, str):
            response['body'] = body
        else:
            response['body'] = json.dumps(body)
    
    return response 