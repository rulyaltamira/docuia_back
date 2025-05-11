"""
Utilidades para generar respuestas HTTP estándar para API Gateway.
"""
import json
import logging
from src.utils.cors_middleware import add_cors_headers # Asumiendo que está en el mismo nivel o PYTHONPATH está configurado

logger = logging.getLogger()

def create_error_response(status_code, message, error_code=None, decimal_encoder_cls=None, is_internal_error=False):
    """
    Crea una respuesta de error HTTP estándar.

    Args:
        status_code (int): Código de estado HTTP.
        message (str): Mensaje de error descriptivo para el cliente (si no es error interno).
        error_code (str, optional): Un código de error específico de la aplicación.
        decimal_encoder_cls: Clase para serializar Decimales a JSON.
        is_internal_error (bool): Si es True, el mensaje para el cliente será genérico.
                                   El 'message' original se logueará.

    Returns:
        dict: Diccionario de respuesta de API Gateway.
    """
    error_payload = {}
    if is_internal_error:
        logger.error(f"Error interno del servidor: {message}") # Loguear el error real
        error_payload['error'] = "Error interno del servidor. Intente más tarde."
    else:
        error_payload['error'] = message

    if error_code:
        error_payload['error_code'] = error_code
    
    body_json = json.dumps(error_payload, cls=decimal_encoder_cls) if decimal_encoder_cls else json.dumps(error_payload)
    
    return {
        'statusCode': status_code,
        'headers': add_cors_headers({'Content-Type': 'application/json'}),
        'body': body_json
    }

def create_success_response(data, status_code=200, decimal_encoder_cls=None):
    """
    Crea una respuesta de éxito HTTP estándar.

    Args:
        data (dict or list): Datos a incluir en el cuerpo de la respuesta.
        status_code (int): Código de estado HTTP (por defecto 200).
        decimal_encoder_cls: Clase para serializar Decimales a JSON.

    Returns:
        dict: Diccionario de respuesta de API Gateway.
    """
    body_json = json.dumps(data, cls=decimal_encoder_cls) if decimal_encoder_cls else json.dumps(data)
    
    return {
        'statusCode': status_code,
        'headers': add_cors_headers({'Content-Type': 'application/json'}),
        'body': body_json
    }

# Ejemplo de cómo podrían usarse en un handler:
# from src.utils.response_helpers import create_error_response, create_success_response
# from src.handlers.document_manager import DecimalEncoder # Suponiendo que DecimalEncoder está accesible
# 
# if not data_found:
#     return create_error_response(404, "Recurso no encontrado", error_code="RES_NOT_FOUND", decimal_encoder_cls=DecimalEncoder)
# 
# return create_success_response({"data": data_found}, decimal_encoder_cls=DecimalEncoder) 