# docpilot-backend/src/utils/response_helper.py
# Utilidades para formatear respuestas de API

import json
import decimal

# Clase para manejar la serialización de objetos Decimal a JSON
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return float(obj)  # Convertir Decimal a float
        return super(DecimalEncoder, self).default(obj)

def build_response(status_code, body=None, headers=None):
    """
    Construye una respuesta formateada para API Gateway
    """
    # Establecer encabezados CORS predeterminados
    default_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',  # Permisivo para desarrollo, ajustar en producción
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Requested-With',
        'Access-Control-Allow-Methods': 'OPTIONS,GET,POST,PUT,DELETE'
    }
    
    # Combinar con headers proporcionados
    merged_headers = {**default_headers, **(headers or {})}
    
    response = {
        'statusCode': status_code,
        'headers': merged_headers
    }
    
    if body is not None:
        # Usar el codificador personalizado para manejar objetos Decimal
        response['body'] = json.dumps(body, cls=DecimalEncoder)
        
    return response

def success_response(data=None, message=None):
    """Respuesta de éxito (200 OK)"""
    body = {}
    
    if data is not None:
        body.update(data)
    
    if message:
        body['message'] = message
        
    return build_response(200, body)

def created_response(data=None, message=None):
    """Respuesta de creación exitosa (201 Created)"""
    body = {}
    
    if data is not None:
        body.update(data)
    
    if message:
        body['message'] = message
        
    return build_response(201, body)

def error_response(status_code, message):
    """Respuesta de error"""
    return build_response(status_code, {'error': message})

def bad_request(message="Bad request"):
    """Respuesta 400 Bad Request"""
    return error_response(400, message)

def not_found(message="Resource not found"):
    """Respuesta 404 Not Found"""
    return error_response(404, message)

def server_error(message="Internal server error"):
    """Respuesta 500 Internal Server Error"""
    return error_response(500, message)

def options_response():
    """
    Respuesta para solicitudes OPTIONS preflight
    """
    return build_response(200, None)