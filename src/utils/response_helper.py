# docpilot-backend/src/utils/response_helper.py
# Utilidades para formatear respuestas de API

import json

def build_response(status_code, body=None, headers=None):
    """
    Construye una respuesta formateada para API Gateway
    """
    response = {
        'statusCode': status_code,
        'headers': headers or {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',  # Para CORS
            'Access-Control-Allow-Credentials': True
        }
    }
    
    if body is not None:
        response['body'] = json.dumps(body)
        
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