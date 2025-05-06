import json

def error_response(status_code, message):
    """
    Genera una respuesta de error estándar
    
    Args:
        status_code (int): Código de estado HTTP
        message (str): Mensaje de error
        
    Returns:
        dict: Respuesta formateada para API Gateway
    """
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Origin'
        },
        'body': json.dumps({
            'success': False,
            'error': message
        })
    } 

def success_response(data):
    """
    Genera una respuesta exitosa estándar
    
    Args:
        data (dict): Datos a incluir en la respuesta
        
    Returns:
        dict: Respuesta formateada para API Gateway
    """
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Origin'
        },
        'body': json.dumps(data)
    } 