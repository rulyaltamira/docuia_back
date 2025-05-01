# docpilot-backend/src/handlers/cors_handler.py
"""
Manejador para respuestas OPTIONS (preflight) de CORS.
Este handler específico garantiza que todas las solicitudes OPTIONS
reciban la respuesta adecuada con los headers CORS necesarios.
"""

import json
import logging
from src.utils.cors_middleware import add_cors_headers

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Manejador específico para solicitudes OPTIONS (preflight CORS)
    
    Args:
        event (dict): Evento de invocación de API Gateway
        context (object): Contexto de ejecución de Lambda
        
    Returns:
        dict: Respuesta HTTP con encabezados CORS adecuados
    """
    logger.info("Procesando solicitud OPTIONS para CORS preflight")
    
    # Crear la respuesta con los encabezados CORS completos
    response = {
        'statusCode': 200,
        'headers': add_cors_headers(),
        'body': ''
    }
    
    return response