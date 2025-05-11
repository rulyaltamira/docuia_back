"""
Utilidades para interactuar con DynamoDB de forma común y segura.
"""
import json
import logging
from src.utils.cors_middleware import add_cors_headers # Asumiendo que está en el mismo nivel o PYTHONPATH está configurado

logger = logging.getLogger()
# logger.setLevel(logging.INFO) # Configurar nivel de logging en el handler que lo usa o globalmente

def get_document_and_verify_tenant(d_table, document_id, expected_tenant_id, id_key_name='id', tenant_id_key_name='tenant_id', decimal_encoder_cls=None):
    """
    Obtiene un ítem de DynamoDB por su ID y verifica que pertenezca al tenant esperado.

    Args:
        d_table: Objeto de tabla DynamoDB (boto3.resource('dynamodb').Table('TableName')).
        document_id (str): El ID del documento/ítem a obtener.
        expected_tenant_id (str): El tenant_id con el que se debe comparar el ítem.
        id_key_name (str): Nombre de la clave primaria en la tabla (por defecto 'id').
        tenant_id_key_name (str): Nombre del atributo que almacena el tenant_id en el ítem (por defecto 'tenant_id').
        decimal_encoder_cls: Clase codificadora JSON para manejar decimales (opcional).

    Returns:
        tuple: (document_item, None) si es exitoso y la verificación pasa.
               (None, error_response_dict) si el documento no se encuentra o la verificación del tenant falla.
    """
    if not d_table or not document_id or not expected_tenant_id:
        logger.error("get_document_and_verify_tenant: Faltan parámetros obligatorios (tabla, document_id o expected_tenant_id).")
        error_body = {'error': 'Error interno del servidor por parámetros faltantes para búsqueda de documento.'}
        return None, {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(error_body, cls=decimal_encoder_cls) if decimal_encoder_cls else json.dumps(error_body)
        }

    try:
        response = d_table.get_item(Key={id_key_name: document_id})
    except Exception as e:
        logger.error(f"Error obteniendo ítem {document_id} de la tabla {d_table.name}: {str(e)}")
        error_body = {'error': 'Error interno al acceder a la base de datos.'}
        return None, {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(error_body, cls=decimal_encoder_cls) if decimal_encoder_cls else json.dumps(error_body)
        }

    if 'Item' not in response:
        logger.warning(f"Ítem no encontrado: {document_id} en tabla {d_table.name}")
        error_body = {'error': f'{id_key_name.capitalize()} no encontrado'} # Mensaje genérico
        return None, {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(error_body, cls=decimal_encoder_cls) if decimal_encoder_cls else json.dumps(error_body)
        }

    document_item = response['Item']

    if document_item.get(tenant_id_key_name) != expected_tenant_id:
        logger.error(f"Acceso denegado: Ítem {document_id} (tenant: {document_item.get(tenant_id_key_name)}) no pertenece al tenant esperado {expected_tenant_id}.")
        error_body = {'error': 'Acceso denegado a este recurso.'}
        return None, {
            'statusCode': 403, # Forbidden
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(error_body, cls=decimal_encoder_cls) if decimal_encoder_cls else json.dumps(error_body)
        }
    
    logger.info(f"Ítem {document_id} obtenido y verificado para tenant {expected_tenant_id}.")
    return document_item, None 