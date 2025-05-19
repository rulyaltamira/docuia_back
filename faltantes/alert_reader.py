"""
Handler para leer y listar alertas del sistema DocPilot
"""

import json
import os
import boto3
import logging
from decimal import Decimal
from botocore.exceptions import ClientError
from src.utils.cors_middleware import add_cors_headers

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE'))
DEFAULT_LIMIT = 10

class DecimalEncoder(json.JSONEncoder):
    #\"\"\"Codificador JSON para manejar objetos Decimal de DynamoDB.\"\"\"
    def default(self, obj):
        if isinstance(obj, Decimal):
            # Convertir Decimal a string para mantener la precisión, 
            # o a float/int si es apropiado para el caso de uso.
            # Elegir string para generalidad.
            return str(obj) 
        # Dejar que la clase base maneje otros tipos
        return super(DecimalEncoder, self).default(obj)

def get_tenant_id_from_headers(headers):
   #\"\"\"Extrae el tenant_id de las cabeceras, insensible a mayúsculas/minúsculas.\"\"\"
    if not headers:
        return None
    # Buscar tanto 'x-tenant-id' como 'X-Tenant-Id' (y otras variaciones)
    for key in headers:
        if key.lower() == 'x-tenant-id':
            return headers[key]
    return None

def lambda_handler(event, context):

    try:
        logger.info(f"Evento recibido para listar alertas: {json.dumps(event)}")

        headers = event.get('headers', {})
        tenant_id = get_tenant_id_from_headers(headers)

        if not tenant_id:
            logger.warning("Falta la cabecera x-tenant-id")
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requiere la cabecera x-tenant-id'})
            }

        logger.info(f"Listando alertas para tenant: {tenant_id}")

        # Obtener parámetros de consulta
        params = event.get('queryStringParameters') if event.get('queryStringParameters') else {}
        limit = int(params.get('limit', DEFAULT_LIMIT))
        search_term = params.get('search', '').strip()
        # Para paginación: obtener la clave del último elemento de la página anterior
        exclusive_start_key_str = params.get('nextToken', None)
        exclusive_start_key = json.loads(exclusive_start_key_str) if exclusive_start_key_str else None

        # Construir parámetros de consulta/escaneo para DynamoDB
        # Nota: Usar 'query' sería más eficiente si tuviéramos un GSI por tenant_id.
        # Por ahora, usaremos 'scan' con un filtro. ¡Esto puede ser lento/costoso para tablas grandes!
        scan_kwargs = {
            'Limit': limit,
            'FilterExpression': boto3.dynamodb.conditions.Attr('tenant_id').eq(tenant_id)
        }

        # Añadir filtro de búsqueda si se proporciona (búsqueda simple en 'message' o 'details')
        # Esto es un ejemplo, ajusta los campos de búsqueda según tu modelo de datos
        if search_term:
             scan_kwargs['FilterExpression'] = scan_kwargs['FilterExpression'] & (
                 boto3.dynamodb.conditions.Attr('message').contains(search_term) |
                 boto3.dynamodb.conditions.Attr('details').contains(search_term) | # Asumiendo que tienes un campo details
                 boto3.dynamodb.conditions.Attr('alert_type').contains(search_term) 
             )

        # Añadir paginación si se proporciona el token
        if exclusive_start_key:
            scan_kwargs['ExclusiveStartKey'] = exclusive_start_key
            logger.info(f"Continuando escaneo con ExclusiveStartKey: {exclusive_start_key}")


        logger.info(f"Argumentos del Scan: {scan_kwargs}")
        
        # Realizar la operación de escaneo
        response = alerts_table.scan(**scan_kwargs)

        items = response.get('Items', [])
        last_evaluated_key = response.get('LastEvaluatedKey', None)
        
        # El 'nextToken' para la siguiente solicitud será el LastEvaluatedKey
        next_token = json.dumps(last_evaluated_key, cls=DecimalEncoder) if last_evaluated_key else None

        logger.info(f"Encontradas {len(items)} alertas. Hay más resultados: {bool(last_evaluated_key)}")

        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'alerts': items,
                'pagination': {
                    'limit': limit,
                    'nextToken': next_token # Token para la próxima página
                },
                 'search': search_term   
            }, cls=DecimalEncoder)
        }

    except ClientError as e:
        logger.error(f"Error de DynamoDB: {e.response['Error']['Message']}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno del servidor al consultar alertas'})
        }
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error inesperado en lambda_handler: {str(e)}")
        logger.error(f"Traceback: {error_trace}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno del servidor'})
        } 