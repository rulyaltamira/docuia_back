"""
Handler para leer y listar alertas del sistema DocPilot
"""

import json
import os
import boto3
import logging
# from decimal import Decimal # Ya no se necesita aquí, se importa el encoder
from botocore.exceptions import ClientError # Mantener para manejo específico si es necesario

# Importar helpers de utilidad
from src.utils.cors_middleware import add_cors_headers
from src.utils.auth_utils import get_tenant_id_or_error
from src.utils.response_helpers import create_success_response, create_error_response
from src.utils.encoders import DecimalEncoder # Importar el encoder centralizado

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE'))
DEFAULT_LIMIT = 10 # Mantener como constante local o mover a un config si se usa en más sitios

# Ya no se necesita DecimalEncoder local ni get_tenant_id_from_headers local

def lambda_handler(event, context):
    try:
        logger.info(f"Evento recibido para listar alertas: {json.dumps(event)}")

        tenant_id, error_resp = get_tenant_id_or_error(event, decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp

        logger.info(f"Listando alertas para tenant: {tenant_id}")

        params = event.get('queryStringParameters', {}) or {}
        limit = int(params.get('limit', DEFAULT_LIMIT))
        search_term = params.get('search', '').strip()
        exclusive_start_key_str = params.get('nextToken')
        exclusive_start_key = None
        if exclusive_start_key_str:
            try:
                exclusive_start_key = json.loads(exclusive_start_key_str) 
            except json.JSONDecodeError:
                logger.warning("nextToken inválido, no es un JSON válido. Ignorando.")
                # No devolver error, simplemente no paginar y empezar desde el principio

        scan_kwargs = {
            'Limit': limit,
            'FilterExpression': boto3.dynamodb.conditions.Attr('tenant_id').eq(tenant_id)
        }

        if search_term:
             scan_kwargs['FilterExpression'] = scan_kwargs['FilterExpression'] & (
                 boto3.dynamodb.conditions.Attr('message').contains(search_term) |
                 boto3.dynamodb.conditions.Attr('details').contains(search_term) | 
                 boto3.dynamodb.conditions.Attr('alert_type').contains(search_term) 
             )

        if exclusive_start_key:
            scan_kwargs['ExclusiveStartKey'] = exclusive_start_key
            logger.info(f"Continuando escaneo con ExclusiveStartKey: {exclusive_start_key}")

        logger.info(f"Argumentos del Scan: {scan_kwargs}")
        
        response = alerts_table.scan(**scan_kwargs)
        items = response.get('Items', [])
        last_evaluated_key = response.get('LastEvaluatedKey')
        next_token = json.dumps(last_evaluated_key, cls=DecimalEncoder) if last_evaluated_key else None

        logger.info(f"Encontradas {len(items)} alertas. Hay más resultados: {bool(last_evaluated_key)}")

        return create_success_response(
            data={
                'alerts': items,
                'pagination': {'limit': limit, 'nextToken': next_token},
                'search': search_term   
            },
            decimal_encoder_cls=DecimalEncoder
        )

    except ClientError as e_dynamo:
        logger.error(f"Error de DynamoDB en alert_reader: {e_dynamo.response['Error']['Message']}")
        return create_error_response(500, "Error interno del servidor al consultar alertas", error_code="DYNAMODB_ERROR", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error inesperado en alert_reader: {str(e)}", exc_info=True)
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True) 