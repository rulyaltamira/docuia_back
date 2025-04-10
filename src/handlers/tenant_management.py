# docpilot-backend/src/handlers/tenant_management.py
import json
import os
import uuid
import boto3
import secrets
from datetime import datetime
import logging

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
tenant_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

def lambda_handler(event, context):
    """Maneja operaciones CRUD para tenants (clientes)"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'POST' and path == '/tenants':
        return create_tenant(event, context)
    elif http_method == 'PUT' and '/tenants/' in path:
        return update_tenant(event, context)
    elif http_method == 'DELETE' and '/tenants/' in path:
        return delete_tenant(event, context)
    elif http_method == 'GET' and path == '/tenants':
        return list_tenants(event, context)
    elif http_method == 'GET' and '/tenants/' in path:
        return get_tenant(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Operación no válida'})
        }

def create_tenant(event, context):
    """Crea un nuevo cliente/organización en el sistema"""
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        tenant_name = body.get('name')
        plan = body.get('plan', 'free')
        
        if not tenant_name:
            logger.error("Falta el nombre del tenant")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'El nombre del cliente es obligatorio'})
            }
        
        logger.info(f"Creando nuevo tenant: {tenant_name}, plan: {plan}")
        
        # Generar ID único y API key
        tenant_id = str(uuid.uuid4())
        api_key = f"docpilot_{secrets.token_urlsafe(32)}"
        webhook_secret = secrets.token_hex(16)
        
        # Crear estructura de carpetas en S3
        folder_paths = [
            f"tenants/{tenant_id}/raw/email/",
            f"tenants/{tenant_id}/raw/manual/",
            f"tenants/{tenant_id}/processed/"
        ]
        
        for path in folder_paths:
            s3.put_object(
                Bucket=MAIN_BUCKET,
                Key=path,
                Body=''
            )
        
        logger.info(f"Estructura de carpetas creada en S3 para tenant: {tenant_id}")
        
        # Guardar información en DynamoDB
        timestamp = datetime.now().isoformat()
        tenant_table.put_item(Item={
            'tenant_id': tenant_id,
            'name': tenant_name,
            'plan': plan,
            'status': 'active',
            'created_at': timestamp,
            'updated_at': timestamp,
            'settings': body.get('settings', {}),
            'webhook_url': body.get('webhook_url', ''),
            'webhook_secret': webhook_secret,
            'api_key': api_key
        })
        
        logger.info(f"Información guardada en DynamoDB para tenant: {tenant_id}")
        
        return {
            'statusCode': 201,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'tenant_id': tenant_id,
                'name': tenant_name,
                'created_at': timestamp,
                'api_key': api_key,
                'webhook_secret': webhook_secret
            })
        }
        
    except Exception as e:
        logger.error(f"Error creando tenant: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def update_tenant(event, context):
    """Actualiza información de un cliente existente"""
    try:
        # Obtener tenant_id de la ruta
        tenant_id = event['pathParameters']['tenant_id']
        
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        logger.info(f"Actualizando tenant: {tenant_id}")
        
        # Verificar que el tenant existe
        response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        # Construir expresión de actualización
        update_expression = "set updated_at = :t"
        expression_values = {
            ':t': datetime.now().isoformat()
        }
        
        # Agregar campos a actualizar
        fields = {
            'name': 'name',
            'plan': 'plan',
            'status': 'status',
            'webhook_url': 'webhook_url',
            'settings': 'settings'
        }
        
        for field, db_field in fields.items():
            if field in body:
                update_expression += f", {db_field} = :{field}"
                expression_values[f':{field}'] = body[field]
        
        # Actualizar en DynamoDB
        tenant_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )
        
        logger.info(f"Tenant actualizado correctamente: {tenant_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Cliente actualizado correctamente'})
        }
        
    except Exception as e:
        logger.error(f"Error actualizando tenant: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def delete_tenant(event, context):
    """Marca un cliente como inactivo (no elimina datos)"""
    try:
        # Obtener tenant_id de la ruta
        tenant_id = event['pathParameters']['tenant_id']
        
        logger.info(f"Desactivando tenant: {tenant_id}")
        
        # Verificar que el tenant existe
        response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        # Marcar como inactivo en lugar de eliminar
        tenant_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression="set #status = :s, updated_at = :t",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':s': 'inactive',
                ':t': datetime.now().isoformat()
            }
        )
        
        logger.info(f"Tenant desactivado correctamente: {tenant_id}")
        
        # Nota: No eliminamos los datos de S3, solo marcamos el tenant como inactivo
        # Esto permite recuperación y cumplimiento de políticas de retención
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Cliente desactivado correctamente'})
        }
        
    except Exception as e:
        logger.error(f"Error desactivando tenant: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def list_tenants(event, context):
    """Lista todos los clientes activos"""
    try:
        logger.info("Listando tenants activos")
        
        response = tenant_table.scan(
            FilterExpression='#status = :s',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':s': 'active'}
        )
        
        tenants = response.get('Items', [])
        
        # Eliminar información sensible
        for tenant in tenants:
            if 'api_key' in tenant:
                del tenant['api_key']
            if 'webhook_secret' in tenant:
                del tenant['webhook_secret']
        
        logger.info(f"Encontrados {len(tenants)} tenants activos")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'tenants': tenants})
        }
        
    except Exception as e:
        logger.error(f"Error listando tenants: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_tenant(event, context):
    """Obtiene información de un cliente específico"""
    try:
        # Obtener tenant_id de la ruta
        tenant_id = event['pathParameters']['tenant_id']
        
        logger.info(f"Obteniendo información de tenant: {tenant_id}")
        
        # Obtener información del tenant
        response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        tenant = response['Item']
        
        # Eliminar información sensible
        if 'api_key' in tenant:
            del tenant['api_key']
        if 'webhook_secret' in tenant:
            del tenant['webhook_secret']
        
        logger.info(f"Información de tenant obtenida: {tenant_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'tenant': tenant})
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo tenant: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }