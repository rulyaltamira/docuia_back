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
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

# Definir planes disponibles con sus límites
TENANT_PLANS = {
    'free': {
        'max_users': 3,
        'max_documents': 100,
        'max_storage_mb': 100,
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': False,
            'custom_domain': False,
            'api_access': False
        }
    },
    'basic': {
        'max_users': 10,
        'max_documents': 1000,
        'max_storage_mb': 1000,
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': True,
            'custom_domain': False,
            'api_access': True
        }
    },
    'premium': {
        'max_users': 50,
        'max_documents': 10000,
        'max_storage_mb': 10000,
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': True,
            'custom_domain': True,
            'api_access': True
        }
    },
    'enterprise': {
        'max_users': -1,  # Ilimitado
        'max_documents': -1,  # Ilimitado
        'max_storage_mb': -1,  # Ilimitado
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': True,
            'custom_domain': True,
            'api_access': True
        }
    }
}

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
    elif http_method == 'GET' and path == '/tenant-plans':
        return get_tenant_plans(event, context)
    elif http_method == 'GET' and '/tenants/' in path and '/usage' in path:
        return get_tenant_usage(event, context)
    elif http_method == 'PUT' and '/tenants/' in path and '/plan' in path:
        return update_tenant_plan(event, context)
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
        
        # Validar que el plan seleccionado existe
        if plan not in TENANT_PLANS:
            logger.error(f"Plan no válido: {plan}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': f'Plan no válido. Opciones disponibles: {", ".join(TENANT_PLANS.keys())}'})
            }
        
        logger.info(f"Creando nuevo tenant: {tenant_name}, plan: {plan}")
        
        # Generar ID único y claves de seguridad
        tenant_id = str(uuid.uuid4())
        api_key = f"docpilot_{secrets.token_urlsafe(32)}"
        webhook_secret = secrets.token_hex(16)
        
        # Crear estructura de carpetas en S3
        folder_paths = [
            f"tenants/{tenant_id}/raw/email/",
            f"tenants/{tenant_id}/raw/manual/",
            f"tenants/{tenant_id}/processed/",
            f"tenants/{tenant_id}/quarantine/"
        ]
        
        for path in folder_paths:
            s3.put_object(
                Bucket=MAIN_BUCKET,
                Key=path,
                Body=''
            )
        
        logger.info(f"Estructura de carpetas creada en S3 para tenant: {tenant_id}")
        
        # Obtener límites del plan seleccionado
        plan_limits = TENANT_PLANS.get(plan, TENANT_PLANS['free'])
        
        # Configuración inicial para el tenant
        initial_settings = body.get('settings', {})
        
        # Asegurar que hay configuraciones básicas
        if 'email_domain' not in initial_settings:
            initial_settings['email_domain'] = f"{tenant_id}.docpilot.com"
        
        # Guardar información en DynamoDB con el modelo extendido
        timestamp = datetime.now().isoformat()
        tenant_table.put_item(Item={
            'tenant_id': tenant_id,
            'name': tenant_name,
            'plan': plan,
            'status': 'active',
            'created_at': timestamp,
            'updated_at': timestamp,
            'limits': {
                'max_users': plan_limits['max_users'],
                'max_documents': plan_limits['max_documents'],
                'max_storage_mb': plan_limits['max_storage_mb']
            },
            'usage': {
                'users_count': 0,
                'documents_count': 0,
                'storage_used_mb': 0,
                'last_updated': timestamp
            },
            'features': plan_limits['features'],
            'settings': initial_settings,
            'webhook_url': body.get('webhook_url', ''),
            'webhook_secret': webhook_secret,
            'api_key': api_key,
            'billing_info': body.get('billing_info', {}),
            'custom_domain': body.get('custom_domain', '')
        })
        
        logger.info(f"Información guardada en DynamoDB para tenant: {tenant_id}")
        
        return {
            'statusCode': 201,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'tenant_id': tenant_id,
                'name': tenant_name,
                'plan': plan,
                'limits': plan_limits,
                'created_at': timestamp,
                'api_key': api_key,
                'webhook_secret': webhook_secret,
                'email_domain': initial_settings.get('email_domain')
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
        
        tenant = response['Item']
        
        # Construir expresión de actualización
        update_expression = "set updated_at = :t"
        expression_values = {
            ':t': datetime.now().isoformat()
        }
        
        # Agregar campos a actualizar
        fields = {
            'name': 'name',
            'status': 'status',
            'webhook_url': 'webhook_url',
            'custom_domain': 'custom_domain',
            'billing_info': 'billing_info'
        }
        
        for field, db_field in fields.items():
            if field in body:
                update_expression += f", {db_field} = :{field}"
                expression_values[f':{field}'] = body[field]
        
        # Manejo especial para settings (merge en lugar de reemplazo)
        if 'settings' in body:
            # Obtener settings actuales y fusionar con los nuevos
            current_settings = tenant.get('settings', {})
            new_settings = {**current_settings, **body['settings']}
            
            update_expression += ", settings = :settings"
            expression_values[':settings'] = new_settings
        
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
            UpdateExpression="set #status = :s, updated_at = :t, deactivated_at = :d",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':s': 'inactive',
                ':t': datetime.now().isoformat(),
                ':d': datetime.now().isoformat()
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
        
        # Añadir soporte para filtros
        query_params = event.get('queryStringParameters', {}) or {}
        status_filter = query_params.get('status', 'active')
        
        filter_expression = '#status = :s'
        expression_values = {':s': status_filter}
        
        # Filtrar por plan si se proporciona
        if 'plan' in query_params:
            filter_expression += " AND plan = :p"
            expression_values[':p'] = query_params.get('plan')
        
        response = tenant_table.scan(
            FilterExpression=filter_expression,
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues=expression_values
        )
        
        tenants = response.get('Items', [])
        
        # Eliminar información sensible
        for tenant in tenants:
            if 'api_key' in tenant:
                del tenant['api_key']
            if 'webhook_secret' in tenant:
                del tenant['webhook_secret']
        
        logger.info(f"Encontrados {len(tenants)} tenants con status: {status_filter}")
        
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

def get_tenant_plans(event, context):
    """Obtiene lista de planes disponibles y sus características"""
    try:
        logger.info("Obteniendo planes disponibles")
        
        # Devolver información de planes quitando datos sensibles si los hubiera
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'plans': TENANT_PLANS})
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo planes: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def update_tenant_plan(event, context):
    """Actualiza el plan de un tenant y sus límites asociados"""
    try:
        # Obtener tenant_id de la ruta
        tenant_id = event['pathParameters']['tenant_id']
        
        # Obtener nuevo plan del body
        body = json.loads(event.get('body', '{}'))
        new_plan = body.get('plan')
        
        if not new_plan:
            logger.error("Falta el parámetro plan")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'El parámetro plan es obligatorio'})
            }
        
        # Validar que el plan seleccionado existe
        if new_plan not in TENANT_PLANS:
            logger.error(f"Plan no válido: {new_plan}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': f'Plan no válido. Opciones disponibles: {", ".join(TENANT_PLANS.keys())}'})
            }
        
        logger.info(f"Actualizando plan de tenant {tenant_id} a: {new_plan}")
        
        # Verificar que el tenant existe
        response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        tenant = response['Item']
        old_plan = tenant.get('plan', 'free')
        
        # Obtener límites del nuevo plan
        plan_limits = TENANT_PLANS.get(new_plan, TENANT_PLANS['free'])
        
        # Actualizar plan, límites y características
        tenant_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression="set plan = :p, limits = :l, features = :f, updated_at = :t, plan_history = list_append(if_not_exists(plan_history, :empty_list), :h)",
            ExpressionAttributeValues={
                ':p': new_plan,
                ':l': {
                    'max_users': plan_limits['max_users'],
                    'max_documents': plan_limits['max_documents'],
                    'max_storage_mb': plan_limits['max_storage_mb']
                },
                ':f': plan_limits['features'],
                ':t': datetime.now().isoformat(),
                ':empty_list': [],
                ':h': [{
                    'date': datetime.now().isoformat(),
                    'old_plan': old_plan,
                    'new_plan': new_plan
                }]
            }
        )
        
        logger.info(f"Plan actualizado correctamente para tenant: {tenant_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'message': 'Plan actualizado correctamente',
                'tenant_id': tenant_id,
                'old_plan': old_plan,
                'new_plan': new_plan,
                'limits': {
                    'max_users': plan_limits['max_users'],
                    'max_documents': plan_limits['max_documents'],
                    'max_storage_mb': plan_limits['max_storage_mb']
                },
                'features': plan_limits['features']
            })
        }
        
    except Exception as e:
        logger.error(f"Error actualizando plan: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_tenant_usage(event, context):
    """Obtiene estadísticas de uso de un tenant"""
    try:
        # Obtener tenant_id de la ruta
        tenant_id = event['pathParameters']['tenant_id']
        
        logger.info(f"Obteniendo estadísticas de uso de tenant: {tenant_id}")
        
        # Verificar que el tenant existe
        response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        tenant = response['Item']
        
        # Recalcular uso actual (esto debería hacerse periódicamente por otra función)
        updated_usage = calculate_tenant_usage(tenant_id)
        
        # Obtener límites del plan
        limits = tenant.get('limits', {
            'max_users': 0,
            'max_documents': 0,
            'max_storage_mb': 0
        })
        
        # Calcular porcentajes de uso
        usage_percentages = {}
        
        for key in ['max_users', 'max_documents', 'max_storage_mb']:
            limit = limits.get(key, 0)
            usage_key = key.replace('max_', '') + '_count' if 'users' in key or 'documents' in key else 'storage_used_mb'
            usage = updated_usage.get(usage_key, 0)
            
            # Si el límite es -1 (ilimitado), establecer porcentaje en 0
            if limit < 0:
                usage_percentages[key] = 0
            else:
                usage_percentages[key] = min(100, round((usage / limit) * 100, 2)) if limit > 0 else 100
        
        # Construir respuesta
        usage_info = {
            'tenant_id': tenant_id,
            'plan': tenant.get('plan', 'free'),
            'limits': limits,
            'usage': updated_usage,
            'usage_percentages': usage_percentages
        }
        
        logger.info(f"Estadísticas de uso obtenidas para tenant: {tenant_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(usage_info)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de uso: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def calculate_tenant_usage(tenant_id):
    """
    Calcula el uso actual de recursos de un tenant
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Métricas de uso actualizadas
    """
    try:
        # Inicializar contadores
        users_count = 0
        documents_count = 0
        storage_used_bytes = 0
        
        # Contar usuarios activos
        user_response = users_table.scan(
            FilterExpression="tenant_id = :t AND #status = :s",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":s": "active"
            },
            ExpressionAttributeNames={
                "#status": "status"
            }
        )
        
        users_count = len(user_response.get('Items', []))
        
        # Contar documentos y calcular espacio usado (excluyendo eliminados)
        document_response = contracts_table.scan(
            FilterExpression="tenant_id = :t AND #status <> :s",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":s": "deleted"
            },
            ExpressionAttributeNames={
                "#status": "status"
            }
        )
        
        documents = document_response.get('Items', [])
        documents_count = len(documents)
        
        # Sumar tamaño de todos los documentos
        for doc in documents:
            storage_used_bytes += doc.get('file_size', 0)
        
        # Convertir bytes a MB
        storage_used_mb = round(storage_used_bytes / (1024 * 1024), 2)
        
        # Crear objeto de uso actualizado
        usage = {
            'users_count': users_count,
            'documents_count': documents_count,
            'storage_used_mb': storage_used_mb,
            'last_updated': datetime.now().isoformat()
        }
        
        # Actualizar la información de uso en la tabla de tenants
        tenant_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression="set usage = :u",
            ExpressionAttributeValues={
                ':u': usage
            }
        )
        
        logger.info(f"Uso calculado para tenant {tenant_id}: {usage}")
        
        return usage
        
    except Exception as e:
        logger.error(f"Error calculando uso del tenant: {str(e)}")
        # Devolver un objeto vacío en caso de error
        return {
            'users_count': 0,
            'documents_count': 0,
            'storage_used_mb': 0,
            'last_updated': datetime.now().isoformat(),
            'error': str(e)
        }