# docpilot-backend/src/handlers/tenant_management.py
import json
import os
import uuid
import boto3
import secrets
from datetime import datetime
import logging

# Importar helpers
from src.utils.response_helpers import create_success_response, create_error_response
from src.utils.validation_helpers import validate_required_fields, validate_plan_or_error
from src.utils.db_helpers import get_item_or_404

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
tenant_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

<<<<<<< Updated upstream
=======
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

# Codificador personalizado para manejar tipos Decimal
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super(DecimalEncoder, self).default(o)

>>>>>>> Stashed changes
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
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos requeridos
        validation_error = validate_required_fields(body, ['name'])
        if validation_error:
            return create_error_response(validation_error["status_code"], validation_error["error_message"], validation_error["error_code"], decimal_encoder_cls=DecimalEncoder)

        tenant_name = body.get('name')
<<<<<<< Updated upstream
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
=======
        plan = body.get('plan', 'free') # Default a 'free' si no se especifica

        # Validar que el plan seleccionado existe
        plan_validation_error = validate_plan_or_error(plan, TENANT_PLANS, decimal_encoder_cls=DecimalEncoder)
        if plan_validation_error:
            # validate_plan_or_error ahora devuelve un dict simple, necesitamos construir la respuesta
            return create_error_response(plan_validation_error["status_code"], plan_validation_error["error_message"], plan_validation_error["error_code"], decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Creando nuevo tenant: {tenant_name}, plan: {plan}")
        
>>>>>>> Stashed changes
        tenant_id = str(uuid.uuid4())
        api_key = f"docpilot_{secrets.token_urlsafe(32)}"
        webhook_secret = secrets.token_hex(16)
        
        folder_paths = [
<<<<<<< Updated upstream
            f"tenants/{tenant_id}/raw/email/",
            f"tenants/{tenant_id}/raw/manual/",
            f"tenants/{tenant_id}/processed/"
=======
            f"tenants/{tenant_id}/raw/email/", f"tenants/{tenant_id}/raw/manual/",
            f"tenants/{tenant_id}/processed/", f"tenants/{tenant_id}/quarantine/"
>>>>>>> Stashed changes
        ]
        for path_item in folder_paths: # path es una palabra reservada por el lambda_handler
            s3.put_object(Bucket=MAIN_BUCKET, Key=path_item, Body='')
        logger.info(f"Estructura de carpetas S3 creada para tenant: {tenant_id}")
        
<<<<<<< Updated upstream
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
=======
        plan_config = TENANT_PLANS[plan] # Ya validado que el plan existe
        initial_settings = body.get('settings', {})
        if 'email_domain' not in initial_settings:
            initial_settings['email_domain'] = f"{tenant_id}.docpilot.com"
        
        timestamp = datetime.now().isoformat()
        tenant_item = {
            'tenant_id': tenant_id, 'name': tenant_name, 'plan': plan, 'status': 'active',
            'created_at': timestamp, 'updated_at': timestamp,
            'limits': { 'max_users': plan_config['max_users'], 'max_documents': plan_config['max_documents'], 'max_storage_mb': plan_config['max_storage_mb'] },
            'usage': { 'users_count': 0, 'documents_count': 0, 'storage_used_mb': 0, 'last_updated': timestamp },
            'features': plan_config['features'], 'settings': initial_settings,
            'webhook_url': body.get('webhook_url', ''), 'webhook_secret': webhook_secret,
            'api_key': api_key, 'billing_info': body.get('billing_info', {}),
            'custom_domain': body.get('custom_domain', '')
        }
        tenant_table.put_item(Item=tenant_item)
        logger.info(f"Información guardada en DynamoDB para tenant: {tenant_id}")
        
        response_data = {
            'tenant_id': tenant_id, 'name': tenant_name, 'plan': plan,
            'limits': plan_config, # Devolver todo el objeto de plan_config para 'limits' y 'features'
            'features': plan_config['features'],
            'created_at': timestamp, 'api_key': api_key, 'webhook_secret': webhook_secret,
            'email_domain': initial_settings.get('email_domain')
>>>>>>> Stashed changes
        }
        return create_success_response(response_data, status_code=201, decimal_encoder_cls=DecimalEncoder)
        
    except json.JSONDecodeError as json_err:
        logger.error(f"Error parseando JSON en create_tenant: {str(json_err)}")
        return create_error_response(400, "Cuerpo de solicitud JSON inválido.", error_code="INVALID_JSON", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error creando tenant: {str(e)}")
<<<<<<< Updated upstream
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }
=======
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def update_tenant(event, context):
    """Actualiza información de un cliente existente"""
    try:
        tenant_id_from_path = event.get('pathParameters', {}).get('tenant_id')
        if not tenant_id_from_path:
            return create_error_response(400, "Falta el tenant_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        body = json.loads(event.get('body', '{}'))
        logger.info(f"Actualizando tenant: {tenant_id_from_path}")
        
        # Verificar que el tenant existe
<<<<<<< Updated upstream
        response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
=======
        tenant, error_resp = get_item_or_404(tenant_table, {'tenant_id': tenant_id_from_path}, "Cliente", decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
>>>>>>> Stashed changes
        
        # Construir expresión de actualización
        update_expression_parts = ["updated_at = :t_updated"]
        expression_values = {':t_updated': datetime.now().isoformat()}
        expression_names = {} # Para atributos que son palabras reservadas
        
<<<<<<< Updated upstream
        # Agregar campos a actualizar
        fields = {
            'name': 'name',
            'plan': 'plan',
            'status': 'status',
            'webhook_url': 'webhook_url',
            'settings': 'settings'
        }
=======
        # Campos permitidos para actualización directa
        allowed_direct_updates = ['name', 'status', 'webhook_url', 'custom_domain', 'billing_info']
>>>>>>> Stashed changes
        
        for field in allowed_direct_updates:
            if field in body:
                placeholder = f":val_{field}"
                # Si el nombre del campo es una palabra reservada de DynamoDB, usar ExpressionAttributeNames
                # Ejemplo: si 'status' fuera palabra reservada, haríamos: attr_name = "#s"; expression_names["#s"] = "status"
                # Pero 'name', 'status', 'webhook_url', etc. no lo son típicamente como atributos de primer nivel.
                update_expression_parts.append(f"{field} = {placeholder}")
                expression_values[placeholder] = body[field]
        
<<<<<<< Updated upstream
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
=======
        # Manejo especial para settings (merge)
        if 'settings' in body and isinstance(body['settings'], dict):
            current_settings = tenant.get('settings', {})
            # Solo actualizar/añadir claves presentes en body['settings'], no reemplazar todo el objeto.
            # Esto requiere construir el UpdateExpression de forma más granular para cada sub-campo de settings.
            # Por simplicidad en este refactor, si 'settings' viene, se reemplaza completo.
            # Para un merge real, se necesitaría: "settings.#key = :val_key" por cada key en body['settings']
            # y añadir a expression_names y expression_values correspondientemente.
            # Por ahora, mantendremos el reemplazo completo si 'settings' está en el body.
            if body['settings']: # Solo actualizar si no es un diccionario vacío
                update_expression_parts.append("settings = :settings_val")
                expression_values[':settings_val'] = body['settings']

        if len(update_expression_parts) == 1: # Solo se está actualizando updated_at
            return create_error_response(400, "No se proporcionaron campos válidos para actualizar.", decimal_encoder_cls=DecimalEncoder)
        
        final_update_expression = "set " + ", ".join(update_expression_parts)
        
        update_params = {
            'Key': {'tenant_id': tenant_id_from_path},
            'UpdateExpression': final_update_expression,
            'ExpressionAttributeValues': expression_values,
            'ReturnValues': "UPDATED_NEW" # O ALL_NEW para obtener todo el ítem actualizado
>>>>>>> Stashed changes
        }
        if expression_names: # Si se usaron nombres de atributo placeholder
            update_params['ExpressionAttributeNames'] = expression_names
            
        updated_response = tenant_table.update_item(**update_params)
        logger.info(f"Tenant actualizado: {tenant_id_from_path}. Respuesta: {updated_response}")
        
        return create_success_response({'message': 'Cliente actualizado correctamente', 'tenant_id': tenant_id_from_path, 'updated_attributes': updated_response.get('Attributes',{})}, decimal_encoder_cls=DecimalEncoder)
        
    except json.JSONDecodeError as json_err:
        logger.error(f"Error parseando JSON en update_tenant: {str(json_err)}")
        return create_error_response(400, "Cuerpo de solicitud JSON inválido.", error_code="INVALID_JSON", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error actualizando tenant: {str(e)}")
<<<<<<< Updated upstream
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }
=======
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def delete_tenant(event, context):
    """Marca un cliente como inactivo (no elimina datos)"""
    try:
        tenant_id_from_path = event.get('pathParameters', {}).get('tenant_id')
        if not tenant_id_from_path:
            return create_error_response(400, "Falta el tenant_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Desactivando tenant: {tenant_id_from_path}")
        
<<<<<<< Updated upstream
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
=======
        # Verificar que el tenant existe (no necesitamos el item en sí, solo confirmar existencia antes de update)
        _, error_resp = get_item_or_404(tenant_table, {'tenant_id': tenant_id_from_path}, "Cliente", decimal_encoder_cls=DecimalEncoder)
        if error_resp: # Si no se encuentra (404) o hay otro error (500)
            return error_resp 
        
        # Marcar como inactivo en lugar de eliminar
        # (Nota: No hay verificación explícita si ya está inactivo, update_item lo manejará idempotentemente para el status)
        update_response = tenant_table.update_item(
            Key={'tenant_id': tenant_id_from_path},
            UpdateExpression="set #s = :new_status, updated_at = :ua, deactivated_at = :da",
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':new_status': 'inactive',
                ':ua': datetime.now().isoformat(),
                ':da': datetime.now().isoformat()
            },
            ReturnValues="UPDATED_NEW"
        )
        
        logger.info(f"Tenant desactivado: {tenant_id_from_path}. Respuesta: {update_response}")
        # Para DELETE, es común devolver 204 No Content si es exitoso.
        # create_success_response por defecto devuelve 200, pero podemos pasarle un string vacío o un mensaje simple.
        return create_success_response(None, status_code=204) # O { 'message': 'Cliente desactivado'}
        
    except Exception as e:
        logger.error(f"Error desactivando tenant: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def list_tenants(event, context):
    """Lista todos los clientes""" # Descripción actualizada, el filtro de status se maneja abajo
    try:
        logger.info("Listando tenants")
        
<<<<<<< Updated upstream
        response = tenant_table.scan(
            FilterExpression='#status = :s',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':s': 'active'}
        )
=======
        query_params = event.get('queryStringParameters', {}) or {}
        status_filter = query_params.get('status') # Puede ser None si no se provee
        plan_filter = query_params.get('plan')     # Puede ser None

        filter_expressions = []
        expression_values = {}
        expression_names = {} # Para atributos que son palabras reservadas

        if status_filter:
            filter_expressions.append("#s = :status_val")
            expression_names["#s"] = "status"
            expression_values[":status_val"] = status_filter
        
        if plan_filter:
            filter_expressions.append("plan = :plan_val") # 'plan' no es palabra reservada
            expression_values[":plan_val"] = plan_filter

        scan_params = {}
        if filter_expressions:
            scan_params['FilterExpression'] = " AND ".join(filter_expressions)
            scan_params['ExpressionAttributeValues'] = expression_values
            if expression_names: # Solo añadir si se usó
                scan_params['ExpressionAttributeNames'] = expression_names
>>>>>>> Stashed changes
        
        response = tenant_table.scan(**scan_params)
        tenants = response.get('Items', [])
        
        # Eliminar información sensible para la lista
        safe_tenants = []
        for tenant in tenants:
            tenant_copy = tenant.copy()
            if 'api_key' in tenant_copy: del tenant_copy['api_key']
            if 'webhook_secret' in tenant_copy: del tenant_copy['webhook_secret']
            safe_tenants.append(tenant_copy)
        
<<<<<<< Updated upstream
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
=======
        logger.info(f"Encontrados {len(safe_tenants)} tenants con filtros: status='{status_filter}', plan='{plan_filter}'")
        return create_success_response({'tenants': safe_tenants}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        logger.error(f"Error listando tenants: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def get_tenant(event, context):
    """Obtiene información de un cliente específico"""
    try:
        tenant_id_from_path = event.get('pathParameters', {}).get('tenant_id')
        if not tenant_id_from_path:
            return create_error_response(400, "Falta el tenant_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Obteniendo información de tenant: {tenant_id_from_path}")
        
        tenant, error_resp = get_item_or_404(tenant_table, {'tenant_id': tenant_id_from_path}, "Cliente", decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
        
<<<<<<< Updated upstream
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
=======
        # Eliminar información sensible antes de devolver
        tenant_copy = tenant.copy()
        if 'api_key' in tenant_copy: del tenant_copy['api_key']
        if 'webhook_secret' in tenant_copy: del tenant_copy['webhook_secret']
        
        logger.info(f"Información de tenant obtenida: {tenant_id_from_path}")
        return create_success_response({'tenant': tenant_copy}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        logger.error(f"Error obteniendo tenant: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def get_tenant_plans(event, context):
    """Obtiene lista de planes disponibles y sus características"""
    try:
        logger.info("Obteniendo planes disponibles")
        # TENANT_PLANS es una constante global, no hay datos sensibles directos aquí que necesiten DecimalEncoder para la estructura del plan en sí.
        return create_success_response({'plans': TENANT_PLANS})
    except Exception as e:
        logger.error(f"Error obteniendo planes: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def update_tenant_plan(event, context):
    """Actualiza el plan de un tenant y sus límites asociados"""
    try:
        tenant_id_from_path = event.get('pathParameters', {}).get('tenant_id')
        if not tenant_id_from_path:
            return create_error_response(400, "Falta el tenant_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        body = json.loads(event.get('body', '{}'))
        
        validation_err = validate_required_fields(body, ['plan'], decimal_encoder_cls=DecimalEncoder)
        if validation_err:
             return create_error_response(validation_err["status_code"], validation_err["error_message"], validation_err["error_code"], decimal_encoder_cls=DecimalEncoder)

        new_plan = body.get('plan')
        
        plan_validation_error = validate_plan_or_error(new_plan, TENANT_PLANS, decimal_encoder_cls=DecimalEncoder)
        if plan_validation_error:
            return create_error_response(plan_validation_error["status_code"], plan_validation_error["error_message"], plan_validation_error["error_code"], decimal_encoder_cls=DecimalEncoder)
        
        logger.info(f"Actualizando plan de tenant {tenant_id_from_path} a: {new_plan}")
        
        tenant, error_resp = get_item_or_404(tenant_table, {'tenant_id': tenant_id_from_path}, "Cliente", decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
        
        old_plan = tenant.get('plan', 'free')
        plan_config = TENANT_PLANS[new_plan] # Plan ya validado
        
        update_response = tenant_table.update_item(
            Key={'tenant_id': tenant_id_from_path},
            UpdateExpression="set plan = :p, limits = :l, features = :f, updated_at = :t, plan_history = list_append(if_not_exists(plan_history, :empty_list), :h)",
            ExpressionAttributeValues={
                ':p': new_plan,
                ':l': { 'max_users': plan_config['max_users'], 'max_documents': plan_config['max_documents'], 'max_storage_mb': plan_config['max_storage_mb'] },
                ':f': plan_config['features'], ':t': datetime.now().isoformat(),
                ':empty_list': [], ':h': [{'date': datetime.now().isoformat(), 'old_plan': old_plan, 'new_plan': new_plan}]
            },
            ReturnValues="ALL_NEW" # Devolver todo el item actualizado para confirmar
        )
        logger.info(f"Plan actualizado para tenant: {tenant_id_from_path}. Nuevos atributos: {update_response.get('Attributes')}")
        
        # Extraer los datos relevantes para la respuesta del cliente de Attributes
        updated_tenant_info = update_response.get('Attributes', {})
        response_data = {
            'message': 'Plan actualizado correctamente',
            'tenant_id': tenant_id_from_path,
            'new_plan': updated_tenant_info.get('plan'),
            'limits': updated_tenant_info.get('limits'),
            'features': updated_tenant_info.get('features')
        }
        return create_success_response(response_data, decimal_encoder_cls=DecimalEncoder)
        
    except json.JSONDecodeError as json_err:
        logger.error(f"Error parseando JSON en update_tenant_plan: {str(json_err)}")
        return create_error_response(400, "Cuerpo de solicitud JSON inválido.", error_code="INVALID_JSON", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error actualizando plan: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def get_tenant_usage(event, context):
    """Obtiene estadísticas de uso de un tenant"""
    try:
        tenant_id_from_path = event.get('pathParameters', {}).get('tenant_id')
        if not tenant_id_from_path:
            return create_error_response(400, "Falta el tenant_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Obteniendo uso de tenant: {tenant_id_from_path}")
        
        tenant, error_resp = get_item_or_404(tenant_table, {'tenant_id': tenant_id_from_path}, "Cliente", decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
        
        # La función calculate_tenant_usage ya actualiza el item del tenant con el uso más reciente.
        # Así que, después de llamarla, el 'usage' en el item 'tenant' que obtuvimos podría estar desactualizado.
        # Sería mejor obtener el tenant DESPUÉS de calcular el uso, o que calculate_tenant_usage devuelva el item actualizado.
        # Por ahora, usaremos el usage calculado y los límites del tenant obtenido inicialmente.
        
        current_usage = calculate_tenant_usage(tenant_id_from_path) # Esta función ya loguea y actualiza el tenant.
        if 'error' in current_usage: # Si hubo un error calculando el uso
            return create_error_response(500, f"Error calculando el uso del tenant: {current_usage['error']}", decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

        limits = tenant.get('limits', {'max_users': 0, 'max_documents': 0, 'max_storage_mb': 0})
        usage_percentages = {}
        
        usage_map = {
            'max_users': 'users_count',
            'max_documents': 'documents_count',
            'max_storage_mb': 'storage_used_mb'
        }

        for limit_key, usage_field in usage_map.items():
            limit_value = limits.get(limit_key, 0)
            current_value = current_usage.get(usage_field, 0)
            if limit_value < 0: # Ilimitado
                usage_percentages[usage_field] = 0
            else:
                usage_percentages[usage_field] = min(100, round((current_value / limit_value) * 100, 2)) if limit_value > 0 else 100 if current_value > 0 else 0
        
        usage_info = {
            'tenant_id': tenant_id_from_path,
            'plan': tenant.get('plan', 'free'),
            'limits': limits,
            'current_usage': current_usage,
            'usage_percentages': usage_percentages
        }
        return create_success_response(usage_info, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        logger.error(f"Error obteniendo uso de tenant: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

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
>>>>>>> Stashed changes
        }