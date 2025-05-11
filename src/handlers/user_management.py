# docpilot-backend/src/handlers/user_management.py
import json
import os
import uuid
import boto3
import logging
from datetime import datetime
import secrets

<<<<<<< Updated upstream
=======
# Importar utilidades
from src.utils.tenant_limits_validator import can_create_user, update_tenant_usage
from src.utils.auth_utils import get_tenant_id_or_error
from src.utils.response_helpers import create_success_response, create_error_response
from src.utils.field_validator import validate_required_fields
from src.utils.db_helpers import get_item_or_404
from src.utils.validation_helpers import validate_required_fields

>>>>>>> Stashed changes
# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
cognito = boto3.client('cognito-idp')
user_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
tenant_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
USER_POOL_ID = os.environ.get('USER_POOL_ID')

# DecimalEncoder debería estar definido aquí o importado
# class DecimalEncoder(json.JSONEncoder): ... 

def lambda_handler(event, context):
    """Maneja operaciones CRUD para usuarios"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'POST' and path == '/users':
        return create_user(event, context)
    elif http_method == 'PUT' and '/users/' in path:
        return update_user(event, context)
    elif http_method == 'DELETE' and '/users/' in path:
        return delete_user(event, context)
    elif http_method == 'GET' and path == '/users':
        return list_users(event, context)
    elif http_method == 'GET' and '/users/' in path:
        return get_user(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Operación no válida'})
        }

def create_user(event, context):
    """Crea un nuevo usuario en el sistema"""
    try:
        body = json.loads(event.get('body', '{}'))
        
        required_fields = ['email', 'tenant_id']
        validation_error = validate_required_fields(body, required_fields)
        if validation_error: 
            return create_error_response(
                status_code=validation_error["status_code"],
                message=validation_error["error_message"],
                error_code=validation_error["error_code"],
                decimal_encoder_cls=DecimalEncoder
            )

        email = body.get('email', '').lower().strip()
        tenant_id = body.get('tenant_id') 
        role = body.get('role', 'user')
        
        logger.info(f"Creando nuevo usuario: {email}, tenant: {tenant_id}, rol: {role}")
        
        tenant, error_resp = get_item_or_404(tenant_table, {'tenant_id': tenant_id}, "Cliente", decimal_encoder_cls=DecimalEncoder)
        if error_resp: 
            return error_resp 
        
        if tenant.get('status') != 'active':
            logger.error(f"Tenant no activo: {tenant_id}")
            return create_error_response(400, 'El cliente no está activo', error_code="TENANT_NOT_ACTIVE", decimal_encoder_cls=DecimalEncoder)
        
<<<<<<< Updated upstream
        # Generar contraseña temporal
=======
        limits_check = can_create_user(tenant_id)
        if not limits_check['can_proceed']:
            logger.warning(f"No se puede crear usuario: {limits_check['reason']}")
            # Usar create_error_response
            return create_error_response(403, limits_check['reason'], error_code="LIMIT_REACHED_USER", decimal_encoder_cls=DecimalEncoder)
        
>>>>>>> Stashed changes
        temp_password = generate_temp_password()
        
        try:
            cognito_response = cognito.admin_create_user(
                UserPoolId=USER_POOL_ID,
                Username=email,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'email_verified', 'Value': 'true'},
                    {'Name': 'custom:tenant_id', 'Value': tenant_id},
                    {'Name': 'custom:role', 'Value': role}
                ],
                TemporaryPassword=temp_password,
                MessageAction='SUPPRESS'  
            )
            cognito_id = cognito_response['User']['Username']
            logger.info(f"Usuario creado en Cognito: {cognito_id}")
        except Exception as e_cognito:
            logger.error(f"Error al crear usuario en Cognito: {str(e_cognito)}")
            if "UsernameExistsException" in str(e_cognito):
                return create_error_response(409, "El correo electrónico ya está en uso.", error_code="EMAIL_EXISTS_COGNITO", decimal_encoder_cls=DecimalEncoder)
            # Usar create_error_response para otros errores de Cognito
            return create_error_response(400, f"Error al interactuar con el servicio de usuarios: {str(e_cognito)}", error_code="COGNITO_ERROR", decimal_encoder_cls=DecimalEncoder)
        
        user_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        user_item = {
            'user_id': user_id, 'tenant_id': tenant_id, 'email': email, 'role': role,
            'status': 'active', 'created_at': timestamp, 'last_login': None,
            'preferences': body.get('preferences', {}), 'cognito_id': cognito_id
        }
        user_table.put_item(Item=user_item)
        logger.info(f"Usuario guardado en DynamoDB: {user_id}")
<<<<<<< Updated upstream
        
        # TODO: Enviar email de bienvenida con instrucciones
        
        return {
            'statusCode': 201,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'user_id': user_id,
                'email': email,
                'role': role,
                'temp_password': temp_password,  # Solo en desarrollo, eliminar en producción
                'created_at': timestamp
            })
=======
        update_tenant_usage(tenant_id, 'add_user')
        
        response_data = {
            'user_id': user_id, 'email': email, 'role': role, 'created_at': timestamp
            # temp_password no se incluye en la respuesta por seguridad, incluso en dev.
            # Si se necesita para pruebas, obtenerla de otra manera o loguearla solo en dev.
>>>>>>> Stashed changes
        }
        return create_success_response(response_data, status_code=201, decimal_encoder_cls=DecimalEncoder)
        
    except json.JSONDecodeError as json_error:
        logger.error(f"Error parseando JSON del body en create_user: {str(json_error)}")
        return create_error_response(400, "El cuerpo de la solicitud no es un JSON válido.", error_code="INVALID_JSON_BODY", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error creando usuario: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def update_user(event, context):
    """Actualiza información de un usuario existente"""
    try:
        user_id = event.get('pathParameters', {}).get('user_id')
        if not user_id:
            return create_error_response(400, "Falta el user_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        body = json.loads(event.get('body', '{}'))
        logger.info(f"Actualizando usuario: {user_id} con body: {body}")
        
        # Verificar que el usuario existe
        user, error_resp = get_item_or_404(user_table, {'user_id': user_id}, "Usuario", decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
        
        update_expression_parts = []
        expression_values = {}
        expression_names = {} # Para manejar atributos que son palabras reservadas

        allowed_fields_to_update = {'role': 'custom:role', 'status': '#user_status', 'preferences': 'preferences'}
        # 'status' es una palabra reservada en DynamoDB, por eso se usa #user_status como placeholder

        for field_key, cognito_attr_name in allowed_fields_to_update.items():
            if field_key in body:
                placeholder = f":val_{field_key}"
                if field_key == 'status': # Nombre de atributo reservado
                    update_expression_parts.append(f"#user_status = {placeholder}")
                    expression_names['#user_status'] = 'status'
                else:
                    update_expression_parts.append(f"{field_key} = {placeholder}")
                expression_values[placeholder] = body[field_key]
        
        if not update_expression_parts:
            return create_error_response(400, "No se proporcionaron campos válidos para actualizar.", decimal_encoder_cls=DecimalEncoder)
        
        update_expression = "set " + ", ".join(update_expression_parts)
        
        update_params = {
            'Key': {'user_id': user_id},
            'UpdateExpression': update_expression,
            'ExpressionAttributeValues': expression_values,
            'ReturnValues': "UPDATED_NEW"
        }
        if expression_names: # Solo añadir si no está vacío
            update_params['ExpressionAttributeNames'] = expression_names
            
        updated_item_response = user_table.update_item(**update_params)
        logger.info(f"Usuario actualizado en DynamoDB: {user_id}. Respuesta: {updated_item_response}")
        
        # Actualizar atributos en Cognito si es necesario
        if 'role' in body and 'cognito_id' in user:
            try:
                cognito.admin_update_user_attributes(
                    UserPoolId=USER_POOL_ID,
                    Username=user['cognito_id'],
                    UserAttributes=[
                        {'Name': 'custom:role', 'Value': body['role']}
                    ]
                )
                logger.info(f"Rol actualizado en Cognito para usuario: {user['cognito_id']}")
            except Exception as e_cognito_update:
                # Loguear error pero continuar, ya que DynamoDB se actualizó.
                # Considerar una estrategia de compensación si Cognito falla críticamente.
                logger.error(f"Error actualizando rol en Cognito para {user['cognito_id']}: {str(e_cognito_update)}")

        # Considerar si se debe deshabilitar/habilitar en Cognito si el status cambia
        if 'status' in body and body['status'] == 'inactive' and 'cognito_id' in user:
            try:
                cognito.admin_disable_user(UserPoolId=USER_POOL_ID, Username=user['cognito_id'])
                logger.info(f"Usuario {user['cognito_id']} deshabilitado en Cognito.")
            except Exception as e_disable_cognito:
                logger.error(f"Error deshabilitando usuario en Cognito {user['cognito_id']}: {str(e_disable_cognito)}")
        elif 'status' in body and body['status'] == 'active' and 'cognito_id' in user:
             # Verificar si el usuario estaba previamente deshabilitado en Cognito antes de intentar habilitar
             # Esto puede requerir una llamada admin_get_user a Cognito primero
            try:
                cognito_user_details = cognito.admin_get_user(UserPoolId=USER_POOL_ID, Username=user['cognito_id'])
                if not cognito_user_details.get('Enabled', True):
                    cognito.admin_enable_user(UserPoolId=USER_POOL_ID, Username=user['cognito_id'])
                    logger.info(f"Usuario {user['cognito_id']} habilitado en Cognito.")
            except Exception as e_enable_cognito:
                logger.error(f"Error habilitando usuario en Cognito {user['cognito_id']}: {str(e_enable_cognito)}")
        
        return create_success_response({'message': 'Usuario actualizado correctamente', 'updated_attributes': updated_item_response.get('Attributes')}, decimal_encoder_cls=DecimalEncoder)
        
    except json.JSONDecodeError as json_error:
        logger.error(f"Error parseando JSON del body en update_user: {str(json_error)}")
        return create_error_response(400, "El cuerpo de la solicitud no es un JSON válido.", error_code="INVALID_JSON_BODY", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error actualizando usuario: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def delete_user(event, context):
    """Desactiva un usuario (no lo elimina físicamente)"""
    try:
        user_id = event.get('pathParameters', {}).get('user_id')
        if not user_id:
            return create_error_response(400, "Falta el user_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Solicitud para desactivar usuario: {user_id}")
        
        user, error_resp = get_item_or_404(user_table, {'user_id': user_id}, "Usuario", decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
        
<<<<<<< Updated upstream
        # Verificar que el usuario existe
        response = user_table.get_item(Key={'user_id': user_id})
        if 'Item' not in response:
            logger.error(f"Usuario no encontrado: {user_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Usuario no encontrado'})
            }
        
        user = response['Item']
=======
        tenant_id = user.get('tenant_id') # Necesario para update_tenant_usage
        cognito_id = user.get('cognito_id')

        if user.get('status') == 'inactive':
            logger.info(f"Usuario {user_id} ya está desactivado.")
            return create_success_response({'message': 'Usuario ya está desactivado'}, decimal_encoder_cls=DecimalEncoder)
>>>>>>> Stashed changes
        
        user_table.update_item(
            Key={'user_id': user_id},
<<<<<<< Updated upstream
            UpdateExpression="set #status = :s",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':s': 'inactive'}
=======
            UpdateExpression="set #user_status = :s, deactivated_at = :d",
            ExpressionAttributeNames={'#user_status': 'status'},
            ExpressionAttributeValues={':s': 'inactive', ':d': datetime.now().isoformat()}
>>>>>>> Stashed changes
        )
        logger.info(f"Usuario {user_id} desactivado en DynamoDB.")
        
<<<<<<< Updated upstream
        logger.info(f"Usuario desactivado en DynamoDB: {user_id}")
        
        # Deshabilitar usuario en Cognito
        cognito.admin_disable_user(
            UserPoolId=USER_POOL_ID,
            Username=user['cognito_id']
        )
        
        logger.info(f"Usuario deshabilitado en Cognito: {user['cognito_id']}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Usuario desactivado correctamente'})
        }
=======
        if cognito_id:
            try:
                cognito.admin_disable_user(UserPoolId=USER_POOL_ID, Username=cognito_id)
                logger.info(f"Usuario {cognito_id} deshabilitado en Cognito.")
            except Exception as e_cognito_disable:
                # Loguear el error pero continuar, ya que el estado principal está en DynamoDB
                logger.error(f"Error deshabilitando usuario {cognito_id} en Cognito: {str(e_cognito_disable)}")
        else:
            logger.warning(f"No se encontró cognito_id para el usuario {user_id}, no se pudo deshabilitar en Cognito.")

        if tenant_id: # Solo actualizar uso si tenemos tenant_id
            update_tenant_usage(tenant_id, 'remove_user')
        else:
            logger.warning(f"No se encontró tenant_id para el usuario {user_id}, no se pudo actualizar el uso del tenant.")
            
        return create_success_response({'message': 'Usuario desactivado correctamente'}, decimal_encoder_cls=DecimalEncoder)
>>>>>>> Stashed changes
        
    except Exception as e:
        logger.error(f"Error desactivando usuario {user_id if 'user_id' in locals() else 'desconocido'}: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def list_users(event, context):
    """Lista usuarios por tenant"""
    try:
<<<<<<< Updated upstream
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Listando usuarios para tenant: {tenant_id}")
        
        # Scanear usuarios por tenant (en producción, usar un GSI)
        response = user_table.scan(
            FilterExpression='tenant_id = :t',
            ExpressionAttributeValues={':t': tenant_id}
        )
=======
        # Obtener tenant_id usando el helper
        tenant_id, error_resp = get_tenant_id_or_error(event)
        if error_resp:
            return error_resp
        
        query_params = event.get('queryStringParameters', {}) or {}
        status_filter = query_params.get('status', 'active')
        logger.info(f"Listando usuarios para tenant: {tenant_id}, status: {status_filter}")
        
        filter_expression = 'tenant_id = :t'
        expression_values = {':t': tenant_id}
        expression_names = None 

        if status_filter != 'all':
            filter_expression += ' AND #status_attr = :s' 
            expression_values[':s'] = status_filter
            expression_names = {'#status_attr': 'status'}
>>>>>>> Stashed changes
        
        scan_params = {
            'FilterExpression': filter_expression,
            'ExpressionAttributeValues': expression_values
        }
        if expression_names:
            scan_params['ExpressionAttributeNames'] = expression_names
            
        response = user_table.scan(**scan_params)
        users = response.get('Items', [])
        
<<<<<<< Updated upstream
=======
        if 'role' in query_params:
            role_filter = query_params.get('role')
            users = [user for user in users if user.get('role') == role_filter]
        
        users.sort(key=lambda x: x.get('created_at', ''), reverse=True)
>>>>>>> Stashed changes
        logger.info(f"Encontrados {len(users)} usuarios para tenant: {tenant_id}")
        
        return create_success_response({'users': users})
        
    except Exception as e:
        logger.error(f"Error listando usuarios: {str(e)}")
        return create_error_response(500, str(e), is_internal_error=True)

def get_user(event, context):
    """Obtiene información de un usuario específico"""
    try:
        user_id = event.get('pathParameters', {}).get('user_id')
        if not user_id:
            return create_error_response(400, "Falta el user_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Obteniendo información de usuario: {user_id}")
        
        user, error_resp = get_item_or_404(user_table, {'user_id': user_id}, "Usuario", decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
        
<<<<<<< Updated upstream
        user = response['Item']
=======
        # Obtener información del tenant para incluir en la respuesta (lógica original mantenida)
        if user.get('tenant_id'):
            try:
                # No es crítico si esto falla, así que no usamos get_item_or_404 aquí para no sobreescribir el error principal.
                tenant_response = tenant_table.get_item(Key={'tenant_id': user['tenant_id']})
                if 'Item' in tenant_response:
                    tenant = tenant_response['Item']
                    user['tenant_name'] = tenant.get('name', '')
                else:
                    logger.warning(f"Tenant {user['tenant_id']} no encontrado para el usuario {user_id}, no se pudo añadir tenant_name.")
            except Exception as e_tenant:
                logger.warning(f"Error obteniendo información del tenant para usuario {user_id}: {str(e_tenant)}")
>>>>>>> Stashed changes
        
        logger.info(f"Información de usuario obtenida: {user_id}")
        return create_success_response({'user': user}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        logger.error(f"Error obteniendo usuario {user_id if 'user_id' in locals() else 'desconocido'}: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def generate_temp_password():
    """Genera una contraseña temporal segura"""
    return f"DocP!{secrets.token_hex(8)}"