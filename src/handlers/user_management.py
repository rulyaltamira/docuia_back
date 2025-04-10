# docpilot-backend/src/handlers/user_management.py
import json
import os
import uuid
import boto3
import logging
from datetime import datetime
import secrets

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
cognito = boto3.client('cognito-idp')
user_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
tenant_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
USER_POOL_ID = os.environ.get('USER_POOL_ID')

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
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        email = body.get('email', '').lower().strip()
        tenant_id = body.get('tenant_id')
        role = body.get('role', 'user')
        
        # Validaciones
        if not email or not tenant_id:
            logger.error("Faltan campos obligatorios: email o tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Email y tenant_id son obligatorios'})
            }
        
        logger.info(f"Creando nuevo usuario: {email}, tenant: {tenant_id}, rol: {role}")
        
        # Verificar que el tenant existe y está activo
        tenant_response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Cliente no encontrado'})
            }
        
        if tenant_response['Item'].get('status') != 'active':
            logger.error(f"Tenant no activo: {tenant_id}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'El cliente no está activo'})
            }
        
        # Generar contraseña temporal
        temp_password = generate_temp_password()
        
        # Crear usuario en Cognito
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
                MessageAction='SUPPRESS'  # Enviaremos nuestro propio email
            )
            
            cognito_id = cognito_response['User']['Username']
            logger.info(f"Usuario creado en Cognito: {cognito_id}")
            
        except Exception as e:
            logger.error(f"Error al crear usuario en Cognito: {str(e)}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': f"Error al crear usuario en Cognito: {str(e)}"})
            }
        
        # Crear usuario en DynamoDB
        user_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        user_table.put_item(Item={
            'user_id': user_id,
            'tenant_id': tenant_id,
            'email': email,
            'role': role,
            'status': 'active',
            'created_at': timestamp,
            'last_login': None,
            'preferences': body.get('preferences', {}),
            'cognito_id': cognito_id
        })
        
        logger.info(f"Usuario guardado en DynamoDB: {user_id}")
        
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
        }
        
    except Exception as e:
        logger.error(f"Error creando usuario: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def update_user(event, context):
    """Actualiza información de un usuario existente"""
    try:
        # Obtener user_id de la ruta
        user_id = event['pathParameters']['user_id']
        
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        logger.info(f"Actualizando usuario: {user_id}")
        
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
        
        # Construir expresión de actualización
        update_expression = "set "
        expression_values = {}
        
        # Campos que se pueden actualizar
        fields = ['role', 'status', 'preferences']
        
        for field in fields:
            if field in body:
                if len(expression_values) > 0:
                    update_expression += ", "
                update_expression += f"{field} = :{field}"
                expression_values[f':{field}'] = body[field]
        
        # Si no hay nada que actualizar
        if not expression_values:
            logger.warning("No se proporcionaron campos para actualizar")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'No se proporcionaron campos para actualizar'})
            }
        
        # Actualizar en DynamoDB
        user_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )
        
        logger.info(f"Usuario actualizado en DynamoDB: {user_id}")
        
        # Actualizar atributos en Cognito si es necesario
        if 'role' in body:
            cognito.admin_update_user_attributes(
                UserPoolId=USER_POOL_ID,
                Username=user['cognito_id'],
                UserAttributes=[
                    {'Name': 'custom:role', 'Value': body['role']}
                ]
            )
            logger.info(f"Rol actualizado en Cognito para usuario: {user['cognito_id']}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Usuario actualizado correctamente'})
        }
        
    except Exception as e:
        logger.error(f"Error actualizando usuario: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def delete_user(event, context):
    """Desactiva un usuario (no lo elimina)"""
    try:
        # Obtener user_id de la ruta
        user_id = event['pathParameters']['user_id']
        
        logger.info(f"Desactivando usuario: {user_id}")
        
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
        
        # Desactivar usuario en DynamoDB
        user_table.update_item(
            Key={'user_id': user_id},
            UpdateExpression="set #status = :s",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':s': 'inactive'}
        )
        
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
        
    except Exception as e:
        logger.error(f"Error desactivando usuario: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def list_users(event, context):
    """Lista usuarios por tenant"""
    try:
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
        
        users = response.get('Items', [])
        
        logger.info(f"Encontrados {len(users)} usuarios para tenant: {tenant_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'users': users})
        }
        
    except Exception as e:
        logger.error(f"Error listando usuarios: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_user(event, context):
    """Obtiene información de un usuario específico"""
    try:
        # Obtener user_id de la ruta
        user_id = event['pathParameters']['user_id']
        
        logger.info(f"Obteniendo información de usuario: {user_id}")
        
        # Obtener información del usuario
        response = user_table.get_item(Key={'user_id': user_id})
        if 'Item' not in response:
            logger.error(f"Usuario no encontrado: {user_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Usuario no encontrado'})
            }
        
        user = response['Item']
        
        logger.info(f"Información de usuario obtenida: {user_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'user': user})
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo usuario: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def generate_temp_password():
    """Genera una contraseña temporal segura"""
    return f"DocP!{secrets.token_hex(8)}"