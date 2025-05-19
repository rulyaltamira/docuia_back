# docpilot-backend/src/utils/auth_middleware.py
# Middleware de autorización para control de acceso granular

import os
import boto3
import logging
import json
from functools import wraps

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuración de servicios AWS
dynamodb = boto3.resource('dynamodb')
roles_table = dynamodb.Table(os.environ.get('ROLES_TABLE'))
permissions_table = dynamodb.Table(os.environ.get('PERMISSIONS_TABLE'))
user_roles_table = dynamodb.Table(os.environ.get('USER_ROLES_TABLE'))
role_permissions_table = dynamodb.Table(os.environ.get('ROLE_PERMISSIONS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))

# Importar el middleware CORS para usarlo en las respuestas
from src.utils.cors_middleware import add_cors_headers

def validate_permission(user_id, permission, resource=None, tenant_id=None):
    """
    Verifica si un usuario tiene un permiso específico sobre un recurso
    
    Args:
        user_id (str): ID del usuario
        permission (str): Permiso a verificar (ej: 'document:read', 'tenant:edit')
        resource (str, optional): Recurso específico (ej: ID de documento)
        tenant_id (str, optional): ID del tenant
        
    Returns:
        bool: True si tiene permiso, False en caso contrario
    """
    try:
        # Si no se proporciona tenant_id, buscarlo en la información del usuario
        if not tenant_id:
            user_response = users_table.get_item(Key={'user_id': user_id})
            if 'Item' in user_response:
                tenant_id = user_response['Item'].get('tenant_id')
                if not tenant_id:
                    logger.warning(f"Usuario {user_id} no tiene tenant_id asignado")
                    return False
            else:
                logger.warning(f"Usuario {user_id} no encontrado")
                return False
        
        # Obtener los roles del usuario
        user_roles = get_user_roles(user_id, tenant_id)
        
        if not user_roles:
            logger.warning(f"Usuario {user_id} no tiene roles asignados para tenant {tenant_id}")
            return False
        
        # Para cada rol, verificar si tiene el permiso requerido
        for role in user_roles:
            role_id = role.get('role_id')
            
            # Verificar si el rol tiene el permiso requerido
            if has_role_permission(role_id, permission, resource, tenant_id):
                return True
        
        # Si no se encontró el permiso en ningún rol
        return False
        
    except Exception as e:
        logger.error(f"Error validando permiso '{permission}' para usuario {user_id}: {str(e)}")
        # En caso de error, preferimos denegar acceso por seguridad
        return False

def get_user_roles(user_id, tenant_id):
    """
    Obtiene los roles asignados a un usuario dentro de un tenant
    
    Args:
        user_id (str): ID del usuario
        tenant_id (str): ID del tenant
        
    Returns:
        list: Lista de roles asignados al usuario
    """
    try:
        # Consultar roles directamente asignados a este usuario
        response = user_roles_table.scan(
            FilterExpression="user_id = :u AND tenant_id = :t",
            ExpressionAttributeValues={
                ':u': user_id,
                ':t': tenant_id
            }
        )
        
        user_roles = response.get('Items', [])
        
        # Si no hay roles específicos, verificar el rol en la tabla de usuarios (retrocompatibilidad)
        if not user_roles:
            user_response = users_table.get_item(Key={'user_id': user_id})
            if 'Item' in user_response:
                user = user_response['Item']
                if user.get('tenant_id') == tenant_id and 'role' in user:
                    # Buscar el rol en la tabla de roles
                    role_response = roles_table.scan(
                        FilterExpression="tenant_id = :t AND role_name = :r",
                        ExpressionAttributeValues={
                            ':t': tenant_id,
                            ':r': user['role']
                        }
                    )
                    
                    roles = role_response.get('Items', [])
                    if roles:
                        user_roles = [{
                            'user_id': user_id,
                            'role_id': roles[0]['role_id'],
                            'tenant_id': tenant_id
                        }]
                    else:
                        # Si el rol no está en la tabla, usar un valor predeterminado 
                        # para mantener compatibilidad
                        legacy_role = "admin" if user['role'] == "admin" else "user"
                        user_roles = [{
                            'user_id': user_id,
                            'role_id': f"legacy_{legacy_role}",
                            'tenant_id': tenant_id
                        }]
        
        return user_roles
        
    except Exception as e:
        logger.error(f"Error obteniendo roles para usuario {user_id}: {str(e)}")
        return []

def has_role_permission(role_id, permission, resource=None, tenant_id=None):
    """
    Verifica si un rol tiene un permiso específico
    
    Args:
        role_id (str): ID del rol
        permission (str): Permiso a verificar
        resource (str, optional): Recurso específico
        tenant_id (str, optional): ID del tenant
        
    Returns:
        bool: True si el rol tiene el permiso, False en caso contrario
    """
    try:
        # Primero manejar roles legacy (para compatibilidad)
        if role_id == "legacy_admin":
            # Los administradores legacy tienen todos los permisos
            return True
        elif role_id == "legacy_user":
            # Para usuarios legacy, verificar si es un permiso básico
            basic_permissions = [
                'document:read', 'document:create', 'document:download',
                'profile:read', 'profile:edit'
            ]
            return permission in basic_permissions
        
        # Para roles normales, verificar en la tabla de permisos
        response = role_permissions_table.scan(
            FilterExpression="role_id = :r AND permission = :p",
            ExpressionAttributeValues={
                ':r': role_id,
                ':p': permission
            }
        )
        
        role_permissions = response.get('Items', [])
        
        # Si se encontró una asignación de permiso explícita
        if role_permissions:
            # Si hay un recurso específico, verificar si coincide
            if resource:
                for perm in role_permissions:
                    # Si hay una restricción de recurso en el permiso
                    if 'resource_id' in perm:
                        # El permiso solo aplica al recurso específico
                        if perm['resource_id'] == resource:
                            return True
                    else:
                        # El permiso aplica a todos los recursos de este tipo
                        return True
                
                # No se encontró un permiso para el recurso específico
                return False
            else:
                # No hay recurso específico, el permiso general es suficiente
                return True
        
        # Verificar permisos comodín (ej: document:* incluye document:read, document:create, etc.)
        wildcard_permission = permission.split(':')[0] + ':*'
        
        response = role_permissions_table.scan(
            FilterExpression="role_id = :r AND permission = :p",
            ExpressionAttributeValues={
                ':r': role_id,
                ':p': wildcard_permission
            }
        )
        
        wildcard_permissions = response.get('Items', [])
        
        return len(wildcard_permissions) > 0
        
    except Exception as e:
        logger.error(f"Error verificando permiso '{permission}' para rol {role_id}: {str(e)}")
        return False

def get_user_permissions(user_id, tenant_id=None):
    """
    Obtiene todos los permisos que tiene un usuario
    
    Args:
        user_id (str): ID del usuario
        tenant_id (str, optional): ID del tenant
        
    Returns:
        list: Lista de permisos del usuario
    """
    try:
        # Si no se proporciona tenant_id, buscarlo en la información del usuario
        if not tenant_id:
            user_response = users_table.get_item(Key={'user_id': user_id})
            if 'Item' in user_response:
                tenant_id = user_response['Item'].get('tenant_id')
                if not tenant_id:
                    logger.warning(f"Usuario {user_id} no tiene tenant_id asignado")
                    return []
            else:
                logger.warning(f"Usuario {user_id} no encontrado")
                return []
        
        # Obtener los roles del usuario
        user_roles = get_user_roles(user_id, tenant_id)
        
        if not user_roles:
            # Si no hay roles específicos pero es admin o user, usar permisos legacy
            user_response = users_table.get_item(Key={'user_id': user_id})
            if 'Item' in user_response:
                user = user_response['Item']
                if user.get('role') == 'admin':
                    return ['*']  # Admin tiene todos los permisos
                elif user.get('role') == 'user':
                    return [
                        'document:read', 'document:create', 'document:download',
                        'profile:read', 'profile:edit'
                    ]
            return []
        
        # Conjunto para almacenar permisos únicos
        all_permissions = set()
        
        # Para cada rol, obtener sus permisos
        for role in user_roles:
            role_id = role.get('role_id')
            
            # Manejar roles legacy
            if role_id == "legacy_admin":
                all_permissions.add('*')  # Admin tiene todos los permisos
                break  # No es necesario seguir comprobando
            elif role_id == "legacy_user":
                basic_permissions = [
                    'document:read', 'document:create', 'document:download',
                    'profile:read', 'profile:edit'
                ]
                for perm in basic_permissions:
                    all_permissions.add(perm)
                continue
            
            # Para roles normales, consultar la tabla de permisos
            response = role_permissions_table.scan(
                FilterExpression="role_id = :r",
                ExpressionAttributeValues={
                    ':r': role_id
                }
            )
            
            for perm in response.get('Items', []):
                all_permissions.add(perm['permission'])
        
        return list(all_permissions)
        
    except Exception as e:
        logger.error(f"Error obteniendo permisos para usuario {user_id}: {str(e)}")
        return []

def filter_by_permission(items, user_id, permission, resource_field=None, tenant_id=None):
    """
    Filtra una lista de items según los permisos del usuario
    
    Args:
        items (list): Lista de items a filtrar
        user_id (str): ID del usuario
        permission (str): Permiso requerido (ej: 'document:read')
        resource_field (str, optional): Campo que contiene el ID del recurso
        tenant_id (str, optional): ID del tenant
        
    Returns:
        list: Lista filtrada de items
    """
    try:
        # Verificar si el usuario tiene permiso global
        if validate_permission(user_id, permission, None, tenant_id):
            # Si tiene permiso global, devolver todos los items
            return items
        
        # Si no tiene permiso global, pero se especificó un campo de recurso
        if resource_field:
            # Filtrar items uno por uno
            filtered_items = []
            for item in items:
                resource_id = item.get(resource_field)
                if resource_id and validate_permission(user_id, permission, resource_id, tenant_id):
                    filtered_items.append(item)
            
            return filtered_items
        
        # Si no hay campo de recurso y no tiene permiso global, denegar acceso a todo
        return []
        
    except Exception as e:
        logger.error(f"Error filtrando items por permiso '{permission}': {str(e)}")
        return []

def require_permission(permission, resource_param=None):
    """
    Decorador para requerir un permiso específico en funciones Lambda
    
    Args:
        permission (str): Permiso requerido (ej: 'document:read')
        resource_param (str, optional): Nombre del parámetro que contiene el ID del recurso
        
    Returns:
        function: Decorador que verifica el permiso
    """
    def decorator(func):
        @wraps(func)
        def wrapper(event, context):
            try:
                # Extraer user_id y tenant_id de la solicitud
                user_id = None
                tenant_id = None
                
                # Primero buscar en query params
                query_params = event.get('queryStringParameters', {}) or {}
                tenant_id = query_params.get('tenant_id')
                user_id = query_params.get('user_id')
                
                # Si no están en query params, buscar en el body
                if not tenant_id or not user_id:
                    if event.get('body'):
                        body = json.loads(event.get('body', '{}'))
                        tenant_id = tenant_id or body.get('tenant_id')
                        user_id = user_id or body.get('user_id')
                
                # También buscar en los headers
                headers = event.get('headers', {}) or {}
                tenant_id = tenant_id or headers.get('x-tenant-id')
                user_id = user_id or headers.get('x-user-id')
                
                # Verificar que tengamos los valores necesarios
                if not user_id:
                    return {
                        'statusCode': 401,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'Se requiere user_id para autorización'})
                    }
                
                if not tenant_id:
                    return {
                        'statusCode': 400,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'Se requiere tenant_id para autorización'})
                    }
                
                # Obtener el recurso si se especificó un parámetro
                resource = None
                if resource_param:
                    # Buscar en path parameters
                    if 'pathParameters' in event and event['pathParameters']:
                        resource = event['pathParameters'].get(resource_param)
                    
                    # Buscar en query params si no está en path
                    if not resource:
                        resource = query_params.get(resource_param)
                    
                    # Buscar en body si no está en otros lugares
                    if not resource and event.get('body'):
                        body = json.loads(event.get('body', '{}')) if isinstance(event.get('body'), str) else event.get('body', {})
                        resource = body.get(resource_param)
                
                # Validar el permiso
                if not validate_permission(user_id, permission, resource, tenant_id):
                    logger.warning(f"Acceso denegado: Usuario {user_id} no tiene permiso '{permission}' para recurso {resource}")
                    return {
                        'statusCode': 403,
                        'headers': add_cors_headers({'Content-Type': 'application/json'}),
                        'body': json.dumps({'error': 'No tiene permiso para realizar esta acción'})
                    }
                
                # Si tiene permiso, ejecutar la función original
                return func(event, context)
            
            except Exception as e:
                logger.error(f"Error en middleware de autorización: {str(e)}")
                return {
                    'statusCode': 500,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': f"Error de autorización: {str(e)}"})
                }
        
        return wrapper
    
    return decorator