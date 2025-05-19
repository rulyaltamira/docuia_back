# docpilot-backend/src/handlers/role_management.py
# Gestión de roles y permisos para control de acceso granular

import json
import os
import boto3
import logging
import uuid
from datetime import datetime

# Importar utilidades
from src.utils.auth_middleware import validate_permission, require_permission, get_user_permissions, get_user_roles
from src.utils.response_helper import success_response, error_response, created_response
from src.utils.cors_middleware import cors_wrapper, add_cors_headers

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
roles_table = dynamodb.Table(os.environ.get('ROLES_TABLE'))
permissions_table = dynamodb.Table(os.environ.get('PERMISSIONS_TABLE'))
user_roles_table = dynamodb.Table(os.environ.get('USER_ROLES_TABLE'))
role_permissions_table = dynamodb.Table(os.environ.get('ROLE_PERMISSIONS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))

# Definir permisos del sistema
SYSTEM_PERMISSIONS = {
    # Permisos de documentos
    'document:read': 'Ver documentos',
    'document:create': 'Crear documentos',
    'document:update': 'Actualizar documentos',
    'document:delete': 'Eliminar documentos',
    'document:download': 'Descargar documentos',
    
    # Permisos de usuarios
    'user:read': 'Ver usuarios',
    'user:create': 'Crear usuarios',
    'user:update': 'Actualizar usuarios',
    'user:delete': 'Eliminar usuarios',
    
    # Permisos de roles
    'role:read': 'Ver roles',
    'role:create': 'Crear roles',
    'role:update': 'Actualizar roles',
    'role:delete': 'Eliminar roles',
    'role:assign': 'Asignar roles a usuarios',
    
    # Permisos de tenant
    'tenant:read': 'Ver información del tenant',
    'tenant:update': 'Actualizar tenant',
    'tenant:configure': 'Configurar tenant (opciones avanzadas)',
    
    # Permisos de alertas
    'alert:read': 'Ver alertas',
    'alert:manage': 'Gestionar alertas',
    'alert:rule': 'Administrar reglas de alertas',
    
    # Permisos de estadísticas
    'stats:view': 'Ver estadísticas básicas',
    'stats:advanced': 'Ver estadísticas avanzadas',
    'stats:export': 'Exportar estadísticas',
    
    # Permisos de auditoría
    'audit:view': 'Ver logs de auditoría',
    'audit:export': 'Exportar logs de auditoría',
    
    # Permisos de configuración de correo
    'email:configure': 'Configurar opciones de correo',
    
    # Permisos administrativos
    'admin:full': 'Acceso administrativo completo'
}

def lambda_handler(event, context):
    """Maneja operaciones CRUD para roles y permisos"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    # Rutas para gestión de roles
    if http_method == 'GET' and path == '/roles':
        return list_roles(event, context)
    elif http_method == 'POST' and path == '/roles':
        return create_role(event, context)
    elif http_method == 'GET' and '/roles/' in path:
        return get_role(event, context)
    elif http_method == 'PUT' and '/roles/' in path:
        return update_role(event, context)
    elif http_method == 'DELETE' and '/roles/' in path:
        return delete_role(event, context)
    
    # Rutas para gestión de permisos
    elif http_method == 'GET' and path == '/permissions':
        return list_permissions(event, context)
    elif http_method == 'GET' and path == '/permissions/system':
        return list_system_permissions(event, context)
    
    # Rutas para asignación de roles a usuarios
    elif http_method == 'POST' and path == '/user-roles':
        return assign_role_to_user(event, context)
    elif http_method == 'GET' and path == '/user-roles':
        return list_user_roles(event, context)
    elif http_method == 'DELETE' and '/user-roles/' in path:
        return remove_role_from_user(event, context)
        
    # Rutas para asignación de permisos a roles
    elif http_method == 'POST' and path == '/role-permissions':
        return assign_permission_to_role(event, context)
    elif http_method == 'GET' and path == '/role-permissions':
        return list_role_permissions(event, context)
    elif http_method == 'DELETE' and '/role-permissions/' in path:
        return remove_permission_from_role(event, context)
    
    # Ruta para obtener permisos del usuario actual
    elif http_method == 'GET' and path == '/my-permissions':
        return get_my_permissions(event, context)
    
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return error_response(400, 'Operación no válida')

# ---- Gestión de Roles ----

@require_permission('role:read')
def list_roles(event, context):
    """Lista todos los roles disponibles para un tenant"""
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Consultar roles para el tenant
        response = roles_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={
                ':t': tenant_id
            }
        )
        
        roles = response.get('Items', [])
        
        # Añadir información sobre número de usuarios por rol
        for role in roles:
            role_id = role.get('role_id')
            
            # Contar usuarios con este rol
            user_count_response = user_roles_table.scan(
                FilterExpression="role_id = :r AND tenant_id = :t",
                ExpressionAttributeValues={
                    ':r': role_id,
                    ':t': tenant_id
                }
            )
            
            role['user_count'] = len(user_count_response.get('Items', []))
        
        logger.info(f"Recuperados {len(roles)} roles para tenant: {tenant_id}")
        
        return success_response({
            'roles': roles,
            'count': len(roles)
        })
        
    except Exception as e:
        logger.error(f"Error listando roles: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:create')
def create_role(event, context):
    """Crea un nuevo rol en el sistema"""
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos obligatorios
        required_fields = ['tenant_id', 'role_name', 'description']
        missing_fields = [field for field in required_fields if field not in body]
        
        if missing_fields:
            logger.error(f"Faltan campos obligatorios: { ', '.join(missing_fields)}")
            return error_response(400, f"Campos obligatorios: { ', '.join(missing_fields)}")
        
        tenant_id = body.get('tenant_id')
        role_name = body.get('role_name')
        description = body.get('description')
        
        # Verificar que no exista un rol con el mismo nombre en el tenant
        response = roles_table.scan(
            FilterExpression="tenant_id = :t AND role_name = :n",
            ExpressionAttributeValues={
                ':t': tenant_id,
                ':n': role_name
            }
        )
        
        if response.get('Items'):
            logger.warning(f"Ya existe un rol con el nombre '{role_name}' en el tenant {tenant_id}")
            return error_response(409, f"Ya existe un rol con el nombre '{role_name}'")
        
        # Crear nuevo rol
        role_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        new_role = {
            'role_id': role_id,
            'tenant_id': tenant_id,
            'role_name': role_name,
            'description': description,
            'created_at': timestamp,
            'updated_at': timestamp,
            'created_by': body.get('created_by', 'system'),
            'is_system_role': False,  # Roles creados por usuarios nunca son de sistema
            'status': 'active'
        }
        
        # Guardar en DynamoDB
        roles_table.put_item(Item=new_role)
        
        logger.info(f"Rol creado: {role_id} - {role_name} para tenant {tenant_id}")
        
        # Asignar permisos iniciales si se proporcionaron
        initial_permissions = body.get('permissions', [])
        if initial_permissions:
            for permission in initial_permissions:
                try:
                    role_permissions_table.put_item(Item={
                        'id': str(uuid.uuid4()),
                        'role_id': role_id,
                        'permission': permission,
                        'created_at': timestamp,
                        'created_by': body.get('created_by', 'system')
                    })
                except Exception as e:
                    logger.warning(f"Error asignando permiso inicial {permission} a rol {role_id}: {str(e)}")
        
        return created_response({
            'role_id': role_id,
            'role_name': role_name,
            'description': description,
            'tenant_id': tenant_id,
            'created_at': timestamp
        })
        
    except Exception as e:
        logger.error(f"Error creando rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:read')
def get_role(event, context):
    """Obtiene detalles de un rol específico"""
    try:
        # Obtener role_id de la ruta
        role_id = event['pathParameters']['role_id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Obtener información del rol
        response = roles_table.get_item(Key={'role_id': role_id})
        
        if 'Item' not in response:
            logger.error(f"Rol no encontrado: {role_id}")
            return error_response(404, 'Rol no encontrado')
        
        role = response['Item']
        
        # Verificar que el rol pertenece al tenant
        if role.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de acceso a rol de otro tenant: {role_id}")
            return error_response(403, 'No tiene permiso para acceder a este rol')
        
        # Obtener permisos asignados al rol
        permissions_response = role_permissions_table.scan(
            FilterExpression="role_id = :r",
            ExpressionAttributeValues={
                ':r': role_id
            }
        )
        
        role_permissions = [item.get('permission') for item in permissions_response.get('Items', [])]
        
        # Contar usuarios con este rol
        user_count_response = user_roles_table.scan(
            FilterExpression="role_id = :r AND tenant_id = :t",
            ExpressionAttributeValues={
                ':r': role_id,
                ':t': tenant_id
            }
        )
        
        user_count = len(user_count_response.get('Items', []))
        
        # Añadir información adicional a la respuesta
        result = {
            'role': role,
            'permissions': role_permissions,
            'user_count': user_count
        }
        
        logger.info(f"Recuperado rol {role_id} con {len(role_permissions)} permisos")
        
        return success_response(result)
        
    except Exception as e:
        logger.error(f"Error obteniendo rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:update')
def update_role(event, context):
    """Actualiza un rol existente"""
    try:
        # Obtener role_id de la ruta
        role_id = event['pathParameters']['role_id']
        
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar tenant_id
        tenant_id = body.get('tenant_id')
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Verificar que el rol existe
        response = roles_table.get_item(Key={'role_id': role_id})
        
        if 'Item' not in response:
            logger.error(f"Rol no encontrado: {role_id}")
            return error_response(404, 'Rol no encontrado')
        
        role = response['Item']
        
        # Verificar que el rol pertenece al tenant
        if role.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de modificar rol de otro tenant: {role_id}")
            return error_response(403, 'No tiene permiso para modificar este rol')
        
        # Verificar si se intenta modificar un rol del sistema
        if role.get('is_system_role', False) and not body.get('force_update', False):
            logger.warning(f"Intento de modificar rol del sistema: {role_id}")
            return error_response(403, 'No se puede modificar un rol del sistema sin el parámetro force_update')
        
        # Construir expresión de actualización
        update_expression = "set updated_at = :updated_at"
        expression_values = {
            ':updated_at': datetime.now().isoformat()
        }
        
        # Campos actualizables
        updatable_fields = {
            'role_name': 'role_name',
            'description': 'description',
            'status': 'status'
        }
        
        for field, db_field in updatable_fields.items():
            if field in body:
                update_expression += f", {db_field} = :{field}"
                expression_values[f':{field}'] = body[field]
        
        # Actualizar en DynamoDB
        roles_table.update_item(
            Key={'role_id': role_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )
        
        logger.info(f"Rol actualizado: {role_id}")
        
        # Si se proporcionan permisos, actualizar también los permisos
        if 'permissions' in body and isinstance(body['permissions'], list):
            # Eliminar permisos actuales
            current_permissions_response = role_permissions_table.scan(
                FilterExpression="role_id = :r",
                ExpressionAttributeValues={
                    ':r': role_id
                }
            )
            
            for item in current_permissions_response.get('Items', []):
                try:
                    role_permissions_table.delete_item(Key={'id': item['id']})
                except Exception as e:
                    logger.warning(f"Error eliminando permiso {item['id']}: {str(e)}")
            
            # Asignar nuevos permisos
            timestamp = datetime.now().isoformat()
            for permission in body['permissions']:
                try:
                    role_permissions_table.put_item(Item={
                        'id': str(uuid.uuid4()),
                        'role_id': role_id,
                        'permission': permission,
                        'created_at': timestamp,
                        'created_by': body.get('updated_by', 'system')
                    })
                except Exception as e:
                    logger.warning(f"Error asignando permiso {permission} a rol {role_id}: {str(e)}")
        
        return success_response({
            'message': 'Rol actualizado correctamente',
            'role_id': role_id
        })
        
    except Exception as e:
        logger.error(f"Error actualizando rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:delete')
def delete_role(event, context):
    """Elimina un rol del sistema"""
    try:
        # Obtener role_id de la ruta
        role_id = event['pathParameters']['role_id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Verificar que el rol existe
        response = roles_table.get_item(Key={'role_id': role_id})
        
        if 'Item' not in response:
            logger.error(f"Rol no encontrado: {role_id}")
            return error_response(404, 'Rol no encontrado')
        
        role = response['Item']
        
        # Verificar que el rol pertenece al tenant
        if role.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de eliminar rol de otro tenant: {role_id}")
            return error_response(403, 'No tiene permiso para eliminar este rol')
        
        # Verificar si es un rol del sistema
        if role.get('is_system_role', False) and not query_params.get('force', '').lower() == 'true':
            logger.warning(f"Intento de eliminar rol del sistema: {role_id}")
            return error_response(403, 'No se puede eliminar un rol del sistema sin el parámetro force=true')
        
        # Verificar si hay usuarios asignados a este rol
        user_roles_response = user_roles_table.scan(
            FilterExpression="role_id = :r",
            ExpressionAttributeValues={
                ':r': role_id
            }
        )
        
        if user_roles_response.get('Items') and not query_params.get('force', '').lower() == 'true':
            logger.warning(f"Intento de eliminar rol con usuarios asignados: {role_id}")
            return error_response(400, 'No se puede eliminar un rol con usuarios asignados. Use force=true para forzar la eliminación')
        
        # Eliminar asignaciones de usuarios a este rol
        for user_role in user_roles_response.get('Items', []):
            try:
                user_roles_table.delete_item(Key={'id': user_role['id']})
            except Exception as e:
                logger.warning(f"Error eliminando asignación de rol a usuario {user_role['id']}: {str(e)}")
        
        # Eliminar permisos asociados a este rol
        permissions_response = role_permissions_table.scan(
            FilterExpression="role_id = :r",
            ExpressionAttributeValues={
                ':r': role_id
            }
        )
        
        for permission in permissions_response.get('Items', []):
            try:
                role_permissions_table.delete_item(Key={'id': permission['id']})
            except Exception as e:
                logger.warning(f"Error eliminando permiso {permission['id']}: {str(e)}")
        
        # Eliminar el rol
        roles_table.delete_item(Key={'role_id': role_id})
        
        logger.info(f"Rol eliminado: {role_id}")
        
        return success_response({
            'message': 'Rol eliminado correctamente',
            'role_id': role_id
        })
        
    except Exception as e:
        logger.error(f"Error eliminando rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

# ---- Gestión de Permisos ----

@require_permission('role:read')
def list_permissions(event, context):
    """Lista todos los permisos existentes en el sistema"""
    try:
        # Este endpoint devuelve los permisos que están siendo utilizados en el sistema
        
        # Obtener permisos de la tabla
        response = permissions_table.scan()
        
        permissions = response.get('Items', [])
        
        # Si no hay permisos personalizados, devolver solo los del sistema
        if not permissions:
            return list_system_permissions(event, context)
        
        # Añadir permisos del sistema
        for perm_code, perm_desc in SYSTEM_PERMISSIONS.items():
            # Verificar si ya existe
            if not any(p['permission_code'] == perm_code for p in permissions):
                permissions.append({
                    'permission_code': perm_code,
                    'description': perm_desc,
                    'is_system_permission': True
                })
        
        logger.info(f"Recuperados {len(permissions)} permisos")
        
        return success_response({
            'permissions': permissions,
            'count': len(permissions)
        })
        
    except Exception as e:
        logger.error(f"Error listando permisos: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def list_system_permissions(event, context):
    """Lista los permisos predefinidos del sistema"""
    try:
        # Convertir el diccionario a una lista de objetos
        permissions = [
            {
                'permission_code': code,
                'description': desc,
                'is_system_permission': True
            }
            for code, desc in SYSTEM_PERMISSIONS.items()
        ]
        
        # Agrupar por categoría
        grouped_permissions = {}
        for perm in permissions:
            category = perm['permission_code'].split(':')[0]
            if category not in grouped_permissions:
                grouped_permissions[category] = []
            
            grouped_permissions[category].append(perm)
        
        logger.info(f"Recuperados {len(permissions)} permisos del sistema")
        
        return success_response({
            'permissions': permissions,
            'grouped_permissions': grouped_permissions,
            'count': len(permissions)
        })
        
    except Exception as e:
        logger.error(f"Error listando permisos del sistema: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

# ---- Asignación de Roles a Usuarios ----

@require_permission('role:assign')
def assign_role_to_user(event, context):
    """Asigna un rol a un usuario"""
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos obligatorios
        required_fields = ['tenant_id', 'user_id', 'role_id']
        missing_fields = [field for field in required_fields if field not in body]
        
        if missing_fields:
            logger.error(f"Faltan campos obligatorios: { ', '.join(missing_fields)}")
            return error_response(400, f"Campos obligatorios: { ', '.join(missing_fields)}")
        
        tenant_id = body.get('tenant_id')
        user_id = body.get('user_id')
        role_id = body.get('role_id')
        
        # Verificar que el usuario existe y pertenece al tenant
        user_response = users_table.get_item(Key={'user_id': user_id})
        if 'Item' not in user_response:
            logger.error(f"Usuario no encontrado: {user_id}")
            return error_response(404, 'Usuario no encontrado')
        
        user = user_response['Item']
        if user.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de asignar rol a usuario de otro tenant: {user_id}")
            return error_response(403, 'No tiene permiso para asignar roles a este usuario')
        
        # Verificar que el rol existe y pertenece al tenant
        role_response = roles_table.get_item(Key={'role_id': role_id})
        if 'Item' not in role_response:
            logger.error(f"Rol no encontrado: {role_id}")
            return error_response(404, 'Rol no encontrado')
        
        role = role_response['Item']
        if role.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de asignar rol de otro tenant: {role_id}")
            return error_response(403, 'No tiene permiso para asignar este rol')
        
        # Verificar si el usuario ya tiene este rol asignado
        user_role_response = user_roles_table.scan(
            FilterExpression="user_id = :u AND role_id = :r",
            ExpressionAttributeValues={
                ':u': user_id,
                ':r': role_id
            }
        )
        
        if user_role_response.get('Items'):
            logger.warning(f"El usuario {user_id} ya tiene asignado el rol {role_id}")
            return error_response(409, 'El usuario ya tiene asignado este rol')
        
        # Crear nueva asignación
        user_role_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        user_roles_table.put_item(Item={
            'id': user_role_id,
            'user_id': user_id,
            'role_id': role_id,
            'tenant_id': tenant_id,
            'created_at': timestamp,
            'created_by': body.get('created_by', 'system')
        })
        
        logger.info(f"Rol {role_id} asignado a usuario {user_id}")
        
        return created_response({
            'message': 'Rol asignado correctamente',
            'user_id': user_id,
            'role_id': role_id,
            'role_name': role.get('role_name'),
            'id': user_role_id
        })
        
    except Exception as e:
        logger.error(f"Error asignando rol a usuario: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:read')
def list_user_roles(event, context):
    """Lista los roles asignados a un usuario"""
    try:
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        user_id = query_params.get('user_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        if not user_id:
            logger.error("Falta parámetro user_id")
            return error_response(400, 'El parámetro user_id es obligatorio')
        
        # Verificar que el usuario pertenece al tenant
        user_response = users_table.get_item(Key={'user_id': user_id})
        if 'Item' not in user_response or user_response['Item'].get('tenant_id') != tenant_id:
            logger.warning(f"Intento de acceso a información de usuario de otro tenant: {user_id}")
            return error_response(403, 'No tiene permiso para acceder a información de este usuario')
        
        # Obtener roles asignados
        response = user_roles_table.scan(
            FilterExpression="user_id = :u AND tenant_id = :t",
            ExpressionAttributeValues={
                ':u': user_id,
                ':t': tenant_id
            }
        )
        
        user_roles = response.get('Items', [])
        
        # Obtener detalles de cada rol
        detailed_roles = []
        
        for user_role in user_roles:
            role_id = user_role.get('role_id')
            role_response = roles_table.get_item(Key={'role_id': role_id})
            
            if 'Item' in role_response:
                role = role_response['Item']
                detailed_roles.append({
                    'id': user_role.get('id'),
                    'user_id': user_id,
                    'role_id': role_id,
                    'role_name': role.get('role_name'),
                    'description': role.get('description'),
                    'created_at': user_role.get('created_at')
                })
        
        logger.info(f"Recuperados {len(detailed_roles)} roles para usuario {user_id}")
        
        return success_response({
            'user_roles': detailed_roles,
            'count': len(detailed_roles)
        })
        
    except Exception as e:
        logger.error(f"Error listando roles de usuario: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:assign')
def remove_role_from_user(event, context):
    """Elimina un rol asignado a un usuario"""
    try:
        # Obtener id de la asignación de la ruta
        user_role_id = event['pathParameters']['id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Verificar que la asignación existe
        response = user_roles_table.get_item(Key={'id': user_role_id})
        
        if 'Item' not in response:
            logger.error(f"Asignación de rol no encontrada: {user_role_id}")
            return error_response(404, 'Asignación de rol no encontrada')
        
        user_role = response['Item']
        
        # Verificar que la asignación pertenece al tenant
        if user_role.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de eliminar asignación de rol de otro tenant: {user_role_id}")
            return error_response(403, 'No tiene permiso para eliminar esta asignación de rol')
        
        # Eliminar la asignación
        user_roles_table.delete_item(Key={'id': user_role_id})
        
        logger.info(f"Asignación de rol eliminada: {user_role_id}")
        
        return success_response({
            'message': 'Asignación de rol eliminada correctamente',
            'id': user_role_id
        })
        
    except Exception as e:
        logger.error(f"Error eliminando asignación de rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

# ---- Asignación de Permisos a Roles ----

@require_permission('role:update')
def assign_permission_to_role(event, context):
    """Asigna un permiso a un rol"""
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos obligatorios
        required_fields = ['role_id', 'permission']
        missing_fields = [field for field in required_fields if field not in body]
        
        if missing_fields:
            logger.error(f"Faltan campos obligatorios: { ', '.join(missing_fields)}")
            return error_response(400, f"Campos obligatorios: { ', '.join(missing_fields)}")
        
        role_id = body.get('role_id')
        permission = body.get('permission')
        
        # Verificar que el rol existe
        role_response = roles_table.get_item(Key={'role_id': role_id})
        if 'Item' not in role_response:
            logger.error(f"Rol no encontrado: {role_id}")
            return error_response(404, 'Rol no encontrado')
        
        role = role_response['Item']
        
        # Verificar que el permiso existe o es un permiso del sistema
        is_valid_permission = False
        
        # Verificar si es un permiso del sistema
        if permission in SYSTEM_PERMISSIONS:
            is_valid_permission = True
        else:
            # Verificar en la tabla de permisos personalizados
            perm_response = permissions_table.scan(
                FilterExpression="permission_code = :p",
                ExpressionAttributeValues={
                    ':p': permission
                }
            )
            
            if perm_response.get('Items'):
                is_valid_permission = True
        
        if not is_valid_permission:
            logger.warning(f"Permiso inválido: {permission}")
            return error_response(400, f"Permiso inválido: {permission}")
        
        # Verificar si el rol ya tiene este permiso
        role_perm_response = role_permissions_table.scan(
            FilterExpression="role_id = :r AND permission = :p",
            ExpressionAttributeValues={
                ':r': role_id,
                ':p': permission
            }
        )
        
        if role_perm_response.get('Items'):
            logger.warning(f"El rol {role_id} ya tiene asignado el permiso {permission}")
            return error_response(409, 'El rol ya tiene asignado este permiso')
        
        # Crear nueva asignación de permiso
        permission_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        role_permissions_table.put_item(Item={
            'id': permission_id,
            'role_id': role_id,
            'permission': permission,
            'created_at': timestamp,
            'created_by': body.get('created_by', 'system'),
            'resource_id': body.get('resource_id')  # Opcional, para permisos específicos
        })
        
        logger.info(f"Permiso {permission} asignado a rol {role_id}")
        
        return created_response({
            'message': 'Permiso asignado correctamente',
            'role_id': role_id,
            'permission': permission,
            'id': permission_id
        })
        
    except Exception as e:
        logger.error(f"Error asignando permiso a rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:read')
def list_role_permissions(event, context):
    """Lista los permisos asignados a un rol"""
    try:
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        role_id = query_params.get('role_id')
        
        if not role_id:
            logger.error("Falta parámetro role_id")
            return error_response(400, 'El parámetro role_id es obligatorio')
        
        # Verificar que el rol existe
        role_response = roles_table.get_item(Key={'role_id': role_id})
        if 'Item' not in role_response:
            logger.error(f"Rol no encontrado: {role_id}")
            return error_response(404, 'Rol no encontrado')
        
        role = role_response['Item']
        
        # Obtener permisos del rol
        response = role_permissions_table.scan(
            FilterExpression="role_id = :r",
            ExpressionAttributeValues={
                ':r': role_id
            }
        )
        
        role_permissions = response.get('Items', [])
        
        # Añadir descripciones de permisos del sistema
        for perm in role_permissions:
            permission_code = perm.get('permission')
            if permission_code in SYSTEM_PERMISSIONS:
                perm['description'] = SYSTEM_PERMISSIONS[permission_code]
        
        logger.info(f"Recuperados {len(role_permissions)} permisos para rol {role_id}")
        
        return success_response({
            'role': role,
            'permissions': role_permissions,
            'count': len(role_permissions)
        })
        
    except Exception as e:
        logger.error(f"Error listando permisos de rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

@require_permission('role:update')
def remove_permission_from_role(event, context):
    """Elimina un permiso asignado a un rol"""
    try:
        # Obtener id de la asignación de la ruta
        permission_id = event['pathParameters']['id']
        
        # Verificar que la asignación existe
        response = role_permissions_table.get_item(Key={'id': permission_id})
        
        if 'Item' not in response:
            logger.error(f"Asignación de permiso no encontrada: {permission_id}")
            return error_response(404, 'Asignación de permiso no encontrada')
        
        permission_assignment = response['Item']
        role_id = permission_assignment.get('role_id')
        
        # Verificar que el rol existe
        role_response = roles_table.get_item(Key={'role_id': role_id})
        if 'Item' not in role_response:
            logger.error(f"Rol no encontrado: {role_id}")
            return error_response(404, 'Rol no encontrado')
        
        role = role_response['Item']
        
        # Verificar que el usuario tiene permiso para este tenant
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        if role.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de eliminar permiso de rol de otro tenant: {role_id}")
            return error_response(403, 'No tiene permiso para eliminar permisos de este rol')
        
        # Eliminar la asignación de permiso
        role_permissions_table.delete_item(Key={'id': permission_id})
        
        logger.info(f"Permiso {permission_assignment.get('permission')} eliminado del rol {role_id}")
        
        return success_response({
            'message': 'Permiso eliminado correctamente',
            'id': permission_id,
            'role_id': role_id,
            'permission': permission_assignment.get('permission')
        })
        
    except Exception as e:
        logger.error(f"Error eliminando permiso de rol: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

# ---- Permisos del Usuario Actual ----

@cors_wrapper
def get_my_permissions(event, context):
    """Obtiene los permisos del usuario actual"""
    try:
        # Obtener user_id y tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        user_id = query_params.get('user_id')
        tenant_id = query_params.get('tenant_id')
        
        if not user_id or not tenant_id:
            logger.error("Faltan parámetros user_id o tenant_id")
            return error_response(400, 'Los parámetros user_id y tenant_id son obligatorios')
        
        logger.info(f"Buscando permisos para user_id: {user_id}, tenant_id: {tenant_id}")
        
        # 1. Obtener información del token JWT si está disponible
        user_email = None
        authorization = event.get('headers', {}).get('Authorization') or event.get('headers', {}).get('authorization')
        if authorization and authorization.startswith('Bearer '):
            try:
                import base64
                import json
                
                # Extraer y decodificar el token
                token = authorization.split(' ')[1]
                # El token JWT tiene 3 partes separadas por puntos
                token_parts = token.split('.')
                if len(token_parts) >= 2:
                    # Decodificar la segunda parte (payload)
                    # Puede ser necesario añadir padding
                    payload = token_parts[1]
                    payload += '=' * ((4 - len(payload) % 4) % 4)  # Añadir padding si es necesario
                    decoded_payload = base64.b64decode(payload)
                    token_data = json.loads(decoded_payload)
                    
                    # Extraer email y sub (ID de cognito)
                    user_email = token_data.get('email')
                    cognito_id = token_data.get('sub')
                    
                    logger.info(f"Información extraída del token: email={user_email}, cognito_id={cognito_id}")
                    
                    # Si el ID de usuario coincide con el sub del token, estamos en el caso de Cognito ID
                    if user_id == cognito_id:
                        logger.info(f"El user_id coincide con el ID de Cognito del token")
            except Exception as e:
                logger.warning(f"Error decodificando token JWT: {str(e)}")
        
        # 2. Verificar si el user_id es un ID de Cognito en formato email
        user_response = users_table.scan(
            FilterExpression="cognito_id = :c",
            ExpressionAttributeValues={
                ':c': user_id
            }
        )
        
        user_items = user_response.get('Items', [])
        
        # 3. Si no se encontró y tenemos email del token, buscar por email
        if not user_items and user_email:
            logger.info(f"Buscando usuario por email: {user_email}")
            user_response = users_table.scan(
                FilterExpression="email = :e",
                ExpressionAttributeValues={
                    ':e': user_email
                }
            )
            user_items = user_response.get('Items', [])
        
        # 4. Si aún no se encuentra, buscar por coincidencia parcial en cognito_id
        if not user_items:
            logger.info(f"Buscando usuario por coincidencia parcial en cognito_id")
            user_response = users_table.scan(
                FilterExpression="contains(cognito_id, :c)",
                ExpressionAttributeValues={
                    ':c': user_id.split('-')[0] if '-' in user_id else user_id
                }
            )
            user_items = user_response.get('Items', [])
        
        if user_items:
            # Si se encuentra un usuario por alguno de los métodos, usar su user_id real
            user = user_items[0]
            real_user_id = user.get('user_id')
            real_tenant_id = user.get('tenant_id')
            
            logger.info(f"Usuario encontrado, user_id real: {real_user_id}, tenant_id real: {real_tenant_id}")
            
            # Verificar que el tenant_id proporcionado coincida con el del usuario
            if tenant_id != real_tenant_id and tenant_id != 'default':
                logger.warning(f"tenant_id proporcionado {tenant_id} no coincide con el del usuario {real_tenant_id}")
                tenant_id = real_tenant_id
            
            user_id = real_user_id
        else:
            # Si no se encuentra el usuario, intentar crear uno temporal basado en el email
            if user_email:
                logger.warning(f"Usuario no encontrado en DynamoDB. Creando usuario temporal basado en email: {user_email}")
                # Generar respuesta para usuario con privilegios mínimos
                return success_response({
                    'user_id': user_id,
                    'tenant_id': tenant_id,
                    'permissions': [],
                    'roles': [],
                    'is_admin': False,
                    'message': 'Usuario temporal con privilegios mínimos'
                })
            else:
                # 5. Intentar buscar directamente por user_id
                user_response = users_table.get_item(Key={'user_id': user_id})
                if 'Item' in user_response:
                    user = user_response['Item']
                    real_tenant_id = user.get('tenant_id')
                    
                    logger.info(f"Usuario encontrado por user_id directo, tenant_id real: {real_tenant_id}")
                    
                    # Verificar que el tenant_id proporcionado coincida con el del usuario
                    if tenant_id != real_tenant_id and tenant_id != 'default':
                        logger.warning(f"tenant_id proporcionado {tenant_id} no coincide con el del usuario {real_tenant_id}")
                        tenant_id = real_tenant_id
                else:
                    logger.error(f"No se encontró usuario con ID: {user_id}")
                    return success_response({
                        'user_id': user_id,
                        'tenant_id': tenant_id,
                        'permissions': [],
                        'roles': [],
                        'is_admin': False,
                        'message': 'Usuario no encontrado en sistema'
                    })
        
        # Obtener roles y permisos del usuario
        user_roles = get_user_roles(user_id, tenant_id)
        permissions = get_user_permissions(user_id, tenant_id)
        
        # Verificar si el usuario es admin en la tabla de usuarios
        is_admin = False
        user_response = users_table.get_item(Key={'user_id': user_id})
        if 'Item' in user_response:
            is_admin = user_response['Item'].get('role') == 'admin'
            
        # Si no hay roles específicos pero el campo role es 'admin', considerarlo admin
        if not user_roles and is_admin:
            logger.info(f"Usuario {user_id} es admin según el campo role")
            permissions = ['*']  # Admin tiene todos los permisos
            user_roles = ['legacy_admin']  # Añadir rol ficticio para indicar que es admin
        
        logger.info(f"Permisos para usuario {user_id} en tenant {tenant_id}: {permissions}")
        logger.info(f"Roles para usuario {user_id} en tenant {tenant_id}: {user_roles}")
        logger.info(f"Es admin: {is_admin}")
        
        response_data = {
            'user_id': user_id,
            'tenant_id': tenant_id,
            'permissions': permissions,
            'roles': user_roles if isinstance(user_roles, list) else [role.get('role_id', 'unknown') for role in user_roles],
            'is_admin': is_admin
        }
        
        return success_response(response_data)
        
    except Exception as e:
        logger.error(f"Error obteniendo permisos: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}") 