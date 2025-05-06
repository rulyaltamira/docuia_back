# docpilot-backend/src/utils/tenant_limits_validator.py
import boto3
import os
import logging
from datetime import datetime

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))

def can_create_user(tenant_id):
    """
    Verifica si un tenant puede crear un nuevo usuario basado en su límite de plan
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resultado de la verificación con mensaje explicativo
    """
    try:
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'can_proceed': False,
                'reason': 'Tenant no encontrado',
                'limit_reached': False
            }
        
        tenant = tenant_response['Item']
        
        # Verificar si el tenant está activo
        if tenant.get('status') != 'active':
            logger.warning(f"Tenant no está activo: {tenant_id}")
            return {
                'can_proceed': False,
                'reason': 'Tenant inactivo',
                'limit_reached': False
            }
        
        # Obtener límite de usuarios del plan
        max_users = tenant.get('limits', {}).get('max_users', 0)
        
        # Si es -1, significa ilimitado
        if max_users < 0:
            return {
                'can_proceed': True,
                'reason': 'Sin límite de usuarios',
                'limit_reached': False
            }
        
        # Contar usuarios activos actuales
        current_users = tenant.get('usage', {}).get('users_count')
        
        # Si no hay información de uso actualizada, contar manualmente
        if current_users is None:
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
            
            current_users = len(user_response.get('Items', []))
        
        # Verificar límite
        if current_users >= max_users:
            logger.warning(f"Límite de usuarios alcanzado para tenant {tenant_id}: {current_users}/{max_users}")
            return {
                'can_proceed': False,
                'reason': f'Límite de usuarios alcanzado ({current_users}/{max_users})',
                'limit_reached': True,
                'current': current_users,
                'limit': max_users
            }
        
        # Puede crear usuario
        return {
            'can_proceed': True,
            'reason': f'Dentro del límite de usuarios ({current_users}/{max_users})',
            'limit_reached': False,
            'current': current_users,
            'limit': max_users
        }
        
    except Exception as e:
        logger.error(f"Error verificando límite de usuarios: {str(e)}")
        return {
            'can_proceed': False,
            'reason': f'Error verificando límite: {str(e)}',
            'limit_reached': False
        }

def can_upload_file(tenant_id, file_size_bytes=0):
    """
    Verifica si un tenant puede subir un nuevo archivo basado en su límite de plan
    
    Args:
        tenant_id (str): ID del tenant
        file_size_bytes (int): Tamaño del archivo en bytes
        
    Returns:
        dict: Resultado de la verificación con mensaje explicativo
    """
    try:
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'can_proceed': False,
                'reason': 'Tenant no encontrado',
                'limit_reached': False
            }
        
        tenant = tenant_response['Item']
        
        # Verificar si el tenant está activo
        if tenant.get('status') != 'active':
            logger.warning(f"Tenant no está activo: {tenant_id}")
            return {
                'can_proceed': False,
                'reason': 'Tenant inactivo',
                'limit_reached': False
            }
        
        # Obtener límites del plan
        limits = tenant.get('limits', {})
        max_documents = limits.get('max_documents', 0)
        max_storage_mb = limits.get('max_storage_mb', 0)
        
        usage = tenant.get('usage', {})
        current_documents = usage.get('documents_count', 0)
        current_storage_mb = usage.get('storage_used_mb', 0)
        
        # Verificar límite de documentos (si es -1, es ilimitado)
        if max_documents >= 0 and current_documents >= max_documents:
            logger.warning(f"Límite de documentos alcanzado para tenant {tenant_id}: {current_documents}/{max_documents}")
            return {
                'can_proceed': False,
                'reason': f'Límite de documentos alcanzado ({current_documents}/{max_documents})',
                'limit_reached': True,
                'limit_type': 'documents'
            }
        
        # Verificar límite de almacenamiento (si es -1, es ilimitado)
        if max_storage_mb >= 0:
            # Convertir tamaño del archivo a MB
            file_size_mb = file_size_bytes / (1024 * 1024)
            
            # Verificar si el nuevo archivo excede el límite
            if (current_storage_mb + file_size_mb) > max_storage_mb:
                logger.warning(f"Límite de almacenamiento alcanzado para tenant {tenant_id}: {current_storage_mb}/{max_storage_mb} MB")
                return {
                    'can_proceed': False,
                    'reason': f'Límite de almacenamiento alcanzado ({current_storage_mb}/{max_storage_mb} MB)',
                    'limit_reached': True,
                    'limit_type': 'storage',
                    'file_size_mb': round(file_size_mb, 2)
                }
        
        # Puede subir archivo
        return {
            'can_proceed': True,
            'reason': 'Dentro de los límites de plan',
            'limit_reached': False
        }
        
    except Exception as e:
        logger.error(f"Error verificando límites para subida de archivo: {str(e)}")
        return {
            'can_proceed': False,
            'reason': f'Error verificando límites: {str(e)}',
            'limit_reached': False
        }

def can_process_document(tenant_id):
    """
    Verifica si un tenant puede procesar documentos basado en su plan
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resultado de la verificación con mensaje explicativo
    """
    try:
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return {
                'can_proceed': False,
                'reason': 'Tenant no encontrado',
                'limit_reached': False
            }
        
        tenant = tenant_response['Item']
        
        # Verificar si el tenant está activo
        if tenant.get('status') != 'active':
            logger.warning(f"Tenant no está activo: {tenant_id}")
            return {
                'can_proceed': False,
                'reason': 'Tenant inactivo',
                'limit_reached': False
            }
        
        # Verificar si el plan incluye procesamiento de documentos
        features = tenant.get('features', {})
        if not features.get('document_processing', False):
            logger.warning(f"Procesamiento de documentos no disponible en el plan de {tenant_id}")
            return {
                'can_proceed': False,
                'reason': 'Procesamiento de documentos no disponible en su plan',
                'limit_reached': True,
                'feature_unavailable': True
            }
        
        # Verificar si hay límite de documentos procesados por mes
        limits = tenant.get('limits', {})
        max_monthly_processing = limits.get('max_monthly_processing')
        
        if max_monthly_processing is not None and max_monthly_processing >= 0:
            # Calcular documentos procesados en el mes actual
            # Esta lógica podría refinarse para calcular correctamente por mes calendario
            current_month = datetime.now().strftime("%Y-%m")
            
            # Contar documentos procesados en el mes actual
            # Esto podría optimizarse con un GSI para búsquedas más eficientes
            monthly_processed_docs = count_monthly_processed_documents(tenant_id, current_month)
            
            if monthly_processed_docs >= max_monthly_processing:
                logger.warning(f"Límite mensual de procesamiento alcanzado para tenant {tenant_id}: {monthly_processed_docs}/{max_monthly_processing}")
                return {
                    'can_proceed': False,
                    'reason': f'Límite mensual de procesamiento alcanzado ({monthly_processed_docs}/{max_monthly_processing})',
                    'limit_reached': True,
                    'current': monthly_processed_docs,
                    'limit': max_monthly_processing
                }
        
        # Puede procesar documento
        return {
            'can_proceed': True,
            'reason': 'Procesamiento autorizado',
            'limit_reached': False
        }
        
    except Exception as e:
        logger.error(f"Error verificando capacidad de procesamiento: {str(e)}")
        return {
            'can_proceed': False,
            'reason': f'Error verificando capacidad: {str(e)}',
            'limit_reached': False
        }

def update_tenant_usage(tenant_id, operation, value=1):
    """
    Actualiza contadores de uso de recursos para un tenant
    
    Args:
        tenant_id (str): ID del tenant
        operation (str): Operación a realizar (add_user, remove_user, add_document, remove_document, add_storage, remove_storage)
        value (int/float): Valor a añadir/restar (default: 1)
        
    Returns:
        bool: True si la actualización fue exitosa, False en caso contrario
    """
    try:
        # Obtener información actual del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return False
        
        tenant = tenant_response['Item']
        
        # Inicializar objeto de uso si no existe
        usage = tenant.get('usage', {
            'users_count': 0,
            'documents_count': 0,
            'storage_used_mb': 0,
            'last_updated': datetime.now().isoformat()
        })
        
        # Actualizar contador según la operación
        if operation == 'add_user':
            usage['users_count'] = usage.get('users_count', 0) + value
        elif operation == 'remove_user':
            usage['users_count'] = max(0, usage.get('users_count', 0) - value)
        elif operation == 'add_document':
            usage['documents_count'] = usage.get('documents_count', 0) + value
        elif operation == 'remove_document':
            usage['documents_count'] = max(0, usage.get('documents_count', 0) - value)
        elif operation == 'add_storage':
            # value aquí está en MB
            usage['storage_used_mb'] = usage.get('storage_used_mb', 0) + value
        elif operation == 'remove_storage':
            # value aquí está en MB
            usage['storage_used_mb'] = max(0, usage.get('storage_used_mb', 0) - value)
        else:
            logger.warning(f"Operación no válida: {operation}")
            return False
        
        # Actualizar timestamp
        usage['last_updated'] = datetime.now().isoformat()
        
        # Guardar cambios en DynamoDB
        tenants_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression="set usage = :u",
            ExpressionAttributeValues={
                ':u': usage
            }
        )
        
        logger.info(f"Uso actualizado para tenant {tenant_id}: {operation} {value}")
        return True
        
    except Exception as e:
        logger.error(f"Error actualizando uso de tenant: {str(e)}")
        return False

def count_monthly_processed_documents(tenant_id, month_str):
    """
    Cuenta documentos procesados en un mes específico para un tenant
    
    Args:
        tenant_id (str): ID del tenant
        month_str (str): Mes en formato "YYYY-MM"
        
    Returns:
        int: Número de documentos procesados
    """
    try:
        # Scan documentos procesados en el mes indicado
        # Esto podría optimizarse con un GSI en producción
        response = contracts_table.scan(
            FilterExpression="tenant_id = :t AND begins_with(processed_at, :m) AND #status = :s",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":m": month_str,
                ":s": "processed"
            },
            ExpressionAttributeNames={
                "#status": "status"
            }
        )
        
        count = len(response.get('Items', []))
        
        # Si hay paginación (más de 1MB de resultados), continuamos el scan
        while 'LastEvaluatedKey' in response:
            response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND begins_with(processed_at, :m) AND #status = :s",
                ExpressionAttributeValues={
                    ":t": tenant_id,
                    ":m": month_str,
                    ":s": "processed"
                },
                ExpressionAttributeNames={
                    "#status": "status"
                },
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            
            count += len(response.get('Items', []))
        
        return count
        
    except Exception as e:
        logger.error(f"Error contando documentos procesados: {str(e)}")
        return 0

def has_feature(tenant_id, feature_name):
    """
    Verifica si un tenant tiene una característica específica habilitada en su plan
    
    Args:
        tenant_id (str): ID del tenant
        feature_name (str): Nombre de la característica a verificar
        
    Returns:
        bool: True si la característica está disponible, False en caso contrario
    """
    try:
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return False
        
        tenant = tenant_response['Item']
        
        # Verificar si el tenant está activo
        if tenant.get('status') != 'active':
            logger.warning(f"Tenant no está activo: {tenant_id}")
            return False
        
        # Verificar si la característica está disponible
        features = tenant.get('features', {})
        has_feature = features.get(feature_name, False)
        
        return has_feature
        
    except Exception as e:
        logger.error(f"Error verificando característica: {str(e)}")
        return False