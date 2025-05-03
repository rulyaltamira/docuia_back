#!/usr/bin/env python
# coding: utf-8

import boto3
import json
import argparse
import sys
import re
import logging
from datetime import datetime

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configurar clientes AWS
dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
s3 = boto3.client('s3', region_name='eu-west-1')
cognito = boto3.client('cognito-idp', region_name='eu-west-1')

# Nombres de recursos
TENANTS_TABLE = 'docpilot-newsystem-v2-tenants-dev'
USERS_TABLE = 'docpilot-newsystem-v2-users-dev'
MAIN_BUCKET = 'docpilot-newsystem-v2-main-dev'
USER_POOL_ID = 'eu-west-1_U76ZEVpde'

def confirm_action(message):
    """Solicita confirmación al usuario"""
    confirm = input(f"{message} (s/n): ").lower()
    return confirm == 's' or confirm == 'si' or confirm == 'yes' or confirm == 'y'

def list_tenants(pattern=None):
    """Lista todos los tenants, opcionalmente filtrando por patrón"""
    tenants_table = dynamodb.Table(TENANTS_TABLE)
    response = tenants_table.scan()
    items = response.get('Items', [])
    
    # Seguir escaneando si hay más resultados
    while 'LastEvaluatedKey' in response:
        response = tenants_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        items.extend(response.get('Items', []))
    
    if pattern:
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        filtered_items = [
            item for item in items 
            if compiled_pattern.search(item.get('tenant_id', '')) or 
               compiled_pattern.search(item.get('name', ''))
        ]
        return filtered_items
    
    return items

def list_users_for_tenant(tenant_id):
    """Lista todos los usuarios para un tenant específico"""
    users_table = dynamodb.Table(USERS_TABLE)
    
    # Usamos scan con filtro para buscar por tenant_id
    response = users_table.scan(
        FilterExpression="tenant_id = :t",
        ExpressionAttributeValues={":t": tenant_id}
    )
    
    users = response.get('Items', [])
    
    # Seguir escaneando si hay más resultados
    while 'LastEvaluatedKey' in response:
        response = users_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={":t": tenant_id},
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
        users.extend(response.get('Items', []))
    
    return users

def delete_s3_folders(tenant_id):
    """Elimina las carpetas S3 asociadas con el tenant"""
    prefix = f"tenants/{tenant_id}/"
    logger.info(f"Eliminando objetos S3 con prefijo: {prefix}")
    
    # Listar objetos con el prefijo
    objects_to_delete = []
    response = s3.list_objects_v2(Bucket=MAIN_BUCKET, Prefix=prefix)
    
    if 'Contents' in response:
        objects_to_delete.extend([{'Key': obj['Key']} for obj in response['Contents']])
        
        # Seguir listando si hay más objetos
        while response['IsTruncated']:
            response = s3.list_objects_v2(
                Bucket=MAIN_BUCKET,
                Prefix=prefix,
                ContinuationToken=response['NextContinuationToken']
            )
            if 'Contents' in response:
                objects_to_delete.extend([{'Key': obj['Key']} for obj in response['Contents']])
    
    # Eliminar objetos si se encontraron
    if objects_to_delete:
        logger.info(f"Eliminando {len(objects_to_delete)} objetos S3 para tenant {tenant_id}")
        s3.delete_objects(
            Bucket=MAIN_BUCKET,
            Delete={'Objects': objects_to_delete, 'Quiet': True}
        )
    else:
        logger.info(f"No se encontraron objetos S3 para tenant {tenant_id}")
    
    return len(objects_to_delete)

def delete_cognito_user(username):
    """Elimina un usuario de Cognito"""
    try:
        logger.info(f"Eliminando usuario Cognito: {username}")
        cognito.admin_delete_user(
            UserPoolId=USER_POOL_ID,
            Username=username
        )
        return True
    except Exception as e:
        logger.error(f"Error eliminando usuario Cognito {username}: {str(e)}")
        return False

def delete_tenant(tenant_id, force=False):
    """Elimina un tenant y todos sus recursos asociados"""
    tenants_table = dynamodb.Table(TENANTS_TABLE)
    users_table = dynamodb.Table(USERS_TABLE)
    
    # 1. Verificar que existe el tenant
    try:
        response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return False
        
        tenant = response['Item']
        tenant_name = tenant.get('name', tenant_id)
    except Exception as e:
        logger.error(f"Error obteniendo tenant {tenant_id}: {str(e)}")
        return False
    
    # Confirmar eliminación si no es forzada
    if not force:
        confirmed = confirm_action(f"¿Está seguro que desea eliminar el tenant '{tenant_name}' ({tenant_id}) y todos sus recursos asociados?")
        if not confirmed:
            logger.info(f"Eliminación de tenant {tenant_id} cancelada por el usuario")
            return False
    
    # 2. Listar usuarios del tenant
    users = list_users_for_tenant(tenant_id)
    logger.info(f"Se encontraron {len(users)} usuarios para el tenant {tenant_id}")
    
    # 3. Eliminar usuarios de DynamoDB y Cognito
    deleted_users = 0
    for user in users:
        try:
            user_id = user.get('user_id')
            email = user.get('email')
            cognito_id = user.get('cognito_id')
            
            logger.info(f"Eliminando usuario {email} (ID: {user_id})")
            
            # Eliminar de Cognito si es posible
            if cognito_id and not cognito_id.startswith('pendiente-'):
                delete_cognito_user(cognito_id)
            
            # Eliminar de DynamoDB
            users_table.delete_item(Key={'user_id': user_id})
            deleted_users += 1
            
        except Exception as e:
            logger.error(f"Error eliminando usuario {user.get('email')}: {str(e)}")
    
    # 4. Eliminar carpetas S3
    deleted_objects = delete_s3_folders(tenant_id)
    
    # 5. Eliminar tenant de DynamoDB
    try:
        logger.info(f"Eliminando tenant {tenant_id} de DynamoDB")
        tenants_table.delete_item(Key={'tenant_id': tenant_id})
    except Exception as e:
        logger.error(f"Error eliminando tenant {tenant_id} de DynamoDB: {str(e)}")
        return False
    
    # Resumen de la operación
    logger.info(f"Tenant {tenant_id} eliminado con éxito")
    logger.info(f"  - {deleted_users} usuarios eliminados")
    logger.info(f"  - {deleted_objects} objetos S3 eliminados")
    
    return True

def cleanup_by_pattern(pattern, force=False):
    """Limpia todos los tenants que coinciden con un patrón"""
    tenants = list_tenants(pattern)
    
    if not tenants:
        logger.info(f"No se encontraron tenants que coincidan con el patrón: {pattern}")
        return
    
    logger.info(f"Se encontraron {len(tenants)} tenants que coinciden con el patrón: {pattern}")
    for tenant in tenants:
        tenant_id = tenant.get('tenant_id')
        tenant_name = tenant.get('name', tenant_id)
        logger.info(f"  - {tenant_name} (ID: {tenant_id})")
    
    if not force:
        confirmed = confirm_action(f"¿Está seguro que desea eliminar estos {len(tenants)} tenants?")
        if not confirmed:
            logger.info("Operación cancelada por el usuario")
            return
    
    # Eliminar cada tenant
    deleted = 0
    for tenant in tenants:
        tenant_id = tenant.get('tenant_id')
        if delete_tenant(tenant_id, force=True):
            deleted += 1
    
    logger.info(f"Limpieza completada: {deleted} de {len(tenants)} tenants eliminados")

def main():
    parser = argparse.ArgumentParser(description='Herramienta para limpiar tenants de prueba y sus recursos asociados')
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')
    
    # Comando para listar tenants
    list_parser = subparsers.add_parser('list', help='Listar tenants')
    list_parser.add_argument('--pattern', '-p', help='Patrón de búsqueda (expresión regular)')
    
    # Comando para eliminar un tenant específico
    delete_parser = subparsers.add_parser('delete', help='Eliminar un tenant específico')
    delete_parser.add_argument('tenant_id', help='ID del tenant a eliminar')
    delete_parser.add_argument('--force', '-f', action='store_true', help='No pedir confirmación')
    
    # Comando para limpiar tenants por patrón
    cleanup_parser = subparsers.add_parser('cleanup', help='Limpiar tenants por patrón')
    cleanup_parser.add_argument('pattern', help='Patrón de búsqueda (expresión regular)')
    cleanup_parser.add_argument('--force', '-f', action='store_true', help='No pedir confirmación')
    
    args = parser.parse_args()
    
    # Ejecutar el comando correspondiente
    if args.command == 'list':
        tenants = list_tenants(args.pattern)
        print(f"Se encontraron {len(tenants)} tenants:")
        for tenant in tenants:
            print(f"  - {tenant.get('name', 'N/A')} (ID: {tenant.get('tenant_id')}, Status: {tenant.get('status', 'N/A')})")
    
    elif args.command == 'delete':
        success = delete_tenant(args.tenant_id, args.force)
        if success:
            print(f"Tenant {args.tenant_id} eliminado con éxito")
        else:
            print(f"Error eliminando tenant {args.tenant_id}")
            sys.exit(1)
    
    elif args.command == 'cleanup':
        cleanup_by_pattern(args.pattern, args.force)
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main() 