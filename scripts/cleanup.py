#!/usr/bin/env python
# coding: utf-8

import boto3
import logging
import argparse
from botocore.exceptions import ClientError

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

# Configuración de recursos
STAGE = 'dev'
SERVICE = 'docpilot-newsystem-v2'
USER_POOL_ID = 'eu-west-1_uJTvs1HT7'

# Nombres de tablas DynamoDB
TABLES = [
    f"{SERVICE}-contracts-{STAGE}",
    f"{SERVICE}-tenants-{STAGE}",
    f"{SERVICE}-users-{STAGE}",
    f"{SERVICE}-alerts-{STAGE}",
    f"{SERVICE}-alert-rules-{STAGE}",
    f"{SERVICE}-alert-preferences-{STAGE}",
    f"{SERVICE}-roles-{STAGE}",
    f"{SERVICE}-permissions-{STAGE}",
    f"{SERVICE}-user-roles-{STAGE}",
    f"{SERVICE}-role-permissions-{STAGE}",
    f"{SERVICE}-statistics-{STAGE}",
    f"{SERVICE}-reports-{STAGE}",
    f"{SERVICE}-report-schedules-{STAGE}"
]

# Nombres de buckets S3
BUCKETS = [
    f"{SERVICE}-main-{STAGE}",
    f"{SERVICE}-ses-{STAGE}",
    f"{SERVICE}-audit-{STAGE}"
]

def confirm_action(message):
    """Solicita confirmación al usuario"""
    confirm = input(f"{message} (s/n): ").lower()
    return confirm in ['s', 'si', 'yes', 'y']

def delete_all_s3_objects(bucket_name):
    """Elimina todos los objetos de un bucket S3"""
    try:
        logger.info(f"Eliminando objetos del bucket: {bucket_name}")
        
        # Listar todos los objetos
        paginator = s3.get_paginator('list_objects_v2')
        total_objects = 0
        
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                if objects:
                    s3.delete_objects(
                        Bucket=bucket_name,
                        Delete={'Objects': objects, 'Quiet': True}
                    )
                    total_objects += len(objects)
        
        logger.info(f"Se eliminaron {total_objects} objetos del bucket {bucket_name}")
        return True
    except Exception as e:
        logger.error(f"Error eliminando objetos del bucket {bucket_name}: {str(e)}")
        return False

def delete_all_cognito_users():
    """Elimina todos los usuarios del User Pool"""
    try:
        logger.info(f"Eliminando usuarios del User Pool: {USER_POOL_ID}")
        
        # Listar todos los usuarios
        paginator = cognito.get_paginator('list_users')
        total_users = 0
        
        for page in paginator.paginate(UserPoolId=USER_POOL_ID):
            for user in page['Users']:
                try:
                    cognito.admin_delete_user(
                        UserPoolId=USER_POOL_ID,
                        Username=user['Username']
                    )
                    total_users += 1
                except Exception as e:
                    logger.error(f"Error eliminando usuario {user['Username']}: {str(e)}")
        
        logger.info(f"Se eliminaron {total_users} usuarios de Cognito")
        return True
    except Exception as e:
        logger.error(f"Error eliminando usuarios de Cognito: {str(e)}")
        return False

def delete_all_dynamodb_items(table_name):
    """Elimina todos los items de una tabla DynamoDB"""
    try:
        table = dynamodb.Table(table_name)
        logger.info(f"Eliminando items de la tabla: {table_name}")
        
        # Obtener la clave primaria de la tabla
        key_schema = table.key_schema
        hash_key = next(key['AttributeName'] for key in key_schema if key['KeyType'] == 'HASH')
        range_key = next((key['AttributeName'] for key in key_schema if key['KeyType'] == 'RANGE'), None)
        
        # Escanear y eliminar todos los items
        total_items = 0
        scan_kwargs = {}
        done = False
        
        while not done:
            response = table.scan(**scan_kwargs)
            items = response.get('Items', [])
            
            for item in items:
                key = {hash_key: item[hash_key]}
                if range_key:
                    key[range_key] = item[range_key]
                
                table.delete_item(Key=key)
                total_items += 1
            
            done = 'LastEvaluatedKey' not in response
            if not done:
                scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
        
        logger.info(f"Se eliminaron {total_items} items de la tabla {table_name}")
        return True
    except Exception as e:
        logger.error(f"Error eliminando items de la tabla {table_name}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Limpia todos los recursos del backend')
    parser.add_argument('--force', '-f', action='store_true', help='No pedir confirmación')
    args = parser.parse_args()
    
    if not args.force:
        if not confirm_action("⚠️ ADVERTENCIA: Este script eliminará TODOS los datos del backend. ¿Está seguro?"):
            logger.info("Operación cancelada por el usuario")
            return
    
    # 1. Limpiar Cognito
    logger.info("=== Limpiando Cognito User Pool ===")
    delete_all_cognito_users()
    
    # 2. Limpiar S3
    logger.info("\n=== Limpiando buckets S3 ===")
    for bucket in BUCKETS:
        delete_all_s3_objects(bucket)
    
    # 3. Limpiar DynamoDB
    logger.info("\n=== Limpiando tablas DynamoDB ===")
    for table in TABLES:
        delete_all_dynamodb_items(table)
    
    logger.info("\n✅ Limpieza completada")

if __name__ == '__main__':
    main() 