#!/usr/bin/env python3
# scripts/cleanup.py
# Script para limpiar registros de prueba de DynamoDB, S3 y Cognito

import boto3
import argparse
import logging
import sys
import yaml
import os

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Configuración por defecto
REGION = 'eu-west-1'
STAGE = 'dev'
SERVICE_NAME = 'docpilot-newsystem-v2'

def get_service_config():
    """Obtiene la configuración del servicio desde serverless.yml"""
    try:
        with open('serverless.yml', 'r') as file:
            config = yaml.safe_load(file)
            return config.get('service', SERVICE_NAME)
    except Exception as e:
        logger.warning(f"No se pudo leer serverless.yml: {str(e)}")
        return SERVICE_NAME

def clean_dynamodb_tenant(tenant_id, tables, region=REGION, stage=STAGE):
    """Limpia los registros relacionados con un tenant específico en las tablas DynamoDB"""
    dynamodb = boto3.resource('dynamodb', region_name=region)
    service_name = get_service_config()
    
    logger.info(f"Eliminando registros del tenant '{tenant_id}' en DynamoDB...")
    
    for table_name in tables:
        full_table_name = f"{service_name}-{table_name}-{stage}"
        table = dynamodb.Table(full_table_name)
        
        try:
            # Diferentes enfoques según la estructura de la tabla
            if table_name == 'tenants':
                # Para la tabla tenants, eliminamos directamente por tenant_id
                response = table.delete_item(Key={'tenant_id': tenant_id})
                logger.info(f"Eliminado tenant {tenant_id} de la tabla {full_table_name}")
            elif table_name in ['users', 'roles', 'alerts', 'alert-rules', 'alert-preferences']:
                # Para tablas con un índice directo pero que contienen tenant_id como atributo
                # Primero escaneamos para encontrar elementos relacionados
                scan_kwargs = {
                    'FilterExpression': 'tenant_id = :tid',
                    'ExpressionAttributeValues': {':tid': tenant_id}
                }
                
                done = False
                count = 0
                while not done:
                    response = table.scan(**scan_kwargs)
                    items = response.get('Items', [])
                    
                    # Eliminar cada elemento encontrado
                    for item in items:
                        # Determinar la clave primaria según la tabla
                        if table_name == 'users':
                            key = {'user_id': item['user_id']}
                        elif table_name == 'roles':
                            key = {'role_id': item['role_id']}
                        elif table_name == 'alerts':
                            key = {'alert_id': item['alert_id']}
                        elif table_name == 'alert-rules':
                            key = {'rule_id': item['rule_id']}
                        elif table_name == 'alert-preferences':
                            key = {'preference_id': item['preference_id']}
                        
                        table.delete_item(Key=key)
                        count += 1
                    
                    # Verificar si hay más elementos para escanear
                    if 'LastEvaluatedKey' in response:
                        scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
                    else:
                        done = True
                
                logger.info(f"Eliminados {count} elementos de {tenant_id} en tabla {full_table_name}")
            elif table_name in ['user-roles', 'role-permissions']:
                # Para tablas de relación donde tenant_id es un atributo
                scan_kwargs = {
                    'FilterExpression': 'tenant_id = :tid',
                    'ExpressionAttributeValues': {':tid': tenant_id}
                }
                
                done = False
                count = 0
                while not done:
                    response = table.scan(**scan_kwargs)
                    items = response.get('Items', [])
                    
                    # Eliminar cada elemento encontrado
                    for item in items:
                        table.delete_item(Key={'id': item['id']})
                        count += 1
                    
                    # Verificar si hay más elementos para escanear
                    if 'LastEvaluatedKey' in response:
                        scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
                    else:
                        done = True
                
                logger.info(f"Eliminados {count} elementos de {tenant_id} en tabla {full_table_name}")
        except Exception as e:
            logger.error(f"Error limpiando tabla {full_table_name}: {str(e)}")

def clean_s3_tenant(tenant_id, buckets, region=REGION, stage=STAGE):
    """Elimina los objetos de S3 relacionados con un tenant específico"""
    s3 = boto3.resource('s3', region_name=region)
    service_name = get_service_config()
    
    logger.info(f"Eliminando objetos del tenant '{tenant_id}' en S3...")
    
    for bucket_name in buckets:
        full_bucket_name = f"{service_name}-{bucket_name}-{stage}"
        
        try:
            bucket = s3.Bucket(full_bucket_name)
            
            # Eliminar objetos en la carpeta del tenant
            prefix = f"tenants/{tenant_id}/"
            count = 0
            
            for obj in bucket.objects.filter(Prefix=prefix):
                obj.delete()
                count += 1
            
            logger.info(f"Eliminados {count} objetos de {prefix} en bucket {full_bucket_name}")
            
        except Exception as e:
            logger.error(f"Error limpiando bucket {full_bucket_name}: {str(e)}")

def clean_cognito_users(emails, region=REGION, stage=STAGE):
    """Elimina usuarios de Cognito por email"""
    cognito = boto3.client('cognito-idp', region_name=region)
    service_name = get_service_config()
    
    # Obtener el ID del user pool
    try:
        response = cognito.list_user_pools(MaxResults=60)
        user_pools = response.get('UserPools', [])
        
        user_pool_id = None
        for pool in user_pools:
            if pool['Name'].startswith(f"{service_name}-user-pool-{stage}"):
                user_pool_id = pool['Id']
                break
        
        if not user_pool_id:
            logger.error(f"No se encontró el User Pool para {service_name}-{stage}")
            return
        
        logger.info(f"Eliminando usuarios de Cognito en User Pool {user_pool_id}...")
        
        for email in emails:
            try:
                # Verificar si el usuario existe
                try:
                    user_info = cognito.admin_get_user(
                        UserPoolId=user_pool_id,
                        Username=email
                    )
                    
                    # Eliminar el usuario
                    cognito.admin_delete_user(
                        UserPoolId=user_pool_id,
                        Username=email
                    )
                    
                    logger.info(f"Usuario {email} eliminado de Cognito")
                except cognito.exceptions.UserNotFoundException:
                    logger.info(f"Usuario {email} no encontrado en Cognito")
                    
            except Exception as e:
                logger.error(f"Error eliminando usuario {email} de Cognito: {str(e)}")
        
    except Exception as e:
        logger.error(f"Error obteniendo User Pools: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Limpia datos de prueba de DynamoDB, S3 y Cognito')
    parser.add_argument('--tenant', required=True, help='ID del tenant a eliminar')
    parser.add_argument('--email', help='Email(s) del administrador a eliminar de Cognito', nargs='+')
    parser.add_argument('--region', default=REGION, help=f'Región AWS (default: {REGION})')
    parser.add_argument('--stage', default=STAGE, help=f'Etapa (default: {STAGE})')
    
    args = parser.parse_args()
    
    # Tablas DynamoDB a limpiar
    tables = [
        'tenants', 
        'users', 
        'roles', 
        'user-roles', 
        'role-permissions',
        'alerts',
        'alert-rules',
        'alert-preferences'
    ]
    
    # Buckets S3 a limpiar
    buckets = ['main', 'ses', 'audit']
    
    # Ejecutar limpieza
    clean_dynamodb_tenant(args.tenant, tables, args.region, args.stage)
    clean_s3_tenant(args.tenant, buckets, args.region, args.stage)
    
    if args.email:
        clean_cognito_users(args.email, args.region, args.stage)
    
    logger.info("Limpieza completada")

if __name__ == "__main__":
    main() 