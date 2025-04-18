# docpilot-backend/scripts/normalize_s3_keys.py
"""
Script para normalizar nombres de archivos en S3 que contienen caracteres especiales.
Este script:
1. Busca todos los archivos en los buckets S3 de DocPilot
2. Identifica aquellos con caracteres especiales en el nombre
3. Crea una versión codificada del nombre
4. Copia el archivo con el nuevo nombre codificado
5. Actualiza las referencias en DynamoDB
6. Elimina el archivo original (opcional)

Uso: python normalize_s3_keys.py [--bucket nombre_bucket] [--tenant tenant_id] [--dry-run] [--delete-originals]
"""

import argparse
import boto3
import sys
import json
import logging
from datetime import datetime
import re
import os
import urllib.parse
import time

# Importar módulo de utilidades para manejo de rutas S3
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils.s3_path_helper import encode_s3_key, decode_s3_key, is_encoded, extract_filename_from_key, split_s3_path

# Configuración del logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"s3_migration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

def get_all_buckets():
    """Obtiene todos los buckets S3 disponibles"""
    s3 = boto3.client('s3')
    return [bucket['Name'] for bucket in s3.list_buckets()['Buckets']]

def get_docpilot_buckets():
    """Obtiene los buckets relevantes para DocPilot"""
    all_buckets = get_all_buckets()
    return [bucket for bucket in all_buckets if 'docpilot' in bucket.lower()]

def list_s3_objects(bucket, prefix=None, tenant_id=None):
    """Lista objetos en un bucket S3, opcionalmente filtrando por prefijo o tenant"""
    s3 = boto3.client('s3')
    paginator = s3.get_paginator('list_objects_v2')
    
    params = {'Bucket': bucket}
    if prefix:
        params['Prefix'] = prefix
    
    object_list = []
    
    # Usar paginación para manejar grandes cantidades de objetos
    for page in paginator.paginate(**params):
        if 'Contents' not in page:
            continue
            
        for obj in page['Contents']:
            # Si se especifica tenant_id, filtrar por él
            if tenant_id:
                path_info = split_s3_path(obj['Key'])
                if path_info.get('tenant_id') != tenant_id:
                    continue
                    
            object_list.append(obj)
    
    return object_list

def needs_encoding(key):
    """Determina si una clave S3 necesita ser codificada"""
    if is_encoded(key):
        return False
        
    # Verificar si tiene caracteres especiales o no ASCII
    has_special_chars = any(ord(c) > 127 or c in ' áéíóúñÁÉÍÓÚÑ@%&$#+' for c in key)
    return has_special_chars

def get_dynamodb_documents_by_s3_key(table_name, s3_key):
    """Busca documentos en DynamoDB que referencian una clave S3"""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    
    # Escanear la tabla buscando documentos con la clave S3
    response = table.scan(
        FilterExpression="s3_key = :key",
        ExpressionAttributeValues={':key': s3_key}
    )
    
    return response.get('Items', [])

def update_dynamodb_document(table_name, doc_id, old_key, new_key):
    """Actualiza la referencia de clave S3 en un documento DynamoDB"""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    
    # Extraer el nombre de archivo original y codificado
    old_filename = extract_filename_from_key(old_key)
    encoded_filename = extract_filename_from_key(new_key)
    
    try:
        # Actualizar el documento
        response = table.update_item(
            Key={'id': doc_id},
            UpdateExpression="set s3_key = :s, encoded_filename = :ef",
            ExpressionAttributeValues={
                ':s': new_key,
                ':ef': encoded_filename
            },
            ReturnValues="UPDATED_NEW"
        )
        return True
    except Exception as e:
        logger.error(f"Error actualizando documento {doc_id}: {str(e)}")
        return False

def copy_s3_object(source_bucket, source_key, dest_bucket, dest_key):
    """Copia un objeto de S3 a una nueva ubicación"""
    s3 = boto3.client('s3')
    
    try:
        # Obtener metadatos originales
        head_response = s3.head_object(Bucket=source_bucket, Key=source_key)
        content_type = head_response.get('ContentType', 'application/octet-stream')
        metadata = head_response.get('Metadata', {})
        
        # Si no existe una entrada para el nombre original, añadirla
        if 'original_filename' not in metadata:
            metadata['original_filename'] = extract_filename_from_key(source_key)
        
        # Copiar objeto con metadatos
        s3.copy_object(
            Bucket=dest_bucket,
            Key=dest_key,
            CopySource={'Bucket': source_bucket, 'Key': source_key},
            MetadataDirective='REPLACE',
            ContentType=content_type,
            Metadata=metadata
        )
        return True
    except Exception as e:
        logger.error(f"Error copiando objeto de S3 {source_key}: {str(e)}")
        return False

def delete_s3_object(bucket, key):
    """Elimina un objeto de S3"""
    s3 = boto3.client('s3')
    
    try:
        s3.delete_object(Bucket=bucket, Key=key)
        return True
    except Exception as e:
        logger.error(f"Error eliminando objeto S3 {key}: {str(e)}")
        return False

def normalize_objects(bucket, objects, contracts_table, dry_run=False, delete_originals=False):
    """Normaliza una lista de objetos S3"""
    results = {
        'total': len(objects),
        'need_encoding': 0,
        'succeeded': 0,
        'failed': 0,
        'db_updated': 0,
        'deleted': 0
    }
    
    for obj in objects:
        key = obj['Key']
        
        # Verificar si necesita codificación
        if not needs_encoding(key):
            continue
            
        results['need_encoding'] += 1
        logger.info(f"Procesando {key}")
        
        # Generar nueva clave codificada
        path_parts = key.split('/')
        filename = path_parts[-1]
        encoded_filename = encode_s3_key(filename)
        new_key = '/'.join(path_parts[:-1] + [encoded_filename])
        
        if dry_run:
            logger.info(f"[DRY RUN] Se codificaría: {key} -> {new_key}")
            continue
        
        # Copiar objeto con el nuevo nombre
        if copy_s3_object(bucket, key, bucket, new_key):
            logger.info(f"Copiado exitosamente: {key} -> {new_key}")
            
            # Buscar documentos en DynamoDB que referencian este objeto
            documents = get_dynamodb_documents_by_s3_key(contracts_table, key)
            
            # Actualizar referencias en DynamoDB
            db_updated = 0
            for doc in documents:
                doc_id = doc.get('id')
                if update_dynamodb_document(contracts_table, doc_id, key, new_key):
                    logger.info(f"Actualizada referencia en DynamoDB para documento {doc_id}")
                    db_updated += 1
                else:
                    logger.error(f"Error actualizando referencia en DynamoDB para documento {doc_id}")
            
            results['db_updated'] += db_updated
            
            # Eliminar objeto original si se solicita
            if delete_originals:
                if delete_s3_object(bucket, key):
                    logger.info(f"Eliminado original: {key}")
                    results['deleted'] += 1
                else:
                    logger.error(f"Error eliminando original: {key}")
            
            results['succeeded'] += 1
        else:
            logger.error(f"Error copiando objeto: {key}")
            results['failed'] += 1
    
    return results

def main():
    """Función principal del script"""
    parser = argparse.ArgumentParser(description='Normaliza nombres de archivos en S3 con caracteres especiales')
    parser.add_argument('--bucket', help='Nombre del bucket S3 a procesar')
    parser.add_argument('--tenant', help='ID del tenant a procesar (opcional)')
    parser.add_argument('--prefix', help='Prefijo de ruta S3 a procesar (opcional)')
    parser.add_argument('--contracts-table', help='Nombre de la tabla DynamoDB de contratos')
    parser.add_argument('--dry-run', action='store_true', help='Ejecutar sin realizar cambios')
    parser.add_argument('--delete-originals', action='store_true', help='Eliminar archivos originales después de copiarlos')
    
    args = parser.parse_args()
    
    # Determinar el bucket a usar
    bucket_to_use = None
    if args.bucket:
        bucket_to_use = args.bucket
    else:
        docpilot_buckets = get_docpilot_buckets()
        if len(docpilot_buckets) == 1:
            bucket_to_use = docpilot_buckets[0]
        elif len(docpilot_buckets) > 1:
            print("Se encontraron múltiples buckets de DocPilot:")
            for i, bucket in enumerate(docpilot_buckets):
                print(f"{i+1}. {bucket}")
            choice = input("Seleccione el número del bucket a usar: ")
            try:
                bucket_to_use = docpilot_buckets[int(choice) - 1]
            except (ValueError, IndexError):
                print("Selección inválida")
                sys.exit(1)
        else:
            print("No se encontraron buckets de DocPilot. Especifique uno con --bucket")
            sys.exit(1)
    
    # Determinar la tabla DynamoDB a usar
    contracts_table = None
    if args.contracts_table:
        contracts_table = args.contracts_table
    else:
        # Intentar inferir nombre de tabla a partir del bucket
        if 'dev' in bucket_to_use:
            contracts_table = 'docpilot-newsystem-contracts-dev'
        elif 'prod' in bucket_to_use:
            contracts_table = 'docpilot-newsystem-contracts-prod'
        else:
            contracts_table = 'docpilot-newsystem-contracts-dev'  # Por defecto
        
        confirm = input(f"Se usará la tabla DynamoDB '{contracts_table}'. ¿Es correcto? (s/n): ")
        if confirm.lower() != 's':
            print("Especifique la tabla con --contracts-table")
            sys.exit(1)
    
    # Mostrar resumen de la operación
    print("\nResumen de la operación:")
    print(f"- Bucket: {bucket_to_use}")
    print(f"- Tabla DynamoDB: {contracts_table}")
    if args.tenant:
        print(f"- Tenant: {args.tenant}")
    if args.prefix:
        print(f"- Prefijo: {args.prefix}")
    print(f"- Modo: {'Simulación (no se realizarán cambios)' if args.dry_run else 'Ejecución real'}")
    print(f"- Eliminar originales: {'Sí' if args.delete_originals else 'No'}")
    
    if not args.dry_run:
        confirm = input("\n¡ADVERTENCIA! Esta operación modificará archivos y datos. ¿Continuar? (s/n): ")
        if confirm.lower() != 's':
            print("Operación cancelada")
            sys.exit(0)
    
    # Listar objetos S3
    logger.info(f"Listando objetos en bucket {bucket_to_use}")
    objects = list_s3_objects(bucket_to_use, args.prefix, args.tenant)
    logger.info(f"Se encontraron {len(objects)} objetos")
    
    # Normalizar objetos
    start_time = time.time()
    results = normalize_objects(
        bucket_to_use, 
        objects, 
        contracts_table, 
        dry_run=args.dry_run, 
        delete_originals=args.delete_originals
    )
    end_time = time.time()
    
    # Mostrar resultados
    logger.info("\nResumen de la normalización:")
    logger.info(f"- Total de objetos analizados: {results['total']}")
    logger.info(f"- Objetos que necesitaban codificación: {results['need_encoding']}")
    if not args.dry_run:
        logger.info(f"- Objetos codificados exitosamente: {results['succeeded']}")
        logger.info(f"- Objetos con errores: {results['failed']}")
        logger.info(f"- Documentos DynamoDB actualizados: {results['db_updated']}")
        if args.delete_originals:
            logger.info(f"- Objetos originales eliminados: {results['deleted']}")
    logger.info(f"- Tiempo total de ejecución: {end_time - start_time:.2f} segundos")

if __name__ == "__main__":
    main()