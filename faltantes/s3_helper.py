# docpilot-backend/src/utils/s3_helper.py
# Utilidades para interactuar con S3

import boto3
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_s3_client():
    """Obtiene un cliente de S3"""
    return boto3.client('s3')

def upload_file_to_s3(bucket, key, file_content, content_type=None, metadata=None):
    """Sube un archivo a S3"""
    s3_client = get_s3_client()
    
    put_params = {
        'Bucket': bucket,
        'Key': key,
        'Body': file_content
    }
    
    if content_type:
        put_params['ContentType'] = content_type
    
    if metadata:
        put_params['Metadata'] = metadata
    
    try:
        response = s3_client.put_object(**put_params)
        return response
    except ClientError as e:
        logger.error(f"Error al subir archivo a S3: {e}")
        raise

def download_file_from_s3(bucket, key):
    """Descarga un archivo de S3"""
    s3_client = get_s3_client()
    
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return {
            'content': response['Body'].read(),
            'content_type': response.get('ContentType'),
            'metadata': response.get('Metadata', {})
        }
    except ClientError as e:
        logger.error(f"Error al descargar archivo de S3: {e}")
        raise

def generate_presigned_url(bucket, key, expiration=300, operation='get_object', content_type=None):
    """Genera una URL prefirmada para subir o descargar un archivo"""
    s3_client = get_s3_client()
    
    params = {
        'Bucket': bucket,
        'Key': key,
        'ExpiresIn': expiration
    }
    
    if content_type and operation == 'put_object':
        params['ContentType'] = content_type
    
    try:
        url = s3_client.generate_presigned_url(operation, Params=params)
        return url
    except ClientError as e:
        logger.error(f"Error al generar URL prefirmada: {e}")
        raise

def check_file_exists(bucket, key):
    """Verifica si un archivo existe en S3"""
    s3_client = get_s3_client()
    
    try:
        s3_client.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == '404':
            return False
        else:
            logger.error(f"Error al verificar existencia de archivo en S3: {e}")
            raise

def list_objects(bucket, prefix=None):
    """Lista objetos en un bucket de S3"""
    s3_client = get_s3_client()
    
    params = {
        'Bucket': bucket
    }
    
    if prefix:
        params['Prefix'] = prefix
    
    try:
        response = s3_client.list_objects_v2(**params)
        return response.get('Contents', [])
    except ClientError as e:
        logger.error(f"Error al listar objetos en S3: {e}")
        raise

def delete_file(bucket, key):
    """Elimina un archivo de S3"""
    s3_client = get_s3_client()
    
    try:
        response = s3_client.delete_object(Bucket=bucket, Key=key)
        return response
    except ClientError as e:
        logger.error(f"Error al eliminar archivo de S3: {e}")
        raise

def create_folder(bucket, folder_path):
    """Crea una carpeta en S3 (añadiendo un objeto vacío con / al final)"""
    if not folder_path.endswith('/'):
        folder_path += '/'
        
    s3_client = get_s3_client()
    
    try:
        response = s3_client.put_object(Bucket=bucket, Key=folder_path, Body='')
        return response
    except ClientError as e:
        logger.error(f"Error al crear carpeta en S3: {e}")
        raise

def copy_file(source_bucket, source_key, dest_bucket, dest_key, metadata=None, content_type=None):
    """Copia un archivo dentro de S3"""
    s3_client = get_s3_client()
    
    params = {
        'Bucket': dest_bucket,
        'Key': dest_key,
        'CopySource': f"{source_bucket}/{source_key}"
    }
    
    # Si se proporciona metadata, usamos la estrategia de reemplazo
    if metadata or content_type:
        params['MetadataDirective'] = 'REPLACE'
        
        if metadata:
            params['Metadata'] = metadata
            
        if content_type:
            params['ContentType'] = content_type
    
    try:
        response = s3_client.copy_object(**params)
        return response
    except ClientError as e:
        logger.error(f"Error al copiar archivo en S3: {e}")
        raise