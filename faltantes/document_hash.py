# docpilot-backend/src/utils/document_hash.py
"""
Utilidades para calcular y verificar hashes de documentos.
Este módulo permite la detección de archivos duplicados.
"""

import hashlib
import boto3
import os
import logging
import base64
import io

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Obtener referencia a DynamoDB
dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE', ''))

def calculate_file_hash(file_content, algorithm='sha256'):
    """
    Calcula el hash de un archivo.
    
    Args:
        file_content (bytes): Contenido del archivo
        algorithm (str): Algoritmo de hash (sha256, md5, etc.)
        
    Returns:
        str: Hash hexadecimal del archivo
    """
    if algorithm == 'sha256':
        return hashlib.sha256(file_content).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(file_content).hexdigest()
    else:
        raise ValueError(f"Algoritmo de hash no soportado: {algorithm}")

def calculate_hash_from_s3(bucket, key, algorithm='sha256'):
    """
    Calcula el hash de un archivo en S3.
    
    Args:
        bucket (str): Nombre del bucket S3
        key (str): Clave del objeto S3
        algorithm (str): Algoritmo de hash (sha256, md5, etc.)
        
    Returns:
        str: Hash hexadecimal del archivo
    """
    try:
        s3 = boto3.client('s3')
        response = s3.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read()
        return calculate_file_hash(content, algorithm)
    except Exception as e:
        logger.error(f"Error calculando hash para {bucket}/{key}: {str(e)}")
        raise

def calculate_hash_from_base64(base64_content, algorithm='sha256'):
    """
    Calcula el hash de un archivo codificado en base64.
    
    Args:
        base64_content (str): Contenido del archivo en base64
        algorithm (str): Algoritmo de hash (sha256, md5, etc.)
        
    Returns:
        str: Hash hexadecimal del archivo
    """
    try:
        # Decodificar el contenido base64
        if isinstance(base64_content, str):
            # Eliminar posible prefijo de data URL
            if base64_content.startswith('data:'):
                base64_content = base64_content.split(',', 1)[1]
            content = base64.b64decode(base64_content)
        else:
            content = base64_content
            
        return calculate_file_hash(content, algorithm)
    except Exception as e:
        logger.error(f"Error calculando hash desde base64: {str(e)}")
        raise

def check_duplicate_document(tenant_id, doc_hash, exclude_id=None):
    """
    Verifica si un documento con el mismo hash ya existe para el tenant.
    
    Args:
        tenant_id (str): ID del tenant
        doc_hash (str): Hash SHA-256 del documento
        exclude_id (str, optional): ID de documento a excluir de la verificación
        
    Returns:
        dict: Información sobre si el documento es duplicado
    """
    try:
        # Construir filtro para buscar documentos con el mismo hash y tenant_id
        filter_expression = "tenant_id = :t AND document_hash = :h AND #status <> :s"
        expression_values = {
            ":t": tenant_id,
            ":h": doc_hash,
            ":s": "deleted"  # Excluir documentos eliminados
        }
        
        # Si se proporciona un ID para excluir, añadirlo al filtro
        if exclude_id:
            filter_expression += " AND id <> :id"
            expression_values[":id"] = exclude_id
        
        # Buscar documentos con el mismo hash
        response = contracts_table.scan(
            FilterExpression=filter_expression,
            ExpressionAttributeValues=expression_values,
            ExpressionAttributeNames={
                "#status": "status"
            }
        )
        
        items = response.get('Items', [])
        
        if items:
            # Encontramos un duplicado (usar el primero)
            return {
                'is_duplicate': True,
                'original_doc': items[0],
                'duplicates': items
            }
        else:
            return {
                'is_duplicate': False,
                'original_doc': None,
                'duplicates': []
            }
            
    except Exception as e:
        logger.error(f"Error verificando duplicados: {str(e)}")
        return {
            'is_duplicate': False,
            'original_doc': None,
            'duplicates': [],
            'error': str(e)
        }

def update_document_hash(doc_id, doc_hash):
    """
    Actualiza el hash de un documento en DynamoDB.
    
    Args:
        doc_id (str): ID del documento
        doc_hash (str): Hash del documento
        
    Returns:
        bool: True si la actualización fue exitosa, False en caso contrario
    """
    try:
        contracts_table.update_item(
            Key={'id': doc_id},
            UpdateExpression="set document_hash = :h",
            ExpressionAttributeValues={':h': doc_hash}
        )
        return True
    except Exception as e:
        logger.error(f"Error actualizando hash para documento {doc_id}: {str(e)}")
        return False

def handle_duplicate_document(doc_id, original_doc_id):
    """
    Marca un documento como duplicado y lo asocia con el original.
    
    Args:
        doc_id (str): ID del documento duplicado
        original_doc_id (str): ID del documento original
        
    Returns:
        bool: True si la operación fue exitosa, False en caso contrario
    """
    try:
        contracts_table.update_item(
            Key={'id': doc_id},
            UpdateExpression="set is_duplicate = :d, original_doc_id = :o",
            ExpressionAttributeValues={
                ':d': True,
                ':o': original_doc_id
            }
        )
        return True
    except Exception as e:
        logger.error(f"Error marcando documento {doc_id} como duplicado: {str(e)}")
        return False