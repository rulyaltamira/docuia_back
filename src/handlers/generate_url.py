# docpilot-backend/src/handlers/generate_url.py
import json
import os
import uuid
import boto3
from datetime import datetime
import logging

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

def lambda_handler(event, context):
    """Genera una URL prefirmada para subir un documento a S3"""
    try:
        # Extraer parámetros de la consulta de API Gateway
        query_params = event.get('queryStringParameters', {}) or {}
        
        # Validar parámetros obligatorios
        if 'filename' not in query_params:
            logger.error("Parámetro 'filename' no proporcionado")
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'El parámetro filename es obligatorio'})
            }
        
        # Extraer y validar parámetros
        filename = query_params.get('filename')
        content_type = query_params.get('contentType', 'application/octet-stream')
        description = query_params.get('description', '')
        tenant_id = query_params.get('tenant_id', 'default')
        user_id = query_params.get('userId', 'anonymous')
        
        logger.info(f"Generando URL para archivo: {filename}, tenant: {tenant_id}, usuario: {user_id}")
        
        # Generar ID único para el documento
        doc_id = str(uuid.uuid4())
        
        # Construir ruta para el archivo en S3
        file_key = f"tenants/{tenant_id}/raw/manual/{doc_id}/{filename}"
        
        # Generar URL prefirmada
        url = s3.generate_presigned_url(
            'put_object',
            Params={
                'Bucket': MAIN_BUCKET,
                'Key': file_key,
                'ContentType': content_type
            },
            ExpiresIn=300  # 5 minutos
        )
        
        logger.info(f"URL prefirmada generada para archivo: {file_key}")
        
        # Registrar metadatos preliminares en DynamoDB
        timestamp = datetime.now().isoformat()
        contracts_table.put_item(Item={
            'id': doc_id,
            'tenant_id': tenant_id,
            'source': 'manual',
            'filename': filename,
            's3_key': file_key,
            'timestamp': timestamp,
            'content_type': content_type,
            'user_id': user_id,
            'description': description,
            'status': 'awaiting_upload'
        })
        
        logger.info(f"Metadatos preliminares guardados en DynamoDB para documento: {doc_id}")
        
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'upload_url': url,
                'file_id': doc_id,
                'expires_in': 300
            })
        }
    
    except Exception as e:
        logger.error(f"Error generando URL prefirmada: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': str(e)})
        }