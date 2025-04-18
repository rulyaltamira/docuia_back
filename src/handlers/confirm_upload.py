# docpilot-backend/src/handlers/confirm_upload.py
import json
import os
import boto3
from datetime import datetime
import logging
import hashlib

# Importar utilidades para manejo de rutas S3
from src.utils.s3_path_helper import decode_s3_key

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

def lambda_handler(event, context):
    """Confirma que un archivo ha sido subido exitosamente a S3"""
    try:
        # Extraer datos del cuerpo
        body = json.loads(event.get('body', '{}'))
        file_id = body.get('file_id')
        
        # Validar parámetros obligatorios
        if not file_id:
            logger.error("Parámetro 'file_id' no proporcionado")
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'El parámetro file_id es obligatorio'})
            }
        
        logger.info(f"Confirmando subida para documento: {file_id}")
        
        # Obtener información actual del documento
        response = contracts_table.get_item(Key={'id': file_id})
        
        if 'Item' not in response:
            logger.error(f"Documento no encontrado: {file_id}")
            return {
                'statusCode': 404,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Documento no encontrado'})
            }
        
        item = response['Item']
        
        # Verificar que el archivo existe en S3
        try:
            s3_key = item['s3_key']
            s3_response = s3.head_object(Bucket=MAIN_BUCKET, Key=s3_key)
            
            # Calcular hash del documento para detección de duplicados
            file_response = s3.get_object(Bucket=MAIN_BUCKET, Key=s3_key)
            file_content = file_response['Body'].read()
            document_hash = hashlib.sha256(file_content).hexdigest()
            
            # Verificar si es un duplicado
            duplicate_check = check_duplicate(item['tenant_id'], document_hash)
            
            update_expression = "set #status = :s, upload_confirmed_at = :t, document_hash = :h"
            expression_values = {
                ':s': 'pending_processing',
                ':t': datetime.now().isoformat(),
                ':h': document_hash
            }
            
            expression_names = {
                '#status': 'status'
            }
            
            # Si es un duplicado, marcarlo como tal
            if duplicate_check['is_duplicate']:
                original_doc = duplicate_check['original_doc']
                update_expression += ", is_duplicate = :d, original_doc_id = :o"
                expression_values[':d'] = True
                expression_values[':o'] = original_doc['id']
            
            # Asegurar que el nombre original está guardado
            if 'filename' not in item and 's3_key' in item:
                filename_parts = item['s3_key'].split('/')
                if len(filename_parts) > 0:
                    encoded_filename = filename_parts[-1]
                    original_filename = decode_s3_key(encoded_filename)
                    update_expression += ", filename = :f, encoded_filename = :ef"
                    expression_values[':f'] = original_filename
                    expression_values[':ef'] = encoded_filename
            
            # Actualizar estado en DynamoDB
            contracts_table.update_item(
                Key={'id': file_id},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_names,
                ExpressionAttributeValues=expression_values
            )
            
            logger.info(f"Subida confirmada para documento: {file_id}")
            
            response_body = {
                'message': 'Subida confirmada',
                'file_id': file_id
            }
            
            # Añadir información de duplicado si aplica
            if duplicate_check['is_duplicate']:
                response_body['is_duplicate'] = True
                response_body['original_doc_id'] = original_doc['id']
                response_body['original_filename'] = original_doc.get('filename', '')
                logger.info(f"Documento marcado como duplicado. Original: {original_doc['id']}")
            
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps(response_body)
            }
            
        except s3.exceptions.ClientError as e:
            logger.error(f"Archivo no encontrado en S3: {item['s3_key']}")
            return {
                'statusCode': 404,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Archivo no encontrado en S3'})
            }
    
    except Exception as e:
        logger.error(f"Error confirmando subida: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': str(e)})
        }

def check_duplicate(tenant_id, doc_hash):
    """
    Verifica si un documento con el mismo hash ya existe para el tenant
    
    Args:
        tenant_id (str): ID del tenant
        doc_hash (str): Hash SHA-256 del documento
        
    Returns:
        dict: Información sobre si el documento es duplicado
    """
    try:
        # Buscar documentos con el mismo hash y tenant_id
        response = contracts_table.scan(
            FilterExpression="tenant_id = :t AND document_hash = :h AND #status <> :s",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":h": doc_hash,
                ":s": "deleted"  # Excluir documentos eliminados
            },
            ExpressionAttributeNames={
                "#status": "status"
            }
        )
        
        items = response.get('Items', [])
        
        if items:
            # Encontramos un duplicado (usar el primero)
            return {
                'is_duplicate': True,
                'original_doc': items[0]
            }
        else:
            return {
                'is_duplicate': False,
                'original_doc': None
            }
            
    except Exception as e:
        logger.error(f"Error verificando duplicados: {str(e)}")
        return {
            'is_duplicate': False,
            'original_doc': None
        }