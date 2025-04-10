# docpilot-backend/src/handlers/confirm_upload.py
import json
import os
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
            s3.head_object(Bucket=MAIN_BUCKET, Key=item['s3_key'])
            
            # Actualizar estado en DynamoDB
            contracts_table.update_item(
                Key={'id': file_id},
                UpdateExpression="set #status = :s, upload_confirmed_at = :t",
                ExpressionAttributeNames={
                    '#status': 'status'
                },
                ExpressionAttributeValues={
                    ':s': 'pending_processing',
                    ':t': datetime.now().isoformat()
                }
            )
            
            logger.info(f"Subida confirmada para documento: {file_id}")
            
            # Aquí se podría implementar una notificación a webhooks externos para integración B2B
            
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({
                    'message': 'Subida confirmada',
                    'file_id': file_id
                })
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