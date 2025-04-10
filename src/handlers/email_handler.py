# docpilot-backend/src/handlers/email_handler.py
import json
import os
import uuid
import boto3
import email
from email import policy
from email.parser import BytesParser
from datetime import datetime
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuración de servicios AWS
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))

# Configuración de buckets
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')
SES_BUCKET = os.environ.get('SES_BUCKET')

def lambda_handler(event, context):
    """
    Manejador principal para procesar emails recibidos a través de SES
    """
    try:
        # Extraer datos del evento S3 (cuál archivo se creó)
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']
        
        logger.info(f"Procesando email desde S3: {bucket}/{key}")
        
        # Obtener el email desde S3
        s3_object = s3.get_object(Bucket=bucket, Key=key)
        raw_email = s3_object['Body'].read()
        
        # Parsear el email
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
        subject = msg.get('subject', 'No Subject')
        from_address = msg.get('from', '')
        
        if isinstance(from_address, list) and len(from_address) > 0:
            from_address = from_address[0]
        
        logger.info(f"Email de: {from_address}, Asunto: {subject}")
        
        # Por defecto, usar tenant "default"
        # En un sistema completo, se identificaría el tenant por el dominio o correo
        tenant_id = "default"
        
        # Extraer cuerpo del email
        body = ""
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            if "attachment" not in content_disposition:
                if content_type == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='replace')
                    break
                elif content_type == "text/html" and not body:
                    body = part.get_payload(decode=True).decode('utf-8', errors='replace')
        
        # Procesar adjuntos
        processed_files = 0
        for part in msg.iter_attachments():
            filename = part.get_filename()
            if not filename:
                continue
                
            content_type = part.get_content_type()
            content = part.get_payload(decode=True)
            
            # Solo procesar archivos PDF o DOCX
            allowed_types = ['application/pdf', 'application/msword', 
                           'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
            if content_type not in allowed_types and not filename.lower().endswith(('.pdf', '.docx', '.doc')):
                logger.info(f"Omitiendo archivo no soportado: {filename}, tipo: {content_type}")
                continue
            
            # Generar ID único para el documento
            doc_id = str(uuid.uuid4())
            
            # Definir ruta multi-tenant
            file_key = f"tenants/{tenant_id}/raw/email/{doc_id}/{filename}"
            
            # Guardar archivo en S3
            s3.put_object(
                Bucket=MAIN_BUCKET, 
                Key=file_key, 
                Body=content,
                ContentType=content_type,
                Metadata={
                    'source': 'email',
                    'email_subject': subject,
                    'email_from': from_address
                }
            )
            
            logger.info(f"Archivo guardado en S3: {file_key}")
            
            # Registrar metadatos en DynamoDB
            timestamp = datetime.now().isoformat()
            contracts_table.put_item(Item={
                'id': doc_id,
                'tenant_id': tenant_id,
                'source': 'email',
                'filename': filename,
                's3_key': file_key,
                'timestamp': timestamp,
                'email_timestamp': datetime.now().isoformat(),
                'email_from': from_address,
                'email_subject': subject,
                'content_type': content_type,
                'file_size': len(content),
                'status': 'pending_processing'
            })
            
            logger.info(f"Metadatos guardados en DynamoDB para documento: {doc_id}")
            processed_files += 1
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f"Procesados {processed_files} adjuntos del email",
                'from': from_address,
                'subject': subject,
                'processed_files': processed_files
            })
        }
    
    except Exception as e:
        logger.error(f"Error procesando email: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }