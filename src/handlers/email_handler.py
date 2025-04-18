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

# Importar el nuevo módulo de manejo de rutas S3
from src.utils.s3_path_helper import encode_s3_key

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
        
        # Identificar el tenant a partir del correo destinatario
        # Por defecto, usar tenant "default"
        tenant_id = determine_tenant_from_email(msg)
        
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
            original_filename = part.get_filename()
            if not original_filename:
                continue
            
            # Codificar el nombre de archivo para S3
            encoded_filename = encode_s3_key(original_filename)
                
            content_type = part.get_content_type()
            content = part.get_payload(decode=True)
            
            # Solo procesar archivos PDF o DOCX
            allowed_types = ['application/pdf', 'application/msword', 
                           'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
            if content_type not in allowed_types and not original_filename.lower().endswith(('.pdf', '.docx', '.doc')):
                logger.info(f"Omitiendo archivo no soportado: {original_filename}, tipo: {content_type}")
                continue
            
            # Generar ID único para el documento
            doc_id = str(uuid.uuid4())
            
            # Definir ruta multi-tenant con nombre de archivo codificado
            file_key = f"tenants/{tenant_id}/raw/email/{doc_id}/{encoded_filename}"
            
            # Guardar archivo en S3
            s3.put_object(
                Bucket=MAIN_BUCKET, 
                Key=file_key, 
                Body=content,
                ContentType=content_type,
                Metadata={
                    'source': 'email',
                    'email_subject': subject,
                    'email_from': from_address,
                    'original_filename': original_filename
                }
            )
            
            logger.info(f"Archivo guardado en S3: {file_key}")
            
            # Registrar metadatos en DynamoDB
            timestamp = datetime.now().isoformat()
            contracts_table.put_item(Item={
                'id': doc_id,
                'tenant_id': tenant_id,
                'source': 'email',
                'filename': original_filename,  # Guardar nombre original para visualización
                'encoded_filename': encoded_filename,  # Guardar nombre codificado para referencia
                's3_key': file_key,
                'timestamp': timestamp,
                'email_timestamp': datetime.now().isoformat(),
                'email_from': from_address,
                'email_subject': subject,
                'email_body': body[:1000] if body else "",  # Guardar parte del cuerpo para contexto
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

def determine_tenant_from_email(msg):
    """
    Determina el tenant_id a partir del destinatario del correo
    Formato esperado: username@tenant-id.docpilot.com o documents@tenant-id.docpilot.com
    """
    try:
        # Obtener destinatarios
        to_addresses = msg.get('to', [])
        if isinstance(to_addresses, str):
            to_addresses = [to_addresses]
        
        cc_addresses = msg.get('cc', [])
        if isinstance(cc_addresses, str):
            cc_addresses = [cc_addresses]
        
        # Combinar destinatarios
        all_recipients = to_addresses + cc_addresses
        
        # Buscar dominios de DocPilot
        for recipient in all_recipients:
            if '@' in recipient and '.docpilot.com' in recipient.lower():
                email_parts = recipient.split('@')
                if len(email_parts) == 2:
                    domain = email_parts[1].lower()
                    if domain.endswith('.docpilot.com'):
                        tenant_part = domain.replace('.docpilot.com', '')
                        # Si el dominio es tenant-id.docpilot.com, extraer tenant-id
                        if '-' in tenant_part:
                            tenant_id = tenant_part
                            logger.info(f"Tenant identificado desde el correo: {tenant_id}")
                            return tenant_id
        
        # Si no se encuentra un tenant específico, usar 'default'
        logger.info("No se pudo identificar tenant desde el correo, usando 'default'")
        return 'default'
    
    except Exception as e:
        logger.warning(f"Error identificando tenant desde email: {str(e)}")
        return 'default'