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

# Importar el módulo de manejo de rutas S3
from src.utils.s3_path_helper import encode_s3_key
# Importar módulo de utilidades de respuesta
from src.utils.response_helper import success_response, error_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuración de servicios AWS
s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))

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
        tenant_info = determine_tenant_from_email(msg)
        tenant_id = tenant_info['tenant_id']
        
        # Verificar si el remitente está autorizado para este tenant
        auth_result = verify_sender_authorization(from_address, tenant_id)
        
        if not auth_result['is_authorized']:
            logger.warning(f"Remitente no autorizado: {from_address} para tenant: {tenant_id}")
            
            # Manejar email no autorizado (guardar en quarentena o notificar)
            handle_unauthorized_email(msg, tenant_id, from_address, auth_result['reason'])
            
            return {
                'statusCode': 403,
                'body': json.dumps({
                    'message': f"Email rechazado. Remitente no autorizado: {from_address}",
                    'reason': auth_result['reason']
                })
            }
        
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
                    'original_filename': original_filename,
                    'tenant_id': tenant_id,
                    'authorized_user': auth_result.get('user_id', 'whitelist')
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
                'status': 'pending_processing',
                'authorized_by': auth_result.get('user_id', 'whitelist')
            })
            
            logger.info(f"Metadatos guardados en DynamoDB para documento: {doc_id}")
            processed_files += 1
        
        # Si hay al menos un archivo procesado, enviar notificación de éxito
        if processed_files > 0:
            # Enviar notificación de confirmación al remitente si está configurado
            if auth_result.get('send_notifications', True):
                send_processing_confirmation(from_address, tenant_id, processed_files, subject)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f"Procesados {processed_files} adjuntos del email",
                'from': from_address,
                'subject': subject,
                'processed_files': processed_files,
                'tenant_id': tenant_id
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
    
    Returns:
        dict: Información sobre el tenant identificado y el destinatario usado
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
                    username = email_parts[0].lower()
                    domain = email_parts[1].lower()
                    
                    if domain.endswith('.docpilot.com'):
                        # Extraer tenant-id del dominio
                        tenant_part = domain.replace('.docpilot.com', '')
                        
                        # Verificar que el tenant existe
                        try:
                            tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_part})
                            if 'Item' in tenant_response:
                                logger.info(f"Tenant identificado desde el dominio: {tenant_part}")
                                return {
                                    'tenant_id': tenant_part,
                                    'recipient': recipient,
                                    'username': username,
                                    'is_valid': True
                                }
                        except Exception as e:
                            logger.warning(f"Error verificando tenant {tenant_part}: {str(e)}")
        
        # Si no se encuentra un tenant específico, verificar si hay un tenant default configurado
        try:
            default_tenant_response = tenants_table.get_item(Key={'tenant_id': 'default'})
            if 'Item' in default_tenant_response:
                logger.info("Usando tenant 'default' para el email")
                return {
                    'tenant_id': 'default',
                    'recipient': all_recipients[0] if all_recipients else 'unknown',
                    'username': 'unknown',
                    'is_valid': True
                }
        except Exception as e:
            logger.warning(f"Error verificando tenant default: {str(e)}")
        
        # Si no hay tenant default, usar placeholder para guardar en cuarentena
        logger.warning("No se pudo identificar tenant, usando 'quarantine'")
        return {
            'tenant_id': 'quarantine',
            'recipient': all_recipients[0] if all_recipients else 'unknown',
            'username': 'unknown',
            'is_valid': False
        }
    
    except Exception as e:
        logger.warning(f"Error identificando tenant desde email: {str(e)}")
        return {
            'tenant_id': 'quarantine',
            'recipient': 'error',
            'username': 'error',
            'is_valid': False
        }

def verify_sender_authorization(email_address, tenant_id):
    """
    Verifica si un remitente está autorizado para enviar documentos al tenant
    
    Args:
        email_address (str): Dirección de correo del remitente
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resultado de la verificación
    """
    try:
        # Si el tenant es 'quarantine', no autorizar
        if tenant_id == 'quarantine':
            return {
                'is_authorized': False,
                'reason': 'Tenant inválido o no reconocido'
            }
        
        # Verificar si el remitente es un usuario registrado
        email_normalized = email_address.lower().strip()
        
        # Buscar usuarios con ese email en el tenant específico
        response = users_table.scan(
            FilterExpression="tenant_id = :t AND email = :e AND #status = :s",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":e": email_normalized,
                ":s": "active"
            },
            ExpressionAttributeNames={
                "#status": "status"
            }
        )
        
        users = response.get('Items', [])
        
        if users:
            user = users[0]
            logger.info(f"Remitente autorizado como usuario registrado: {user['user_id']}")
            return {
                'is_authorized': True,
                'user_id': user['user_id'],
                'user_role': user.get('role', 'user'),
                'method': 'registered_user',
                'send_notifications': user.get('preferences', {}).get('email_notifications', True)
            }
        
        # Verificar si el tenant tiene una whitelist de remitentes
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' in tenant_response:
            tenant = tenant_response['Item']
            
            # Verificar si hay una whitelist configurada
            whitelist = tenant.get('settings', {}).get('email_whitelist', [])
            
            if whitelist:
                # Verificar si el dominio o email completo está en la whitelist
                email_domain = email_normalized.split('@')[-1] if '@' in email_normalized else ""
                
                for entry in whitelist:
                    # Coincidencia exacta de email
                    if entry.lower() == email_normalized:
                        logger.info(f"Remitente autorizado por whitelist exacta: {entry}")
                        return {
                            'is_authorized': True,
                            'method': 'whitelist_exact',
                            'whitelist_entry': entry
                        }
                    
                    # Coincidencia de dominio (si la entrada comienza con @)
                    if entry.startswith('@') and email_domain == entry[1:].lower():
                        logger.info(f"Remitente autorizado por dominio en whitelist: {entry}")
                        return {
                            'is_authorized': True,
                            'method': 'whitelist_domain',
                            'whitelist_entry': entry
                        }
                
                # Si hay whitelist pero el remitente no está en ella
                logger.warning(f"Remitente no encontrado en whitelist: {email_normalized}")
                return {
                    'is_authorized': False,
                    'reason': 'Remitente no autorizado para este tenant'
                }
            
            # Verificar si el tenant acepta todos los correos (configuración permisiva)
            accept_all = tenant.get('settings', {}).get('accept_all_emails', False)
            
            if accept_all:
                logger.info(f"Remitente aceptado por política permisiva del tenant: {tenant_id}")
                return {
                    'is_authorized': True,
                    'method': 'tenant_accept_all'
                }
            
            # Por defecto, si no hay whitelist ni configuración permisiva, rechazar
            logger.warning(f"Remitente rechazado por política restrictiva del tenant: {tenant_id}")
            return {
                'is_authorized': False,
                'reason': 'Remitente no autorizado para este tenant'
            }
        
        # Si llegamos aquí, no pudimos verificar la autorización
        logger.warning(f"No se pudo verificar autorización para {email_normalized} en tenant {tenant_id}")
        return {
            'is_authorized': False,
            'reason': 'No se pudo verificar la autorización'
        }
        
    except Exception as e:
        logger.error(f"Error verificando autorización del remitente: {str(e)}")
        return {
            'is_authorized': False,
            'reason': f"Error verificando autorización: {str(e)}"
        }

def handle_unauthorized_email(msg, tenant_id, from_address, reason):
    """
    Maneja emails de remitentes no autorizados (guardar en cuarentena y notificar)
    
    Args:
        msg (email.message.Message): El mensaje de correo
        tenant_id (str): ID del tenant al que iba dirigido
        from_address (str): Dirección del remitente
        reason (str): Motivo del rechazo
    """
    try:
        # Generar un ID único para el email rechazado
        reject_id = str(uuid.uuid4())
        
        # Guardar el email original en una carpeta de cuarentena
        quarantine_key = f"quarantine/{tenant_id}/{reject_id}.eml"
        
        # Serializar el email completo
        email_content = msg.as_bytes()
        
        # Guardar en S3
        s3.put_object(
            Bucket=MAIN_BUCKET,
            Key=quarantine_key,
            Body=email_content,
            ContentType='message/rfc822',
            Metadata={
                'tenant_id': tenant_id,
                'from_address': from_address,
                'subject': msg.get('subject', 'No Subject'),
                'rejection_reason': reason,
                'timestamp': datetime.now().isoformat()
            }
        )
        
        logger.info(f"Email no autorizado guardado en cuarentena: {quarantine_key}")
        
        # Registrar el rechazo en DynamoDB (opcional)
        # Puedes crear una tabla específica para esto o usar una existente
        
        # Notificar al administrador del tenant sobre el email rechazado
        notify_unauthorized_email(tenant_id, from_address, msg.get('subject', 'No Subject'), reason, reject_id)
        
        # Opcionalmente, notificar al remitente que su email fue rechazado
        # notify_sender_of_rejection(from_address, tenant_id, reason)
        
    except Exception as e:
        logger.error(f"Error manejando email no autorizado: {str(e)}")

def notify_unauthorized_email(tenant_id, from_address, subject, reason, reject_id):
    """
    Notifica a los administradores del tenant sobre un email rechazado
    
    Args:
        tenant_id (str): ID del tenant
        from_address (str): Dirección del remitente rechazado
        subject (str): Asunto del email
        reason (str): Motivo del rechazo
        reject_id (str): ID único del rechazo
    """
    try:
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.warning(f"No se pudo notificar rechazo: Tenant no encontrado: {tenant_id}")
            return
        
        tenant = tenant_response['Item']
        
        # Obtener emails de administradores del tenant
        admin_email = tenant.get('settings', {}).get('admin_email')
        
        if not admin_email:
            # Si no hay admin_email configurado, buscar usuarios administradores
            admin_users_response = users_table.scan(
                FilterExpression="tenant_id = :t AND #role = :r AND #status = :s",
                ExpressionAttributeValues={
                    ":t": tenant_id,
                    ":r": "admin",
                    ":s": "active"
                },
                ExpressionAttributeNames={
                    "#role": "role",
                    "#status": "status"
                }
            )
            
            admin_users = admin_users_response.get('Items', [])
            
            if not admin_users:
                logger.warning(f"No se encontraron administradores para notificar en tenant: {tenant_id}")
                return
            
            admin_email = admin_users[0].get('email')
        
        if not admin_email:
            logger.warning(f"No se pudo encontrar email para notificación en tenant: {tenant_id}")
            return
        
        # Crear mensaje de notificación
        rejection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        notification_body = f"""
        Se ha recibido un email que fue rechazado por falta de autorización:
        
        Tenant: {tenant.get('name', tenant_id)}
        Remitente: {from_address}
        Asunto: {subject}
        Fecha y hora: {rejection_time}
        Motivo del rechazo: {reason}
        ID de referencia: {reject_id}
        
        El email original se ha guardado en cuarentena para su revisión.
        
        Si este remitente debería estar autorizado, puede:
        1. Agregar el correo a la whitelist del tenant
        2. Registrar al remitente como usuario en el sistema
        3. Cambiar la configuración del tenant para aceptar todos los correos
        
        No responda a este mensaje.
        """
        
        # Enviar notificación por email
        ses.send_email(
            Source='notifications@docpilot.com',  # Debe ser un remitente verificado en SES
            Destination={
                'ToAddresses': [admin_email]
            },
            Message={
                'Subject': {
                    'Data': f'[DocPilot] Email rechazado en {tenant.get("name", tenant_id)}'
                },
                'Body': {
                    'Text': {
                        'Data': notification_body
                    }
                }
            }
        )
        
        logger.info(f"Notificación de rechazo enviada a: {admin_email}")
        
    except Exception as e:
        logger.error(f"Error enviando notificación de email rechazado: {str(e)}")

def send_processing_confirmation(to_address, tenant_id, num_files, subject):
    """
    Envía confirmación de procesamiento al remitente
    
    Args:
        to_address (str): Dirección del remitente
        tenant_id (str): ID del tenant
        num_files (int): Número de archivos procesados
        subject (str): Asunto del email original
    """
    try:
        # Obtener información del tenant para personalizar el mensaje
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            logger.warning(f"No se pudo enviar confirmación: Tenant no encontrado: {tenant_id}")
            return False
        
        tenant = tenant_response['Item']
        tenant_name = tenant.get('name', tenant_id)
        
        # Verificar si las notificaciones están habilitadas para este tenant
        if not tenant.get('settings', {}).get('send_confirmations', True):
            logger.info(f"Confirmaciones deshabilitadas para tenant: {tenant_id}")
            return False
        
        # Crear mensaje de confirmación
        files_text = "archivo" if num_files == 1 else "archivos"
        confirmation_body = f"""
        Hemos recibido correctamente su email con el asunto:
        "{subject}"
        
        Se han procesado {num_files} {files_text} adjuntos.
        
        Este es un mensaje automático, por favor no responda.
        
        Atentamente,
        El equipo de {tenant_name}
        """
        
        # Enviar confirmación por email
        ses.send_email(
            Source=f'no-reply@{tenant_id}.docpilot.com',  # Debe ser un remitente verificado en SES
            Destination={
                'ToAddresses': [to_address]
            },
            Message={
                'Subject': {
                    'Data': f'[{tenant_name}] Confirmación de recepción de documentos'
                },
                'Body': {
                    'Text': {
                        'Data': confirmation_body
                    }
                }
            }
        )
        
        logger.info(f"Confirmación enviada a: {to_address}")
        return True
        
    except Exception as e:
        logger.error(f"Error enviando confirmación: {str(e)}")
        return False