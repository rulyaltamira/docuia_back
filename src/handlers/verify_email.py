import json
import os
import boto3
import logging
from datetime import datetime
from src.utils.response_helper import success_response, error_response
import time

# Configuración de logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Inicializar clientes AWS
cognito = boto3.client('cognito-idp')
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')

# Obtener nombres de tablas de variables de entorno
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
USER_POOL_ID = os.environ.get('USER_POOL_ID', 'eu-west-1_uJTvs1HT7')
SES_SENDER_EMAIL = os.environ.get('SES_SENDER_EMAIL', 'ruly.altamirano@ereace.es')

def lambda_handler(event, context):
    """
    Verifica el email de un usuario y envía el correo de confirmación
    """
    try:
        # Verificar que el remitente está configurado
        if not SES_SENDER_EMAIL:
            logger.error("SES_SENDER_EMAIL no está configurado")
            return error_response(500, 'Error de configuración del servidor')

        # Verificar que el remitente está verificado en SES
        try:
            verification_attrs = ses.get_identity_verification_attributes(
                Identities=[SES_SENDER_EMAIL]
            )
            sender_status = verification_attrs['VerificationAttributes'].get(SES_SENDER_EMAIL, {}).get('VerificationStatus')
            if sender_status != 'Success':
                logger.error(f"El remitente {SES_SENDER_EMAIL} no está verificado en SES")
                return error_response(500, 'Error de configuración del servidor de correo')
        except Exception as e:
            logger.error(f"Error verificando estado del remitente en SES: {str(e)}")
            return error_response(500, 'Error verificando configuración de correo')

        # Obtener token y tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        token = query_params.get('token')
        tenant_id = query_params.get('tenant')
        
        if not token or not tenant_id:
            logger.error("Faltan parámetros token o tenant")
            return error_response(400, 'Los parámetros token y tenant son obligatorios')
        
        # Buscar usuario con ese token
        response = users_table.scan(
            FilterExpression="tenant_id = :t AND verification_token = :v",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":v": token
            }
        )
        
        user_items = response.get('Items', [])
        
        if not user_items:
            logger.error(f"Token de verificación no válido: {token}")
            return error_response(400, 'Token de verificación no válido o expirado')
        
        user = user_items[0]
        email = user.get('email')
        user_id = user.get('user_id')
        
        # Verificar si el token ha expirado
        expiry = user.get('verification_expiry')
        if expiry and datetime.fromisoformat(expiry) < datetime.now():
            logger.error(f"Token de verificación expirado para el usuario: {email}")
            return error_response(400, 'El token de verificación ha expirado')
        
        logger.info(f"Verificando email para usuario: {email}")
        
        try:
            # Verificar estado actual del usuario en Cognito
            try:
                user_info = cognito.admin_get_user(
                    UserPoolId=USER_POOL_ID,
                    Username=email
                )
                current_status = user_info.get('UserStatus')
                
                # Si el usuario ya está en FORCE_CHANGE_PASSWORD, significa que ya está verificado
                if current_status == 'FORCE_CHANGE_PASSWORD':
                    logger.info(f"Usuario {email} ya está verificado y pendiente de cambio de contraseña")
                    # Actualizar estado en DynamoDB si es necesario
                    users_table.update_item(
                        Key={'user_id': user_id},
                        UpdateExpression="SET #status = :s, email_verified = :v, cognito_status = :cs",
                        ExpressionAttributeNames={
                            '#status': 'status'
                        },
                        ExpressionAttributeValues={
                            ':s': 'active',
                            ':v': True,
                            ':cs': 'FORCE_CHANGE_PASSWORD'
                        }
                    )
                    return {
                        'statusCode': 200,
                        'headers': {
                            'Access-Control-Allow-Origin': 'https://verify.docpilot.link',
                            'Access-Control-Allow-Credentials': 'false'
                        },
                        'body': json.dumps({
                            'message': 'Tu email ya está verificado. Por favor, inicia sesión con tu contraseña temporal y cámbiala cuando el sistema te lo solicite.',
                            'status': 'already_verified'
                        })
                    }
            except Exception as e:
                logger.error(f"Error verificando estado en Cognito: {str(e)}")
                # Continuamos con el proceso normal si no podemos verificar el estado
            
            # Confirmar el registro del usuario en Cognito
            try:
                cognito.admin_confirm_sign_up(
                    UserPoolId=USER_POOL_ID,
                    Username=email
                )
                logger.info(f"Registro confirmado en Cognito para: {email}")
            except cognito.exceptions.NotAuthorizedException as e:
                if 'User cannot be confirmed. Current status is FORCE_CHANGE_PASSWORD' in str(e):
                    logger.info(f"Usuario {email} ya está confirmado y pendiente de cambio de contraseña")
                    # No es un error, continuamos con la actualización de atributos
                else:
                    raise e
            
            # Actualizar atributos del usuario en Cognito
            cognito.admin_update_user_attributes(
                UserPoolId=USER_POOL_ID,
                Username=email,
                UserAttributes=[
                    {'Name': 'email_verified', 'Value': 'true'}
                ]
            )
            logger.info(f"Atributos actualizados en Cognito para: {email}")
            
            # Actualizar estado en DynamoDB
            users_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression="SET #status = :s, email_verified = :v, cognito_status = :cs",
                ExpressionAttributeNames={
                    '#status': 'status'
                },
                ExpressionAttributeValues={
                    ':s': 'active',
                    ':v': True,
                    ':cs': 'FORCE_CHANGE_PASSWORD'
                }
            )
            logger.info(f"Estado actualizado en DynamoDB para usuario: {user_id}")
            
            # Enviar correo de confirmación y verificar resultado
            email_sent = send_confirmation_email(email)
            if not email_sent:
                logger.warning("No se pudo enviar el correo de confirmación, pero el usuario está verificado")
            
            # Redirigir al usuario a la página de inicio de sesión
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': 'https://verify.docpilot.link',
                    'Access-Control-Allow-Credentials': 'false'
                },
                'body': json.dumps({
                    'message': 'Email verificado correctamente. Por favor, inicia sesión con tu contraseña temporal y cámbiala cuando el sistema te lo solicite.',
                    'status': 'verified'
                })
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error actualizando usuario en Cognito/DynamoDB: {error_msg}")
            
            if 'User cannot be confirmed. Current status is FORCE_CHANGE_PASSWORD' in error_msg:
                return {
                    'statusCode': 200,
                    'headers': {
                        'Access-Control-Allow-Origin': 'https://verify.docpilot.link',
                        'Access-Control-Allow-Credentials': 'false'
                    },
                    'body': json.dumps({
                        'message': 'Tu email ya está verificado. Por favor, inicia sesión con tu contraseña temporal y cámbiala cuando el sistema te lo solicite.',
                        'status': 'already_verified'
                    })
                }
            else:
                return error_response(500, 'Error al verificar el email. Por favor, contacta con soporte técnico.')
            
    except Exception as e:
        logger.error(f"Error en el proceso de verificación: {str(e)}")
        return error_response(500, 'Error inesperado en la verificación. Por favor, contacta con soporte técnico.')

def send_confirmation_email(email):
    """
    Envía el correo de confirmación después de verificar el email
    """
    try:
        # Verificar que el destinatario es válido
        if not email or '@' not in email:
            logger.error(f"Dirección de correo inválida: {email}")
            return False

        # Verificar que el remitente está verificado en SES
        try:
            verification_attrs = ses.get_identity_verification_attributes(
                Identities=[SES_SENDER_EMAIL]
            )
            sender_status = verification_attrs['VerificationAttributes'].get(SES_SENDER_EMAIL, {}).get('VerificationStatus')
            if sender_status != 'Success':
                logger.error(f"El remitente {SES_SENDER_EMAIL} no está verificado en SES. Estado: {sender_status}")
                return False
            logger.info(f"Remitente {SES_SENDER_EMAIL} verificado correctamente en SES")
        except Exception as e:
            logger.error(f"Error verificando estado del remitente en SES: {str(e)}")
            return False

        subject = "¡Tu cuenta ha sido verificada!"
        body_text = """
        ¡Felicitaciones! Tu cuenta ha sido verificada correctamente.
        
        Ya puedes iniciar sesión en la plataforma usando tu email y la contraseña temporal que te enviamos anteriormente.
        
        Recuerda que deberás cambiar tu contraseña en el primer inicio de sesión.
        
        Atentamente,
        El equipo de DocPilot
        """
        
        # Intentar enviar el correo con reintentos
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                logger.info(f"Intento {retry_count + 1} de envío de correo de confirmación a {email}")
                response = ses.send_email(
                    Source=SES_SENDER_EMAIL,
                    Destination={
                        'ToAddresses': [email]
                    },
                    Message={
                        'Subject': {'Data': subject},
                        'Body': {'Text': {'Data': body_text}}
                    }
                )
                message_id = response.get('MessageId')
                logger.info(f"Correo de confirmación enviado a {email}. Message ID: {message_id}")
                return True
                
            except ses.exceptions.MessageRejected as e:
                logger.error(f"Mensaje rechazado por SES: {str(e)}")
                return False
                
            except ses.exceptions.MailFromDomainNotVerifiedException as e:
                logger.error(f"Dominio del remitente no verificado: {str(e)}")
                return False
                
            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    logger.error(f"Error enviando correo después de {max_retries} intentos: {str(e)}")
                    return False
                logger.warning(f"Reintento {retry_count} de {max_retries} para enviar correo: {str(e)}")
                time.sleep(1)  # Esperar 1 segundo entre reintentos
                
        return False
        
    except Exception as e:
        logger.error(f"Error general enviando correo de confirmación: {str(e)}")
        return False 