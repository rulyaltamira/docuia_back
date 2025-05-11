import json
import os
import boto3
import logging
from datetime import datetime
from src.utils.response_helpers import create_success_response, create_error_response
from src.utils.encoders import DecimalEncoder
import time
import uuid

# Configuración de logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Inicializar clientes AWS
cognito = boto3.client('cognito-idp')
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')

# Obtener nombres de tablas de variables de entorno
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
roles_table = dynamodb.Table(os.environ.get('ROLES_TABLE'))
user_roles_table = dynamodb.Table(os.environ.get('USER_ROLES_TABLE'))
role_permissions_table = dynamodb.Table(os.environ.get('ROLE_PERMISSIONS_TABLE'))
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
            return create_error_response(500, 'Error de configuración del servidor')

        # Verificar que el remitente está verificado en SES
        try:
            verification_attrs = ses.get_identity_verification_attributes(
                Identities=[SES_SENDER_EMAIL]
            )
            sender_status = verification_attrs['VerificationAttributes'].get(SES_SENDER_EMAIL, {}).get('VerificationStatus')
            if sender_status != 'Success':
                logger.error(f"El remitente {SES_SENDER_EMAIL} no está verificado en SES")
                return create_error_response(500, 'Error de configuración del servidor de correo')
        except Exception as e:
            logger.error(f"Error verificando estado del remitente en SES: {str(e)}")
            return create_error_response(500, 'Error verificando configuración de correo')

        # Obtener token y tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        token = query_params.get('token')
        tenant_id = query_params.get('tenant')
        
        if not token or not tenant_id:
            logger.error("Faltan parámetros token o tenant")
            return create_error_response(400, 'Los parámetros token y tenant son obligatorios')
        
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
            return create_error_response(400, 'Token de verificación no válido o expirado')
        
        user = user_items[0]
        email = user.get('email')
        user_id = user.get('user_id')
        
        # Verificar si el token ha expirado
        expiry = user.get('verification_expiry')
        if expiry and datetime.fromisoformat(expiry) < datetime.now():
            logger.error(f"Token de verificación expirado para el usuario: {email}")
            return create_error_response(400, 'El token de verificación ha expirado')
        
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
                    
                    # NUEVO: Asignar rol de administrador al usuario si no tiene ninguno asignado
                    try:
                        # Verificar si ya tiene roles asignados
                        user_roles_response = user_roles_table.scan(
                            FilterExpression="user_id = :u AND tenant_id = :t",
                            ExpressionAttributeValues={
                                ":u": user_id,
                                ":t": tenant_id
                            }
                        )
                        
                        if not user_roles_response.get('Items'):
                            # Buscar rol admin para este tenant
                            admin_roles = roles_table.scan(
                                FilterExpression="tenant_id = :t AND role_name = :r",
                                ExpressionAttributeValues={
                                    ':t': tenant_id,
                                    ':r': 'admin'
                                }
                            ).get('Items', [])
                            
                            if admin_roles:
                                admin_role_id = admin_roles[0]['role_id']
                                timestamp = datetime.now().isoformat()
                                
                                # Asignar el rol al usuario
                                user_role_id = str(uuid.uuid4())
                                user_roles_table.put_item(Item={
                                    'id': user_role_id,
                                    'user_id': user_id,
                                    'role_id': admin_role_id,
                                    'tenant_id': tenant_id,
                                    'created_at': timestamp
                                })
                                
                                logger.info(f"Rol admin asignado al usuario ya verificado: {user_id}")
                            else:
                                # Crear rol admin si no existe
                                admin_role_id = str(uuid.uuid4())
                                timestamp = datetime.now().isoformat()
                                
                                # Crear rol admin
                                roles_table.put_item(Item={
                                    'role_id': admin_role_id,
                                    'tenant_id': tenant_id,
                                    'role_name': 'admin',
                                    'description': 'Administrador del sistema con acceso completo',
                                    'created_at': timestamp,
                                    'updated_at': timestamp,
                                    'created_by': 'system',
                                    'is_system_role': True,
                                    'status': 'active'
                                })
                                
                                logger.info(f"Rol admin creado para tenant {tenant_id}")
                                
                                # Asignar permisos estándar al rol admin
                                system_permissions = [
                                    'document:read', 'document:create', 'document:update', 'document:delete', 'document:download',
                                    'user:read', 'user:create', 'user:update', 'user:delete',
                                    'role:read', 'role:create', 'role:update', 'role:delete', 'role:assign',
                                    'tenant:read', 'tenant:update', 'tenant:configure',
                                    'alert:read', 'alert:manage', 'alert:rule',
                                    'stats:view', 'stats:advanced', 'stats:export',
                                    'audit:view', 'audit:export',
                                    'email:configure',
                                    'admin:full'
                                ]
                                
                                for permission in system_permissions:
                                    permission_id = str(uuid.uuid4())
                                    role_permissions_table.put_item(Item={
                                        'id': permission_id,
                                        'role_id': admin_role_id,
                                        'permission': permission,
                                        'tenant_id': tenant_id,
                                        'created_at': timestamp
                                    })
                                
                                # Asignar el rol al usuario
                                user_role_id = str(uuid.uuid4())
                                user_roles_table.put_item(Item={
                                    'id': user_role_id,
                                    'user_id': user_id,
                                    'role_id': admin_role_id,
                                    'tenant_id': tenant_id,
                                    'created_at': timestamp
                                })
                                
                                logger.info(f"Rol admin creado y asignado al usuario: {user_id}")
                        else:
                            logger.info(f"El usuario {user_id} ya tiene roles asignados")
                            
                    except Exception as e:
                        logger.error(f"Error asignando rol admin al usuario verificado: {str(e)}")
                        # Continuar el proceso aunque falle la asignación de rol
                    
                    # Usar los nuevos helpers estandarizados
                    return create_success_response(
                        {
                            'message': 'Tu email ya está verificado. Por favor, inicia sesión con tu contraseña temporal y cámbiala cuando el sistema te lo solicite.',
                            'status': 'already_verified'
                        },
                        decimal_encoder_cls=DecimalEncoder
                    )
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
            
            # NUEVO: Asignar rol de administrador al usuario si no tiene ninguno asignado
            try:
                # Verificar si ya tiene roles asignados
                user_roles_response = user_roles_table.scan(
                    FilterExpression="user_id = :u AND tenant_id = :t",
                    ExpressionAttributeValues={
                        ":u": user_id,
                        ":t": tenant_id
                    }
                )
                
                if not user_roles_response.get('Items'):
                    # Buscar rol admin para este tenant
                    admin_roles = roles_table.scan(
                        FilterExpression="tenant_id = :t AND role_name = :r",
                        ExpressionAttributeValues={
                            ':t': tenant_id,
                            ':r': 'admin'
                        }
                    ).get('Items', [])
                    
                    if admin_roles:
                        admin_role_id = admin_roles[0]['role_id']
                        timestamp = datetime.now().isoformat()
                        
                        # Asignar el rol al usuario
                        user_role_id = str(uuid.uuid4())
                        user_roles_table.put_item(Item={
                            'id': user_role_id,
                            'user_id': user_id,
                            'role_id': admin_role_id,
                            'tenant_id': tenant_id,
                            'created_at': timestamp
                        })
                        
                        logger.info(f"Rol admin asignado al usuario recién verificado: {user_id}")
                    else:
                        # Crear rol admin si no existe
                        admin_role_id = str(uuid.uuid4())
                        timestamp = datetime.now().isoformat()
                        
                        # Crear rol admin
                        roles_table.put_item(Item={
                            'role_id': admin_role_id,
                            'tenant_id': tenant_id,
                            'role_name': 'admin',
                            'description': 'Administrador del sistema con acceso completo',
                            'created_at': timestamp,
                            'updated_at': timestamp,
                            'created_by': 'system',
                            'is_system_role': True,
                            'status': 'active'
                        })
                        
                        logger.info(f"Rol admin creado para tenant {tenant_id}")
                        
                        # Asignar permisos estándar al rol admin
                        system_permissions = [
                            'document:read', 'document:create', 'document:update', 'document:delete', 'document:download',
                            'user:read', 'user:create', 'user:update', 'user:delete',
                            'role:read', 'role:create', 'role:update', 'role:delete', 'role:assign',
                            'tenant:read', 'tenant:update', 'tenant:configure',
                            'alert:read', 'alert:manage', 'alert:rule',
                            'stats:view', 'stats:advanced', 'stats:export',
                            'audit:view', 'audit:export',
                            'email:configure',
                            'admin:full'
                        ]
                        
                        for permission in system_permissions:
                            permission_id = str(uuid.uuid4())
                            role_permissions_table.put_item(Item={
                                'id': permission_id,
                                'role_id': admin_role_id,
                                'permission': permission,
                                'tenant_id': tenant_id,
                                'created_at': timestamp
                            })
                        
                        # Asignar el rol al usuario
                        user_role_id = str(uuid.uuid4())
                        user_roles_table.put_item(Item={
                            'id': user_role_id,
                            'user_id': user_id,
                            'role_id': admin_role_id,
                            'tenant_id': tenant_id,
                            'created_at': timestamp
                        })
                        
                        logger.info(f"Rol admin creado y asignado al usuario: {user_id}")
                else:
                    logger.info(f"El usuario {user_id} ya tiene roles asignados")
                    
            except Exception as e:
                logger.error(f"Error asignando rol admin al usuario verificado: {str(e)}")
                # Continuar el proceso aunque falle la asignación de rol
            
            # Enviar email de confirmación y verificar resultado
            email_sent = send_confirmation_email(email)
            if not email_sent:
                logger.warning("No se pudo enviar el correo de confirmación, pero el usuario está verificado")
            
            # Usar los nuevos helpers estandarizados
            return create_success_response(
                {
                    'message': 'Email verificado correctamente. Por favor, inicia sesión con tu contraseña temporal y cámbiala cuando el sistema te lo solicite.',
                    'status': 'verified'
                },
                decimal_encoder_cls=DecimalEncoder
            )
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error actualizando usuario en Cognito/DynamoDB: {error_msg}")
            
            if 'User cannot be confirmed. Current status is FORCE_CHANGE_PASSWORD' in error_msg:
                return create_success_response(
                    {
                        'message': 'Tu email ya está verificado. Por favor, inicia sesión con tu contraseña temporal y cámbiala cuando el sistema te lo solicite.',
                        'status': 'already_verified'
                    },
                    decimal_encoder_cls=DecimalEncoder
                )
            else:
                return create_error_response(500, 'Error al verificar el email. Por favor, contacta con soporte técnico.')
            
    except Exception as e:
        logger.error(f"Error en el proceso de verificación: {str(e)}")
        return create_error_response(500, 'Error inesperado en la verificación. Por favor, contacta con soporte técnico.')

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
            logger.info(f"Verificando identidad del remitente en SES: {SES_SENDER_EMAIL}")
            verification_attrs = ses.get_identity_verification_attributes(
                Identities=[SES_SENDER_EMAIL]
            )
            logger.debug(f"Atributos de verificación recibidos: {verification_attrs}")
            
            if not verification_attrs.get('VerificationAttributes') or SES_SENDER_EMAIL not in verification_attrs.get('VerificationAttributes', {}):
                logger.error(f"El remitente {SES_SENDER_EMAIL} no está registrado en SES")
                return False
                
            sender_status = verification_attrs['VerificationAttributes'].get(SES_SENDER_EMAIL, {}).get('VerificationStatus')
            logger.info(f"Estado de verificación del remitente {SES_SENDER_EMAIL}: {sender_status}")
            
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
        
        logger.info(f"Preparando envío de correo a {email} (remitente: {SES_SENDER_EMAIL}, asunto: '{subject}')")
        
        # Intentar enviar el correo con reintentos
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                logger.info(f"Intento {retry_count + 1} de envío de correo de confirmación a {email}")
                
                # Crear la estructura del mensaje para logging
                message_structure = {
                    'Source': SES_SENDER_EMAIL,
                    'Destination': {'ToAddresses': [email]},
                    'Message': {
                        'Subject': {'Data': subject},
                        'Body': {'Text': {'Data': 'Contenido del correo...' if len(body_text) > 100 else body_text}}
                    }
                }
                logger.debug(f"Estructura del mensaje a enviar: {json.dumps(message_structure)}")
                
                # Realizar el envío
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
                logger.debug(f"Respuesta completa de SES: {response}")
                return True
                
            except ses.exceptions.MessageRejected as e:
                logger.error(f"Mensaje rechazado por SES: {str(e)}")
                logger.error(f"Detalles adicionales del error MessageRejected: {type(e).__name__}")
                return False
                
            except ses.exceptions.MailFromDomainNotVerifiedException as e:
                logger.error(f"Dominio del remitente no verificado: {str(e)}")
                logger.error(f"Detalles adicionales del error MailFromDomainNotVerifiedException: {type(e).__name__}")
                return False
                
            except Exception as e:
                retry_count += 1
                logger.error(f"Error en intento {retry_count}: {str(e)}")
                logger.error(f"Tipo de error: {type(e).__name__}")
                
                if retry_count == max_retries:
                    logger.error(f"Error enviando correo después de {max_retries} intentos: {str(e)}")
                    return False
                    
                logger.warning(f"Reintento {retry_count} de {max_retries} para enviar correo: {str(e)}")
                time.sleep(1)  # Esperar 1 segundo entre reintentos
                
        return False
        
    except Exception as e:
        logger.error(f"Error general enviando correo de confirmación: {str(e)}")
        logger.error(f"Tipo de error: {type(e).__name__}")
        return False 