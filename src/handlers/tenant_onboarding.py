# docpilot-backend/src/handlers/tenant_onboarding.py
# Proceso automatizado de onboarding para nuevos tenants

import json
import os
import uuid
import boto3
import logging
import secrets
from datetime import datetime
import re

# Importar utilidades
from src.utils.s3_helper import create_folder
from src.utils.response_helper import success_response, error_response, created_response

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
cognito = boto3.client('cognito-idp')
ses = boto3.client('ses')
tenant_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')
SES_BUCKET = os.environ.get('SES_BUCKET')
USER_POOL_ID = os.environ.get('USER_POOL_ID', '')

# Definir planes disponibles con sus límites (obtenidos de tenant_management.py)
TENANT_PLANS = {
    'free': {
        'max_users': 3,
        'max_documents': 100,
        'max_storage_mb': 100,
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': False,
            'custom_domain': False,
            'api_access': False
        }
    },
    'basic': {
        'max_users': 10,
        'max_documents': 1000,
        'max_storage_mb': 1000,
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': True,
            'custom_domain': False,
            'api_access': True
        }
    },
    'premium': {
        'max_users': 50,
        'max_documents': 10000,
        'max_storage_mb': 10000,
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': True,
            'custom_domain': True,
            'api_access': True
        }
    },
    'enterprise': {
        'max_users': -1,  # Ilimitado
        'max_documents': -1,  # Ilimitado
        'max_storage_mb': -1,  # Ilimitado
        'features': {
            'email_integration': True,
            'document_processing': True,
            'advanced_analytics': True,
            'custom_domain': True,
            'api_access': True
        }
    }
}

def lambda_handler(event, context):
    """Maneja el proceso de onboarding de nuevos tenants"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'POST' and path == '/tenants/onboard':
        return onboard_new_tenant(event, context)
    elif http_method == 'POST' and path == '/tenants/onboard/admin':
        return create_admin_user(event, context)
    elif http_method == 'GET' and path == '/tenants/onboard/status':
        return check_onboarding_status(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return error_response(400, 'Operación no válida')

def onboard_new_tenant(event, context):
    """
    Inicia el proceso de onboarding para un nuevo tenant.
    Incluye:
    1. Creación de registro en DynamoDB
    2. Creación de estructura de carpetas en S3
    3. Configuración inicial de SES (opcional)
    4. Inicialización de configuraciones por defecto
    """
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos obligatorios
        required_fields = ['name', 'plan', 'admin_email']
        missing_fields = [field for field in required_fields if field not in body]
        
        if missing_fields:
            logger.error(f"Faltan campos obligatorios: {', '.join(missing_fields)}")
            return error_response(400, f"Campos obligatorios: {', '.join(missing_fields)}")
        
        tenant_name = body.get('name')
        plan = body.get('plan', 'free')
        admin_email = body.get('admin_email')
        custom_domain = body.get('custom_domain', '')
        
        # Validar plan
        if plan not in TENANT_PLANS:
            logger.error(f"Plan no válido: {plan}")
            return error_response(400, f"Plan no válido. Opciones disponibles: {', '.join(TENANT_PLANS.keys())}")
        
        logger.info(f"Iniciando onboarding para tenant: {tenant_name}, plan: {plan}, admin: {admin_email}")
        
        # Generar tenant_id normalizado basado en el nombre
        tenant_id = normalize_tenant_id(tenant_name)
        
        # Verificar si el tenant_id ya existe
        if tenant_exists(tenant_id):
            alt_tenant_id = f"{tenant_id}-{str(uuid.uuid4())[:8]}"
            logger.warning(f"Tenant ID {tenant_id} ya existe, usando alternativo: {alt_tenant_id}")
            tenant_id = alt_tenant_id
        
        # Iniciar proceso de onboarding
        result = create_tenant_resources(tenant_id, tenant_name, plan, admin_email, custom_domain, body)
        
        if not result['success']:
            return error_response(500, result['message'])
            
        # Si hay correo de administrador, crear usuario (o programar creación)
        admin_result = {}
        if admin_email:
            admin_result = schedule_admin_creation(tenant_id, admin_email, body.get('admin_name', ''))
        
        return created_response({
            'tenant_id': tenant_id, 
            'name': tenant_name,
            'plan': plan,
            'status': 'onboarding_started',
            'admin_email': admin_email,
            'admin_status': admin_result.get('status', 'pending'),
            'resources_created': result['resources_created'],
            'message': 'Proceso de onboarding iniciado correctamente'
        })
    
    except Exception as e:
        logger.error(f"Error en onboarding: {str(e)}")
        return error_response(500, f"Error iniciando onboarding: {str(e)}")

def normalize_tenant_id(tenant_name):
    """
    Normaliza un nombre de tenant para crear un tenant_id válido
    - Convierte a minúsculas
    - Reemplaza espacios por guiones
    - Elimina caracteres especiales
    - Trunca a 20 caracteres
    
    Args:
        tenant_name (str): Nombre del tenant
        
    Returns:
        str: tenant_id normalizado
    """
    # Convertir a minúsculas y reemplazar espacios por guiones
    tenant_id = tenant_name.lower().replace(' ', '-')
    
    # Eliminar caracteres que no sean alfanuméricos o guiones
    tenant_id = re.sub(r'[^a-z0-9-]', '', tenant_id)
    
    # Eliminar múltiples guiones consecutivos
    tenant_id = re.sub(r'-+', '-', tenant_id)
    
    # Eliminar guiones al principio o final
    tenant_id = tenant_id.strip('-')
    
    # Truncar a 20 caracteres
    tenant_id = tenant_id[:20]
    
    # Si quedó vacío (caso extremo), usar un ID aleatorio
    if not tenant_id:
        tenant_id = f"tenant-{str(uuid.uuid4())[:8]}"
    
    return tenant_id

def tenant_exists(tenant_id):
    """
    Verifica si un tenant_id ya existe
    
    Args:
        tenant_id (str): ID del tenant a verificar
        
    Returns:
        bool: True si existe, False si no
    """
    try:
        response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        return 'Item' in response
    except Exception as e:
        logger.error(f"Error verificando existencia del tenant: {str(e)}")
        return False

def create_tenant_resources(tenant_id, tenant_name, plan, admin_email, custom_domain, additional_data=None):
    """
    Crea todos los recursos necesarios para un nuevo tenant
    
    Args:
        tenant_id (str): ID del tenant
        tenant_name (str): Nombre del tenant
        plan (str): Plan seleccionado
        admin_email (str): Email del administrador
        custom_domain (str): Dominio personalizado (opcional)
        additional_data (dict): Datos adicionales del formulario
        
    Returns:
        dict: Resultado de la operación
    """
    resources_created = []
    try:
        # 1. Crear estructura de carpetas en S3
        folder_paths = [
            f"tenants/{tenant_id}/raw/email/",
            f"tenants/{tenant_id}/raw/manual/",
            f"tenants/{tenant_id}/processed/",
            f"tenants/{tenant_id}/quarantine/"
        ]
        
        for path in folder_paths:
            create_folder(MAIN_BUCKET, path)
            resources_created.append(f"S3 folder: {path}")
        
        logger.info(f"Estructura de carpetas creada en S3 para tenant: {tenant_id}")
        
        # 2. Generar claves de seguridad
        api_key = f"docpilot_{secrets.token_urlsafe(32)}"
        webhook_secret = secrets.token_hex(16)
        
        # 3. Obtener límites del plan seleccionado
        plan_limits = TENANT_PLANS.get(plan, TENANT_PLANS['free'])
        
        # 4. Configuración inicial para el tenant
        initial_settings = additional_data.get('settings', {}) if additional_data else {}
        
        # Asegurar que hay configuraciones básicas
        if 'email_domain' not in initial_settings:
            initial_settings['email_domain'] = f"{tenant_id}.docpilot.com"
        
        if admin_email and 'admin_email' not in initial_settings:
            initial_settings['admin_email'] = admin_email
            
        # 5. Configurar dominio SES si es necesario
        ses_domain_status = 'not_configured'
        if plan_limits['features'].get('email_integration', False):
            # Aquí solo preparamos la configuración, la verificación se hará después
            email_domain = custom_domain if custom_domain else initial_settings['email_domain']
            ses_domain_status = 'pending_verification'
            
            logger.info(f"Preparado dominio para verificación SES: {email_domain}")
            resources_created.append(f"SES domain prepared: {email_domain}")
        
        # 6. Guardar información en DynamoDB
        timestamp = datetime.now().isoformat()
        tenant_item = {
            'tenant_id': tenant_id,
            'name': tenant_name,
            'plan': plan,
            'status': 'onboarding',  # Estado inicial durante onboarding
            'created_at': timestamp,
            'updated_at': timestamp,
            'onboarding_status': {
                'started_at': timestamp,
                'completion_percentage': 25,  # Inicial
                'steps_completed': ['tenant_registration', 's3_folders'],
                'steps_pending': ['admin_user_creation', 'domain_verification'],
                'current_step': 'admin_user_creation'
            },
            'limits': {
                'max_users': plan_limits['max_users'],
                'max_documents': plan_limits['max_documents'],
                'max_storage_mb': plan_limits['max_storage_mb']
            },
            'usage': {
                'users_count': 0,
                'documents_count': 0,
                'storage_used_mb': 0,
                'last_updated': timestamp
            },
            'features': plan_limits['features'],
            'settings': initial_settings,
            'webhook_url': additional_data.get('webhook_url', '') if additional_data else '',
            'webhook_secret': webhook_secret,
            'api_key': api_key,
            'billing_info': additional_data.get('billing_info', {}) if additional_data else {},
            'custom_domain': custom_domain
        }
        
        tenant_table.put_item(Item=tenant_item)
        logger.info(f"Información guardada en DynamoDB para tenant: {tenant_id}")
        resources_created.append("DynamoDB tenant record")
        
        # 7. Registrar metadatos adicionales si se proporcionaron
        if additional_data and 'industry' in additional_data:
            # Los campos adicionales se pueden usar para análisis o personalización
            tenant_metadata = {
                'tenant_id': tenant_id,
                'industry': additional_data.get('industry', ''),
                'company_size': additional_data.get('company_size', ''),
                'country': additional_data.get('country', ''),
                'referral_source': additional_data.get('referral_source', ''),
                'created_at': timestamp
            }
            # Opcional: guardar en otra tabla o en el mismo registro
        
        return {
            'success': True,
            'tenant_id': tenant_id,
            'resources_created': resources_created,
            'ses_domain_status': ses_domain_status
        }
        
    except Exception as e:
        logger.error(f"Error creando recursos para tenant {tenant_id}: {str(e)}")
        return {
            'success': False,
            'message': f"Error creando recursos: {str(e)}",
            'resources_created': resources_created
        }

def schedule_admin_creation(tenant_id, admin_email, admin_name=''):
    """
    Programa la creación del usuario administrador
    
    Args:
        tenant_id (str): ID del tenant
        admin_email (str): Email del administrador
        admin_name (str): Nombre del administrador (opcional)
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        # Opción 1: Crear administrador inmediatamente
        return create_admin_user_internal(tenant_id, admin_email, admin_name)
        
        # Opción 2: Programar creación para después (ej. cuando se verifique el dominio)
        # En este caso, se podría guardar en DynamoDB y tener otro proceso que lo ejecute
    except Exception as e:
        logger.error(f"Error programando creación de administrador: {str(e)}")
        return {
            'status': 'error',
            'message': f"Error programando creación de administrador: {str(e)}"
        }

def create_admin_user(event, context):
    """
    Endpoint para crear manualmente un usuario administrador
    """
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos obligatorios
        required_fields = ['tenant_id', 'email']
        missing_fields = [field for field in required_fields if field not in body]
        
        if missing_fields:
            logger.error(f"Faltan campos obligatorios: {', '.join(missing_fields)}")
            return error_response(400, f"Campos obligatorios: {', '.join(missing_fields)}")
        
        tenant_id = body.get('tenant_id')
        email = body.get('email')
        name = body.get('name', '')
        
        # Verificar que el tenant existe
        tenant_response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return error_response(404, 'Tenant no encontrado')
        
        # Crear usuario administrador
        result = create_admin_user_internal(tenant_id, email, name)
        
        if result['status'] == 'success':
            # Actualizar estado de onboarding
            update_onboarding_status(tenant_id, 'admin_user_creation')
            return success_response(result)
        else:
            return error_response(500, result['message'])
            
    except Exception as e:
        logger.error(f"Error creando usuario administrador: {str(e)}")
        return error_response(500, f"Error creando usuario administrador: {str(e)}")

def create_admin_user_internal(tenant_id, email, name=''):
    """
    Crea un usuario administrador para un tenant
    
    Args:
        tenant_id (str): ID del tenant
        email (str): Email del administrador
        name (str): Nombre del administrador (opcional)
        
    Returns:
        dict: Resultado de la operación
    """
    try:
        # Normalizar email (minúsculas, sin espacios)
        email = email.lower().strip()
        
        # Verificar que el usuario no existe ya
        email_exists = False
        try:
            # Buscar usuarios con ese email en el tenant específico
            response = users_table.scan(
                FilterExpression="tenant_id = :t AND email = :e",
                ExpressionAttributeValues={
                    ":t": tenant_id,
                    ":e": email
                }
            )
            
            email_exists = len(response.get('Items', [])) > 0
            
        except Exception as e:
            logger.warning(f"Error verificando existencia de email: {str(e)}")
            # Continuamos el proceso aunque falle esta verificación
        
        if email_exists:
            logger.warning(f"El email {email} ya existe para el tenant {tenant_id}")
            return {
                'status': 'warning',
                'message': 'El email ya existe para este tenant',
                'email': email
            }
        
        # Generar contraseña temporal
        temp_password = generate_temp_password()
        
        # Crear usuario en Cognito
        try:
            cognito_response = cognito.admin_create_user(
                UserPoolId=USER_POOL_ID,
                Username=email,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'email_verified', 'Value': 'true'},
                    {'Name': 'custom:tenant_id', 'Value': tenant_id},
                    {'Name': 'custom:role', 'Value': 'admin'}
                ],
                TemporaryPassword=temp_password,
                MessageAction='SUPPRESS'  # Enviaremos nuestro propio email
            )
            
            cognito_id = cognito_response['User']['Username']
            logger.info(f"Usuario administrador creado en Cognito: {cognito_id}")
            
        except Exception as e:
            logger.error(f"Error al crear usuario en Cognito: {str(e)}")
            return {
                'status': 'error',
                'message': f"Error al crear usuario en Cognito: {str(e)}"
            }
        
        # Crear usuario en DynamoDB
        user_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Preparar nombre si se proporcionó
        display_name = name if name else email.split('@')[0]
        
        user_table.put_item(Item={
            'user_id': user_id,
            'tenant_id': tenant_id,
            'email': email,
            'name': display_name,
            'role': 'admin',
            'status': 'active',
            'created_at': timestamp,
            'last_login': None,
            'preferences': {
                'email_notifications': True,
                'language': 'es',
                'timezone': 'UTC'
            },
            'cognito_id': cognito_id
        })
        
        logger.info(f"Usuario administrador guardado en DynamoDB: {user_id}")
        
        # Actualizar contador de usuarios en el tenant
        try:
            tenant_table.update_item(
                Key={'tenant_id': tenant_id},
                UpdateExpression="SET usage.users_count = if_not_exists(usage.users_count, :zero) + :one",
                ExpressionAttributeValues={
                    ':zero': 0,
                    ':one': 1
                }
            )
        except Exception as e:
            logger.warning(f"Error actualizando contador de usuarios: {str(e)}")
        
        # Enviar email de bienvenida (sería implementado en un sistema de notificaciones)
        try:
            send_welcome_email(email, tenant_id, temp_password)
        except Exception as e:
            logger.warning(f"Error enviando email de bienvenida: {str(e)}")
        
        return {
            'status': 'success',
            'user_id': user_id,
            'email': email,
            'temp_password': temp_password,  # Solo en desarrollo, eliminar en producción
            'created_at': timestamp
        }
        
    except Exception as e:
        logger.error(f"Error interno creando usuario administrador: {str(e)}")
        return {
            'status': 'error',
            'message': f"Error interno: {str(e)}"
        }

def check_onboarding_status(event, context):
    """
    Verifica el estado del proceso de onboarding para un tenant
    """
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Obtener información del tenant
        tenant_response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return error_response(404, 'Tenant no encontrado')
        
        tenant = tenant_response['Item']
        
        # Verificar estado del proceso de onboarding
        onboarding_status = tenant.get('onboarding_status', {})
        
        # Si el tenant está activo, significa que el onboarding está completo
        if tenant.get('status') == 'active':
            onboarding_status['completion_percentage'] = 100
            onboarding_status['current_step'] = 'completed'
            onboarding_status['steps_pending'] = []
            
            if 'completed_at' not in onboarding_status:
                onboarding_status['completed_at'] = datetime.now().isoformat()
                
                # Actualizar estado en DynamoDB
                tenant_table.update_item(
                    Key={'tenant_id': tenant_id},
                    UpdateExpression="set onboarding_status.completed_at = :t, onboarding_status.completion_percentage = :p",
                    ExpressionAttributeValues={
                        ':t': onboarding_status['completed_at'],
                        ':p': 100
                    }
                )
        
        # Procesar estado para la respuesta
        response_data = {
            'tenant_id': tenant_id,
            'tenant_name': tenant.get('name', ''),
            'status': tenant.get('status', 'unknown'),
            'onboarding': {
                'started_at': onboarding_status.get('started_at', ''),
                'completed_at': onboarding_status.get('completed_at', None),
                'completion_percentage': onboarding_status.get('completion_percentage', 0),
                'current_step': onboarding_status.get('current_step', ''),
                'steps_completed': onboarding_status.get('steps_completed', []),
                'steps_pending': onboarding_status.get('steps_pending', [])
            }
        }
        
        return success_response(response_data)
        
    except Exception as e:
        logger.error(f"Error verificando estado de onboarding: {str(e)}")
        return error_response(500, f"Error verificando estado: {str(e)}")

def update_onboarding_status(tenant_id, completed_step):
    """
    Actualiza el estado del proceso de onboarding
    
    Args:
        tenant_id (str): ID del tenant
        completed_step (str): Paso completado
    """
    try:
        # Obtener información actual del tenant
        tenant_response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return False
        
        tenant = tenant_response['Item']
        onboarding_status = tenant.get('onboarding_status', {
            'started_at': datetime.now().isoformat(),
            'completion_percentage': 0,
            'steps_completed': [],
            'steps_pending': ['tenant_registration', 's3_folders', 'admin_user_creation', 'domain_verification'],
            'current_step': 'tenant_registration'
        })
        
        # Lista de todos los pasos del proceso de onboarding
        all_steps = ['tenant_registration', 's3_folders', 'admin_user_creation', 'domain_verification']
        
        # Actualizar listas de pasos completados y pendientes
        steps_completed = onboarding_status.get('steps_completed', [])
        if completed_step not in steps_completed:
            steps_completed.append(completed_step)
            
        steps_pending = [step for step in all_steps if step not in steps_completed]
        
        # Determinar paso actual
        current_step = 'completed' if not steps_pending else steps_pending[0]
        
        # Calcular porcentaje de completitud
        completion_percentage = int((len(steps_completed) / len(all_steps)) * 100)
        
        # Actualizar en DynamoDB
        update_expression = """
            set onboarding_status.steps_completed = :sc,
                onboarding_status.steps_pending = :sp,
                onboarding_status.current_step = :cs,
                onboarding_status.completion_percentage = :cp,
                updated_at = :ua
        """
        
        expression_values = {
            ':sc': steps_completed,
            ':sp': steps_pending,
            ':cs': current_step,
            ':cp': completion_percentage,
            ':ua': datetime.now().isoformat()
        }
        
        # Si está completado, actualizar estado general y fecha de completitud
        if not steps_pending:
            update_expression += ", status = :s, onboarding_status.completed_at = :ca"
            expression_values[':s'] = 'active'
            expression_values[':ca'] = datetime.now().isoformat()
        
        tenant_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )
        
        logger.info(f"Estado de onboarding actualizado para tenant {tenant_id}: {completion_percentage}% completado")
        return True
        
    except Exception as e:
        logger.error(f"Error actualizando estado de onboarding: {str(e)}")
        return False

def generate_temp_password():
    """Genera una contraseña temporal segura"""
    return f"DocP!{secrets.token_hex(8)}"

def send_welcome_email(email, tenant_id, temp_password):
    """
    Envía un email de bienvenida al administrador
    
    Args:
        email (str): Email del administrador
        tenant_id (str): ID del tenant
        temp_password (str): Contraseña temporal
    """
    # Obtener información del tenant
    try:
        tenant_response = tenant_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return False
        
        tenant = tenant_response['Item']
        tenant_name = tenant.get('name', tenant_id)
        
        # Verificar si el tenant tiene dominio verificado para envío de correos
        # En caso contrario, usar dominio por defecto de DocPilot
        sender_domain = tenant.get('settings', {}).get('email_domain', 'docpilot.com')
        
        # Verificar si el dominio está verificado en SES
        domain_verified = False
        try:
            verification_response = ses.get_identity_verification_attributes(
                Identities=[sender_domain]
            )
            
            domain_attributes = verification_response.get('VerificationAttributes', {}).get(sender_domain, {})
            domain_verified = domain_attributes.get('VerificationStatus') == 'Success'
        except Exception as e:
            logger.warning(f"Error verificando dominio: {str(e)}")
        
        # Usar dominio verificado o fallback a dominio por defecto
        sender_email = f"no-reply@{sender_domain}" if domain_verified else "no-reply@docpilot.com"
        
        # Preparar mensaje
        subject = f"Bienvenido a {tenant_name} en DocPilot"
        
        body_text = f"""
        Bienvenido a {tenant_name} en DocPilot!
        
        Su cuenta de administrador ha sido creada correctamente. Ahora puede acceder al sistema con las siguientes credenciales:
        
        Email: {email}
        Contraseña temporal: {temp_password}
        
        Importante: Deberá cambiar la contraseña temporal en su primer inicio de sesión.
        
        Acceda a la plataforma en: https://app.docpilot.com
        
        Atentamente,
        El equipo de DocPilot
        """
        
        # Enviar email
        ses.send_email(
            Source=sender_email,
            Destination={'ToAddresses': [email]},
            Message={
                'Subject': {'Data': subject},
                'Body': {
                    'Text': {'Data': body_text}
                }
            }
        )
        
        logger.info(f"Email de bienvenida enviado a: {email}")
        return True
        
    except Exception as e:
        logger.error(f"Error enviando email de bienvenida: {str(e)}")
        return False