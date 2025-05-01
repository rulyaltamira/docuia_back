# docpilot-backend/src/handlers/alerts/alert_notifier.py
"""
Notificador de alertas para el sistema DocPilot

Este módulo gestiona el envío de notificaciones de alertas a través de diferentes canales:
- Email
- Dashboard
- Webhook
- SMS (preparado para implementación futura)

Se puede invocar desde SQS, Lambda o API Gateway.
"""

import json
import os
import boto3
import logging
from datetime import datetime
import urllib.request
import urllib.error
import urllib.parse
from src.utils.cors_middleware import add_cors_headers

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')
alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE'))
alert_preferences_table = dynamodb.Table(os.environ.get('ALERT_PREFERENCES_TABLE', ''))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))

def lambda_handler(event, context):
    """
    Envía notificaciones de alerta a través de diferentes canales.
    """
    try:
        logger.info(f"Evento recibido: {json.dumps(event)}")
        
        # Determinar tipo de invocación
        if 'Records' in event:
            # Invocación desde SQS
            logger.info(f"Procesando {len(event['Records'])} mensajes de SQS")
            processed_alerts = 0
            
            for record in event['Records']:
                try:
                    message_body = json.loads(record['body'])
                    result = process_alert_notification(message_body)
                    if result.get('success', False):
                        processed_alerts += 1
                except Exception as e:
                    logger.error(f"Error procesando mensaje SQS: {str(e)}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': f'Procesados {processed_alerts} de {len(event["Records"])} mensajes'
                })
            }
        
        elif event.get('httpMethod'):
            # Invocación desde API Gateway
            http_method = event.get('httpMethod', '')
            path = event.get('path', '')
            
            if http_method == 'POST' and path == '/alerts/notify':
                # Procesar la notificación directamente
                body = json.loads(event.get('body', '{}'))
                result = process_alert_notification(body)
                
                if result.get('success', False):
                    return {
                        'statusCode': 200,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({
                            'message': 'Notificación enviada correctamente',
                            'details': result
                        })
                    }
                else:
                    return {
                        'statusCode': 400,
                        'headers': {
                            'Content-Type': 'application/json',
                            'Access-Control-Allow-Origin': '*'
                        },
                        'body': json.dumps({
                            'error': 'Error enviando notificación',
                            'details': result.get('message', 'Error desconocido')
                        })
                    }
            
            elif http_method == 'POST' and path == '/alerts/preferences':
                return update_alert_preferences(event, context)
            
            elif http_method == 'GET' and path == '/alerts/preferences':
                return get_alert_preferences(event, context)
            
            elif http_method == 'GET' and path == '/alerts/summary':
                return get_alerts_summary(event, context)
            
            else:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({'error': 'Operación no válida'})
                }
        
        else:
            # Invocación directa desde otra función Lambda
            logger.info("Invocación directa desde Lambda")
            return process_alert_notification(event)
            
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error en lambda_handler: {str(e)}")
        logger.error(f"Traceback: {error_trace}")
        
        # Si la invocación fue desde API Gateway, retornar error 500
        if event.get('httpMethod'):
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'error': 'Error interno del servidor',
                    'details': str(e)
                })
            }
        return {
            'success': False,
            'error': str(e)
        }

def process_alert_notification(event_data):
    """
    Procesa una notificación de alerta y la envía por los canales configurados
    
    Args:
        event_data (dict): Datos de la alerta a notificar
        
    Returns:
        dict: Resultado del procesamiento
    """
    try:
        logger.info(f"Procesando datos de alerta: {json.dumps(event_data)}")
        
        # Validar campos requeridos
        if 'alert_id' not in event_data:
            return {
                'success': False,
                'message': 'Se requiere alert_id'
            }
        
        alert_id = event_data.get('alert_id')
        
        # Si se proporciona un canal específico, solo notificar por ese canal
        specific_channel = event_data.get('channel')
        
        logger.info(f"Procesando notificación para alerta: {alert_id}, canal: {specific_channel or 'todos'}")
        
        # Obtener datos de la alerta
        alert_data = get_alert_data(alert_id)
        
        if not alert_data:
            return {
                'success': False,
                'message': f'Alerta no encontrada: {alert_id}'
            }
        
        tenant_id = alert_data.get('tenant_id')
        channels = alert_data.get('notification_channels', ['dashboard'])
        
        # Obtener preferencias de notificación de usuarios
        user_preferences = get_notification_preferences(tenant_id, alert_data)
        
        # Resultados de notificación
        notification_results = {}
        
        # Notificar por cada canal configurado
        if not specific_channel or specific_channel == 'dashboard':
            # Dashboard siempre se actualiza (no requiere notificación externa)
            update_dashboard_status(alert_id, 'sent')
            notification_results['dashboard'] = {
                'success': True,
                'message': 'Actualizado estado en dashboard'
            }
        
        if (not specific_channel or specific_channel == 'email') and 'email' in channels:
            # Enviar notificaciones por email
            email_result = send_email_notifications(alert_data, user_preferences)
            notification_results['email'] = email_result
            
            # Actualizar estado de notificación
            if email_result.get('success', False):
                update_notification_status(alert_id, 'email', 'sent')
            else:
                update_notification_status(alert_id, 'email', 'failed')
        
        if (not specific_channel or specific_channel == 'webhook') and 'webhook' in channels:
            # Enviar notificación por webhook
            webhook_result = send_webhook_notification(alert_data, tenant_id)
            notification_results['webhook'] = webhook_result
            
            # Actualizar estado de notificación
            if webhook_result.get('success', False):
                update_notification_status(alert_id, 'webhook', 'sent')
            else:
                update_notification_status(alert_id, 'webhook', 'failed')
        
        if (not specific_channel or specific_channel == 'sms') and 'sms' in channels:
            # La implementación de SMS requeriría un servicio adicional como SNS o un proveedor externo
            # Por ahora, lo marcamos como no implementado
            notification_results['sms'] = {
                'success': False,
                'message': 'Notificaciones SMS no implementadas'
            }
            update_notification_status(alert_id, 'sms', 'not_implemented')
        
        # Determinar resultado general
        overall_success = any(result.get('success', False) for result in notification_results.values())
        
        return {
            'success': overall_success,
            'alert_id': alert_id,
            'channels': notification_results
        }
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error procesando alerta: {str(e)}")
        logger.error(f"Traceback: {error_trace}")
        return {
            'success': False,
            'message': f"Error interno: {str(e)}"
        }

def get_alert_data(alert_id):
    """
    Obtiene los datos completos de una alerta
    
    Args:
        alert_id (str): ID de la alerta
        
    Returns:
        dict: Datos de la alerta o None si no existe
    """
    try:
        response = alerts_table.get_item(Key={'alert_id': alert_id})
        if 'Item' in response:
            return response['Item']
        else:
            logger.warning(f"Alerta no encontrada: {alert_id}")
            return None
    except Exception as e:
        logger.error(f"Error obteniendo datos de alerta: {str(e)}")
        return None

def get_notification_preferences(tenant_id, alert_data):
    """
    Obtiene las preferencias de notificación de los usuarios para esta alerta
    
    Args:
        tenant_id (str): ID del tenant
        alert_data (dict): Datos de la alerta
        
    Returns:
        dict: Preferencias de notificación por usuario
    """
    try:
        # Por defecto, notificar a administradores
        admin_users = []
        
        # Obtener usuarios con rol de administrador
        response = users_table.scan(
            FilterExpression="tenant_id = :t AND #role = :r AND #status = :s",
            ExpressionAttributeValues={
                ':t': tenant_id,
                ':r': 'admin',
                ':s': 'active'
            },
            ExpressionAttributeNames={
                '#role': 'role',
                '#status': 'status'
            }
        )
        
        admin_users = response.get('Items', [])
        
        # Si hay una tabla de preferencias, consultar preferencias específicas
        user_preferences = {}
        
        # Verificar si la tabla de preferencias existe
        if alert_preferences_table.table_name:
            try:
                # Consultar preferencias para esta alerta específica
                alert_type = alert_data.get('alert_type')
                severity = alert_data.get('severity', 'medium')
                
                # Buscar preferencias específicas para este tipo de alerta y severidad
                preferences_response = alert_preferences_table.scan(
                    FilterExpression="tenant_id = :t AND (alert_type = :at OR alert_type = :all) AND (min_severity = :s OR min_severity = :lower)",
                    ExpressionAttributeValues={
                        ':t': tenant_id,
                        ':at': alert_type,
                        ':all': 'all',  # Preferencias para todos los tipos de alerta
                        ':s': severity,
                        ':lower': get_lower_severity(severity)
                    }
                )
                
                alert_preferences = preferences_response.get('Items', [])
                
                # Procesar preferencias
                for pref in alert_preferences:
                    user_id = pref.get('user_id')
                    if user_id:
                        user_preferences[user_id] = {
                            'channels': pref.get('channels', ['email', 'dashboard']),
                            'email': pref.get('email')
                        }
                
            except Exception as e:
                logger.warning(f"Error consultando preferencias de alertas: {str(e)}")
                # Continuar con valores por defecto
        
        # Si no hay preferencias específicas, usar valores por defecto para administradores
        if not user_preferences:
            for admin in admin_users:
                user_id = admin.get('user_id')
                user_preferences[user_id] = {
                    'channels': ['email', 'dashboard'],
                    'email': admin.get('email')
                }
        
        return user_preferences
        
    except Exception as e:
        logger.error(f"Error obteniendo preferencias de notificación: {str(e)}")
        return {}

def update_dashboard_status(alert_id, status):
    """
    Actualiza el estado de notificación en el dashboard
    
    Args:
        alert_id (str): ID de la alerta
        status (str): Estado de la notificación
    """
    try:
        alerts_table.update_item(
            Key={'alert_id': alert_id},
            UpdateExpression="set notification_status.dashboard = :s",
            ExpressionAttributeValues={
                ':s': status
            }
        )
        logger.info(f"Estado de dashboard actualizado para alerta {alert_id}: {status}")
        return True
    except Exception as e:
        logger.error(f"Error actualizando estado de dashboard: {str(e)}")
        return False

def update_notification_status(alert_id, channel, status):
    """
    Actualiza el estado de notificación para un canal específico
    
    Args:
        alert_id (str): ID de la alerta
        channel (str): Canal de notificación
        status (str): Estado de la notificación
    """
    try:
        alerts_table.update_item(
            Key={'alert_id': alert_id},
            UpdateExpression=f"set notification_status.{channel} = :s",
            ExpressionAttributeValues={
                ':s': status
            }
        )
        logger.info(f"Estado de {channel} actualizado para alerta {alert_id}: {status}")
        return True
    except Exception as e:
        logger.error(f"Error actualizando estado de {channel}: {str(e)}")
        return False

def send_email_notifications(alert_data, user_preferences):
    """
    Envía notificaciones por email a los usuarios configurados
    
    Args:
        alert_data (dict): Datos de la alerta
        user_preferences (dict): Preferencias de notificación por usuario
        
    Returns:
        dict: Resultado del envío
    """
    try:
        tenant_id = alert_data.get('tenant_id')
        alert_id = alert_data.get('alert_id')
        sent_count = 0
        error_count = 0
        recipients = []
        
        # Obtener información del tenant para personalizar el email
        tenant_info = get_tenant_info(tenant_id)
        tenant_name = tenant_info.get('name', tenant_id)
        
        # Construir asunto y cuerpo del email según el tipo de alerta
        alert_type = alert_data.get('alert_type')
        severity = alert_data.get('severity', 'medium')
        message = alert_data.get('message', 'Alerta del sistema')
        
        # Formatear asunto según severidad
        severity_prefix = {
            'critical': '[CRÍTICO] ',
            'high': '[IMPORTANTE] ',
            'medium': '',
            'low': '',
            'info': ''
        }
        
        subject = f"{severity_prefix.get(severity, '')}{tenant_name} - {format_alert_type(alert_type)}"
        
        # Construir cuerpo del email
        body_html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .alert-container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .alert-header {{ background-color: {get_severity_color(severity)}; color: white; padding: 10px 15px; border-radius: 4px 4px 0 0; }}
                .alert-body {{ border: 1px solid #ddd; border-top: none; padding: 15px; border-radius: 0 0 4px 4px; }}
                .alert-footer {{ margin-top: 20px; font-size: 12px; color: #777; }}
                .alert-button {{ display: inline-block; padding: 10px 15px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <div class="alert-container">
                <div class="alert-header">
                    <h2>{format_alert_type(alert_type)} - {severity.upper()}</h2>
                </div>
                <div class="alert-body">
                    <p><strong>Mensaje:</strong> {message}</p>
                    <p><strong>Fecha:</strong> {alert_data.get('created_at')}</p>
                    <p><strong>ID de alerta:</strong> {alert_id}</p>
                    {get_alert_details_html(alert_data)}
                    <div style="margin-top: 20px; text-align: center;">
                        <a href="{tenant_info.get('dashboard_url', 'https://app.docpilot.com')}/alerts/{alert_id}" class="alert-button">Ver detalles en el dashboard</a>
                    </div>
                </div>
                <div class="alert-footer">
                    <p>Este es un mensaje automático de DocPilot. Por favor, no responda a este correo.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        body_text = f"""
        {format_alert_type(alert_type)} - {severity.upper()}
        
        Mensaje: {message}
        Fecha: {alert_data.get('created_at')}
        ID de alerta: {alert_id}
        
        {get_alert_details_text(alert_data)}
        
        Ver detalles en el dashboard: {tenant_info.get('dashboard_url', 'https://app.docpilot.com')}/alerts/{alert_id}
        
        Este es un mensaje automático de DocPilot. Por favor, no responda a este correo.
        """
        
        # Verificar si podemos enviar desde un dominio verificado del tenant
        sender_email = get_sender_email(tenant_info)
        
        # Enviar a cada usuario según sus preferencias
        for user_id, preferences in user_preferences.items():
            # Verificar si el usuario tiene habilitadas las notificaciones por email
            if 'email' in preferences.get('channels', []) and preferences.get('email'):
                recipient = preferences.get('email')
                
                try:
                    send_email(sender_email, recipient, subject, body_html, body_text)
                    sent_count += 1
                    recipients.append(recipient)
                    logger.info(f"Email enviado a {recipient} para alerta {alert_id}")
                except Exception as e:
                    logger.error(f"Error enviando email a {recipient}: {str(e)}")
                    error_count += 1
        
        return {
            'success': sent_count > 0,
            'sent_count': sent_count,
            'error_count': error_count,
            'recipients': recipients
        }
        
    except Exception as e:
        logger.error(f"Error enviando notificaciones por email: {str(e)}")
        return {
            'success': False,
            'message': f"Error interno: {str(e)}",
            'sent_count': 0,
            'error_count': 0
        }

def send_webhook_notification(alert_data, tenant_id):
    """
    Envía una notificación a través de webhook
    
    Args:
        alert_data (dict): Datos de la alerta
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resultado del envío
    """
    try:
        # Obtener configuración de webhook del tenant
        tenant_info = get_tenant_info(tenant_id)
        webhook_url = tenant_info.get('webhook_url')
        webhook_secret = tenant_info.get('webhook_secret')
        
        if not webhook_url:
            logger.warning(f"Webhook no configurado para tenant: {tenant_id}")
            return {
                'success': False,
                'message': 'Webhook no configurado'
            }
        
        # Preparar datos para el webhook
        webhook_data = {
            'alert_id': alert_data.get('alert_id'),
            'tenant_id': tenant_id,
            'alert_type': alert_data.get('alert_type'),
            'severity': alert_data.get('severity', 'medium'),
            'message': alert_data.get('message'),
            'timestamp': alert_data.get('created_at'),
            'status': alert_data.get('status', 'new'),
            'related_entity_id': alert_data.get('related_entity_id'),
            'related_entity_type': alert_data.get('related_entity_type')
        }
        
        # Añadir datos específicos del evento
        if 'event_data' in alert_data:
            webhook_data['event_data'] = alert_data['event_data']
        
        # Preparar los datos para la solicitud
        data = json.dumps(webhook_data).encode('utf-8')
        
        # Preparar los headers
        headers = {
            'Content-Type': 'application/json'
        }
        
        if webhook_secret:
            # Generar firma HMAC (en una implementación real)
            # Este es un placeholder simplificado
            headers['X-DocPilot-Signature'] = f"t={int(datetime.now().timestamp())},v1=signature"
        
        # Crear la solicitud
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers=headers,
            method='POST'
        )
        
        # Enviar la solicitud con un timeout de 5 segundos
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                
                if 200 <= status_code < 300:
                    logger.info(f"Webhook enviado correctamente: {status_code}")
                    return {
                        'success': True,
                        'status_code': status_code
                    }
                else:
                    response_text = response.read().decode('utf-8')
                    logger.warning(f"Error en webhook: {status_code} - {response_text}")
                    return {
                        'success': False,
                        'status_code': status_code,
                        'message': response_text
                    }
        except urllib.error.URLError as e:
            logger.error(f"Error de conexión webhook: {str(e)}")
            return {
                'success': False,
                'message': f"Error de conexión: {str(e)}"
            }
            
    except Exception as e:
        logger.error(f"Error enviando webhook: {str(e)}")
        return {
            'success': False,
            'message': f"Error interno: {str(e)}"
        }

def get_tenant_info(tenant_id):
    """
    Obtiene información del tenant
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Información del tenant
    """
    try:
        response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' in response:
            return response['Item']
        else:
            logger.warning(f"Tenant no encontrado: {tenant_id}")
            return {}
    except Exception as e:
        logger.error(f"Error obteniendo información del tenant: {str(e)}")
        return {}

def send_email(sender, recipient, subject, body_html, body_text):
    """
    Envía un email usando Amazon SES
    
    Args:
        sender (str): Dirección del remitente
        recipient (str): Dirección del destinatario
        subject (str): Asunto del email
        body_html (str): Cuerpo HTML del email
        body_text (str): Cuerpo de texto plano del email
    """
    try:
        ses.send_email(
            Source=sender,
            Destination={
                'ToAddresses': [recipient]
            },
            Message={
                'Subject': {
                    'Data': subject
                },
                'Body': {
                    'Text': {
                        'Data': body_text
                    },
                    'Html': {
                        'Data': body_html
                    }
                }
            }
        )
        return True
    except Exception as e:
        logger.error(f"Error SES: {str(e)}")
        raise

def update_alert_preferences(event, context):
    """
    Actualiza las preferencias de notificación de un usuario
    """
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos obligatorios
        required_fields = ['tenant_id', 'user_id']
        missing_fields = [field for field in required_fields if field not in body]
        
        if missing_fields:
            logger.error(f"Faltan campos obligatorios: {', '.join(missing_fields)}")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': f"Se requieren campos: {', '.join(missing_fields)}"})
            }
        
        tenant_id = body.get('tenant_id')
        user_id = body.get('user_id')
        
        # Verificar que el usuario existe y pertenece al tenant
        user_response = users_table.get_item(Key={'user_id': user_id})
        if 'Item' not in user_response or user_response['Item'].get('tenant_id') != tenant_id:
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': 'Usuario no válido para este tenant'})
            }
        
        # Preparar datos de preferencias
        timestamp = datetime.now().isoformat()
        
        preferences = {
            'user_id': user_id,
            'tenant_id': tenant_id,
            'email': body.get('email', user_response['Item'].get('email')),
            'alert_type': body.get('alert_type', 'all'),
            'min_severity': body.get('min_severity', 'low'),
            'channels': body.get('channels', ['email', 'dashboard']),
            'updated_at': timestamp
        }
        
        # Guardar preferencias en DynamoDB
        # Si la tabla existe
        if alert_preferences_table.table_name:
            # Generar ID único para la preferencia
            preference_id = f"{user_id}:{body.get('alert_type', 'all')}"
            preferences['preference_id'] = preference_id
            
            alert_preferences_table.put_item(Item=preferences)
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'message': 'Preferencias actualizadas correctamente',
                    'preference_id': preference_id
                })
            }
        else:
            # Si no hay tabla específica, actualizar en la tabla de usuarios
            users_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression="set alert_preferences = :p",
                ExpressionAttributeValues={
                    ':p': {
                        'min_severity': body.get('min_severity', 'low'),
                        'channels': body.get('channels', ['email', 'dashboard']),
                        'updated_at': timestamp
                    }
                }
            )
            
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'message': 'Preferencias actualizadas correctamente',
                    'user_id': user_id
                })
            }
        
    except Exception as e:
        logger.error(f"Error actualizando preferencias: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': f"Error interno: {str(e)}"})
        }

def get_alert_preferences(event, context):
    """
    Obtiene las preferencias de notificación de un usuario
    """
    try:
        # Obtener parámetros de consulta
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        user_id = query_params.get('user_id')
        
        if not tenant_id or not user_id:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': 'Se requieren tenant_id y user_id'})
            }
        
        # Verificar que el usuario existe y pertenece al tenant
        user_response = users_table.get_item(Key={'user_id': user_id})
        if 'Item' not in user_response or user_response['Item'].get('tenant_id') != tenant_id:
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': 'Usuario no válido para este tenant'})
            }
        
        # Obtener preferencias
        preferences = []
        
        # Si la tabla existe
        if alert_preferences_table.table_name:
            # Consultar preferencias específicas del usuario
            response = alert_preferences_table.scan(
                FilterExpression="tenant_id = :t AND user_id = :u",
                ExpressionAttributeValues={
                    ':t': tenant_id,
                    ':u': user_id
                }
            )
            
            preferences = response.get('Items', [])
        else:
            # Si no hay tabla específica, obtener de la tabla de usuarios
            user = user_response['Item']
            user_preferences = user.get('alert_preferences', {})
            
            # Convertir a formato compatible
            if user_preferences:
                preferences = [{
                    'user_id': user_id,
                    'tenant_id': tenant_id,
                    'email': user.get('email'),
                    'alert_type': 'all',
                    'min_severity': user_preferences.get('min_severity', 'low'),
                    'channels': user_preferences.get('channels', ['email', 'dashboard']),
                     'updated_at': user_preferences.get('updated_at', '')
                }]
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'preferences': preferences
            })
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo preferencias: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': f"Error interno: {str(e)}"})
        }

def get_tenant_id_from_headers(headers):
    """Extrae el tenant_id de las cabeceras, insensible a mayúsculas/minúsculas."""
    if not headers:
        return None
    for key in headers:
        if key.lower() == 'x-tenant-id':
            return headers[key]
    return None

def get_alerts_summary(event, context):
    try:
        logger.info(f"Recibido evento para resumen de alertas: {json.dumps(event)}")

        # Obtener tenant_id de las cabeceras
        headers = event.get('headers', {})
        tenant_id = get_tenant_id_from_headers(headers)

        # Obtener user_id de los parámetros de consulta (si aún es necesario)
        params = event.get('queryStringParameters', {})
        if params is None: 
            params = {}
        user_id = params.get('user_id') 

        # Validar tenant_id
        if not tenant_id:
            logger.warning("Falta la cabecera x-tenant-id en la solicitud de resumen")
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requiere la cabecera x-tenant-id'})
            }
        
        # Validar user_id si es necesario para tu lógica
        # if not user_id:
        #     logger.warning("Falta user_id en los parámetros de consulta")
        #     return {
        #         'statusCode': 400,
        #         'headers': {
        #             'Content-Type': 'application/json',
        #             'Access-Control-Allow-Origin': '*'
        #         },
        #         'body': json.dumps({'error': 'Se requiere user_id como parámetro de consulta'})
        #     }

        logger.info(f"Generando resumen de alertas para tenant: {tenant_id}, usuario: {user_id or 'No especificado'}")
        
        # Ejemplo: Contar alertas por severidad para el tenant_id dado
        severities = ['critical', 'high', 'medium', 'low', 'info']
        summary = {severity: 0 for severity in severities}
        total_alerts = 0
        
        # Usar Scan con FilterExpression. Mejor usar Query si hay GSI por tenant.
        scan_kwargs = {
            'FilterExpression': boto3.dynamodb.conditions.Attr('tenant_id').eq(tenant_id),
            'ProjectionExpression': 'alert_id, severity' # Solo traer los campos necesarios
        }
        
        done = False
        start_key = None
        while not done:
            if start_key:
                scan_kwargs['ExclusiveStartKey'] = start_key
            
            response = alerts_table.scan(**scan_kwargs)
            items = response.get('Items', [])
            
            for item in items:
                severity = item.get('severity', 'info').lower()
                if severity in summary:
                    summary[severity] += 1
                total_alerts += 1
                
            start_key = response.get('LastEvaluatedKey', None)
            done = start_key is None
            
        logger.info(f"Resumen calculado: {summary}, Total: {total_alerts}")

        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'summary': summary,
                'total_alerts': total_alerts,
                'tenant_id': tenant_id,
                'user_id': user_id
            })
        }

    except ClientError as e:
        logger.error(f"Error de DynamoDB en resumen: {e.response['Error']['Message']}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno del servidor al consultar resumen de alertas'})
        }
    except Exception as e:
        logger.error(f"Error inesperado en resumen: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno del servidor'})
        }

# Funciones de utilidad

def get_severity_color(severity):
    """Devuelve el color asociado a una severidad"""
    colors = {
        'critical': '#FF0000',  # Rojo
        'high': '#FF7F00',      # Naranja
        'medium': '#FFBF00',    # Ámbar
        'low': '#0077CC',       # Azul
        'info': '#3F9142'       # Verde
    }
    return colors.get(severity, '#777777')

def format_alert_type(alert_type):
    """Formatea un tipo de alerta para visualización"""
    labels = {
        'document_error': 'Error en documento',
        'document_duplicate': 'Documento duplicado',
        'limit_approaching': 'Límite próximo a alcanzarse',
        'limit_reached': 'Límite alcanzado',
        'suspicious_activity': 'Actividad sospechosa',
        'email_processing_error': 'Error procesando email',
        'new_document_received': 'Nuevo documento recibido',
        'domain_verification': 'Verificación de dominio',
        'scheduled_reminder': 'Recordatorio programado',
        'custom': 'Alerta personalizada'
    }
    return labels.get(alert_type, alert_type)

def get_lower_severity(severity):
    """
    Obtiene la severidad inferior a la especificada
    Útil para determinar si se deben enviar alertas basadas en nivel mínimo
    """
    severity_levels = ['critical', 'high', 'medium', 'low', 'info']
    try:
        current_index = severity_levels.index(severity)
        if current_index + 1 < len(severity_levels):
            return severity_levels[current_index + 1]
        return severity
    except ValueError:
        return 'low'  # valor por defecto si no se encuentra

def get_alert_details_html(alert_data):
    """Genera HTML con detalles adicionales de la alerta"""
    event_data = alert_data.get('event_data', {})
    if not event_data:
        return ""
    
    alert_type = alert_data.get('alert_type')
    
    if alert_type == 'document_error':
        return f"""
        <p><strong>ID de documento:</strong> {event_data.get('document_id', 'N/A')}</p>
        <p><strong>Tipo de error:</strong> {event_data.get('error_type', 'Desconocido')}</p>
        <p><strong>Detalles:</strong> {event_data.get('error_details', 'No disponible')}</p>
        """
    
    elif alert_type == 'document_duplicate':
        return f"""
        <p><strong>ID de documento:</strong> {event_data.get('document_id', 'N/A')}</p>
        <p><strong>ID de documento original:</strong> {event_data.get('original_document_id', 'N/A')}</p>
        <p><strong>Nombre de archivo:</strong> {event_data.get('filename', 'No disponible')}</p>
        """
    
    elif alert_type in ['limit_approaching', 'limit_reached']:
        usage_data = event_data.get('usage_data', {}) or event_data.get('limit_data', {})
        limit_type = usage_data.get('limit_type', 'desconocido')
        current = usage_data.get('current_usage', 0)
        maximum = usage_data.get('max_limit', 0)
        
        limit_types = {
            'users': 'usuarios',
            'documents': 'documentos',
            'storage': 'almacenamiento (MB)'
        }
        
        limit_name = limit_types.get(limit_type, limit_type)
        percentage = int((current / maximum) * 100) if maximum > 0 else 0
        
        return f"""
        <p><strong>Tipo de límite:</strong> {limit_name}</p>
        <p><strong>Uso actual:</strong> {current}/{maximum} ({percentage}%)</p>
        <p><strong>Plan actual:</strong> {event_data.get('plan', 'No disponible')}</p>
        """
    
    # Para otros tipos, mostrar datos genéricos
    html = "<p><strong>Detalles adicionales:</strong></p><ul>"
    for key, value in event_data.items():
        if key not in ['tenant_id', 'event_type']:
            html += f"<li><strong>{key}:</strong> {value}</li>"
    html += "</ul>"
    
    return html

def get_alert_details_text(alert_data):
    """Genera texto plano con detalles adicionales de la alerta"""
    event_data = alert_data.get('event_data', {})
    if not event_data:
        return ""
    
    alert_type = alert_data.get('alert_type')
    text = "Detalles adicionales:\n"
    
    if alert_type == 'document_error':
        text += f"""
ID de documento: {event_data.get('document_id', 'N/A')}
Tipo de error: {event_data.get('error_type', 'Desconocido')}
Detalles: {event_data.get('error_details', 'No disponible')}
"""
    
    elif alert_type == 'document_duplicate':
        text += f"""
ID de documento: {event_data.get('document_id', 'N/A')}
ID de documento original: {event_data.get('original_document_id', 'N/A')}
Nombre de archivo: {event_data.get('filename', 'No disponible')}
"""
    
    elif alert_type in ['limit_approaching', 'limit_reached']:
        usage_data = event_data.get('usage_data', {}) or event_data.get('limit_data', {})
        limit_type = usage_data.get('limit_type', 'desconocido')
        current = usage_data.get('current_usage', 0)
        maximum = usage_data.get('max_limit', 0)
        
        limit_types = {
            'users': 'usuarios',
            'documents': 'documentos',
            'storage': 'almacenamiento (MB)'
        }
        
        limit_name = limit_types.get(limit_type, limit_type)
        percentage = int((current / maximum) * 100) if maximum > 0 else 0
        
        text += f"""
Tipo de límite: {limit_name}
Uso actual: {current}/{maximum} ({percentage}%)
Plan actual: {event_data.get('plan', 'No disponible')}
"""
    
    else:
        # Para otros tipos, mostrar datos genéricos
        for key, value in event_data.items():
            if key not in ['tenant_id', 'event_type']:
                text += f"{key}: {value}\n"
    
    return text

def get_sender_email(tenant_info):
    """Determina la dirección de correo electrónico del remitente"""
    # Verificar si hay un dominio verificado configurado
    email_domain = tenant_info.get('settings', {}).get('email_domain')
    
    if email_domain:
        try:
            # Verificar si el dominio está verificado en SES
            verification_response = ses.get_identity_verification_attributes(
                Identities=[email_domain]
            )
            
            domain_attrs = verification_response.get('VerificationAttributes', {}).get(email_domain, {})
            if domain_attrs.get('VerificationStatus') == 'Success':
                return f"alerts@{email_domain}"
        except Exception as e:
            logger.warning(f"Error verificando dominio para correos: {str(e)}")
    
    # Usar dirección por defecto
    return "alerts@docpilot.com"