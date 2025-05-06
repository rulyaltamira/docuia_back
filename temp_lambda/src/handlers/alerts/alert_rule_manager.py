# docpilot-backend/src/handlers/alerts/alert_rule_manager.py
# Gestión de reglas de alerta para el sistema de DocPilot

import json
import os
import boto3
import logging
import uuid
from datetime import datetime

# Importar utilidades
from src.utils.response_helper import success_response, error_response, created_response

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE'))
alert_rules_table = dynamodb.Table(os.environ.get('ALERT_RULES_TABLE'))

# Constantes
VALID_ALERT_TYPES = [
    'document_error',           # Error en procesamiento de documento
    'document_duplicate',       # Documento duplicado detectado
    'limit_approaching',        # Acercándose a un límite del plan
    'limit_reached',            # Límite del plan alcanzado
    'suspicious_activity',      # Actividad sospechosa en la cuenta
    'email_processing_error',   # Error procesando emails
    'new_document_received',    # Nuevo documento recibido (notificación)
    'domain_verification',      # Estados de verificación de dominio
    'scheduled_reminder',       # Recordatorio programado
    'custom'                    # Alerta personalizada
]

VALID_SEVERITY_LEVELS = [
    'critical',    # Requiere atención inmediata
    'high',        # Importante, debe atenderse pronto
    'medium',      # Normal, atención en tiempo regular
    'low',         # Informativa, baja prioridad
    'info'         # Solo informativa
]

VALID_NOTIFICATION_CHANNELS = [
    'email',       # Notificación por email
    'dashboard',   # Notificación en dashboard (siempre activada)
    'webhook',     # Envío a webhook configurado
    'sms'          # Notificación por SMS (si está configurado)
]

def lambda_handler(event, context):
    """Maneja operaciones CRUD para reglas de alerta"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'POST' and path == '/alerts/rules':
        return create_alert_rule(event, context)
    elif http_method == 'GET' and path == '/alerts/rules':
        return list_alert_rules(event, context)
    elif http_method == 'GET' and '/alerts/rules/' in path:
        return get_alert_rule(event, context)
    elif http_method == 'PUT' and '/alerts/rules/' in path:
        return update_alert_rule(event, context)
    elif http_method == 'DELETE' and '/alerts/rules/' in path:
        return delete_alert_rule(event, context)
    elif http_method == 'POST' and path == '/alerts/rules/validate':
        return validate_alert_rule(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return error_response(400, 'Operación no válida')

def create_alert_rule(event, context):
    """
    Crea una nueva regla de alerta
    
    Las reglas de alerta definen cuándo y cómo se generan alertas en el sistema.
    """
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar tenant_id
        tenant_id = body.get('tenant_id')
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Validar campos obligatorios y formato
        validation_result = validate_rule_data(body)
        if not validation_result['is_valid']:
            logger.error(f"Datos de regla inválidos: {validation_result['message']}")
            return error_response(400, validation_result['message'])
        
        # Preparar datos de la regla
        rule_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        alert_rule = {
            'rule_id': rule_id,
            'tenant_id': tenant_id,
            'name': body.get('name'),
            'description': body.get('description', ''),
            'alert_type': body.get('alert_type'),
            'severity': body.get('severity', 'medium'),
            'conditions': body.get('conditions', {}),
            'notification_channels': body.get('notification_channels', ['dashboard']),
            'notification_settings': body.get('notification_settings', {}),
            'enabled': body.get('enabled', True),
            'created_at': timestamp,
            'updated_at': timestamp,
            'created_by': body.get('created_by', 'system')
        }
        
        # Guardar en DynamoDB
        alert_rules_table.put_item(Item=alert_rule)
        
        logger.info(f"Regla de alerta creada: {rule_id} para tenant {tenant_id}")
        
        return created_response({
            'rule_id': rule_id,
            'message': 'Regla de alerta creada correctamente'
        })
        
    except Exception as e:
        logger.error(f"Error creando regla de alerta: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def validate_rule_data(data):
    """
    Valida los datos de una regla de alerta
    
    Args:
        data (dict): Datos de la regla a validar
        
    Returns:
        dict: Resultado de la validación
    """
    # Verificar campos obligatorios
    required_fields = ['name', 'alert_type']
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        return {
            'is_valid': False,
            'message': f"Faltan campos obligatorios: {', '.join(missing_fields)}"
        }
    
    # Validar tipo de alerta
    if data.get('alert_type') not in VALID_ALERT_TYPES:
        return {
            'is_valid': False,
            'message': f"Tipo de alerta no válido. Opciones válidas: {', '.join(VALID_ALERT_TYPES)}"
        }
    
    # Validar severidad si está presente
    if 'severity' in data and data.get('severity') not in VALID_SEVERITY_LEVELS:
        return {
            'is_valid': False,
            'message': f"Nivel de severidad no válido. Opciones válidas: {', '.join(VALID_SEVERITY_LEVELS)}"
        }
    
    # Validar canales de notificación si están presentes
    if 'notification_channels' in data:
        channels = data.get('notification_channels', [])
        invalid_channels = [ch for ch in channels if ch not in VALID_NOTIFICATION_CHANNELS]
        
        if invalid_channels:
            return {
                'is_valid': False,
                'message': f"Canales de notificación no válidos: {', '.join(invalid_channels)}. Opciones válidas: {', '.join(VALID_NOTIFICATION_CHANNELS)}"
            }
    
    # Validar condiciones según el tipo de alerta
    if 'conditions' in data:
        conditions = data.get('conditions', {})
        alert_type = data.get('alert_type')
        
        # Validación específica por tipo de alerta
        if alert_type == 'limit_approaching' or alert_type == 'limit_reached':
            if 'limit_type' not in conditions:
                return {
                    'is_valid': False,
                    'message': "El campo 'limit_type' es obligatorio para alertas de límites"
                }
            
            valid_limit_types = ['users', 'documents', 'storage']
            if conditions.get('limit_type') not in valid_limit_types:
                return {
                    'is_valid': False,
                    'message': f"Tipo de límite no válido. Opciones válidas: {', '.join(valid_limit_types)}"
                }
                
            if alert_type == 'limit_approaching' and 'threshold_percentage' not in conditions:
                return {
                    'is_valid': False,
                    'message': "El campo 'threshold_percentage' es obligatorio para alertas de límite aproximado"
                }
        
        elif alert_type == 'scheduled_reminder':
            if 'schedule' not in conditions:
                return {
                    'is_valid': False,
                    'message': "El campo 'schedule' es obligatorio para recordatorios programados"
                }
    
    # Si pasa todas las validaciones
    return {
        'is_valid': True,
        'message': 'Regla válida'
    }

def list_alert_rules(event, context):
    """
    Lista las reglas de alerta para un tenant
    """
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Filtros adicionales
        alert_type = query_params.get('alert_type')
        enabled = query_params.get('enabled')
        
        # Consultar reglas por tenant_id
        filter_expression = "tenant_id = :t"
        expression_values = {':t': tenant_id}
        
        # Añadir filtros adicionales si se proporcionan
        if alert_type:
            filter_expression += " AND alert_type = :at"
            expression_values[':at'] = alert_type
            
        if enabled is not None:
            # Convertir string a booleano
            enabled_bool = enabled.lower() == 'true'
            filter_expression += " AND enabled = :e"
            expression_values[':e'] = enabled_bool
        
        # Realizar la consulta
        response = alert_rules_table.scan(
            FilterExpression=filter_expression,
            ExpressionAttributeValues=expression_values
        )
        
        rules = response.get('Items', [])
        
        # Ordenar por fecha de creación descendente
        rules.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        logger.info(f"Recuperadas {len(rules)} reglas de alerta para tenant: {tenant_id}")
        
        return success_response({
            'rules': rules,
            'count': len(rules)
        })
        
    except Exception as e:
        logger.error(f"Error listando reglas de alerta: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def get_alert_rule(event, context):
    """
    Obtiene los detalles de una regla de alerta específica
    """
    try:
        # Obtener rule_id de la ruta
        rule_id = event['pathParameters']['rule_id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Obtener regla de DynamoDB
        response = alert_rules_table.get_item(Key={'rule_id': rule_id})
        
        if 'Item' not in response:
            logger.error(f"Regla no encontrada: {rule_id}")
            return error_response(404, 'Regla de alerta no encontrada')
        
        rule = response['Item']
        
        # Verificar que la regla pertenece al tenant
        if rule.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de acceso a regla de otro tenant: {rule_id}")
            return error_response(403, 'No tiene permiso para acceder a esta regla')
        
        logger.info(f"Regla de alerta recuperada: {rule_id}")
        
        return success_response({'rule': rule})
        
    except Exception as e:
        logger.error(f"Error obteniendo regla de alerta: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def update_alert_rule(event, context):
    """
    Actualiza una regla de alerta existente
    """
    try:
        # Obtener rule_id de la ruta
        rule_id = event['pathParameters']['rule_id']
        
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar tenant_id
        tenant_id = body.get('tenant_id')
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Verificar que la regla existe
        response = alert_rules_table.get_item(Key={'rule_id': rule_id})
        
        if 'Item' not in response:
            logger.error(f"Regla no encontrada: {rule_id}")
            return error_response(404, 'Regla de alerta no encontrada')
        
        rule = response['Item']
        
        # Verificar que la regla pertenece al tenant
        if rule.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de modificar regla de otro tenant: {rule_id}")
            return error_response(403, 'No tiene permiso para modificar esta regla')
        
        # Si se están modificando campos que requieren validación
        if any(key in body for key in ['alert_type', 'severity', 'notification_channels', 'conditions']):
            # Crear objeto para validación combinando la regla existente con las actualizaciones
            validation_data = {**rule, **body}
            validation_result = validate_rule_data(validation_data)
            
            if not validation_result['is_valid']:
                logger.error(f"Datos de regla inválidos: {validation_result['message']}")
                return error_response(400, validation_result['message'])
        
        # Construir expresión de actualización
        update_expression = "set updated_at = :updated_at"
        expression_values = {
            ':updated_at': datetime.now().isoformat()
        }
        
        # Añadir campos a actualizar
        update_fields = [
            'name', 'description', 'alert_type', 'severity', 
            'conditions', 'notification_channels', 'notification_settings', 
            'enabled'
        ]
        
        for field in update_fields:
            if field in body:
                update_expression += f", {field} = :{field}"
                expression_values[f':{field}'] = body[field]
        
        # Actualizar en DynamoDB
        alert_rules_table.update_item(
            Key={'rule_id': rule_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_values
        )
        
        logger.info(f"Regla de alerta actualizada: {rule_id}")
        
        return success_response({
            'rule_id': rule_id,
            'message': 'Regla de alerta actualizada correctamente'
        })
        
    except Exception as e:
        logger.error(f"Error actualizando regla de alerta: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def delete_alert_rule(event, context):
    """
    Elimina una regla de alerta
    """
    try:
        # Obtener rule_id de la ruta
        rule_id = event['pathParameters']['rule_id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Verificar que la regla existe y pertenece al tenant
        response = alert_rules_table.get_item(Key={'rule_id': rule_id})
        
        if 'Item' not in response:
            logger.error(f"Regla no encontrada: {rule_id}")
            return error_response(404, 'Regla de alerta no encontrada')
        
        rule = response['Item']
        
        # Verificar que la regla pertenece al tenant
        if rule.get('tenant_id') != tenant_id:
            logger.warning(f"Intento de eliminar regla de otro tenant: {rule_id}")
            return error_response(403, 'No tiene permiso para eliminar esta regla')
        
        # Eliminar la regla
        alert_rules_table.delete_item(Key={'rule_id': rule_id})
        
        logger.info(f"Regla de alerta eliminada: {rule_id}")
        
        return success_response({
            'message': 'Regla de alerta eliminada correctamente',
            'rule_id': rule_id
        })
        
    except Exception as e:
        logger.error(f"Error eliminando regla de alerta: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def validate_alert_rule(event, context):
    """
    Valida una regla de alerta sin crearla
    Útil para validar formularios en el cliente
    """
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar datos
        validation_result = validate_rule_data(body)
        
        return success_response({
            'is_valid': validation_result['is_valid'],
            'message': validation_result['message']
        })
        
    except Exception as e:
        logger.error(f"Error validando regla de alerta: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")