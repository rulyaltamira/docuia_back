# docpilot-backend/src/handlers/alerts/alert_rule_manager.py
# Gestión de reglas de alerta para el sistema de DocPilot

import json
import os
import boto3
import logging
import uuid
from datetime import datetime
import decimal

# Importar utilidades actualizadas
from src.utils.response_helpers import create_success_response, create_error_response # Actualizado
from src.utils.auth_utils import get_tenant_id_or_error # Para obtener tenant_id
from src.utils.db_helpers import get_document_and_verify_tenant # Asegurar importación
# from src.utils.validation_helpers import validate_required_fields # Se podría usar aquí

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
# alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE')) # No se usa en create_alert_rule
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

class DecimalEncoder(json.JSONEncoder): # Añadir DecimalEncoder si las respuestas lo necesitan
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return float(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super(DecimalEncoder, self).default(o)

def lambda_handler(event, context):
    function_name = context.function_name if hasattr(context, 'function_name') else 'local_test'
    print(f"Evento recibido en {function_name}: {json.dumps(event)}")
    
    # TODO: Implementar la lógica del handler.
    # Recuerda reemplazar este placeholder con el código de tu archivo en la carpeta 'faltantes' o desarrollar la nueva lógica.
    
    response_body = {
        'message': f'Handler {function_name} ejecutado exitosamente (placeholder)',
        'input_event': event
    }
    
    return {
        'statusCode': 200,
        'body': json.dumps(response_body),
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*' # Ajustar según necesidad
        }
    }

# Para pruebas locales (opcional)
# if __name__ == '__main__':
#     # Simular un objeto context básico para pruebas locales
#     class MockContext:
#         function_name = "local_test_handler"
#     
#     mock_event = {"key": "value"}
#     # os.environ['MI_VARIABLE_DE_ENTORNO'] = 'valor_test'
#     print(lambda_handler(mock_event, MockContext()))

def validate_rule_data(data): # Refactorizada para devolver un dict para create_error_response o None
    """
    Valida los datos de una regla de alerta.
    Returns: None si es válido, o un diccionario con {message, error_code, status_code} si es inválido.
    """
    required_fields = ['name', 'alert_type']
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return {"message": f"Faltan campos obligatorios: {', '.join(missing_fields)}", "error_code": "MISSING_RULE_FIELDS", "status_code": 400}

    alert_type = data.get('alert_type')
    if alert_type not in VALID_ALERT_TYPES:
        return {"message": f"Tipo de alerta no válido. Válidos: {', '.join(VALID_ALERT_TYPES)}", "error_code": "INVALID_ALERT_TYPE", "status_code": 400}
    
    if 'severity' in data and data.get('severity') not in VALID_SEVERITY_LEVELS:
        return {"message": f"Nivel de severidad no válido. Válidos: {', '.join(VALID_SEVERITY_LEVELS)}", "error_code": "INVALID_SEVERITY", "status_code": 400}
    
    if 'notification_channels' in data:
        channels = data.get('notification_channels', [])
        if not isinstance(channels, list) or any(ch not in VALID_NOTIFICATION_CHANNELS for ch in channels):
            return {"message": f"Canales de notificación inválidos. Válidos: {', '.join(VALID_NOTIFICATION_CHANNELS)}", "error_code": "INVALID_CHANNELS", "status_code": 400}
    
    conditions = data.get('conditions', {})
    if alert_type in ['limit_approaching', 'limit_reached']:
        if 'limit_type' not in conditions or conditions.get('limit_type') not in ['users', 'documents', 'storage']:
            return {"message": "Para alertas de límite, 'limit_type' (users, documents, storage) es obligatorio en conditions.", "error_code": "INVALID_LIMIT_CONDITIONS", "status_code": 400}
        if alert_type == 'limit_approaching' and 'threshold_percentage' not in conditions:
            return {"message": "Para alerta limit_approaching, 'threshold_percentage' es obligatorio en conditions.", "error_code": "MISSING_THRESHOLD", "status_code": 400}
    elif alert_type == 'scheduled_reminder':
        if 'schedule' not in conditions:
            return {"message": "Para alerta scheduled_reminder, 'schedule' (expresión cron) es obligatorio en conditions.", "error_code": "MISSING_SCHEDULE", "status_code": 400}
    
    return None # Es válido

def create_alert_rule(event, context):
    """ Crea una nueva regla de alerta """
    try:
        body = json.loads(event.get('body', '{}'))
        
        # Obtener tenant_id del usuario autenticado (asumiendo que el endpoint está protegido)
        tenant_id, error_resp = get_tenant_id_or_error(event, decimal_encoder_cls=DecimalEncoder) # Pasar DecimalEncoder
        if error_resp:
            return error_resp
        
        # Validar datos de la regla usando la función refactorizada
        validation_error_data = validate_rule_data(body)
        if validation_error_data:
            return create_error_response(
                status_code=validation_error_data["status_code"],
                message=validation_error_data["message"],
                error_code=validation_error_data["error_code"],
                decimal_encoder_cls=DecimalEncoder
            )
        
        rule_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        alert_rule = {
            'rule_id': rule_id,
            'tenant_id': tenant_id, # Usar el tenant_id del token
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
            'created_by': body.get('created_by', 'user') # O obtener el user_id del token si es relevante
        }
        
        alert_rules_table.put_item(Item=alert_rule)
        logger.info(f"Regla de alerta creada: {rule_id} para tenant {tenant_id}")
        
        return create_success_response(
            data={'rule_id': rule_id, 'message': 'Regla de alerta creada correctamente'},
            status_code=201, # HTTP 201 Created
            decimal_encoder_cls=DecimalEncoder
        )
        
    except json.JSONDecodeError as json_err:
        logger.error(f"Error parseando JSON en create_alert_rule: {str(json_err)}")
        return create_error_response(400, "Cuerpo de solicitud JSON inválido.", error_code="INVALID_JSON", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error creando regla de alerta: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def list_alert_rules(event, context):
    """ Lista las reglas de alerta para un tenant """
    try:
        # Obtener tenant_id del usuario autenticado
        tenant_id, error_resp = get_tenant_id_or_error(event, decimal_encoder_cls=DecimalEncoder)
        if error_resp:
            return error_resp
        
        query_params = event.get('queryStringParameters', {}) or {}
        alert_type_filter = query_params.get('alert_type')
        enabled_filter_str = query_params.get('enabled')
        
        logger.info(f"Listando reglas de alerta para tenant: {tenant_id}, filtros: type={alert_type_filter}, enabled={enabled_filter_str}")

        filter_expressions = ["tenant_id = :t"]
        expression_values = {':t': tenant_id}
        # expression_names no se necesita aquí ya que 'tenant_id', 'alert_type', 'enabled' no son palabras reservadas.

        if alert_type_filter:
            filter_expressions.append("alert_type = :at")
            expression_values[':at'] = alert_type_filter
            
        if enabled_filter_str is not None:
            enabled_bool = enabled_filter_str.lower() == 'true'
            filter_expressions.append("enabled = :e")
            expression_values[':e'] = enabled_bool
        
        scan_params = {
            'FilterExpression': " AND ".join(filter_expressions),
            'ExpressionAttributeValues': expression_values
        }
        
        response = alert_rules_table.scan(**scan_params)
        rules = response.get('Items', [])
        rules.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        logger.info(f"Recuperadas {len(rules)} reglas de alerta para tenant: {tenant_id}")
        return create_success_response({'rules': rules, 'count': len(rules)}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        logger.error(f"Error listando reglas de alerta: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def get_alert_rule(event, context):
    """ Obtiene los detalles de una regla de alerta específica """
    try:
        requesting_tenant_id, error_resp = get_tenant_id_or_error(event, decimal_encoder_cls=DecimalEncoder)
        if error_resp: return error_resp

        rule_id = event.get('pathParameters', {}).get('rule_id')
        if not rule_id:
            return create_error_response(400, "Falta el rule_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Obteniendo regla de alerta: {rule_id} para tenant: {requesting_tenant_id}")
        
        rule, error_resp = get_document_and_verify_tenant(
            alert_rules_table, rule_id, requesting_tenant_id, 
            id_key_name='rule_id', tenant_id_key_name='tenant_id', 
            decimal_encoder_cls=DecimalEncoder
        )
        if error_resp: return error_resp
        
        logger.info(f"Regla de alerta recuperada: {rule_id}")
        return create_success_response({'rule': rule}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        logger.error(f"Error obteniendo regla de alerta: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def update_alert_rule(event, context):
    """ Actualiza una regla de alerta existente """
    try:
        requesting_tenant_id, error_resp = get_tenant_id_or_error(event, decimal_encoder_cls=DecimalEncoder)
        if error_resp: return error_resp

        rule_id = event.get('pathParameters', {}).get('rule_id')
        if not rule_id:
            return create_error_response(400, "Falta el rule_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        body = json.loads(event.get('body', '{}'))
        # El tenant_id en el body no se usa para la verificación de pertenencia, se usa el del token.
        # Podría usarse si se permite transferir una regla, pero eso es más complejo.

        logger.info(f"Actualizando regla: {rule_id} para tenant: {requesting_tenant_id}")

        # Verificar que la regla existe y pertenece al tenant solicitante
        rule, error_resp = get_document_and_verify_tenant(
            alert_rules_table, rule_id, requesting_tenant_id, 
            id_key_name='rule_id', tenant_id_key_name='tenant_id', 
            decimal_encoder_cls=DecimalEncoder
        )
        if error_resp: return error_resp
        
        # Validar datos si se modifican campos sensibles
        # Combinar regla existente con actualizaciones para una validación completa
        validation_data_for_update = {**rule, **body} 
        # Eliminar campos no relevantes para la validación de datos de regla (como rule_id, tenant_id del token, timestamps)
        fields_to_remove_for_validation = ['rule_id', 'tenant_id', 'created_at', 'updated_at', 'created_by']
        for field_to_remove in fields_to_remove_for_validation:
            if field_to_remove in validation_data_for_update:
                 del validation_data_for_update[field_to_remove]
        
        # Si se están modificando campos que validate_rule_data verifica
        if any(key in body for key in ['name', 'alert_type', 'severity', 'notification_channels', 'conditions']):
            validation_error_data = validate_rule_data(validation_data_for_update)
            if validation_error_data:
                return create_error_response(validation_error_data["status_code"], validation_error_data["message"], validation_error_data["error_code"], decimal_encoder_cls=DecimalEncoder)
        
        update_expression_parts = ["updated_at = :updated_at"]
        expression_values = {':updated_at': datetime.now().isoformat()}
        
        update_fields = ['name', 'description', 'alert_type', 'severity', 'conditions', 'notification_channels', 'notification_settings', 'enabled']
        for field in update_fields:
            if field in body:
                update_expression_parts.append(f"{field} = :{field}")
                expression_values[f':{field}'] = body[field]
        
        if len(update_expression_parts) == 1: # Solo se actualiza updated_at, no hay otros cambios
            return create_error_response(400, "No se proporcionaron campos válidos para actualizar.", error_code="NO_FIELDS_TO_UPDATE", decimal_encoder_cls=DecimalEncoder)

        final_update_expression = "set " + ", ".join(update_expression_parts)
        
        alert_rules_table.update_item(Key={'rule_id': rule_id}, UpdateExpression=final_update_expression, ExpressionAttributeValues=expression_values)
        logger.info(f"Regla de alerta actualizada: {rule_id}")
        return create_success_response({'rule_id': rule_id, 'message': 'Regla de alerta actualizada correctamente'}, decimal_encoder_cls=DecimalEncoder)
        
    except json.JSONDecodeError as json_err:
        logger.error(f"Error parseando JSON en update_alert_rule: {str(json_err)}")
        return create_error_response(400, "Cuerpo de solicitud JSON inválido.", error_code="INVALID_JSON", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error actualizando regla de alerta: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def delete_alert_rule(event, context):
    """ Elimina una regla de alerta """
    try:
        requesting_tenant_id, error_resp = get_tenant_id_or_error(event, decimal_encoder_cls=DecimalEncoder)
        if error_resp: return error_resp

        rule_id = event.get('pathParameters', {}).get('rule_id')
        if not rule_id:
            return create_error_response(400, "Falta el rule_id en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Eliminando regla de alerta: {rule_id} para tenant: {requesting_tenant_id}")

        # Verificar que la regla existe y pertenece al tenant solicitante antes de eliminar
        _, error_resp = get_document_and_verify_tenant(
            alert_rules_table, rule_id, requesting_tenant_id, 
            id_key_name='rule_id', tenant_id_key_name='tenant_id', 
            decimal_encoder_cls=DecimalEncoder
        )
        if error_resp: # Si no se encuentra (404) o no pertenece (403)
            return error_resp 
        
        alert_rules_table.delete_item(Key={'rule_id': rule_id})
        logger.info(f"Regla de alerta eliminada: {rule_id}")
        # HTTP 204 No Content es común para DELETE exitoso
        return create_success_response(None, status_code=204) 
        
    except Exception as e:
        logger.error(f"Error eliminando regla de alerta: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

def validate_alert_rule(event, context):
    """
    Valida una regla de alerta sin crearla
    Útil para validar formularios en el cliente
    """
    try:
        body = json.loads(event.get('body', '{}'))
        
        # Validar datos usando la función refactorizada
        validation_error_data = validate_rule_data(body)
        
        if validation_error_data: # Si hay un error de validación
            return create_error_response(
                status_code=validation_error_data["status_code"],
                message=validation_error_data["message"],
                error_code=validation_error_data["error_code"],
                decimal_encoder_cls=DecimalEncoder # Asumiendo que DecimalEncoder está definido en el archivo
            )
        else: # Si es válido
            return create_success_response({
                'is_valid': True,
                'message': 'Regla válida'
            }, decimal_encoder_cls=DecimalEncoder)
        
    except json.JSONDecodeError as json_err:
        logger.error(f"Error parseando JSON en validate_alert_rule: {str(json_err)}")
        return create_error_response(400, "Cuerpo de solicitud JSON inválido.", error_code="INVALID_JSON", decimal_encoder_cls=DecimalEncoder)
    except Exception as e:
        logger.error(f"Error validando regla de alerta: {str(e)}")
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)