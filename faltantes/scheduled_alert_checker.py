# docpilot-backend/src/handlers/alerts/scheduled_alert_checker.py
# Verificador periódico de condiciones para alertas programadas

import json
import os
import boto3
import logging
import uuid
from datetime import datetime, timedelta
import time
import croniter

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Clientes y recursos de AWS
dynamodb = boto3.resource('dynamodb')
lambda_client = boto3.client('lambda')
cloudwatch = boto3.client('cloudwatch')
alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE'))
alert_rules_table = dynamodb.Table(os.environ.get('ALERT_RULES_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))

# Nombre de la función de procesamiento de alertas
ALERT_PROCESSOR_FUNCTION = os.environ.get('ALERT_PROCESSOR_FUNCTION', '')

def lambda_handler(event, context):
    """
    Verifica periódicamente reglas de alerta con condiciones temporales
    Se ejecuta mediante un evento programado de CloudWatch Events (EventBridge)
    """
    logger.info("Iniciando verificación periódica de alertas programadas")
    
    # Obtener hora actual
    current_time = datetime.now()
    
    # Si se proporcionan parámetros en el evento, usarlos para filtrar
    tenant_id = event.get('tenant_id')
    check_all_tenants = tenant_id is None
    
    # Procesar todas las reglas de alerta de tipo scheduled_reminder
    processed_rules = 0
    alerts_generated = 0
    
    try:
        # Obtener todas las reglas de tipo scheduled_reminder habilitadas
        if tenant_id:
            # Filtrar por tenant específico
            response = alert_rules_table.scan(
                FilterExpression="alert_type = :type AND enabled = :enabled AND tenant_id = :tenant",
                ExpressionAttributeValues={
                    ':type': 'scheduled_reminder',
                    ':enabled': True,
                    ':tenant': tenant_id
                }
            )
        else:
            # Todas las reglas programadas activas
            response = alert_rules_table.scan(
                FilterExpression="alert_type = :type AND enabled = :enabled",
                ExpressionAttributeValues={
                    ':type': 'scheduled_reminder',
                    ':enabled': True
                }
            )
        
        scheduled_rules = response.get('Items', [])
        logger.info(f"Encontradas {len(scheduled_rules)} reglas de alerta programadas")
        
        # Procesar cada regla
        for rule in scheduled_rules:
            rule_id = rule.get('rule_id')
            rule_tenant_id = rule.get('tenant_id')
            
            # Verificar si el tenant está activo
            tenant_status = check_tenant_status(rule_tenant_id)
            if tenant_status != 'active':
                logger.info(f"Omitiendo regla {rule_id} de tenant inactivo: {rule_tenant_id}")
                continue
            
            try:
                # Verificar si la regla debe ejecutarse ahora
                should_run, next_run = should_rule_run_now(rule, current_time)
                
                if should_run:
                    logger.info(f"Ejecutando regla programada: {rule_id}")
                    processed_rules += 1
                    
                    # Generar alertas basadas en la regla
                    alert_count = process_scheduled_rule(rule, current_time)
                    alerts_generated += alert_count
                    
                    # Actualizar último tiempo de ejecución
                    update_rule_last_run(rule_id, current_time, next_run)
            except Exception as e:
                logger.error(f"Error procesando regla {rule_id}: {str(e)}")
                continue
        
        logger.info(f"Verificación completada. Reglas procesadas: {processed_rules}, Alertas generadas: {alerts_generated}")
        
        # Publicar métricas en CloudWatch
        try:
            publish_metrics(processed_rules, alerts_generated)
        except Exception as e:
            logger.warning(f"No se pudieron publicar métricas: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Verificación de alertas programadas completada',
                'processed_rules': processed_rules,
                'alerts_generated': alerts_generated,
                'check_time': current_time.isoformat()
            })
        }
    
    except Exception as e:
        logger.error(f"Error en verificación de alertas programadas: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': f"Error en verificación: {str(e)}",
                'check_time': current_time.isoformat()
            })
        }

def should_rule_run_now(rule, current_time):
    """
    Determina si una regla programada debe ejecutarse en este momento
    
    Args:
        rule (dict): Regla a verificar
        current_time (datetime): Hora actual
        
    Returns:
        tuple: (debe_ejecutarse, próxima_ejecución)
    """
    conditions = rule.get('conditions', {})
    schedule_type = conditions.get('schedule_type', 'cron')
    
    # Obtener la última ejecución
    last_run = rule.get('last_run')
    
    # Si nunca se ha ejecutado
    if not last_run:
        # Pero tiene una fecha de inicio en el futuro
        if 'start_date' in conditions:
            start_date = parse_datetime(conditions['start_date'])
            if start_date and start_date > current_time:
                # No ejecutar aún
                return False, start_date
        # De lo contrario, ejecutar ahora por primera vez
        return True, calculate_next_run(rule, current_time)
    
    # Si se ejecutó recientemente, verificar según el tipo de programación
    last_run_time = parse_datetime(last_run)
    if not last_run_time:
        # Si hay error en el formato, ejecutar ahora
        return True, calculate_next_run(rule, current_time)
    
    # Obtener próxima ejecución programada
    next_run = rule.get('next_run')
    next_run_time = parse_datetime(next_run) if next_run else None
    
    # Si no hay próxima ejecución calculada o es inválida
    if not next_run_time:
        # Recalcular basándose en la hora actual
        next_run_time = calculate_next_run(rule, current_time)
        # Si es hora o ya ha pasado la hora, ejecutar
        return current_time >= next_run_time, next_run_time
    
    # Verificar si ya es hora de ejecutar
    return current_time >= next_run_time, next_run_time

def calculate_next_run(rule, from_time):
    """
    Calcula la próxima ejecución de una regla programada
    
    Args:
        rule (dict): Regla a analizar
        from_time (datetime): Hora desde la cual calcular
        
    Returns:
        datetime: Próxima hora de ejecución
    """
    conditions = rule.get('conditions', {})
    schedule_type = conditions.get('schedule_type', 'cron')
    
    if schedule_type == 'cron':
        # Formato cron para programación flexible
        cron_expression = conditions.get('cron', '0 12 * * *')  # Por defecto: mediodía diario
        try:
            cron = croniter.croniter(cron_expression, from_time)
            return cron.get_next(datetime)
        except Exception as e:
            logger.warning(f"Error en expresión cron '{cron_expression}': {str(e)}")
            # Programar para un día después como fallback
            return from_time + timedelta(days=1)
    
    elif schedule_type == 'interval':
        # Programación por intervalo
        interval_value = conditions.get('interval_value', 1)
        interval_unit = conditions.get('interval_unit', 'days')
        
        if interval_unit == 'minutes':
            return from_time + timedelta(minutes=interval_value)
        elif interval_unit == 'hours':
            return from_time + timedelta(hours=interval_value)
        elif interval_unit == 'days':
            return from_time + timedelta(days=interval_value)
        elif interval_unit == 'weeks':
            return from_time + timedelta(weeks=interval_value)
        elif interval_unit == 'months':
            # Estimación aproximada para meses (30 días)
            return from_time + timedelta(days=30 * interval_value)
        else:
            # Por defecto, usar días
            return from_time + timedelta(days=interval_value)
    
    elif schedule_type == 'specific_date':
        # Fecha y hora específicas
        specific_date = parse_datetime(conditions.get('specific_date', ''))
        if specific_date and specific_date > from_time:
            return specific_date
        else:
            # Si la fecha ya pasó o es inválida, programar para un día después
            return from_time + timedelta(days=1)
    
    else:
        # Tipo desconocido, usar intervalo diario por defecto
        return from_time + timedelta(days=1)

def update_rule_last_run(rule_id, run_time, next_run):
    """
    Actualiza el registro de la última ejecución de la regla
    
    Args:
        rule_id (str): ID de la regla
        run_time (datetime): Hora de la ejecución
        next_run (datetime): Próxima ejecución calculada
    """
    try:
        alert_rules_table.update_item(
            Key={'rule_id': rule_id},
            UpdateExpression="set last_run = :lr, next_run = :nr, updated_at = :ua",
            ExpressionAttributeValues={
                ':lr': run_time.isoformat(),
                ':nr': next_run.isoformat(),
                ':ua': datetime.now().isoformat()
            }
        )
        logger.info(f"Actualizada última ejecución de regla {rule_id}")
    except Exception as e:
        logger.error(f"Error actualizando última ejecución de regla {rule_id}: {str(e)}")

def process_scheduled_rule(rule, current_time):
    """
    Procesa una regla programada y genera las alertas necesarias
    
    Args:
        rule (dict): Regla a procesar
        current_time (datetime): Hora actual
        
    Returns:
        int: Número de alertas generadas
    """
    conditions = rule.get('conditions', {})
    event_type = conditions.get('event_type', 'scheduled_reminder')
    
    # Según el tipo de evento, buscar entidades relacionadas
    if event_type == 'document_expiration':
        # Buscar documentos próximos a vencer
        return process_document_expiration(rule)
    
    elif event_type == 'tenant_status':
        # Verificar estado del tenant
        return process_tenant_status(rule)
    
    elif event_type == 'custom_reminder':
        # Generar recordatorio personalizado
        return generate_custom_reminder(rule)
    
    else:
        # Evento genérico programado
        return generate_general_alert(rule)

def process_document_expiration(rule):
    """
    Procesa alertas para documentos próximos a vencer
    
    Args:
        rule (dict): Regla a procesar
        
    Returns:
        int: Número de alertas generadas
    """
    conditions = rule.get('conditions', {})
    tenant_id = rule.get('tenant_id')
    days_before = conditions.get('days_before', 7)
    
    # Calcular la fecha objetivo (hoy + días configurados)
    target_date = (datetime.now() + timedelta(days=days_before)).strftime("%Y-%m-%d")
    
    logger.info(f"Buscando documentos que vencen cerca de {target_date}")
    
    try:
        # Buscar documentos con fechas de vencimiento cercanas
        response = contracts_table.scan(
            FilterExpression="tenant_id = :t AND begins_with(expiration_date, :d) AND #status <> :s",
            ExpressionAttributeValues={
                ':t': tenant_id,
                ':d': target_date[:10],  # Solo comparar la parte de fecha (YYYY-MM-DD)
                ':s': 'deleted'
            },
            ExpressionAttributeNames={
                '#status': 'status'
            }
        )
        
        expiring_docs = response.get('Items', [])
        alerts_generated = 0
        
        for doc in expiring_docs:
            # Generar alerta para cada documento
            alert_event = {
                'tenant_id': tenant_id,
                'event_type': 'document_expiration',
                'entity_id': doc.get('id'),
                'entity_type': 'document',
                'document_id': doc.get('id'),
                'document_name': doc.get('filename', 'Documento sin nombre'),
                'expiration_date': doc.get('expiration_date'),
                'days_remaining': days_before,
                'message': f"Documento próximo a vencer en {days_before} días: {doc.get('filename', 'Documento sin nombre')}"
            }
            
            # Enviar a procesador de alertas
            alert_id = trigger_alert_processor(rule.get('rule_id'), alert_event)
            if alert_id:
                alerts_generated += 1
        
        logger.info(f"Alertas generadas para {alerts_generated} documentos próximos a vencer")
        return alerts_generated
        
    except Exception as e:
        logger.error(f"Error procesando alertas de vencimiento de documentos: {str(e)}")
        return 0

def process_tenant_status(rule):
    """
    Procesa alertas basadas en el estado del tenant
    
    Args:
        rule (dict): Regla a procesar
        
    Returns:
        int: Número de alertas generadas
    """
    conditions = rule.get('conditions', {})
    tenant_id = rule.get('tenant_id')
    status_check = conditions.get('status_check', 'usage')
    
    try:
        # Obtener información del tenant
        tenant_info = get_tenant_info(tenant_id)
        
        if not tenant_info:
            logger.warning(f"Tenant no encontrado: {tenant_id}")
            return 0
        
        alerts_generated = 0
        
        if status_check == 'usage':
            # Verificar límites de uso
            usage = tenant_info.get('usage', {})
            limits = tenant_info.get('limits', {})
            
            # Verificar cada tipo de límite
            limit_types = ['users', 'documents', 'storage_mb']
            threshold = conditions.get('threshold_percentage', 80)
            
            for limit_type in limit_types:
                usage_key = f"{limit_type}_count" if limit_type != 'storage_mb' else 'storage_used_mb'
                current_usage = usage.get(usage_key, 0)
                max_limit = limits.get(f"max_{limit_type}", 0)
                
                # Si el límite no es ilimitado y está por encima del umbral
                if max_limit > 0 and current_usage > 0:
                    usage_percentage = (current_usage / max_limit) * 100
                    
                    if usage_percentage >= threshold:
                        # Generar alerta
                        alert_event = {
                            'tenant_id': tenant_id,
                            'event_type': 'limit_approaching',
                            'entity_id': tenant_id,
                            'entity_type': 'tenant',
                            'usage_data': {
                                'limit_type': limit_type.replace('_mb', ''),
                                'current_usage': current_usage,
                                'max_limit': max_limit,
                                'usage_percentage': usage_percentage
                            },
                            'message': f"Uso de {limit_type.replace('_mb', '')} al {int(usage_percentage)}% del límite"
                        }
                        
                        # Enviar a procesador de alertas
                        alert_id = trigger_alert_processor(rule.get('rule_id'), alert_event)
                        if alert_id:
                            alerts_generated += 1
        
        elif status_check == 'billing':
            # Verificar estado de facturación
            billing_info = tenant_info.get('billing_info', {})
            billing_status = billing_info.get('status')
            
            if billing_status == 'overdue':
                # Generar alerta de facturación pendiente
                alert_event = {
                    'tenant_id': tenant_id,
                    'event_type': 'billing_overdue',
                    'entity_id': tenant_id,
                    'entity_type': 'tenant',
                    'billing_data': {
                        'status': billing_status,
                        'days_overdue': billing_info.get('days_overdue', 0),
                        'amount_due': billing_info.get('amount_due', 0)
                    },
                    'message': f"Facturación pendiente de pago desde hace {billing_info.get('days_overdue', 0)} días"
                }
                
                # Enviar a procesador de alertas
                alert_id = trigger_alert_processor(rule.get('rule_id'), alert_event)
                if alert_id:
                    alerts_generated += 1
        
        logger.info(f"Alertas generadas para estado de tenant: {alerts_generated}")
        return alerts_generated
        
    except Exception as e:
        logger.error(f"Error procesando alertas de estado de tenant: {str(e)}")
        return 0

def generate_custom_reminder(rule):
    """
    Genera un recordatorio personalizado basado en la configuración de la regla
    
    Args:
        rule (dict): Regla a procesar
        
    Returns:
        int: Número de alertas generadas (0 o 1)
    """
    conditions = rule.get('conditions', {})
    tenant_id = rule.get('tenant_id')
    reminder_text = conditions.get('reminder_text', 'Recordatorio programado')
    
    try:
        # Generar alerta con el texto personalizado
        alert_event = {
            'tenant_id': tenant_id,
            'event_type': 'scheduled_reminder',
            'message': reminder_text,
            'entity_type': 'system',
            'custom_data': conditions.get('custom_data', {})
        }
        
        # Enviar a procesador de alertas
        alert_id = trigger_alert_processor(rule.get('rule_id'), alert_event)
        
        if alert_id:
            logger.info(f"Recordatorio personalizado generado: {reminder_text}")
            return 1
        else:
            return 0
        
    except Exception as e:
        logger.error(f"Error generando recordatorio personalizado: {str(e)}")
        return 0

def generate_general_alert(rule):
    """
    Genera una alerta general basada en la regla
    
    Args:
        rule (dict): Regla a procesar
        
    Returns:
        int: Número de alertas generadas (0 o 1)
    """
    tenant_id = rule.get('tenant_id')
    
    try:
        # Usar la descripción de la regla como mensaje
        message = rule.get('description', 'Alerta programada')
        
        # Generar alerta
        alert_event = {
            'tenant_id': tenant_id,
            'event_type': 'scheduled_reminder',
            'message': message,
            'entity_type': 'system',
            'rule_name': rule.get('name')
        }
        
        # Enviar a procesador de alertas
        alert_id = trigger_alert_processor(rule.get('rule_id'), alert_event)
        
        if alert_id:
            logger.info(f"Alerta general generada para regla: {rule.get('name')}")
            return 1
        else:
            return 0
        
    except Exception as e:
        logger.error(f"Error generando alerta general: {str(e)}")
        return 0

def trigger_alert_processor(rule_id, event_data):
    """
    Activa la función de procesamiento de alertas
    
    Args:
        rule_id (str): ID de la regla que generó la alerta
        event_data (dict): Datos del evento
        
    Returns:
        str: ID de la alerta generada o None si hay error
    """
    # Añadir rule_id al evento si no está presente
    if 'rule_id' not in event_data:
        event_data['rule_id'] = rule_id
    
    try:
        if ALERT_PROCESSOR_FUNCTION:
            # Invocar Lambda de forma asíncrona
            response = lambda_client.invoke(
                FunctionName=ALERT_PROCESSOR_FUNCTION,
                InvocationType='Event',
                Payload=json.dumps(event_data)
            )
            
            logger.info(f"Invocado procesador de alertas con éxito")
            return str(uuid.uuid4())  # ID temporal, el real se generará en el procesador
        else:
            logger.warning("Nombre de la función de procesamiento de alertas no configurado")
            return None
    except Exception as e:
        logger.error(f"Error invocando procesador de alertas: {str(e)}")
        return None

def check_tenant_status(tenant_id):
    """
    Verifica el estado actual de un tenant
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        str: Estado del tenant ('active', 'inactive', etc.)
    """
    try:
        response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' in response:
            return response['Item'].get('status', 'unknown')
        else:
            return 'not_found'
    except Exception as e:
        logger.error(f"Error verificando estado del tenant {tenant_id}: {str(e)}")
        return 'error'

def get_tenant_info(tenant_id):
    """
    Obtiene información completa de un tenant
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Información del tenant o None si no existe
    """
    try:
        response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' in response:
            return response['Item']
        else:
            return None
    except Exception as e:
        logger.error(f"Error obteniendo información del tenant {tenant_id}: {str(e)}")
        return None

def parse_datetime(datetime_str):
    """
    Parsea un string de fecha/hora a objeto datetime
    
    Args:
        datetime_str (str): String de fecha/hora en formato ISO
        
    Returns:
        datetime: Objeto datetime o None si hay error
    """
    if not datetime_str:
        return None
    
    try:
        # Intentar parsear formato ISO
        return datetime.fromisoformat(datetime_str.replace('Z', '+00:00'))
    except ValueError:
        try:
            # Intentar formato de fecha simple
            return datetime.strptime(datetime_str, "%Y-%m-%d")
        except ValueError:
            logger.warning(f"No se pudo parsear fecha/hora: {datetime_str}")
            return None

def publish_metrics(rules_processed, alerts_generated):
    """
    Publica métricas en CloudWatch
    
    Args:
        rules_processed (int): Número de reglas procesadas
        alerts_generated (int): Número de alertas generadas
    """
    try:
        cloudwatch.put_metric_data(
            Namespace='DocPilot/Alerts',
            MetricData=[
                {
                    'MetricName': 'ScheduledRulesProcessed',
                    'Value': rules_processed,
                    'Unit': 'Count',
                    'Timestamp': datetime.now()
                },
                {
                    'MetricName': 'ScheduledAlertsGenerated',
                    'Value': alerts_generated,
                    'Unit': 'Count',
                    'Timestamp': datetime.now()
                }
            ]
        )
        logger.info("Métricas publicadas en CloudWatch")
    except Exception as e:
        logger.warning(f"Error publicando métricas: {str(e)}")