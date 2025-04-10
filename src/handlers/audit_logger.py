# docpilot-backend/src/handlers/audit_logger.py
import json
import os
import boto3
import uuid
import logging
from datetime import datetime, timedelta

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

logs = boto3.client('logs')
s3 = boto3.client('s3')
AUDIT_BUCKET = os.environ.get('AUDIT_BUCKET')

def lambda_handler(event, context):
    """Maneja operaciones de auditoría"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'POST' and path == '/audit/log':
        return log_activity(event, context)
    elif http_method == 'POST' and path == '/audit/export':
        return export_logs_to_s3(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Operación no válida'})
        }

def log_activity(event, context):
    """Registra actividad en CloudWatch Logs con un grupo específico por tenant"""
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        tenant_id = body.get('tenant_id')
        user_id = body.get('user_id')
        action = body.get('action_type')
        resource_id = body.get('resource_id')
        details = body.get('details', {})
        
        # Validar campos obligatorios
        if not tenant_id or not action or not resource_id:
            logger.error("Faltan campos obligatorios para auditoría")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'tenant_id, action_type y resource_id son obligatorios'})
            }
        
        logger.info(f"Registrando actividad - tenant: {tenant_id}, acción: {action}, recurso: {resource_id}")
        
        # Nombre del grupo de logs por tenant
        log_group_name = f"/docpilot/audit/{tenant_id}"
        # Stream de logs por fecha
        log_stream_name = datetime.now().strftime("%Y/%m/%d")
        
        # Asegurarse de que existe el grupo de logs
        try:
            logs.create_log_group(logGroupName=log_group_name)
            logger.info(f"Grupo de logs creado: {log_group_name}")
        except logs.exceptions.ResourceAlreadyExistsException:
            pass
        
        # Asegurarse de que existe el stream de logs
        try:
            logs.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=log_stream_name
            )
            logger.info(f"Stream de logs creado: {log_stream_name}")
        except logs.exceptions.ResourceAlreadyExistsException:
            pass
        
        # Formato del log
        log_event = {
            'timestamp': datetime.now().isoformat(),
            'tenant_id': tenant_id,
            'user_id': user_id,
            'action': action,
            'resource_id': resource_id,
            'details': details
        }
        
        # Publicar el evento
        logs.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[
                {
                    'timestamp': int(datetime.now().timestamp() * 1000),
                    'message': json.dumps(log_event)
                }
            ]
        )
        
        logger.info(f"Actividad registrada correctamente - tenant: {tenant_id}, acción: {action}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Actividad registrada correctamente'})
        }
    except Exception as e:
        logger.error(f"Error registrando actividad: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def export_logs_to_s3(event, context):
    """Exporta logs de auditoría a S3 para almacenamiento a largo plazo"""
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        tenant_id = body.get('tenant_id')
        days_to_export = body.get('days', 30)
        
        logger.info(f"Exportando logs a S3 - tenant: {tenant_id}, días: {days_to_export}")
        
        if tenant_id:
            # Exportar logs de un tenant específico
            log_group_name = f"/docpilot/audit/{tenant_id}"
            destination_prefix = f"audit-logs/{tenant_id}/"
            export_logs_group(log_group_name, destination_prefix, days_to_export)
            logger.info(f"Exportación iniciada para tenant: {tenant_id}")
        else:
            # Exportar logs de todos los tenants
            response = logs.describe_log_groups(
                logGroupNamePrefix="/docpilot/audit/"
            )
            
            for log_group in response.get('logGroups', []):
                group_name = log_group['logGroupName']
                tenant_id = group_name.split('/')[-1]
                destination_prefix = f"audit-logs/{tenant_id}/"
                export_logs_group(group_name, destination_prefix, days_to_export)
                logger.info(f"Exportación iniciada para tenant: {tenant_id}")
                
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Exportación de logs iniciada'})
        }
    except Exception as e:
        logger.error(f"Error exportando logs: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def export_logs_group(log_group_name, destination_prefix, days):
    """Función auxiliar para exportar un grupo de logs a S3"""
    current_time = int(datetime.now().timestamp() * 1000)
    # n días atrás
    from_time = current_time - (days * 24 * 60 * 60 * 1000)
    
    export_task_id = str(uuid.uuid4())
    
    logs.create_export_task(
        taskName=f"export-{export_task_id}",
        logGroupName=log_group_name,
        fromTime=from_time,
        to=current_time,
        destination=AUDIT_BUCKET,
        destinationPrefix=destination_prefix
    )
    
    logger.info(f"Tarea de exportación creada: {export_task_id} para grupo {log_group_name}")