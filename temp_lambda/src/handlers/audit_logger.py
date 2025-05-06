# docpilot-backend/src/handlers/audit_logger.py
import json
import os
import boto3
import uuid
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from src.utils.cors_middleware import add_cors_headers

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

logs = boto3.client('logs')
s3 = boto3.client('s3')
AUDIT_BUCKET = os.environ.get('AUDIT_BUCKET')

MAX_LOG_EVENTS = 50 # Límite de eventos por página (ajustar según necesidad)

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
    elif http_method == 'GET' and path == '/audit/logs':
        return get_audit_logs(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 404,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Ruta no encontrada'})
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
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
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
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'message': 'Actividad registrada correctamente'})
        }
    except Exception as e:
        logger.error(f"Error registrando actividad: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno registrando actividad'})
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
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'message': 'Exportación de logs iniciada'})
        }
    except Exception as e:
        logger.error(f"Error exportando logs: {str(e)}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno exportando logs'})
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

def get_audit_logs(event, context):
    """Consulta logs de auditoría desde CloudWatch Logs"""
    try:
        query_params = event.get('queryStringParameters') if event.get('queryStringParameters') else {}
        tenant_id = query_params.get('tenant_id')
        limit = int(query_params.get('limit', MAX_LOG_EVENTS))
        next_token = query_params.get('nextToken', None)
        # Podrías añadir filtros por fecha (startTime, endTime), user_id, action, etc.
        # filter_pattern = query_params.get('filter', None) 
        
        if not tenant_id:
            logger.warning("Falta tenant_id para consultar logs de auditoría")
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requiere el parámetro tenant_id'})
            }

        log_group_name = f"/docpilot/audit/{tenant_id}"
        logger.info(f"Consultando logs para grupo: {log_group_name}, límite: {limit}")
        
        # Argumentos para filter_log_events
        filter_args = {
            'logGroupName': log_group_name,
            'limit': limit,
            'interleaved': True # Ordenar por timestamp
        }
        if next_token:
            filter_args['nextToken'] = next_token
            
        # Añadir filtro si se proporciona
        # if filter_pattern:
        #     filter_args['filterPattern'] = filter_pattern

        # Llamar a filter_log_events
        try:
            response = logs.filter_log_events(**filter_args)
        except logs.exceptions.ResourceNotFoundException:
            logger.warning(f"No se encontró el grupo de logs: {log_group_name}")
            return {
                'statusCode': 200,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'logs': [], 'nextToken': None, 'message': 'No hay logs para este tenant aún.'}) # Devuelve vacío si no existe el grupo
            }

        # Procesar la respuesta
        log_events = []
        for event in response.get('events', []):
            try:
                # El mensaje es un JSON string, parsearlo
                log_data = json.loads(event.get('message', '{}'))
                log_events.append({
                    'eventId': event.get('eventId'),
                    'timestamp': datetime.fromtimestamp(event.get('timestamp') / 1000).isoformat() if event.get('timestamp') else None,
                    'ingestionTime': datetime.fromtimestamp(event.get('ingestionTime') / 1000).isoformat() if event.get('ingestionTime') else None,
                    **log_data # Añadir los campos del mensaje parseado (tenant_id, user_id, action, etc.)
                })
            except json.JSONDecodeError:
                logger.warning(f"No se pudo parsear mensaje de log: {event.get('message')}")
                # Incluir el mensaje original si no se puede parsear
                log_events.append({
                    'eventId': event.get('eventId'),
                    'timestamp': datetime.fromtimestamp(event.get('timestamp') / 1000).isoformat() if event.get('timestamp') else None,
                    'ingestionTime': datetime.fromtimestamp(event.get('ingestionTime') / 1000).isoformat() if event.get('ingestionTime') else None,
                    'raw_message': event.get('message')
                })

        next_page_token = response.get('nextToken', None)

        logger.info(f"Encontrados {len(log_events)} eventos de log. Próximo token: {next_page_token}")

        # Usar add_cors_headers
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({
                'logs': log_events,
                'pagination': {
                    'limit': limit,
                    'nextToken': next_page_token
                }
            })
        }

    except ClientError as e:
        logger.error(f"Error de Boto3 consultando logs: {e.response['Error']['Message']}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': f"Error de AWS consultando logs: {e.response['Error']['Code']}"})
        }
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error inesperado consultando logs: {str(e)}")
        logger.error(f"Traceback: {error_trace}")
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno del servidor consultando logs'})
        }