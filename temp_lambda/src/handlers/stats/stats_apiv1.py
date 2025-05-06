# src/handlers/stats/statistics_api.py
# API para consulta de estadísticas

import json
import os
import boto3
import logging
from datetime import datetime, timedelta
from decimal import Decimal
import math

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')

# Inicializar tablas que siempre deben existir
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))

# Inicializar la tabla de estadísticas solo si está configurada
statistics_table = None
if os.environ.get('STATISTICS_TABLE'):
    try:
        statistics_table = dynamodb.Table(os.environ.get('STATISTICS_TABLE'))
        logger.info("Tabla de estadísticas inicializada correctamente")
    except Exception as e:
        logger.warning(f"No se pudo inicializar la tabla de estadísticas: {str(e)}")

# Ayudante para serialización JSON de valores Decimal
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

def lambda_handler(event, context):
    """
    Maneja diversas solicitudes de estadísticas a través de API Gateway
    """
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'GET' and path == '/stats/critical-documents':
        return get_critical_documents(event, context)
    elif http_method == 'GET' and path == '/stats/documents':
        return get_document_stats(event, context)
    elif http_method == 'GET' and path == '/stats/users':
        return get_user_stats(event, context)
    elif http_method == 'GET' and path == '/stats/processing':
        return get_processing_stats(event, context)
    elif http_method == 'GET' and path == '/stats/storage':
        return get_storage_stats(event, context)
    elif http_method == 'GET' and path == '/stats/summary':
        return get_summary_stats(event, context)
    elif http_method == 'GET' and path == '/stats/trends':
        return get_trends_stats(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Operación no válida'})
        }


def get_document_stats(event, context):
    """
    Obtiene estadísticas detalladas de documentos
    """
    try:
        # Obtener parámetros
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id'})
            }
        
        # Período de tiempo
        period = query_params.get('period', 'month')  # day, week, month, year, all
        
        # Calcular rango de fechas según el período
        end_date = datetime.now()
        
        if period == 'day':
            start_date = end_date - timedelta(days=1)
        elif period == 'week':
            start_date = end_date - timedelta(days=7)
        elif period == 'month':
            start_date = end_date - timedelta(days=30)
        elif period == 'year':
            start_date = end_date - timedelta(days=365)
        else:  # 'all'
            start_date = datetime(2000, 1, 1)  # Fecha muy antigua para incluir todo
        
        # Convertir a strings ISO para consultas
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()
        
        try:
            # Consultar documentos en el rango de fecha
            documents_response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND created_at BETWEEN :start AND :end",
                ExpressionAttributeValues={
                    ':t': tenant_id,
                    ':start': start_date_str,
                    ':end': end_date_str
                }
            )
            
            documents = documents_response.get('Items', [])
        except Exception as e:
            logger.error(f"Error consultando documentos: {str(e)}")
            documents = []
        
        # Conteos por estado
        status_counts = {}
        for doc in documents:
            status = doc.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Conteos por fuente
        source_counts = {}
        for doc in documents:
            source = doc.get('source', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        # Conteos por tipo de documento (si existe campo)
        type_counts = {}
        for doc in documents:
            doc_type = doc.get('document_type', 'unclassified')
            type_counts[doc_type] = type_counts.get(doc_type, 0) + 1
        
        # Estadísticas temporales (documentos por día/semana/mes)
        time_series = generate_document_time_series(documents, period)
        
        # Estadísticas de procesamiento
        processing_times = []
        for doc in documents:
            if 'processed_at' in doc and 'created_at' in doc:
                try:
                    created_at = datetime.fromisoformat(doc.get('created_at', ''))
                    processed_at = datetime.fromisoformat(doc.get('processed_at', ''))
                    time_diff = (processed_at - created_at).total_seconds() / 60
                    processing_times.append(time_diff)
                except (ValueError, TypeError):
                    # Ignorar entradas con formato incorrecto
                    pass
        
        avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
        
        # Construir respuesta
        stats = {
            'tenant_id': tenant_id,
            'period': period,
            'total_documents': len(documents),
            'by_status': status_counts,
            'by_source': source_counts,
            'by_type': type_counts,
            'time_series': time_series,
            'processing': {
                'average_minutes': round(avg_processing_time, 2),
                'count_processed': len(processing_times)
            }
        }
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(stats, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de documentos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_user_stats(event, context):
    """
    Obtiene estadísticas detalladas de usuarios
    """
    try:
        # Obtener parámetros
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id'})
            }
        
        # Consultar usuarios por tenant
        response = users_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={':t': tenant_id}
        )
        
        users = response.get('Items', [])
        
        # Conteos por rol
        role_counts = {}
        for user in users:
            role = user.get('role', 'unknown')
            role_counts[role] = role_counts.get(role, 0) + 1
        
        # Conteos por estado
        status_counts = {}
        for user in users:
            status = user.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Actividad de usuarios
        # Usuarios con actividad en los últimos 7 días
        now = datetime.now()
        week_ago = (now - timedelta(days=7)).isoformat()
        
        active_users = 0
        for user in users:
            last_login = user.get('last_login', '')
            if last_login and last_login > week_ago:
                active_users += 1
        
        # Usuarios con actividad en los últimos 30 días
        month_ago = (now - timedelta(days=30)).isoformat()
        monthly_active_users = 0
        for user in users:
            last_login = user.get('last_login', '')
            if last_login and last_login > month_ago:
                monthly_active_users += 1
        
        # Construir respuesta
        stats = {
            'tenant_id': tenant_id,
            'total_users': len(users),
            'by_role': role_counts,
            'by_status': status_counts,
            'activity': {
                'active_last_7days': active_users,
                'active_last_30days': monthly_active_users,
                'inactive_users': len(users) - monthly_active_users
            }
        }
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(stats, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de usuarios: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_processing_stats(event, context):
    """
    Obtiene estadísticas detalladas de procesamiento
    """
    try:
        # Obtener parámetros
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id'})
            }
        
        # Período de tiempo
        period = query_params.get('period', 'month')  # day, week, month, year, all
        
        # Calcular rango de fechas según el período
        end_date = datetime.now()
        
        if period == 'day':
            start_date = end_date - timedelta(days=1)
        elif period == 'week':
            start_date = end_date - timedelta(days=7)
        elif period == 'month':
            start_date = end_date - timedelta(days=30)
        elif period == 'year':
            start_date = end_date - timedelta(days=365)
        else:  # 'all'
            start_date = datetime(2000, 1, 1)  # Fecha muy antigua para incluir todo
        
        # Convertir a strings ISO para consultas
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()
        
        try:
            # Consultar documentos procesados en el rango de fecha
            documents_response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND processed_at BETWEEN :start AND :end",
                ExpressionAttributeValues={
                    ':t': tenant_id,
                    ':start': start_date_str,
                    ':end': end_date_str
                }
            )
            
            processed_docs = documents_response.get('Items', [])
        except Exception as e:
            logger.error(f"Error consultando documentos procesados: {str(e)}")
            processed_docs = []
        
        # Calcular tiempos de procesamiento
        processing_times = []
        for doc in processed_docs:
            if 'created_at' in doc and 'processed_at' in doc:
                try:
                    created = datetime.fromisoformat(doc['created_at'])
                    processed = datetime.fromisoformat(doc['processed_at'])
                    time_diff = (processed - created).total_seconds() / 60  # en minutos
                    processing_times.append(time_diff)
                except (ValueError, TypeError):
                    # Ignorar documentos con fechas inválidas
                    pass
        
        # Estadísticas de tiempos
        stats = {
            'tenant_id': tenant_id,
            'period': period,
            'total_processed': len(processed_docs),
            'processing_times': {
                'average_minutes': round(sum(processing_times) / len(processing_times) if processing_times else 0, 2),
                'min_minutes': round(min(processing_times) if processing_times else 0, 2),
                'max_minutes': round(max(processing_times) if processing_times else 0, 2),
                'median_minutes': round(get_median(processing_times) if processing_times else 0, 2)
            },
            'processing_distribution': {
                'under_1min': sum(1 for t in processing_times if t < 1),
                '1_5min': sum(1 for t in processing_times if 1 <= t < 5),
                '5_15min': sum(1 for t in processing_times if 5 <= t < 15),
                '15_60min': sum(1 for t in processing_times if 15 <= t < 60),
                'over_60min': sum(1 for t in processing_times if t >= 60)
            }
        }
        
        # Cálculos por día
        daily_stats = {}
        for doc in processed_docs:
            if 'processed_at' in doc:
                day = doc['processed_at'][:10]  # Extraer YYYY-MM-DD
                if day not in daily_stats:
                    daily_stats[day] = {'count': 0}
                daily_stats[day]['count'] += 1
        
        stats['daily_stats'] = daily_stats
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(stats, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de procesamiento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_storage_stats(event, context):
    """
    Obtiene estadísticas detalladas de almacenamiento
    """
    try:
        # Obtener parámetros
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id'})
            }
        
        # Obtener datos del tenant para límites
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Tenant no encontrado'})
            }
        
        tenant = tenant_response['Item']
        storage_limit = tenant.get('limits', {}).get('max_storage_mb', -1)
        
        # Consultar todos los documentos activos
        try:
            documents_response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND #status <> :deleted",
                ExpressionAttributeValues={
                    ':t': tenant_id,
                    ':deleted': 'deleted'
                },
                ExpressionAttributeNames={
                    '#status': 'status'
                }
            )
            
            documents = documents_response.get('Items', [])
        except Exception as e:
            logger.error(f"Error consultando documentos activos: {str(e)}")
            documents = []
        
        # Agrupar por tipo de archivo
        by_type = {}
        for doc in documents:
            file_type = doc.get('content_type', 'unknown')
            if file_type == 'application/pdf':
                file_type = 'pdf'
            elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                file_type = 'word'
            elif file_type in ['text/plain', 'text/html']:
                file_type = 'text'
            
            if file_type not in by_type:
                by_type[file_type] = {
                    'count': 0,
                    'size_bytes': 0
                }
            
            by_type[file_type]['count'] += 1
            by_type[file_type]['size_bytes'] += doc.get('file_size', 0)
        
        # Calcular tamaño total
        total_size_bytes = sum(doc.get('file_size', 0) for doc in documents)
        total_size_mb = total_size_bytes / (1024 * 1024)
        
        # Calcular promedio
        avg_size_bytes = total_size_bytes / len(documents) if documents else 0
        
        # Calcular distribución por tamaño
        size_distribution = {
            'under_1mb': sum(1 for doc in documents if doc.get('file_size', 0) < 1024 * 1024),
            '1_5mb': sum(1 for doc in documents if 1024 * 1024 <= doc.get('file_size', 0) < 5 * 1024 * 1024),
            '5_10mb': sum(1 for doc in documents if 5 * 1024 * 1024 <= doc.get('file_size', 0) < 10 * 1024 * 1024),
            'over_10mb': sum(1 for doc in documents if doc.get('file_size', 0) >= 10 * 1024 * 1024)
        }
        
        # Construir la respuesta
        stats = {
            'tenant_id': tenant_id,
            'storage': {
                'total_bytes': total_size_bytes,
                'total_mb': round(total_size_mb, 2),
                'limit_mb': storage_limit,
                'usage_percentage': round((total_size_mb / storage_limit) * 100, 2) if storage_limit > 0 else 0,
                'average_file_size_bytes': round(avg_size_bytes, 2),
                'average_file_size_kb': round(avg_size_bytes / 1024, 2),
                'by_type': by_type,
                'size_distribution': size_distribution
            },
            'files_count': len(documents)
        }
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(stats, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de almacenamiento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_critical_documents(event, context):
    """
    Obtiene documentos críticos (próximos a vencer o con alertas)
    """
    try:
        # Obtener parámetros
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        limit = int(query_params.get('limit', 10))
        
        if not tenant_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id'})
            }
        
        logger.info(f"Obteniendo documentos críticos para tenant: {tenant_id}, límite: {limit}")
        
        # Consultar documentos próximos a vencer
        # Buscar documentos con fechas de vencimiento cercanas
        today = datetime.now()
        thirty_days_future = (today + timedelta(days=30)).strftime("%Y-%m")
        
        try:
            response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND #status <> :deleted AND begins_with(expiration_date, :future)",
                ExpressionAttributeValues={
                    ':t': tenant_id,
                    ':deleted': 'deleted',
                    ':future': thirty_days_future
                },
                ExpressionAttributeNames={
                    '#status': 'status'
                }
            )
            
            documents = response.get('Items', [])
        except Exception as e:
            logger.error(f"Error consultando documentos con fecha de vencimiento: {str(e)}")
            documents = []
        
        # Ordenar por fecha de vencimiento (los más próximos primero)
        documents.sort(key=lambda x: x.get('expiration_date', '9999-12-31'))
        
        # Limitar resultados según parámetro
        critical_docs = documents[:limit]
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'critical_documents': critical_docs,
                'count': len(critical_docs),
                'total_found': len(documents)
            }, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo documentos críticos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }
    
def get_summary_stats(event, context):
    """
    Obtiene un resumen de todas las estadísticas principales
    """
    try:
        # Obtener parámetros
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id'})
            }
        
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        
        if 'Item' not in tenant_response:
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Tenant no encontrado'})
            }
        
        tenant = tenant_response['Item']
        tenant_usage = tenant.get('usage', {})
        tenant_limits = tenant.get('limits', {})
        
        # Crear resumen de alto nivel
        summary = {
            'tenant_id': tenant_id,
            'tenant_name': tenant.get('name', 'Unknown'),
            'plan': tenant.get('plan', 'Unknown'),
            'usage': {
                'documents': {
                    'total': tenant_usage.get('documents_count', 0),
                    'limit': tenant_limits.get('max_documents', -1),
                    'percentage': calculate_percentage(
                        tenant_usage.get('documents_count', 0),
                        tenant_limits.get('max_documents', -1)
                    )
                },
                'users': {
                    'total': tenant_usage.get('users_count', 0),
                    'limit': tenant_limits.get('max_users', -1),
                    'percentage': calculate_percentage(
                        tenant_usage.get('users_count', 0),
                        tenant_limits.get('max_users', -1)
                    )
                },
                'storage': {
                    'total_mb': tenant_usage.get('storage_used_mb', 0),
                    'limit_mb': tenant_limits.get('max_storage_mb', -1),
                    'percentage': calculate_percentage(
                        tenant_usage.get('storage_used_mb', 0),
                        tenant_limits.get('max_storage_mb', -1)
                    )
                }
            },
            'last_update': tenant_usage.get('last_updated', 'Never')
        }
        
        # Añadir estadísticas adicionales
        # Documentos procesados este mes
        current_month = datetime.now().strftime("%Y-%m")
        processed_this_month = count_processed_documents_in_month(tenant_id, current_month)
        
        summary['processing'] = {
            'this_month': processed_this_month,
            'limit': tenant_limits.get('max_monthly_processing', -1),
            'percentage': calculate_percentage(
                processed_this_month,
                tenant_limits.get('max_monthly_processing', -1)
            )
        }
        
        # Disponibilidad de funcionalidades
        summary['features'] = tenant.get('features', {})
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(summary, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo resumen de estadísticas: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_trends_stats(event, context):
    """
    Obtiene estadísticas de tendencias para un tenant
    """
    try:
        # Obtener parámetros
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        metric_type = query_params.get('metric', 'documents')  # documents, users, storage
        period = query_params.get('period', 'month')  # day, week, month, year
        
        if not tenant_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id'})
            }
        
        # Verificar si se puede usar la tabla de estadísticas
        if statistics_table:
            # Implementación utilizando la tabla de estadísticas
            stats = get_time_series_from_stats_table(tenant_id, metric_type, period)
        else:
            # Implementación alternativa usando las tablas de operaciones
            stats = get_time_series_from_operations(tenant_id, metric_type, period)
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(stats, cls=DecimalEncoder)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de tendencias: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

# Funciones auxiliares

def calculate_percentage(value, limit):
    """
    Calcula el porcentaje de uso respecto a un límite
    Si el límite es -1 (ilimitado), retorna 0
    """
    if limit <= 0:
        return 0
    
    percentage = (value / limit) * 100
    return round(min(percentage, 100), 2)  # Limitar a 100% máximo

def generate_document_time_series(documents, period):
    """
    Genera una serie temporal de documentos según el período
    
    Args:
        documents (list): Lista de documentos
        period (str): Período de tiempo (day, week, month, year)
        
    Returns:
        dict: Serie temporal organizada por períodos
    """
    time_series = {}
    
    if not documents:
        return time_series
    
    for doc in documents:
        if 'created_at' not in doc:
            continue
        
        created_at = doc['created_at']
        
        if period == 'day':
            # Agrupar por hora
            key = created_at[:13]  # YYYY-MM-DDTHH
        elif period == 'week':
            # Agrupar por día
            key = created_at[:10]  # YYYY-MM-DD
        elif period == 'month':
            # Agrupar por día
            key = created_at[:10]
        elif period == 'year':
            # Agrupar por mes
            key = created_at[:7]  # YYYY-MM
        else:  # 'all'
            # Agrupar por mes
            key = created_at[:7]
        
        if key not in time_series:
            time_series[key] = {
                'count': 0,
                'by_status': {},
                'by_source': {}
            }
        
        time_series[key]['count'] += 1
        
        # Conteos por estado
        status = doc.get('status', 'unknown')
        if status not in time_series[key]['by_status']:
            time_series[key]['by_status'][status] = 0
        time_series[key]['by_status'][status] += 1
        
        # Conteos por fuente
        source = doc.get('source', 'unknown')
        if source not in time_series[key]['by_source']:
            time_series[key]['by_source'][source] = 0
        time_series[key]['by_source'][source] += 1
    
    # Ordenar cronológicamente
    return dict(sorted(time_series.items()))

def get_median(numbers):
    """
    Calcula la mediana de una lista de números
    """
    if not numbers:
        return 0
    
    sorted_numbers = sorted(numbers)
    n = len(sorted_numbers)
    
    if n % 2 == 0:
        return (sorted_numbers[n//2 - 1] + sorted_numbers[n//2]) / 2
    else:
        return sorted_numbers[n//2]

def count_processed_documents_in_month(tenant_id, month_str):
    """
    Cuenta los documentos procesados en un mes específico
    
    Args:
        tenant_id (str): ID del tenant
        month_str (str): Mes en formato "YYYY-MM"
        
    Returns:
        int: Número de documentos procesados
    """
    try:
        # Consultar documentos procesados en el mes indicado
        response = contracts_table.scan(
            FilterExpression="tenant_id = :t AND begins_with(processed_at, :m) AND #status = :s",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":m": month_str,
                ":s": "processed"
            },
            ExpressionAttributeNames={
                "#status": "status"
            }
        )
        
        count = len(response.get('Items', []))
        
        # Si hay paginación (más de 1MB de resultados), continuamos el scan
        while 'LastEvaluatedKey' in response:
            response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND begins_with(processed_at, :m) AND #status = :s",
                ExpressionAttributeValues={
                    ":t": tenant_id,
                    ":m": month_str,
                    ":s": "processed"
                },
                ExpressionAttributeNames={
                    "#status": "status"
                },
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            
            count += len(response.get('Items', []))
        
        return count
        
    except Exception as e:
        logger.error(f"Error contando documentos procesados: {str(e)}")
        return 0

def get_time_series_from_stats_table(tenant_id, metric_type, period):
    """
    Obtiene estadísticas de series temporales desde la tabla de estadísticas
    
    Args:
        tenant_id (str): ID del tenant
        metric_type (str): Tipo de métrica (documents, users, storage)
        period (str): Período de tiempo (day, week, month, year)
        
    Returns:
        dict: Estadísticas de series temporales
    """
    try:
        # Determinar la métrica específica a consultar
        if metric_type == 'documents':
            metric_id = 'documents_count_total'
        elif metric_type == 'users':
            metric_id = 'users_count_total'
        elif metric_type == 'storage':
            metric_id = 'storage_used_mb'
        else:
            raise ValueError(f"Tipo de métrica no válido: {metric_type}")
        
        # Determinar rango de fechas para la consulta
        end_date = datetime.now()
        if period == 'day':
            start_date = end_date - timedelta(days=1)
        elif period == 'week':
            start_date = end_date - timedelta(days=7)
        elif period == 'month':
            start_date = end_date - timedelta(days=30)
        elif period == 'year':
            start_date = end_date - timedelta(days=365)
        else:
            raise ValueError(f"Período no válido: {period}")
        
        # Consultar estadísticas
        response = statistics_table.query(
            KeyConditionExpression="metric_id = :m AND #timestamp BETWEEN :start AND :end",
            FilterExpression="tenant_id = :t",
            ExpressionAttributeNames={
                "#timestamp": "timestamp"
            },
            ExpressionAttributeValues={
                ":m": metric_id,
                ":t": tenant_id,
                ":start": start_date.isoformat(),
                ":end": end_date.isoformat()
            }
        )
        
        metrics = response.get('Items', [])
        
        # Ordenar por timestamp
        metrics.sort(key=lambda x: x.get('timestamp', ''))
        
        # Convertir a serie temporal
        time_series = []
        for metric in metrics:
            time_series.append({
                'timestamp': metric.get('timestamp', ''),
                'value': metric.get('value', 0)
            })
        
        return {
            'tenant_id': tenant_id,
            'metric_type': metric_type,
            'period': period,
            'time_series': time_series
        }
    
    except Exception as e:
        logger.error(f"Error obteniendo series temporales desde tabla stats: {str(e)}")
        # Fallback a método alternativo
        return get_time_series_from_operations(tenant_id, metric_type, period)

def get_time_series_from_operations(tenant_id, metric_type, period):
    """
    Obtiene series temporales directamente de tablas operativas como alternativa
    
    Args:
        tenant_id (str): ID del tenant
        metric_type (str): Tipo de métrica (documents, users, storage)
        period (str): Período de tiempo (day, week, month, year)
        
    Returns:
        dict: Estadísticas de series temporales
    """
    try:
        # Determinar rango de fechas para la consulta
        end_date = datetime.now()
        if period == 'day':
            start_date = end_date - timedelta(days=1)
            group_by = 'hour'
        elif period == 'week':
            start_date = end_date - timedelta(days=7)
            group_by = 'day'
        elif period == 'month':
            start_date = end_date - timedelta(days=30)
            group_by = 'day'
        elif period == 'year':
            start_date = end_date - timedelta(days=365)
            group_by = 'month'
        else:
            raise ValueError(f"Período no válido: {period}")
        
        time_series = []
        
        if metric_type == 'documents':
            # Consultar documentos creados en el rango de fechas
            documents_response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND created_at BETWEEN :start AND :end",
                ExpressionAttributeValues={
                    ':t': tenant_id,
                    ':start': start_date.isoformat(),
                    ':end': end_date.isoformat()
                }
            )
            
            documents = documents_response.get('Items', [])
            
            # Agrupar por período
            grouped_data = {}
            for doc in documents:
                created_at = doc.get('created_at', '')
                
                if group_by == 'hour':
                    key = created_at[:13]  # YYYY-MM-DDTHH
                elif group_by == 'day':
                    key = created_at[:10]  # YYYY-MM-DD
                elif group_by == 'month':
                    key = created_at[:7]   # YYYY-MM
                
                if key not in grouped_data:
                    grouped_data[key] = 0
                
                grouped_data[key] += 1
            
            # Convertir a serie temporal
            for timestamp, count in sorted(grouped_data.items()):
                time_series.append({
                    'timestamp': timestamp,
                    'value': count
                })
        
        elif metric_type == 'users':
            # Para usuarios, no tenemos suficiente información histórica
            # Simplemente devolvemos el conteo actual
            response = users_table.scan(
                FilterExpression="tenant_id = :t",
                ExpressionAttributeValues={':t': tenant_id}
            )
            
            users = response.get('Items', [])
            
            time_series.append({
                'timestamp': datetime.now().isoformat(),
                'value': len(users)
            })
            
        elif metric_type == 'storage':
            # Para almacenamiento, calculamos el actual
            total_size_bytes = 0
            
            # Consultar documentos activos
            documents_response = contracts_table.scan(
                FilterExpression="tenant_id = :t AND #status <> :deleted",
                ExpressionAttributeValues={
                    ':t': tenant_id,
                    ':deleted': 'deleted'
                },
                ExpressionAttributeNames={
                    '#status': 'status'
                }
            )
            
            documents = documents_response.get('Items', [])
            
            # Calcular tamaño total
            total_size_bytes = sum(doc.get('file_size', 0) for doc in documents)
            total_size_mb = total_size_bytes / (1024 * 1024)
            
            time_series.append({
                'timestamp': datetime.now().isoformat(),
                'value': round(total_size_mb, 2)
            })
        
        return {
            'tenant_id': tenant_id,
            'metric_type': metric_type,
            'period': period,
            'time_series': time_series
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo series temporales desde operaciones: {str(e)}")
        return {
            'tenant_id': tenant_id,
            'metric_type': metric_type,
            'period': period,
            'time_series': [],
            'error': str(e)
        }