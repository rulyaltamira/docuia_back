# src/handlers/stats/metrics_collector.py
# Recolector de métricas para el sistema estadístico

import json
import os
import boto3
import logging
import uuid
from datetime import datetime, timedelta

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
statistics_table = dynamodb.Table(os.environ.get('STATISTICS_TABLE'))
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))

def lambda_handler(event, context):
    """
    Recolecta métricas periódicamente o bajo demanda para estadísticas del sistema
    Se puede invocar manualmente o mediante eventos programados
    """
    try:
        # Determinar modo de operación
        if 'detail-type' in event and event['detail-type'] == 'Scheduled Event':
            # Invocado por CloudWatch Events/EventBridge
            logger.info("Ejecutando recolección programada de métricas")
            return collect_scheduled_metrics()
        elif 'tenant_id' in event:
            # Invocado manualmente para un tenant específico
            tenant_id = event['tenant_id']
            logger.info(f"Ejecutando recolección manual para tenant: {tenant_id}")
            return collect_tenant_metrics(tenant_id)
        elif event.get('httpMethod'):
            # Invocado a través de API Gateway
            http_method = event.get('httpMethod', '')
            path = event.get('path', '')
            
            if http_method == 'POST' and path == '/stats/collect':
                # Obtener datos del body
                body = json.loads(event.get('body', '{}'))
                tenant_id = body.get('tenant_id')
                
                if not tenant_id:
                    return {
                        'statusCode': 400,
                        'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                        'body': json.dumps({'error': 'Se requiere tenant_id'})
                    }
                
                result = collect_tenant_metrics(tenant_id)
                
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps(result)
                }
            else:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps({'error': 'Operación no válida'})
                }
        else:
            # Invocado sin parámetros específicos, ejecutar para todos los tenants
            logger.info("Ejecutando recolección completa de métricas")
            return collect_all_tenants_metrics()
            
    except Exception as e:
        logger.error(f"Error en recolección de métricas: {str(e)}")
        
        # Si fue invocado a través de API Gateway, retornar error
        if event.get('httpMethod'):
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': f"Error interno: {str(e)}"})
            }
        
        # Si fue invocado como Lambda directa, retornar objeto de error
        return {
            'success': False,
            'error': str(e)
        }

def collect_scheduled_metrics():
    """
    Recolecta métricas programadas para todos los tenants activos
    """
    try:
        # Obtener todos los tenants activos
        tenant_response = tenants_table.scan(
            FilterExpression="#status = :s",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":s": "active"}
        )
        
        active_tenants = tenant_response.get('Items', [])
        logger.info(f"Recolectando métricas para {len(active_tenants)} tenants activos")
        
        results = {}
        
        # Recolectar métricas para cada tenant
        for tenant in active_tenants:
            tenant_id = tenant['tenant_id']
            try:
                tenant_result = collect_tenant_metrics(tenant_id)
                results[tenant_id] = {
                    'success': True,
                    'metrics_count': tenant_result.get('metrics_count', 0)
                }
            except Exception as e:
                logger.error(f"Error procesando tenant {tenant_id}: {str(e)}")
                results[tenant_id] = {
                    'success': False,
                    'error': str(e)
                }
        
        return {
            'success': True,
            'tenants_processed': len(active_tenants),
            'results': results
        }
        
    except Exception as e:
        logger.error(f"Error en recolección programada: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def collect_all_tenants_metrics():
    """
    Recolecta todas las métricas para todos los tenants
    """
    # Similar a collect_scheduled_metrics pero con más métricas
    # Implementación...
    pass

def collect_tenant_metrics(tenant_id):
    """
    Recolecta métricas para un tenant específico
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resultado de la recolección
    """
    metrics_collected = 0
    timestamp = datetime.now().isoformat()
    
    # 1. Métricas de documentos
    document_metrics = collect_document_metrics(tenant_id, timestamp)
    metrics_collected += store_metrics(document_metrics)
    
    # 2. Métricas de usuarios
    user_metrics = collect_user_metrics(tenant_id, timestamp)
    metrics_collected += store_metrics(user_metrics)
    
    # 3. Métricas de procesamiento
    processing_metrics = collect_processing_metrics(tenant_id, timestamp)
    metrics_collected += store_metrics(processing_metrics)
    
    # 4. Métricas de almacenamiento
    storage_metrics = collect_storage_metrics(tenant_id, timestamp)
    metrics_collected += store_metrics(storage_metrics)
    
    # 5. Actualizar métricas resumidas en el tenant
    update_tenant_summary(tenant_id, document_metrics, user_metrics, storage_metrics)
    
    return {
        'success': True,
        'tenant_id': tenant_id,
        'timestamp': timestamp,
        'metrics_count': metrics_collected
    }

def collect_document_metrics(tenant_id, timestamp):
    """
    Recolecta métricas relacionadas con documentos
    
    Args:
        tenant_id (str): ID del tenant
        timestamp (str): Timestamp ISO de la recolección
        
    Returns:
        list: Lista de métricas a almacenar
    """
    metrics = []
    
    # Contar documentos por estado
    status_counts = {}
    try:
        # Obtener todos los documentos del tenant
        response = contracts_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={':t': tenant_id}
        )
        
        documents = response.get('Items', [])
        
        # Contar por estado
        for doc in documents:
            status = doc.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Crear métricas de conteo por estado
        for status, count in status_counts.items():
            metrics.append({
                'metric_id': f"documents_count_{status}",
                'tenant_id': tenant_id,
                'timestamp': timestamp,
                'value': count,
                'metric_type': 'count',
                'dimension': 'status',
                'dimension_value': status
            })
        
        # Métrica de total de documentos
        total_docs = sum(status_counts.values())
        metrics.append({
            'metric_id': "documents_count_total",
            'tenant_id': tenant_id,
            'timestamp': timestamp,
            'value': total_docs,
            'metric_type': 'count'
        })
        
        # Métricas de documentos por origen
        source_counts = {}
        for doc in documents:
            source = doc.get('source', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        for source, count in source_counts.items():
            metrics.append({
                'metric_id': f"documents_count_source",
                'tenant_id': tenant_id,
                'timestamp': timestamp,
                'value': count,
                'metric_type': 'count',
                'dimension': 'source',
                'dimension_value': source
            })
        
        # Métricas temporales (documentos por día/semana/mes)
        today = datetime.now().date()
        this_week_start = today - timedelta(days=today.weekday())
        this_month_start = today.replace(day=1)
        
        # Documentos creados hoy
        docs_today = sum(1 for doc in documents 
                         if doc.get('created_at', '').startswith(today.isoformat()))
        
        metrics.append({
            'metric_id': "documents_count_today",
            'tenant_id': tenant_id,
            'timestamp': timestamp,
            'value': docs_today,
            'metric_type': 'count',
            'dimension': 'time_period',
            'dimension_value': 'today'
        })
        
        # Implementar contadores para semana y mes de manera similar
        # ...
        
    except Exception as e:
        logger.error(f"Error recolectando métricas de documentos: {str(e)}")
        # Continuar con otras métricas
    
    return metrics

def collect_user_metrics(tenant_id, timestamp):
    """
    Recolecta métricas relacionadas con usuarios
    
    Args:
        tenant_id (str): ID del tenant
        timestamp (str): Timestamp ISO de la recolección
        
    Returns:
        list: Lista de métricas a almacenar
    """
    metrics = []
    
    try:
        # Contar usuarios por estado y rol
        response = users_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={':t': tenant_id}
        )
        
        users = response.get('Items', [])
        
        # Total de usuarios
        metrics.append({
            'metric_id': "users_count_total",
            'tenant_id': tenant_id,
            'timestamp': timestamp,
            'value': len(users),
            'metric_type': 'count'
        })
        
        # Usuarios por rol
        role_counts = {}
        for user in users:
            role = user.get('role', 'unknown')
            role_counts[role] = role_counts.get(role, 0) + 1
        
        for role, count in role_counts.items():
            metrics.append({
                'metric_id': f"users_count_role",
                'tenant_id': tenant_id,
                'timestamp': timestamp,
                'value': count,
                'metric_type': 'count',
                'dimension': 'role',
                'dimension_value': role
            })
        
        # Usuarios por estado
        status_counts = {}
        for user in users:
            status = user.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        for status, count in status_counts.items():
            metrics.append({
                'metric_id': f"users_count_status",
                'tenant_id': tenant_id,
                'timestamp': timestamp,
                'value': count,
                'metric_type': 'count',
                'dimension': 'status',
                'dimension_value': status
            })
        
        # Usuarios activos (con login reciente en la última semana)
        active_threshold = (datetime.now() - timedelta(days=7)).isoformat()
        active_users = sum(1 for user in users 
                          if user.get('last_login', '') > active_threshold)
        
        metrics.append({
            'metric_id': "users_active_weekly",
            'tenant_id': tenant_id,
            'timestamp': timestamp,
            'value': active_users,
            'metric_type': 'count'
        })
        
    except Exception as e:
        logger.error(f"Error recolectando métricas de usuarios: {str(e)}")
        # Continuar con otras métricas
    
    return metrics

def collect_processing_metrics(tenant_id, timestamp):
    """
    Recolecta métricas relacionadas con procesamiento de documentos
    
    Args:
        tenant_id (str): ID del tenant
        timestamp (str): Timestamp ISO de la recolección
        
    Returns:
        list: Lista de métricas a almacenar
    """
    # Implementación para métricas de procesamiento
    # ...
    return []

def collect_storage_metrics(tenant_id, timestamp):
    """
    Recolecta métricas relacionadas con almacenamiento
    
    Args:
        tenant_id (str): ID del tenant
        timestamp (str): Timestamp ISO de la recolección
        
    Returns:
        list: Lista de métricas a almacenar
    """
    # Implementación para métricas de almacenamiento
    # ...
    return []

def store_metrics(metrics_list):
    """
    Almacena una lista de métricas en DynamoDB
    
    Args:
        metrics_list (list): Lista de métricas a almacenar
        
    Returns:
        int: Número de métricas almacenadas
    """
    if not metrics_list:
        return 0
    
    stored_count = 0
    
    for metric in metrics_list:
        try:
            statistics_table.put_item(Item=metric)
            stored_count += 1
        except Exception as e:
            logger.error(f"Error almacenando métrica {metric.get('metric_id')}: {str(e)}")
    
    return stored_count

def update_tenant_summary(tenant_id, document_metrics, user_metrics, storage_metrics):
    """
    Actualiza las métricas resumidas en el registro del tenant
    
    Args:
        tenant_id (str): ID del tenant
        document_metrics (list): Métricas de documentos
        user_metrics (list): Métricas de usuarios
        storage_metrics (list): Métricas de almacenamiento
    """
    try:
        # Extraer valores relevantes de las métricas recolectadas
        total_docs = next((m['value'] for m in document_metrics 
                          if m['metric_id'] == 'documents_count_total'), 0)
        
        total_users = next((m['value'] for m in user_metrics 
                           if m['metric_id'] == 'users_count_total'), 0)
        
        storage_used = next((m['value'] for m in storage_metrics 
                            if m['metric_id'] == 'storage_used_mb'), 0)
        
        # Actualizar el tenant
        tenants_table.update_item(
            Key={'tenant_id': tenant_id},
            UpdateExpression="set usage.documents_count = :d, usage.users_count = :u, usage.storage_used_mb = :s, usage.last_updated = :t",
            ExpressionAttributeValues={
                ':d': total_docs,
                ':u': total_users,
                ':s': storage_used,
                ':t': datetime.now().isoformat()
            }
        )
        
        logger.info(f"Actualizado resumen de métricas para tenant {tenant_id}")
        
    except Exception as e:
        logger.error(f"Error actualizando resumen de tenant: {str(e)}")
        # No propagar el error, ya que es una operación secundaria

# Para pruebas locales (opcional)
# if __name__ == '__main__':
#     # Simular un objeto context básico para pruebas locales
#     class MockContext:
#         function_name = "local_test_handler"
#     
#     mock_event = {"key": "value"}
#     # os.environ['MI_VARIABLE_DE_ENTORNO'] = 'valor_test'
#     print(lambda_handler(mock_event, MockContext())) 