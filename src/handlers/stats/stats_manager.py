# docpilot-backend/src/handlers/stats/stats_manager.py
# Gestión de estadísticas para DocPilot

import json
import os
import boto3
import logging
from datetime import datetime, timedelta
import decimal

# Clase para manejar la serialización de objetos Decimal a JSON
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return float(obj)  # Convertir Decimal a float
        return super(DecimalEncoder, self).default(obj)

# Importar utilidades
from src.utils.response_helper import success_response, error_response

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
alerts_table = dynamodb.Table(os.environ.get('ALERTS_TABLE'))

def lambda_handler(event, context):
    """Maneja operaciones para estadísticas"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    # Manejar solicitudes OPTIONS para CORS
    if http_method == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Requested-With',
                'Access-Control-Allow-Methods': 'OPTIONS,GET,POST',
                'Access-Control-Allow-Credentials': 'true'
            },
            'body': ''
        }
    
    if http_method == 'GET' and path == '/stats/summary':
        return get_stats_summary(event, context)
    elif http_method == 'GET' and path == '/stats/documents':
        return get_document_stats(event, context)
    elif http_method == 'GET' and path == '/stats/users':
        return get_user_stats(event, context)
    elif http_method == 'GET' and path == '/stats/alerts':
        return get_alert_stats(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return error_response(400, 'Operación no válida')

def get_stats_summary(event, context):
    """
    Obtiene un resumen de estadísticas para un tenant
    """
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        logger.info(f"Obteniendo resumen de estadísticas para tenant: {tenant_id}")
        
        # Obtener información del tenant
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            logger.error(f"Tenant no encontrado: {tenant_id}")
            return error_response(404, 'Tenant no encontrado')
        
        tenant = tenant_response['Item']
        
        # Obtener datos básicos para el resumen
        # 1. Estadísticas de documentos
        doc_stats = get_document_summary(tenant_id)
        
        # 2. Estadísticas de usuarios
        user_stats = get_user_summary(tenant_id)
        
        # 3. Estadísticas de alertas
        alert_stats = get_alert_summary(tenant_id)
        
        # 4. Uso del sistema
        usage_stats = tenant.get('usage', {})
        
        # Construir resumen completo
        summary = {
            'tenant_id': tenant_id,
            'tenant_name': tenant.get('name', ''),
            'plan': tenant.get('plan', 'free'),
            'documents': doc_stats,
            'users': user_stats,
            'alerts': alert_stats,
            'usage': {
                'storage_used_mb': usage_stats.get('storage_used_mb', 0),
                'documents_count': usage_stats.get('documents_count', 0),
                'users_count': usage_stats.get('users_count', 0),
                'last_updated': usage_stats.get('last_updated', datetime.now().isoformat())
            },
            'limits': tenant.get('limits', {})
        }
        
        # Calcular porcentajes de uso
        limits = tenant.get('limits', {})
        if limits:
            max_documents = limits.get('max_documents', 0)
            max_storage = limits.get('max_storage_mb', 0)
            max_users = limits.get('max_users', 0)
            
            usage_percentages = {}
            
            if max_documents > 0:
                usage_percentages['documents'] = min(100, round((doc_stats.get('total', 0) / max_documents) * 100, 1))
            else:
                usage_percentages['documents'] = 0
                
            if max_storage > 0:
                usage_percentages['storage'] = min(100, round((usage_stats.get('storage_used_mb', 0) / max_storage) * 100, 1))
            else:
                usage_percentages['storage'] = 0
                
            if max_users > 0:
                usage_percentages['users'] = min(100, round((user_stats.get('total', 0) / max_users) * 100, 1))
            else:
                usage_percentages['users'] = 0
                
            summary['usage_percentages'] = usage_percentages
        
        return success_response({'summary': summary})
        
    except Exception as e:
        logger.error(f"Error obteniendo resumen de estadísticas: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def get_document_summary(tenant_id):
    """
    Obtiene estadísticas resumidas de documentos
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resumen de estadísticas de documentos
    """
    try:
        # Consultar documentos del tenant (en producción, usar un GSI)
        response = contracts_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={
                ':t': tenant_id
            }
        )
        
        documents = response.get('Items', [])
        
        # Estadísticas básicas
        total_docs = len(documents)
        
        # Contar por estado
        status_counts = {
            'processed': 0,
            'pending_processing': 0,
            'processing': 0,
            'error': 0,
            'deleted': 0,
            'duplicate': 0
        }
        
        # Contar por fuente
        source_counts = {
            'email': 0,
            'manual': 0
        }
        
        # Estadísticas temporales
        last_7_days = 0
        last_30_days = 0
        now = datetime.now()
        
        for doc in documents:
            # Contar por estado
            status = doc.get('status')
            if status in status_counts:
                status_counts[status] += 1
            
            # Contar por fuente
            source = doc.get('source')
            if source in source_counts:
                source_counts[source] += 1
            
            # Estadísticas temporales
            try:
                created_at = datetime.fromisoformat(doc.get('timestamp', '').replace('Z', '+00:00'))
                if (now - created_at).days <= 7:
                    last_7_days += 1
                if (now - created_at).days <= 30:
                    last_30_days += 1
            except ValueError:
                pass
        
        # Construir resumen
        summary = {
            'total': total_docs,
            'active': total_docs - status_counts['deleted'],
            'by_status': status_counts,
            'by_source': source_counts,
            'last_7_days': last_7_days,
            'last_30_days': last_30_days
        }
        
        return summary
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de documentos: {str(e)}")
        return {
            'total': 0,
            'active': 0,
            'by_status': {},
            'by_source': {},
            'last_7_days': 0,
            'last_30_days': 0,
            'error': str(e)
        }

def get_user_summary(tenant_id):
    """
    Obtiene estadísticas resumidas de usuarios
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resumen de estadísticas de usuarios
    """
    try:
        # Consultar usuarios del tenant (en producción, usar un GSI)
        response = users_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={
                ':t': tenant_id
            }
        )
        
        users = response.get('Items', [])
        
        # Estadísticas básicas
        total_users = len(users)
        
        # Contar por rol
        role_counts = {
            'admin': 0,
            'user': 0
        }
        
        # Contar por estado
        status_counts = {
            'active': 0,
            'inactive': 0
        }
        
        for user in users:
            # Contar por rol
            role = user.get('role')
            if role in role_counts:
                role_counts[role] += 1
            
            # Contar por estado
            status = user.get('status')
            if status in status_counts:
                status_counts[status] += 1
        
        # Construir resumen
        summary = {
            'total': total_users,
            'active': status_counts['active'],
            'by_role': role_counts,
            'by_status': status_counts
        }
        
        return summary
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de usuarios: {str(e)}")
        return {
            'total': 0,
            'active': 0,
            'by_role': {},
            'by_status': {},
            'error': str(e)
        }

def get_alert_summary(tenant_id):
    """
    Obtiene estadísticas resumidas de alertas
    
    Args:
        tenant_id (str): ID del tenant
        
    Returns:
        dict: Resumen de estadísticas de alertas
    """
    try:
        # Consultar alertas del tenant (en producción, usar un GSI)
        response = alerts_table.scan(
            FilterExpression="tenant_id = :t",
            ExpressionAttributeValues={
                ':t': tenant_id
            }
        )
        
        alerts = response.get('Items', [])
        
        # Estadísticas básicas
        total_alerts = len(alerts)
        
        # Contar por severidad
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Contar por estado
        status_counts = {
            'new': 0,
            'acknowledged': 0,
            'resolved': 0,
            'dismissed': 0
        }
        
        # Alertas recientes
        last_7_days = 0
        now = datetime.now()
        
        for alert in alerts:
            # Contar por severidad
            severity = alert.get('severity')
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Contar por estado
            status = alert.get('status')
            if status in status_counts:
                status_counts[status] += 1
            
            # Alertas recientes
            try:
                created_at = datetime.fromisoformat(alert.get('created_at', '').replace('Z', '+00:00'))
                if (now - created_at).days <= 7:
                    last_7_days += 1
            except ValueError:
                pass
        
        # Construir resumen
        summary = {
            'total': total_alerts,
            'unresolved': status_counts['new'] + status_counts['acknowledged'],
            'by_severity': severity_counts,
            'by_status': status_counts,
            'last_7_days': last_7_days
        }
        
        return summary
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de alertas: {str(e)}")
        return {
            'total': 0,
            'unresolved': 0,
            'by_severity': {},
            'by_status': {},
            'last_7_days': 0,
            'error': str(e)
        }

def get_document_stats(event, context):
    """
    Obtiene estadísticas detalladas de documentos
    """
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Obtener estadísticas resumidas
        doc_summary = get_document_summary(tenant_id)
        
        # Obtener estadísticas adicionales específicas de documentos
        # Aquí podrías implementar análisis más detallados
        
        return success_response({'statistics': doc_summary})
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de documentos: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def get_user_stats(event, context):
    """
    Obtiene estadísticas detalladas de usuarios
    """
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Obtener estadísticas resumidas
        user_summary = get_user_summary(tenant_id)
        
        # Obtener estadísticas adicionales específicas de usuarios
        # Aquí podrías implementar análisis más detallados
        
        return success_response({'statistics': user_summary})
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de usuarios: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")

def get_alert_stats(event, context):
    """
    Obtiene estadísticas detalladas de alertas
    """
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return error_response(400, 'El parámetro tenant_id es obligatorio')
        
        # Obtener estadísticas resumidas
        alert_summary = get_alert_summary(tenant_id)
        
        # Obtener estadísticas adicionales específicas de alertas
        # Aquí podrías implementar análisis más detallados
        
        return success_response({'statistics': alert_summary})
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas de alertas: {str(e)}")
        return error_response(500, f"Error interno: {str(e)}")