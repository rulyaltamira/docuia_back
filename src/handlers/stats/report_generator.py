# src/handlers/stats/report_generator.py
# Generador de informes para el sistema de estadísticas

import json
import os
import boto3
import logging
import uuid
from datetime import datetime, timedelta
import io
import csv
import xlsxwriter

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
ses = boto3.client('ses')
reports_table = dynamodb.Table(os.environ.get('REPORTS_TABLE'))
report_schedules_table = dynamodb.Table(os.environ.get('REPORT_SCHEDULES_TABLE'))
tenants_table = dynamodb.Table(os.environ.get('TENANTS_TABLE'))
users_table = dynamodb.Table(os.environ.get('USERS_TABLE'))
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

def lambda_handler(event, context):
    """
    Genera informes bajo demanda o programados
    """
    try:
        if 'detail-type' in event and event['detail-type'] == 'Scheduled Event':
            # Invocado por EventBridge para informes programados
            logger.info("Ejecutando generación de informes programados")
            return process_scheduled_reports()
        elif event.get('httpMethod'):
            # Invocado a través de API Gateway
            http_method = event.get('httpMethod', '')
            path = event.get('path', '')
            
            if http_method == 'POST' and path == '/reports/generate':
                # Generar informe bajo demanda
                return generate_report_on_demand(event, context)
            elif http_method == 'GET' and path == '/reports':
                # Listar informes
                return list_reports(event, context)
            elif http_method == 'GET' and path.startswith('/reports/'):
                # Obtener URL de descarga
                return get_report_download_url(event, context)
            elif http_method == 'POST' and path == '/reports/schedule':
                # Programar informe periódico
                return schedule_report(event, context)
            elif http_method == 'GET' and path == '/reports/schedules':
                # Listar programaciones
                return list_report_schedules(event, context)
            elif http_method == 'DELETE' and path.startswith('/reports/schedules/'):
                # Eliminar programación
                return delete_report_schedule(event, context)
            else:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps({'error': 'Operación no válida'})
                }
        else:
            # Invocado directamente para un informe específico
            return generate_report(event)
            
    except Exception as e:
        logger.error(f"Error en generación de informes: {str(e)}")
        
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

def generate_report_on_demand(event, context):
    """Genera un informe bajo demanda a partir de una solicitud API"""
    try:
        # Obtener datos del body
        body = json.loads(event.get('body', '{}'))
        
        # Validar campos obligatorios
        required_fields = ['tenant_id', 'report_type']
        missing_fields = [field for field in required_fields if field not in body]
        
        if missing_fields:
            logger.error(f"Faltan campos obligatorios: {', '.join(missing_fields)}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': f"Campos obligatorios: {', '.join(missing_fields)}"})
            }
        
        # Extraer parámetros
        tenant_id = body.get('tenant_id')
        report_type = body.get('report_type')
        format = body.get('format', 'csv')  # csv, xlsx, json
        period = body.get('period', 'month')  # day, week, month, year, custom
        start_date = body.get('start_date')  # Para período personalizado
        end_date = body.get('end_date')  # Para período personalizado
        
        # Verificar si el tenant existe
        tenant_response = tenants_table.get_item(Key={'tenant_id': tenant_id})
        if 'Item' not in tenant_response:
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Tenant no encontrado'})
            }
        
        # Parámetros para la generación
        report_params = {
            'tenant_id': tenant_id,
            'report_type': report_type,
            'format': format,
            'period': period,
            'created_by': body.get('user_id', 'unknown'),
            'notify_email': body.get('notify_email'),
            'filters': body.get('filters', {})
        }
        
        # Añadir fechas personalizadas si se proporcionan
        if period == 'custom' and start_date and end_date:
            report_params['start_date'] = start_date
            report_params['end_date'] = end_date
        
        # Generar el informe
        result = generate_report(report_params)
        
        if result.get('success', False):
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({
                    'message': 'Informe generado correctamente',
                    'report_id': result.get('report_id'),
                    'download_url': result.get('download_url'),
                    'expires_in': 3600  # URL válida por 1 hora
                })
            }
        else:
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({
                    'error': 'Error generando informe',
                    'details': result.get('error', 'Error desconocido')
                })
            }
        
    except Exception as e:
        logger.error(f"Error generando informe bajo demanda: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

# Resto de funciones...
# process_scheduled_reports, generate_report, list_reports, get_report_download_url,
# schedule_report, list_report_schedules, delete_report_schedule, etc.