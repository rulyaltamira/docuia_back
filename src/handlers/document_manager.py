# docpilot-backend/src/handlers/document_manager.py
import json
import os
import boto3
import logging
from datetime import datetime, timedelta
import hashlib

# Importar módulos de utilidades
from src.utils.s3_path_helper import decode_s3_key, extract_filename_from_key

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

def lambda_handler(event, context):
    """Maneja operaciones para gestionar documentos"""
    # Determinar operación basada en la ruta y método HTTP
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    
    logger.info(f"Solicitud recibida: método {http_method}, ruta {path}")
    
    if http_method == 'GET' and path == '/documents':
        return list_documents(event, context)
    elif http_method == 'GET' and '/documents/' in path and '/view' in path:
        return generate_view_url(event, context)
    elif http_method == 'GET' and '/documents/' in path and '/summary' in path:
        return get_document_summary(event, context)
    elif http_method == 'GET' and '/documents/' in path:
        return get_document(event, context)
    elif http_method == 'DELETE' and '/documents/' in path:
        return delete_document(event, context)
    elif http_method == 'GET' and path == '/stats':
        return get_stats(event, context)
    elif http_method == 'GET' and path == '/documents/check-duplicate':
        return check_duplicate(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Operación no válida'})
        }

def list_documents(event, context):
    """Lista documentos por tenant"""
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Listando documentos para tenant: {tenant_id}")
        
        # Scanear documentos por tenant (en producción, usar un GSI)
        response = contracts_table.scan(
            FilterExpression='tenant_id = :t',
            ExpressionAttributeValues={':t': tenant_id}
        )
        
        documents = response.get('Items', [])
        
        # Asegurar que los nombres de archivos estén decodificados para visualización
        for doc in documents:
            # Si hay un nombre codificado, asegurarse de que el nombre original esté presente
            if 'encoded_filename' in doc and 'filename' not in doc:
                doc['filename'] = decode_s3_key(doc['encoded_filename'])
            
            # Si hay una clave S3, extraer nombre de archivo si no está presente
            if 's3_key' in doc and 'filename' not in doc:
                doc['filename'] = extract_filename_from_key(doc['s3_key'])
        
        # Ordenar por fecha descendente
        documents.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        logger.info(f"Encontrados {len(documents)} documentos para tenant: {tenant_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'documents': documents})
        }
        
    except Exception as e:
        logger.error(f"Error listando documentos: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_document(event, context):
    """Obtiene detalles de un documento específico"""
    try:
        # Obtener document_id de la ruta
        document_id = event['pathParameters']['id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Obteniendo documento: {document_id}, tenant: {tenant_id}")
        
        # Obtener documento de DynamoDB
        response = contracts_table.get_item(Key={'id': document_id})
        
        if 'Item' not in response:
            logger.error(f"Documento no encontrado: {document_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Documento no encontrado'})
            }
        
        document = response['Item']
        
        # Verificar que el documento pertenece al tenant solicitado
        if document.get('tenant_id') != tenant_id:
            logger.error(f"Documento no pertenece al tenant: {tenant_id}")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Acceso denegado a este documento'})
            }
        
        # Asegurar que los nombres de archivos estén decodificados para visualización
        if 'encoded_filename' in document and 'filename' not in document:
            document['filename'] = decode_s3_key(document['encoded_filename'])
        
        # Si hay una clave S3, extraer nombre de archivo si no está presente
        if 's3_key' in document and 'filename' not in document:
            document['filename'] = extract_filename_from_key(document['s3_key'])
        
        logger.info(f"Documento encontrado: {document_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'document': document})
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def generate_view_url(event, context):
    """Genera URL prefirmada para visualizar un documento"""
    try:
        # Obtener document_id de la ruta
        document_id = event['pathParameters']['id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Generando URL de visualización para documento: {document_id}, tenant: {tenant_id}")
        
        # Obtener documento de DynamoDB
        response = contracts_table.get_item(Key={'id': document_id})
        
        if 'Item' not in response:
            logger.error(f"Documento no encontrado: {document_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Documento no encontrado'})
            }
        
        document = response['Item']
        
        # Verificar que el documento pertenece al tenant solicitado
        if document.get('tenant_id') != tenant_id:
            logger.error(f"Documento no pertenece al tenant: {tenant_id}")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Acceso denegado a este documento'})
            }
        
        # Generar URL prefirmada para visualizar el documento
        s3_key = document.get('s3_key')
        
        if not s3_key:
            logger.error(f"S3 key no encontrada para documento: {document_id}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Información de archivo incompleta'})
            }
        
        url = s3.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': MAIN_BUCKET,
                'Key': s3_key
            },
            ExpiresIn=3600  # 1 hora
        )
        
        logger.info(f"URL de visualización generada para documento: {document_id}")
        
        # Obtener nombre de archivo original para mostrar
        filename = document.get('filename')
        if not filename and 'encoded_filename' in document:
            filename = decode_s3_key(document['encoded_filename'])
        elif not filename and 's3_key' in document:
            filename = extract_filename_from_key(document['s3_key'])
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'view_url': url,
                'filename': filename,
                'expires_in': 3600
            })
        }
        
    except Exception as e:
        logger.error(f"Error generando URL de visualización: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_document_summary(event, context):
    """Obtiene el resumen procesado de un documento"""
    try:
        # Obtener document_id de la ruta
        document_id = event['pathParameters']['id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Obteniendo resumen para documento: {document_id}, tenant: {tenant_id}")
        
        # Obtener documento de DynamoDB
        response = contracts_table.get_item(Key={'id': document_id})
        
        if 'Item' not in response:
            logger.error(f"Documento no encontrado: {document_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Documento no encontrado'})
            }
        
        document = response['Item']
        
        # Verificar que el documento pertenece al tenant solicitado
        if document.get('tenant_id') != tenant_id:
            logger.error(f"Documento no pertenece al tenant: {tenant_id}")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Acceso denegado a este documento'})
            }
        
        # Verificar si es un documento duplicado
        if document.get('is_duplicate') == True and document.get('original_doc_id'):
            logger.info(f"Documento duplicado, usando resumen del original: {document.get('original_doc_id')}")
            # Obtener el documento original
            original_response = contracts_table.get_item(Key={'id': document.get('original_doc_id')})
            if 'Item' in original_response:
                original_doc = original_response['Item']
                if 'processing_result' in original_doc:
                    logger.info(f"Usando resumen del documento original")
                    return {
                        'statusCode': 200,
                        'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                        'body': json.dumps(original_doc['processing_result'])
                    }
        
        # Verificar si el resumen ya está en el registro DynamoDB
        if 'processing_result' in document:
            logger.info(f"Resumen encontrado en DynamoDB para documento: {document_id}")
            summary = document['processing_result']
        elif 'processed_key' in document:
            # Si no está en DynamoDB, intentar obtenerlo del archivo en S3
            processed_key = document['processed_key']
            
            try:
                s3_response = s3.get_object(Bucket=MAIN_BUCKET, Key=processed_key)
                summary_json = s3_response['Body'].read().decode('utf-8')
                summary = json.loads(summary_json)
                logger.info(f"Resumen obtenido de S3 para documento: {document_id}")
            except Exception as e:
                logger.error(f"Error obteniendo resumen de S3: {str(e)}")
                return {
                    'statusCode': 404,
                    'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                    'body': json.dumps({'error': 'Resumen no encontrado'})
                }
        else:
            logger.error(f"Documento no procesado: {document_id}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Documento no procesado'})
            }
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(summary)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo resumen: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def delete_document(event, context):
    """Marca un documento como eliminado (no lo elimina físicamente)"""
    try:
        # Obtener document_id de la ruta
        document_id = event['pathParameters']['id']
        
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Eliminando documento: {document_id}, tenant: {tenant_id}")
        
        # Obtener documento de DynamoDB
        response = contracts_table.get_item(Key={'id': document_id})
        
        if 'Item' not in response:
            logger.error(f"Documento no encontrado: {document_id}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Documento no encontrado'})
            }
        
        document = response['Item']
        
        # Verificar que el documento pertenece al tenant solicitado
        if document.get('tenant_id') != tenant_id:
            logger.error(f"Documento no pertenece al tenant: {tenant_id}")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Acceso denegado a este documento'})
            }
        
        # Marcar como eliminado en DynamoDB
        contracts_table.update_item(
            Key={'id': document_id},
            UpdateExpression="set #status = :s, deleted_at = :t",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':s': 'deleted',
                ':t': datetime.now().isoformat()
            }
        )
        
        logger.info(f"Documento marcado como eliminado: {document_id}")
        
        # Nota: No eliminamos físicamente los archivos de S3 para cumplir con políticas de retención
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'message': 'Documento eliminado correctamente'})
        }
        
    except Exception as e:
        logger.error(f"Error eliminando documento: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def get_stats(event, context):
    """Obtiene estadísticas de documentos por tenant"""
    try:
        # Obtener tenant_id de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        
        if not tenant_id:
            logger.error("Falta parámetro tenant_id")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requiere tenant_id como parámetro'})
            }
        
        logger.info(f"Obteniendo estadísticas para tenant: {tenant_id}")
        
        # Scanear documentos por tenant (en producción, usar un GSI)
        response = contracts_table.scan(
            FilterExpression='tenant_id = :t',
            ExpressionAttributeValues={':t': tenant_id}
        )
        
        documents = response.get('Items', [])
        
        # Calcular estadísticas
        total_documents = len(documents)
        
        status_counts = {
            'pending_processing': 0,
            'processing': 0,
            'processed': 0,
            'error': 0,
            'deleted': 0,
            'awaiting_upload': 0,
            'duplicate': 0  # Nueva categoría
        }
        
        source_counts = {
            'email': 0,
            'manual': 0
        }
        
        duplicate_counts = 0
        document_sizes = []
        
        for doc in documents:
            status = doc.get('status')
            source = doc.get('source')
            
            if status in status_counts:
                status_counts[status] += 1
                
            if source in source_counts:
                source_counts[source] += 1
            
            # Contar duplicados
            if doc.get('is_duplicate') == True:
                duplicate_counts += 1
            
            # Acumular tamaños para promedio
            if 'file_size' in doc:
                document_sizes.append(doc['file_size'])
        
        # Calcular documentos activos (no eliminados)
        active_documents = total_documents - status_counts['deleted']
        
        # Calcular tamaño promedio si hay datos
        avg_size = sum(document_sizes) / len(document_sizes) if document_sizes else 0
        
        stats = {
            'totalDocuments': active_documents,
            'pendingDocuments': status_counts['pending_processing'] + status_counts['processing'] + status_counts['awaiting_upload'],
            'processedDocuments': status_counts['processed'],
            'errorDocuments': status_counts['error'],
            'duplicateDocuments': duplicate_counts,
            'averageSize': avg_size,
            'bySource': source_counts,
            'byStatus': status_counts
        }
        
        logger.info(f"Estadísticas calculadas para tenant: {tenant_id}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(stats)
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo estadísticas: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }

def check_duplicate(event, context):
    """Verifica si un archivo es duplicado basado en hash SHA-256"""
    try:
        # Obtener tenant_id y hash de los query params
        query_params = event.get('queryStringParameters', {}) or {}
        tenant_id = query_params.get('tenant_id')
        file_hash = query_params.get('hash')
        
        if not tenant_id or not file_hash:
            logger.error("Faltan parámetros tenant_id o hash")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
                'body': json.dumps({'error': 'Se requieren tenant_id y hash como parámetros'})
            }
        
        logger.info(f"Verificando duplicados para tenant: {tenant_id}, hash: {file_hash}")
        
        # Buscar documentos con el mismo hash y tenant_id
        response = contracts_table.scan(
            FilterExpression="tenant_id = :t AND document_hash = :h",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":h": file_hash
            }
        )
        
        duplicates = response.get('Items', [])
        
        # Excluir documentos eliminados de los resultados
        active_duplicates = [doc for doc in duplicates if doc.get('status') != 'deleted']
        
        is_duplicate = len(active_duplicates) > 0
        
        result = {
            'is_duplicate': is_duplicate,
            'duplicates': active_duplicates if is_duplicate else []
        }
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps(result)
        }
        
    except Exception as e:
        logger.error(f"Error verificando duplicados: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': str(e)})
        }