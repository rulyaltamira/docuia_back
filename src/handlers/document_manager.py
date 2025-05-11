# docpilot-backend/src/handlers/document_manager.py
import json
import os
import boto3
import logging
<<<<<<< Updated upstream
from datetime import datetime, timedelta
=======
from datetime import datetime
from decimal import Decimal

# Importar módulos de utilidades actualizados
from src.utils.s3_path_helper import ensure_filename_present
from src.utils.auth_utils import get_tenant_id_or_error
from src.utils.db_helpers import get_document_and_verify_tenant
from src.utils.response_helpers import create_success_response, create_error_response
>>>>>>> Stashed changes

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
MAIN_BUCKET = os.environ.get('MAIN_BUCKET')

def lambda_handler(event, context):
    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    logger.info(f"DocumentManager: Solicitud {http_method} {path}")

    # Rutas actualizadas en serverless.yml, el router aquí debe coincidir
    if http_method == 'GET' and path == '/documents':
        return list_documents(event, context)
    elif http_method == 'GET' and path.startswith('/documents/'):
        path_parts = path.strip('/').split('/') # documents/{id}/action
        if len(path_parts) == 3 and path_parts[2] == 'view':
            return generate_view_url(event, context)
        elif len(path_parts) == 3 and path_parts[2] == 'summary':
            return get_document_summary(event, context)
        elif len(path_parts) == 2: # Solo /documents/{id}
            return get_document(event, context)
    elif http_method == 'DELETE' and path.startswith('/documents/'):
        return delete_document(event, context)
<<<<<<< Updated upstream
    elif http_method == 'GET' and path == '/stats':
        return get_stats(event, context)
    else:
        logger.warning(f"Operación no válida: {http_method} {path}")
        return {
            'statusCode': 400,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({'error': 'Operación no válida'})
        }
=======
    # El endpoint /stats fue movido a stats_manager.py
    # El endpoint /documents/check-duplicate es manejado por check_duplicates.py
    # No hay un endpoint /documents/check-duplicate GET en este handler
    
    logger.warning(f"DocumentManager: Operación no válida: {http_method} {path}")
    return create_error_response(400, 'Operación no válida en DocumentManager', decimal_encoder_cls=DecimalEncoder)
>>>>>>> Stashed changes

def list_documents(event, context):
    try:
<<<<<<< Updated upstream
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
=======
        tenant_id, error_resp = get_tenant_id_or_error(event, DecimalEncoder)
        if error_resp: return error_resp
>>>>>>> Stashed changes
        
        logger.info(f"Listando documentos para tenant: {tenant_id}")
        response = contracts_table.scan(
            FilterExpression='tenant_id = :t',
            ExpressionAttributeValues={':t': tenant_id}
        )
        documents = response.get('Items', [])
        
<<<<<<< Updated upstream
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
=======
        processed_documents = []
        for doc in documents:
            processed_documents.append(ensure_filename_present(doc))
        
        processed_documents.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        logger.info(f"Encontrados {len(processed_documents)} documentos para tenant: {tenant_id}")
        return create_success_response({'documents': processed_documents}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def get_document(event, context):
    try:
<<<<<<< Updated upstream
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
        
=======
        tenant_id, error_resp = get_tenant_id_or_error(event, DecimalEncoder)
        if error_resp: return error_resp

        document_id = event.get('pathParameters', {}).get('id')
        if not document_id:
            return create_error_response(400, "Falta el ID del documento en la ruta.", decimal_encoder_cls=DecimalEncoder)

>>>>>>> Stashed changes
        logger.info(f"Obteniendo documento: {document_id}, tenant: {tenant_id}")
        document, error_resp = get_document_and_verify_tenant(contracts_table, document_id, tenant_id, decimal_encoder_cls=DecimalEncoder)
        if error_resp: return error_resp
        
<<<<<<< Updated upstream
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
=======
        processed_document = ensure_filename_present(document)
        logger.info(f"Documento encontrado: {document_id}")
        return create_success_response({'document': processed_document}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def generate_view_url(event, context):
    try:
        # La autenticación (y por ende la obtención del tenant_id del token) la hace el authorizer de API Gateway.
        # Aquí, el tenant_id es necesario para la verificación de pertenencia del documento.
        # Usaremos extract_tenant_id directamente ya que la ruta /documents/{id}/view está protegida.
        # Y no necesitamos el error_response genérico de get_tenant_id_or_error si el autorizador ya valida la llamada.
        requesting_tenant_id = extract_tenant_id(event) # Tenant que hace la solicitud
        if not requesting_tenant_id:
            # Esto no debería ocurrir si el autorizador está bien configurado, pero como fallback:
            return create_error_response(400, "No se pudo determinar el tenant_id del solicitante.", decimal_encoder_cls=DecimalEncoder)

        document_id = event.get('pathParameters', {}).get('id')
        if not document_id:
            return create_error_response(400, "Falta el ID del documento en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Generando URL de visualización para doc: {document_id}, solicitado por tenant: {requesting_tenant_id}")
        
        # Usamos requesting_tenant_id para verificar la pertenencia del documento
        document, error_resp = get_document_and_verify_tenant(contracts_table, document_id, requesting_tenant_id, decimal_encoder_cls=DecimalEncoder)
        if error_resp: return error_resp
        
<<<<<<< Updated upstream
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
=======
>>>>>>> Stashed changes
        s3_key = document.get('s3_key')
        if not s3_key:
<<<<<<< Updated upstream
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
=======
            return create_error_response(400, 'Información de archivo incompleta en el documento.', decimal_encoder_cls=DecimalEncoder)
>>>>>>> Stashed changes
        
        url = s3.generate_presigned_url('get_object', Params={'Bucket': MAIN_BUCKET, 'Key': s3_key}, ExpiresIn=3600)
        logger.info(f"URL de visualización generada para documento: {document_id}")
        
<<<<<<< Updated upstream
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
            'body': json.dumps({
                'view_url': url,
                'filename': document.get('filename'),
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
=======
        document_with_filename = ensure_filename_present(document)
        filename_to_display = document_with_filename.get('filename', s3_key.split('/')[-1]) # Fallback al nombre de la key

        return create_success_response({'view_url': url, 'filename': filename_to_display, 'expires_in': 3600}, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def get_document_summary(event, context):
    try:
<<<<<<< Updated upstream
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
=======
        tenant_id, error_resp = get_tenant_id_or_error(event, DecimalEncoder)
        if error_resp: return error_resp
>>>>>>> Stashed changes
        
        document_id = event.get('pathParameters', {}).get('id')
        if not document_id:
            return create_error_response(400, "Falta el ID del documento en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Obteniendo resumen para documento: {document_id}, tenant: {tenant_id}")
        
        document, error_resp = get_document_and_verify_tenant(contracts_table, document_id, tenant_id, decimal_encoder_cls=DecimalEncoder)
        if error_resp: return error_resp
        
<<<<<<< Updated upstream
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
=======
        summary_data = None
        if document.get('is_duplicate') == True and document.get('original_doc_id'):
            logger.info(f"Documento duplicado, usando resumen del original: {document.get('original_doc_id')}")
            original_doc, error_resp_orig = get_document_and_verify_tenant(contracts_table, document.get('original_doc_id'), tenant_id, decimal_encoder_cls=DecimalEncoder)
            if error_resp_orig: 
                logger.warning(f"No se pudo obtener el documento original {document.get('original_doc_id')} para el resumen del duplicado {document_id}: {error_resp_orig['body']}")
                # Continuar para intentar obtener el resumen del duplicado mismo si es posible
            elif original_doc and 'processing_result' in original_doc:
                summary_data = original_doc['processing_result']
                logger.info(f"Usando resumen del documento original {document.get('original_doc_id')}")

        if summary_data is None: # Si no es duplicado con resumen original, o si falló obtener el original
            if 'processing_result' in document:
                summary_data = document['processing_result']
            elif 'processed_key' in document:
                try:
                    s3_response = s3.get_object(Bucket=MAIN_BUCKET, Key=document['processed_key'])
                    summary_json = s3_response['Body'].read().decode('utf-8')
                    summary_data = json.loads(summary_json)
                except Exception as e_s3:
                    return create_error_response(404, f"Resumen no encontrado en S3: {str(e_s3)}", decimal_encoder_cls=DecimalEncoder)
            else:
                return create_error_response(400, 'Documento no procesado o resumen no disponible.', decimal_encoder_cls=DecimalEncoder)
        
        return create_success_response(summary_data, decimal_encoder_cls=DecimalEncoder)
        
    except Exception as e:
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)
>>>>>>> Stashed changes

def delete_document(event, context):
    try:
<<<<<<< Updated upstream
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
=======
        tenant_id, error_resp = get_tenant_id_or_error(event, DecimalEncoder)
        if error_resp: return error_resp

        document_id = event.get('pathParameters', {}).get('id')
        if not document_id:
            return create_error_response(400, "Falta el ID del documento en la ruta.", decimal_encoder_cls=DecimalEncoder)

        logger.info(f"Eliminando documento: {document_id}, tenant: {tenant_id}")
        
        document, error_resp = get_document_and_verify_tenant(contracts_table, document_id, tenant_id, decimal_encoder_cls=DecimalEncoder) # Verifica pertenencia
        if error_resp: return error_resp # Si no se encuentra o no pertenece, retorna error

>>>>>>> Stashed changes
        contracts_table.update_item(
            Key={'id': document_id},
            UpdateExpression="set #s = :s_val, deleted_at = :t",
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={':s_val': 'deleted', ':t': datetime.now().isoformat()}
        )
        logger.info(f"Documento marcado como eliminado: {document_id}")
<<<<<<< Updated upstream
        
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
            'awaiting_upload': 0
        }
        
        source_counts = {
            'email': 0,
            'manual': 0
        }
        
        for doc in documents:
            status = doc.get('status')
            source = doc.get('source')
            
            if status in status_counts:
                status_counts[status] += 1
                
            if source in source_counts:
                source_counts[source] += 1
        
        # Calcular documentos activos (no eliminados)
        active_documents = total_documents - status_counts['deleted']
        
        stats = {
            'totalDocuments': active_documents,
            'pendingDocuments': status_counts['pending_processing'] + status_counts['processing'] + status_counts['awaiting_upload'],
            'processedDocuments': status_counts['processed'],
            'errorDocuments': status_counts['error'],
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
=======
        return create_success_response({'message': 'Documento eliminado correctamente'})
        
    except Exception as e:
        return create_error_response(500, str(e), decimal_encoder_cls=DecimalEncoder, is_internal_error=True)

# La función get_stats fue movida a stats_manager.py
# La función check_duplicate es ahora un handler separado (check_duplicates.py)
>>>>>>> Stashed changes
