# docpilot-backend/src/handlers/check_duplicates.py
import json
import os
import boto3
import logging
import base64

# Importar utilidades para cálculo y verificación de hashes
from src.utils.document_hash import calculate_hash_from_base64, check_duplicate_document

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))

def lambda_handler(event, context):
    """
    Verifica si un archivo es duplicado basado en su hash.
    Este endpoint puede recibir el contenido en base64 para verificar antes de subir,
    o recibir un hash precalculado.
    """
    try:
        # Extraer datos del body
        body = json.loads(event.get('body', '{}'))
        tenant_id = body.get('tenant_id')
        
        # Verificar si se proporciona un ID a excluir (útil para actualizaciones)
        exclude_id = body.get('exclude_id')
        
        # Obtener el hash del documento, ya sea directamente o calculándolo
        doc_hash = body.get('hash')
        
        if not doc_hash and 'file_content' in body:
            # Si se proporciona el contenido del archivo en base64, calcular hash
            base64_content = body.get('file_content')
            doc_hash = calculate_hash_from_base64(base64_content)
            logger.info(f"Hash calculado a partir del contenido: {doc_hash}")
        
        # Validar parámetros obligatorios
        if not tenant_id or not doc_hash:
            logger.error("Faltan parámetros obligatorios (tenant_id o hash/file_content)")
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Se requieren tenant_id y hash o file_content como parámetros'})
            }
        
        logger.info(f"Verificando duplicados para tenant: {tenant_id}, hash: {doc_hash}")
        
        # Verificar si hay duplicados
        duplicate_info = check_duplicate_document(tenant_id, doc_hash, exclude_id)
        
        # Construir respuesta
        response_body = {
            'is_duplicate': duplicate_info['is_duplicate'],
            'hash': doc_hash
        }
        
        # Si hay duplicado, incluir información básica del original
        if duplicate_info['is_duplicate'] and duplicate_info['original_doc']:
            original = duplicate_info['original_doc']
            response_body['original_doc'] = {
                'id': original.get('id'),
                'filename': original.get('filename', ''),
                'upload_date': original.get('timestamp', ''),
                'status': original.get('status', '')
            }
            
            # Si hay múltiples duplicados, incluir lista básica
            if len(duplicate_info['duplicates']) > 1:
                response_body['total_duplicates'] = len(duplicate_info['duplicates'])
                response_body['duplicates'] = [
                    {
                        'id': doc.get('id'),
                        'filename': doc.get('filename', ''),
                        'upload_date': doc.get('timestamp', '')
                    }
                    for doc in duplicate_info['duplicates'][:5]  # Limitar a 5 para no sobrecargar
                ]
        
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps(response_body)
        }
    
    except Exception as e:
        logger.error(f"Error verificando duplicados: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': str(e)})
        }

def handle_duplicate(event, context):
    """
    Maneja cómo proceder con un documento duplicado.
    Opciones: reemplazar, crear nueva versión, ignorar duplicado
    """
    try:
        # Extraer datos del body
        body = json.loads(event.get('body', '{}'))
        doc_id = body.get('document_id')
        action = body.get('action', 'ignore')  # ignore, replace, new_version
        original_doc_id = body.get('original_doc_id')
        
        # Validar parámetros obligatorios
        if not doc_id or not original_doc_id:
            logger.error("Faltan parámetros obligatorios (document_id o original_doc_id)")
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Se requieren document_id y original_doc_id como parámetros'})
            }
        
        logger.info(f"Manejando duplicado: {doc_id}, acción: {action}, original: {original_doc_id}")
        
        if action == 'ignore':
            # Marcar como duplicado y continuar
            contracts_table.update_item(
                Key={'id': doc_id},
                UpdateExpression="set is_duplicate = :d, original_doc_id = :o, #status = :s",
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':d': True,
                    ':o': original_doc_id,
                    ':s': 'duplicate'
                }
            )
            
            response_message = "Documento marcado como duplicado"
            
        elif action == 'replace':
            # Obtener información del documento original
            original_response = contracts_table.get_item(Key={'id': original_doc_id})
            if 'Item' not in original_response:
                return {
                    'statusCode': 404,
                    'headers': {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    'body': json.dumps({'error': 'Documento original no encontrado'})
                }
            
            original = original_response['Item']
            
            # Obtener información del nuevo documento
            new_response = contracts_table.get_item(Key={'id': doc_id})
            if 'Item' not in new_response:
                return {
                    'statusCode': 404,
                    'headers': {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    'body': json.dumps({'error': 'Documento nuevo no encontrado'})
                }
            
            new_doc = new_response['Item']
            
            # Marcar el original como reemplazado y enlazar al nuevo
            contracts_table.update_item(
                Key={'id': original_doc_id},
                UpdateExpression="set #status = :s, replaced_by = :r, replaced_at = :t",
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':s': 'replaced',
                    ':r': doc_id,
                    ':t': new_doc.get('timestamp', '')
                }
            )
            
            # Actualizar el nuevo documento para que no sea un duplicado
            contracts_table.update_item(
                Key={'id': doc_id},
                UpdateExpression="remove is_duplicate, original_doc_id",
                ReturnValues="UPDATED_NEW"
            )
            
            response_message = "Documento original reemplazado por la nueva versión"
            
        elif action == 'new_version':
            # Obtener información del documento original
            original_response = contracts_table.get_item(Key={'id': original_doc_id})
            if 'Item' not in original_response:
                return {
                    'statusCode': 404,
                    'headers': {
                        'Access-Control-Allow-Origin': '*',
                        'Content-Type': 'application/json'
                    },
                    'body': json.dumps({'error': 'Documento original no encontrado'})
                }
            
            original = original_response['Item']
            
            # Obtener versión actual o establecer como 1 si no existe
            current_version = original.get('version', 1)
            
            # Actualizar el nuevo documento como versión nueva
            contracts_table.update_item(
                Key={'id': doc_id},
                UpdateExpression="set version = :v, previous_version = :p",
                ExpressionAttributeValues={
                    ':v': current_version + 1,
                    ':p': original_doc_id
                }
            )
            
            # Actualizar el documento original para referenciar la nueva versión
            contracts_table.update_item(
                Key={'id': original_doc_id},
                UpdateExpression="set has_newer_version = :h, latest_version = :l",
                ExpressionAttributeValues={
                    ':h': True,
                    ':l': doc_id
                }
            )
            
            response_message = f"Documento creado como versión {current_version + 1}"
            
        else:
            return {
                'statusCode': 400,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': f"Acción no válida: {action}"})
            }
        
        return {
            'statusCode': 200,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'message': response_message,
                'document_id': doc_id,
                'action': action
            })
        }
    
    except Exception as e:
        logger.error(f"Error manejando duplicado: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': str(e)})
        }