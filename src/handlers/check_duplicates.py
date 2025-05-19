import json
import os
import boto3
import logging
import base64

# Importar utilidades para cálculo y verificación de hashes
from src.utils.document_hash import calculate_hash_from_base64, check_duplicate_document
from src.utils.cors_middleware import add_cors_headers

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
        # Obtener el cuerpo y verificar si está codificado en Base64
        body_str = event.get('body')
        is_base64_encoded = event.get('isBase64Encoded', False)

        if is_base64_encoded and body_str:
            logger.info("Decodificando cuerpo Base64 para check_duplicates")
            try:
                body_str = base64.b64decode(body_str).decode('utf-8')
            except (base64.binascii.Error, UnicodeDecodeError) as decode_error:
                logger.error(f"Error decodificando Base64: {decode_error}")
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Error decodificando el cuerpo de la solicitud'})
                }

        # Parsear el JSON decodificado (o el original)
        if not body_str:
            logger.error("El cuerpo de la solicitud está vacío o ausente (después de posible decodificación)")
            body = {}
        else:
            try:
                body = json.loads(body_str)
            except json.JSONDecodeError as json_error:
                logger.error(f"Error parseando JSON del cuerpo: {json_error}. Body (decodificado si aplica): {body_str[:500]}")
                return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'El cuerpo de la solicitud no es un JSON válido'})
                }

        # Extraer datos del body parseado
        tenant_id = body.get('tenant_id')
        exclude_id = body.get('exclude_id')
        doc_hash = body.get('hash')
        
        if not doc_hash and 'file_content' in body:
            base64_content = body.get('file_content') # El contenido ya está en texto plano (si fue decodificado)
            # Necesitamos re-codificar a bytes para la función hash si vino como base64 originalmente
            # O idealmente, calcular hash directamente desde el base64 recibido antes de decodificar
            # Por simplicidad ahora, asumimos que calculate_hash_from_base64 puede manejar el string decodificado
            # o que el frontend envía hash si no envía file_content base64.
            # Revisar la función calculate_hash_from_base64 si esto falla.
            try:
                # Intentar calcular desde el string (puede necesitar ajuste en la función util)
                doc_hash = calculate_hash_from_base64(base64_content)
                logger.info(f"Hash calculado a partir del contenido decodificado: {doc_hash}")
            except Exception as hash_error:
                 logger.error(f"Error calculando hash desde el contenido: {hash_error}")
                 return {
                    'statusCode': 500,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Error procesando el contenido del archivo para calcular hash'})
                }

        # Validar parámetros obligatorios
        if not tenant_id or not doc_hash:
            logger.error("Faltan parámetros obligatorios (tenant_id o hash/file_content) en el cuerpo JSON")
            # Usar add_cors_headers
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': 'Se requieren tenant_id y (hash o file_content) en el cuerpo JSON'})
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
        
        # Usar add_cors_headers
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps(response_body)
        }
    
    except Exception as e:
        logger.error(f"Error verificando duplicados: {str(e)}")
        # Usar add_cors_headers
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno verificando duplicados'})
        }

def handle_duplicate(event, context):
    """
    Maneja cómo proceder con un documento duplicado.
    Opciones: reemplazar, crear nueva versión, ignorar duplicado
    """
    try:
        # Aplicar la misma lógica de decodificación Base64 al body si es necesario
        body_str = event.get('body')
        is_base64_encoded = event.get('isBase64Encoded', False)
        if is_base64_encoded and body_str:
            body_str = base64.b64decode(body_str).decode('utf-8')
        
        if not body_str:
            body = {}
        else:
            try:
                body = json.loads(body_str)
            except json.JSONDecodeError as json_error:
                 logger.error(f"Error parseando JSON del cuerpo en handle_duplicate: {json_error}. Body: {body_str[:500]}")
                 return {
                    'statusCode': 400,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'El cuerpo de la solicitud no es un JSON válido'})
                }

        # Extraer datos del body parseado
        doc_id = body.get('document_id')
        action = body.get('action', 'ignore')  # ignore, replace, new_version
        original_doc_id = body.get('original_doc_id')
        
        if not doc_id or not original_doc_id:
            # Usar add_cors_headers
            return {
                'statusCode': 400,
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
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
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
                    'body': json.dumps({'error': 'Documento original no encontrado'})
                }
            
            original = original_response['Item']
            
            # Obtener información del nuevo documento
            new_response = contracts_table.get_item(Key={'id': doc_id})
            if 'Item' not in new_response:
                return {
                    'statusCode': 404,
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
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
                    'headers': add_cors_headers({'Content-Type': 'application/json'}),
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
                'headers': add_cors_headers({'Content-Type': 'application/json'}),
                'body': json.dumps({'error': f"Acción no válida: {action}"})
            }
        
        # Respuesta exitosa
        # Usar add_cors_headers
        return {
            'statusCode': 200,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'message': response_message, 'action': action, 'document_id': doc_id})
        }
    
    except Exception as e:
        logger.error(f"Error manejando duplicado: {str(e)}")
        # Usar add_cors_headers
        return {
            'statusCode': 500,
            'headers': add_cors_headers({'Content-Type': 'application/json'}),
            'body': json.dumps({'error': 'Error interno manejando duplicado'})
        }

# Para pruebas locales (opcional)
# if __name__ == '__main__':
#     class MockContext:
#         function_name = "local_test_handler"
#     
#     mock_event = {"key": "value_check"}
#     print("Testing lambda_handler (checkDuplicates):")
#     print(lambda_handler(mock_event, MockContext()))
#     print("\nTesting handle_duplicate:")
#     mock_event_handle = {"key": "value_handle"}
#     print(handle_duplicate(mock_event_handle, MockContext())) 