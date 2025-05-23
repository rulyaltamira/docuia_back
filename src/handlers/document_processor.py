# docpilot-backend/src/handlers/document_processor.py
import json
import os
import boto3
import logging
import io
import PyPDF2
import docx
from datetime import datetime

# Configuración de servicios
logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
bedrock = boto3.client('bedrock-runtime')
dynamodb = boto3.resource('dynamodb')
contracts_table = dynamodb.Table(os.environ.get('CONTRACTS_TABLE'))
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID')

def extract_text_from_pdf(file_content):
    """Extrae texto de un archivo PDF"""
    with io.BytesIO(file_content) as pdf_file:
        try:
            reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
            return text
        except Exception as e:
            logger.error(f"Error extrayendo texto de PDF: {str(e)}")
            raise

def extract_text_from_docx(file_content):
    """Extrae texto de un archivo DOCX"""
    with io.BytesIO(file_content) as docx_file:
        try:
            doc = docx.Document(docx_file)
            text = ""
            for para in doc.paragraphs:
                text += para.text + "\n"
            return text
        except Exception as e:
            logger.error(f"Error extrayendo texto de DOCX: {str(e)}")
            raise

def extract_text(file_content, file_type):
    """Extrae texto según el tipo de archivo"""
    if file_type == 'application/pdf':
        return extract_text_from_pdf(file_content)
    elif file_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
        return extract_text_from_docx(file_content)
    elif file_type in ['text/plain', 'text/html']:
        return file_content.decode('utf-8', errors='replace')
    else:
        raise ValueError(f"Tipo de archivo no soportado: {file_type}")

def analyze_contract_with_bedrock(text, language='es'):
    """Analiza el texto del contrato usando AWS Bedrock"""
    logger.info(f"Analizando contrato con Bedrock (longitud del texto: {len(text)} caracteres)")
    
    # Limitar el texto a 150K caracteres por restricciones del modelo
    text_truncated = text[:150000] if len(text) > 150000 else text
    
    prompt = f"""
    Analiza el siguiente contrato y proporciona:
    1. Un resumen ejecutivo (máximo 300 palabras)
    2. Las partes involucradas
    3. Fechas clave (inicio, finalización, entrega, etc.)
    4. Obligaciones principales
    5. Cláusulas importantes (penalizaciones, renovación automática, etc.)
    6. Posibles riesgos identificados
    
    Responde en formato JSON con estas claves: "resumen", "partes", "fechas_clave", "obligaciones", "clausulas_importantes", "riesgos".
    Para las fechas, incluye una subclave "timestamp" en formato ISO 8601 (YYYY-MM-DD) cuando sea posible.
    
    Contrato:
    ---
    {text_truncated}
    ---
    """
    
    # Preparar el request para Claude en Bedrock
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "system": "Eres un asistente legal especializado en análisis de contratos. Tu tarea es extraer información relevante de contratos y presentarla en formato JSON estructurado.",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    })
    
    try:
        # Invocar el modelo
        response = bedrock.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=body
        )
        
        # Procesar la respuesta
        response_body = json.loads(response.get('body').read())
        content = response_body.get('content', [{}])[0].get('text', '{}')
        
        # Extraer el JSON de la respuesta
        try:
            # Intenta encontrar el JSON en la respuesta
            if '```json' in content:
                json_start = content.find('```json') + 7
                json_end = content.find('```', json_start)
                json_str = content[json_start:json_end].strip()
                return json.loads(json_str)
            else:
                # Si no está en formato de código, intenta parsear directamente
                return json.loads(content)
        except json.JSONDecodeError:
            # Si falla, devuelve un diccionario con el texto completo
            logger.warning("No se pudo extraer JSON estructurado de la respuesta")
            return {
                "error": "No se pudo extraer JSON estructurado",
                "respuesta_completa": content
            }
    except Exception as e:
        logger.error(f"Error al invocar Bedrock: {str(e)}")
        raise

def lambda_handler(event, context):
    """Procesa un documento cuando es subido a S3"""
    try:
        # Extraer información del evento S3
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']
        
        logger.info(f"Procesando documento: {key}")
        
        # Validar la estructura del path para multi-tenant
        path_parts = key.split('/')
        
        # Solo procesar archivos en el directorio 'raw'
        if 'raw' not in key:
            logger.info(f"Omitiendo archivo no procesable: {key}")
            return {
                'statusCode': 200,
                'body': json.dumps({'message': 'Archivo no procesable, no está en directorio raw'})
            }
        
        # Extraer información del path
        if path_parts[0] == 'tenants' and len(path_parts) >= 6:
            # Estructura: "tenants/{tenant_id}/raw/{source}/{doc_id}/{filename}"
            tenant_id = path_parts[1]
            doc_source = path_parts[3]  # 'email' o 'manual'
            doc_id = path_parts[4]
            filename = path_parts[5]
        else:
            # Estructura legacy: "raw/{source}/{doc_id}/{filename}"
            tenant_id = "default"
            doc_source = path_parts[1]  # 'email' o 'manual'
            doc_id = path_parts[2]
            filename = path_parts[3]
        
        logger.info(f"Documento identificado - tenant: {tenant_id}, id: {doc_id}, fuente: {doc_source}")
        
        # Obtener metadatos actuales del documento
        response = contracts_table.get_item(Key={'id': doc_id})
        if 'Item' not in response:
            logger.error(f"Documento no encontrado en DynamoDB: {doc_id}")
            raise ValueError(f"Documento no encontrado en DynamoDB: {doc_id}")
        
        item = response['Item']
        
        # Actualizar estado a "procesando"
        contracts_table.update_item(
            Key={'id': doc_id},
            UpdateExpression="set #status = :s",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':s': 'processing'}
        )
        
        logger.info(f"Estado actualizado a 'processing' para documento: {doc_id}")
        
        # Obtener el archivo de S3
        s3_response = s3.get_object(Bucket=bucket, Key=key)
        file_content = s3_response['Body'].read()
        content_type = s3_response.get('ContentType', item.get('content_type', 'application/octet-stream'))
        
        logger.info(f"Archivo descargado de S3: {key}, tipo: {content_type}")
        
        # Extraer texto según tipo de archivo
        try:
            text = extract_text(file_content, content_type)
            logger.info(f"Texto extraído correctamente, longitud: {len(text)} caracteres")
        except Exception as e:
            logger.error(f"Error extrayendo texto: {str(e)}")
            contracts_table.update_item(
                Key={'id': doc_id},
                UpdateExpression="set #status = :s, #error = :e",
                ExpressionAttributeNames={'#status': 'status', '#error': 'processing_error'},
                ExpressionAttributeValues={':s': 'error', ':e': f"Error extrayendo texto: {str(e)}"}
            )
            raise e
        
        # Analizar el contrato con Bedrock
        try:
            analysis_result = analyze_contract_with_bedrock(text)
            logger.info(f"Análisis completado para documento: {doc_id}")
            
            # Generar ruta para el resultado procesado
            processed_key = f"tenants/{tenant_id}/processed/{doc_id}/summary.json"
            
            # Guardar resultado en S3
            s3.put_object(
                Bucket=bucket,
                Key=processed_key,
                Body=json.dumps(analysis_result, ensure_ascii=False),
                ContentType='application/json'
            )
            
            logger.info(f"Resultado guardado en S3: {processed_key}")
            
            # Actualizar metadatos en DynamoDB
            contracts_table.update_item(
                Key={'id': doc_id},
                UpdateExpression="set #status = :s, processing_result = :r, processed_at = :t, processed_key = :pk",
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':s': 'processed',
                    ':r': analysis_result,
                    ':t': datetime.now().isoformat(),
                    ':pk': processed_key
                }
            )
            
            logger.info(f"Metadatos actualizados en DynamoDB para documento: {doc_id}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Documento procesado correctamente',
                    'document_id': doc_id,
                    'processed_key': processed_key
                })
            }
            
        except Exception as e:
            logger.error(f"Error en análisis IA: {str(e)}")
            contracts_table.update_item(
                Key={'id': doc_id},
                UpdateExpression="set #status = :s, #error = :e",
                ExpressionAttributeNames={'#status': 'status', '#error': 'processing_error'},
                ExpressionAttributeValues={':s': 'error', ':e': f"Error en análisis IA: {str(e)}"}
            )
            raise e
            
    except Exception as e:
        logger.error(f"Error procesando documento: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }