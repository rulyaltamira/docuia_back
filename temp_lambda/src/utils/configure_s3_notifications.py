import json
import boto3
import os
import logging
import cfnresponse  # Importación corregida

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')

def lambda_handler(event, context):
    logger.info(f"Evento recibido: {json.dumps(event)}")
    
    # Inicializar respuesta
    response_data = {}
    
    try:
        # Determinar si es una solicitud de CloudFormation o una llamada directa
        if 'RequestType' in event:
            # Es una solicitud de CloudFormation Custom Resource
            request_type = event['RequestType']
            properties = event['ResourceProperties']
            
            main_bucket = properties.get('MainBucket')
            ses_bucket = properties.get('SESBucket')
            email_handler_function = properties.get('EmailHandlerFunction')
            document_processor_function = properties.get('DocumentProcessorFunction')
            
            # Manejar diferentes tipos de solicitud
            if request_type == 'Create' or request_type == 'Update':
                configure_buckets(
                    main_bucket,
                    ses_bucket,
                    email_handler_function,
                    document_processor_function,
                    response_data
                )
            
            # Para operaciones Delete, no necesitamos hacer nada ya que los buckets serán eliminados
            
            # Enviar respuesta de éxito
            cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data)
            
        else:
            # Es una llamada directa a la función
            main_bucket = os.environ.get('MAIN_BUCKET')
            ses_bucket = os.environ.get('SES_BUCKET')
            email_handler_function = os.environ.get('EMAIL_HANDLER_FUNCTION')
            document_processor_function = os.environ.get('DOCUMENT_PROCESSOR_FUNCTION')
            
            configure_buckets(
                main_bucket,
                ses_bucket,
                email_handler_function,
                document_processor_function,
                response_data
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps(response_data)
            }
            
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        
        if 'RequestType' in event:
            # Enviar respuesta de error a CloudFormation
            cfnresponse.send(event, context, cfnresponse.FAILED, {'Error': str(e)})
        
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }

def configure_buckets(main_bucket, ses_bucket, email_handler_function, document_processor_function, response_data):
    """Configura las notificaciones para los buckets S3"""
    # Configurar notificaciones del bucket SES
    if ses_bucket and email_handler_function:
        logger.info(f"Configurando notificaciones para bucket SES: {ses_bucket}")
        try:
            s3_client.put_bucket_notification_configuration(
                Bucket=ses_bucket,
                NotificationConfiguration={
                    'LambdaFunctionConfigurations': [
                        {
                            'LambdaFunctionArn': email_handler_function,
                            'Events': ['s3:ObjectCreated:*']
                        }
                    ]
                }
            )
            response_data['SESBucketNotification'] = 'Configurado'
            logger.info(f"Notificaciones para bucket SES configuradas correctamente")
        except Exception as e:
            logger.error(f"Error configurando notificaciones para bucket SES: {str(e)}")
            raise
    
    # Configurar notificaciones del bucket principal
    if main_bucket and document_processor_function:
        logger.info(f"Configurando notificaciones para bucket principal: {main_bucket}")
        try:
            s3_client.put_bucket_notification_configuration(
                Bucket=main_bucket,
                NotificationConfiguration={
                    'LambdaFunctionConfigurations': [
                        {
                            'LambdaFunctionArn': document_processor_function,
                            'Events': ['s3:ObjectCreated:*'],
                            'Filter': {
                                'Key': {
                                    'FilterRules': [
                                        {
                                            'Name': 'suffix',
                                            'Value': '.pdf'
                                        }
                                    ]
                                }
                            }
                        },
                        {
                            'LambdaFunctionArn': document_processor_function,
                            'Events': ['s3:ObjectCreated:*'],
                            'Filter': {
                                'Key': {
                                    'FilterRules': [
                                        {
                                            'Name': 'suffix',
                                            'Value': '.docx'
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            )
            response_data['MainBucketNotification'] = 'Configurado'
            logger.info(f"Notificaciones para bucket principal configuradas correctamente")
        except Exception as e:
            logger.error(f"Error configurando notificaciones para bucket principal: {str(e)}")
            raise