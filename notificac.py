"""
Script para configurar las notificaciones de S3 después del despliegue.
Ejecutar después de que el stack se haya desplegado correctamente.

Uso: python configure_s3_triggers.py
"""

import boto3
import json
import sys

# Nombre del stack de CloudFormation
STACK_NAME = 'docpilot-newsystem-dev'  # Cambiar si se usa un nombre/stage diferente

def get_stack_outputs():
    """Obtiene las salidas del stack de CloudFormation"""
    cf_client = boto3.client('cloudformation')
    
    try:
        response = cf_client.describe_stacks(StackName=STACK_NAME)
        if 'Stacks' not in response or not response['Stacks']:
            print(f"No se encontró el stack: {STACK_NAME}")
            return None
            
        outputs = response['Stacks'][0].get('Outputs', [])
        result = {}
        
        for output in outputs:
            result[output['OutputKey']] = output['OutputValue']
            
        return result
    except Exception as e:
        print(f"Error obteniendo información del stack: {str(e)}")
        return None

def get_lambda_arn(function_name):
    """Obtiene el ARN de una función Lambda"""
    lambda_client = boto3.client('lambda')
    
    try:
        response = lambda_client.get_function(FunctionName=function_name)
        return response['Configuration']['FunctionArn']
    except Exception as e:
        print(f"Error obteniendo ARN de la función Lambda: {str(e)}")
        return None

def configure_bucket_notifications(bucket_name, lambda_arn, events, filters=None):
    """Configura las notificaciones de un bucket S3"""
    s3_client = boto3.client('s3')
    
    config = {
        'LambdaFunctionConfigurations': [
            {
                'LambdaFunctionArn': lambda_arn,
                'Events': events
            }
        ]
    }
    
    # Añadir filtros si se proporcionan
    if filters:
        config['LambdaFunctionConfigurations'][0]['Filter'] = filters
    
    try:
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration=config
        )
        print(f"Notificaciones configuradas para el bucket: {bucket_name}")
        return True
    except Exception as e:
        print(f"Error configurando notificaciones para el bucket {bucket_name}: {str(e)}")
        return False

def main():
    # Obtener información del stack
    print(f"Obteniendo información del stack: {STACK_NAME}...")
    stack_outputs = get_stack_outputs()
    
    if not stack_outputs:
        print("No se pudo obtener información del stack. Abortando.")
        sys.exit(1)
    
    # Obtener nombres de buckets
    main_bucket = stack_outputs.get('MainBucketName')
    ses_bucket = stack_outputs.get('SESBucketName')
    
    if not main_bucket or not ses_bucket:
        print("No se encontraron los nombres de los buckets en las salidas del stack.")
        sys.exit(1)
    
    print(f"Buckets encontrados: Main={main_bucket}, SES={ses_bucket}")
    
    # Obtener ARNs de las funciones Lambda
    email_handler_function = f"docpilot-newsystem-dev-emailHandler"
    document_processor_function = f"docpilot-newsystem-dev-documentProcessor"
    
    email_handler_arn = get_lambda_arn(email_handler_function)
    document_processor_arn = get_lambda_arn(document_processor_function)
    
    if not email_handler_arn or not document_processor_arn:
        print("No se pudieron obtener los ARNs de las funciones Lambda. Abortando.")
        sys.exit(1)
    
    print(f"ARNs de funciones Lambda obtenidos correctamente.")
    
    # Configurar notificación para el bucket SES
    print(f"Configurando notificaciones para el bucket SES: {ses_bucket}...")
    ses_success = configure_bucket_notifications(
        ses_bucket,
        email_handler_arn,
        ['s3:ObjectCreated:*']
    )
    
    # Configurar notificación para el bucket principal con filtros para PDF
    print(f"Configurando notificaciones para el bucket principal: {main_bucket} (PDFs)...")
    pdf_filters = {
        'Key': {
            'FilterRules': [
                {
                    'Name': 'suffix',
                    'Value': '.pdf'
                }
            ]
        }
    }
    
    pdf_success = configure_bucket_notifications(
        main_bucket,
        document_processor_arn,
        ['s3:ObjectCreated:*'],
        pdf_filters
    )
    
    # Configurar notificación para el bucket principal con filtros para DOCX
    print(f"Configurando notificaciones para el bucket principal: {main_bucket} (DOCXs)...")
    docx_filters = {
        'Key': {
            'FilterRules': [
                {
                    'Name': 'suffix',
                    'Value': '.docx'
                }
            ]
        }
    }
    
    docx_success = configure_bucket_notifications(
        main_bucket,
        document_processor_arn,
        ['s3:ObjectCreated:*'],
        docx_filters
    )
    
    # Resumen final
    if ses_success and pdf_success and docx_success:
        print("\n✅ Todas las notificaciones configuradas correctamente.")
    else:
        print("\n⚠️ Hubo errores configurando algunas notificaciones.")
        if not ses_success:
            print("  ❌ Error en bucket SES")
        if not pdf_success:
            print("  ❌ Error en bucket principal (PDFs)")
        if not docx_success:
            print("  ❌ Error en bucket principal (DOCXs)")

if __name__ == "__main__":
    main()