#!/usr/bin/env python
# coding: utf-8

import boto3
import json
import sys
import argparse
import urllib.parse
import requests

# Configurar argumentos de línea de comandos
parser = argparse.ArgumentParser(description='Simular verificación de correo electrónico.')
parser.add_argument('--token', required=True, help='Token de verificación')
parser.add_argument('--tenant', required=True, help='ID del tenant')
parser.add_argument('--api-url', default='https://api.docpilot.com', help='URL base de la API')
parser.add_argument('--local', action='store_true', help='Invocar Lambda directamente en lugar de usar API')
parser.add_argument('--region', default='eu-west-1', help='Región AWS')
parser.add_argument('--stage', default='dev', help='Etapa (dev, test, prod)')

args = parser.parse_args()

# Si es local, invocamos la función Lambda directamente
if args.local:
    SERVICE_NAME = 'docpilot-newsystem-v2'
    FUNCTION_NAME = f"{SERVICE_NAME}-{args.stage}-tenantOnboarding"
    
    print(f"Invocando Lambda directamente: {FUNCTION_NAME}")
    
    # Crear el evento para Lambda
    event = {
        "httpMethod": "GET",
        "path": "/tenants/verify-email",
        "queryStringParameters": {
            "token": args.token,
            "tenant": args.tenant
        },
        "headers": {
            "Content-Type": "application/json"
        }
    }
    
    # Invocar Lambda
    lambda_client = boto3.client('lambda', region_name=args.region)
    try:
        response = lambda_client.invoke(
            FunctionName=FUNCTION_NAME,
            InvocationType='RequestResponse',
            Payload=json.dumps(event)
        )
        
        # Procesar respuesta
        status_code = response['StatusCode']
        payload_bytes = response['Payload'].read()
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        print(f"Status Code: {status_code}")
        print(f"Respuesta:")
        print(json.dumps(payload, indent=2))
        
        # Verificar estado de la verificación
        if status_code == 200:
            print("\n✅ La verificación de correo fue procesada por Lambda")
            status_code = payload.get('statusCode')
            
            if status_code == 302:
                print("   ✅ Verificación exitosa (redirección)")
            elif status_code == 200:
                print("   ✅ Verificación exitosa")
            else:
                error_body = json.loads(payload.get('body', '{}'))
                print(f"   ❌ Error: {error_body.get('error', 'Error desconocido')}")
                
            # Comprobar el estado actual del usuario
            print("\nComprobando estado actualizado del usuario...")
            
            # Obtener info del usuario desde DynamoDB para confirmar verificación
            dynamodb = boto3.resource('dynamodb', region_name=args.region)
            users_table = dynamodb.Table(f"{SERVICE_NAME}-users-{args.stage}")
            
            response = users_table.scan(
                FilterExpression="tenant_id = :t",
                ExpressionAttributeValues={
                    ":t": args.tenant
                }
            )
            
            users = response.get('Items', [])
            
            if users:
                user = users[0]
                print(f"\nEstado actualizado del usuario:")
                print(f"  Email: {user.get('email')}")
                print(f"  Status: {user.get('status')}")
                print(f"  Email verificado: {user.get('email_verified', False)}")
                print(f"  Cognito ID: {user.get('cognito_id')}")
                print(f"  Cognito status: {user.get('cognito_status', 'N/A')}")
                
                cognito_client = boto3.client('cognito-idp', region_name=args.region)
                try:
                    user_pool_id = f"{args.region}_U76ZEVpde"  # Ajustar según el entorno
                    cognito_response = cognito_client.admin_get_user(
                        UserPoolId=user_pool_id,
                        Username=user.get('email')
                    )
                    
                    print("\nInformación en Cognito:")
                    print(f"  UserStatus: {cognito_response.get('UserStatus', 'N/A')}")
                    user_attributes = {attr['Name']: attr['Value'] for attr in cognito_response.get('UserAttributes', [])}
                    print(f"  email_verified: {user_attributes.get('email_verified', 'N/A')}")
                    
                except Exception as e:
                    print(f"\nNo se pudo obtener información de Cognito: {str(e)}")
            
        else:
            print(f"\n❌ Error invocando Lambda: {status_code}")
            print(f"Respuesta: {payload_bytes.decode('utf-8')}")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
else:
    # Hacer una petición HTTP a la API
    encoded_token = urllib.parse.quote(args.token)
    verification_url = f"{args.api_url}/tenants/verify-email?token={encoded_token}&tenant={args.tenant}"
    
    print(f"Enviando solicitud a: {verification_url}")
    
    try:
        response = requests.get(verification_url, allow_redirects=False)
        status_code = response.status_code
        
        print(f"Status Code: {status_code}")
        
        if status_code in [200, 302]:
            print("\n✅ Verificación exitosa")
            
            if status_code == 302:
                print(f"   Redirección a: {response.headers.get('Location')}")
        else:
            print(f"\n❌ Error: {response.text}")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}") 