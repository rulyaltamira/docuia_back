#!/usr/bin/env python
# coding: utf-8

import boto3
import json
import sys
import argparse

# Configurar argumentos de línea de comandos
parser = argparse.ArgumentParser(description='Obtener token de verificación para un usuario.')
parser.add_argument('--tenant', required=True, help='ID del tenant')
parser.add_argument('--email', required=True, help='Email del usuario')
parser.add_argument('--region', default='eu-west-1', help='Región AWS')
parser.add_argument('--stage', default='dev', help='Etapa (dev, test, prod)')

args = parser.parse_args()

# Configurar recursos
SERVICE_NAME = 'docpilot-newsystem-v2'
USERS_TABLE = f"{SERVICE_NAME}-users-{args.stage}"
dynamodb = boto3.resource('dynamodb', region_name=args.region)
users_table = dynamodb.Table(USERS_TABLE)

print(f"Buscando usuario en tabla: {USERS_TABLE}")
print(f"Tenant ID: {args.tenant}")
print(f"Email: {args.email}")

# Buscar el usuario
try:
    response = users_table.scan(
        FilterExpression="tenant_id = :t AND email = :e",
        ExpressionAttributeValues={
            ":t": args.tenant,
            ":e": args.email
        }
    )
    
    users = response.get('Items', [])
    
    if not users:
        print(f"No se encontró el usuario con email {args.email} en el tenant {args.tenant}")
        sys.exit(1)
    
    user = users[0]
    
    # Mostrar información relevante
    print("\n=== Información del Usuario ===")
    print(f"User ID: {user.get('user_id')}")
    print(f"Email: {user.get('email')}")
    print(f"Status: {user.get('status')}")
    print(f"Cognito ID: {user.get('cognito_id')}")
    print(f"Email verificado: {user.get('email_verified', False)}")
    
    # Mostrar token de verificación
    verification_token = user.get('verification_token')
    verification_expiry = user.get('verification_expiry')
    
    if verification_token:
        print("\n=== Token de Verificación ===")
        print(f"Token: {verification_token}")
        print(f"Expira: {verification_expiry}")
        
        # Construir URL de verificación
        verification_url = f"https://verify.docpilot.link?token={verification_token}&tenant={args.tenant}"
        print(f"\nURL de verificación: {verification_url}")
    else:
        print("\nNo se encontró token de verificación para este usuario")
    
except Exception as e:
    print(f"Error: {str(e)}")
    sys.exit(1) 