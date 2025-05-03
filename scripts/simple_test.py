# docpilot-backend/scripts/simple_test.py
# Script simple para probar el onboarding con AWS boto3

import boto3
import json

# Configurar cliente Lambda
lambda_client = boto3.client('lambda', region_name='eu-west-1')

# Datos para crear el tenant
data = {
    "name": "EreaceTest",
    "plan": "free",
    "admin_email": "ruly.altamirano+testdirect@gmail.com",
    "industry": "Technology",
    "company_size": "1-10",
    "country": "Spain"
}

# Crear el evento como esperaría recibirlo API Gateway
event = {
    "httpMethod": "POST",
    "path": "/tenants/onboard",
    "body": json.dumps(data)
}

print("Invocando Lambda directamente...")
print(f"Evento: {json.dumps(event)}")

# Invocar la función Lambda directamente
response = lambda_client.invoke(
    FunctionName='docpilot-newsystem-v2-dev-tenantOnboarding',
    InvocationType='RequestResponse',
    Payload=json.dumps(event)
)

# Obtener la respuesta
payload = response['Payload'].read().decode('utf-8')
print(f"Código de estado Lambda: {response['StatusCode']}")
print(f"Respuesta Lambda: {payload}")

# Guardar también en un archivo para análisis
with open("lambda_direct_response.txt", "w") as f:
    f.write(f"Código de estado Lambda: {response['StatusCode']}\n")
    f.write(f"Respuesta Lambda: {payload}\n")
    f.write(f"Respuesta completa: {json.dumps(dict(response), default=str)}\n") 