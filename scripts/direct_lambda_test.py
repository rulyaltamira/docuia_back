import boto3
import json
import time

# Configurar cliente Lambda
lambda_client = boto3.client('lambda', region_name='eu-west-1')

# Datos para crear el tenant
data = {
    "name": "EreaceDirect",
    "plan": "free",
    "admin_email": "ruly.altamirano+directlambda@gmail.com",
    "industry": "Technology",
    "company_size": "1-10",
    "country": "Spain"
}

# Preparar el evento como lo recibiría el Lambda desde API Gateway
print("Preparando evento para Lambda...")
event = {
    "httpMethod": "POST",
    "path": "/tenants/onboard",
    "body": json.dumps(data),
    "isBase64Encoded": False,
    "headers": {
        "Content-Type": "application/json"
    }
}

print(f"Evento: {json.dumps(event, indent=2)}")

# Invocar la función Lambda directamente
print("\nInvocando Lambda directamente...")
response = lambda_client.invoke(
    FunctionName='docpilot-newsystem-v2-dev-tenantOnboarding',
    InvocationType='RequestResponse',
    Payload=json.dumps(event)
)

# Obtener la respuesta
status_code = response['StatusCode']
payload = json.loads(response['Payload'].read().decode('utf-8'))

print(f"\nRespuesta de Lambda:")
print(f"Status Code: {status_code}")
print(f"Payload: {json.dumps(payload, indent=2)}")

# Guardar en un archivo para análisis
with open("lambda_direct_response.txt", "w") as f:
    f.write(f"Status Code: {status_code}\n")
    f.write(f"Payload: {json.dumps(payload, indent=2)}\n")

print("\nLog guardado en lambda_direct_response.txt") 