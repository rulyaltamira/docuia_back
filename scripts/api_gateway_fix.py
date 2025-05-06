import boto3
import json
import argparse
import sys
import os
from datetime import datetime

# Configuración de servicios y entorno
STAGE = os.environ.get('STAGE', 'dev')
REGION = os.environ.get('AWS_REGION', 'eu-west-1')
SERVICE_NAME = os.environ.get('SERVICE_NAME', 'docpilot-newsystem-v2')
FUNCTION_NAME = f"{SERVICE_NAME}-{STAGE}-tenantOnboarding"
USERS_TABLE = f"{SERVICE_NAME}-users-{STAGE}"
TENANTS_TABLE = f"{SERVICE_NAME}-tenants-{STAGE}"
VERIFICATION_URL = os.environ.get('VERIFICATION_BASE_URL', 'https://verify.docpilot.link')
API_ID = "04rx323x27"  # ID de tu API Gateway

def create_tenant_via_lambda(tenant_name, admin_email, plan="free"):
    """
    Crea un tenant invocando directamente la función Lambda
    """
    print(f"Creando tenant {tenant_name} con administrador {admin_email} (plan: {plan})")
    print(f"Usando función Lambda: {FUNCTION_NAME}")
    
    # Preparar datos
    data = {
        "name": tenant_name,
        "plan": plan,
        "admin_email": admin_email,
        "industry": "Technology",
        "company_size": "1-10",
        "country": "Spain"
    }
    
    # Crear el evento para Lambda
    event = {
        "httpMethod": "POST",
        "path": "/tenants/onboard",
        "body": json.dumps(data),
        "isBase64Encoded": False,
        "headers": {
            "Content-Type": "application/json"
        }
    }
    
    print(f"Invocando Lambda directamente...")
    
    # Configurar cliente Lambda
    lambda_client = boto3.client('lambda', region_name=REGION)
    
    # Invocar Lambda
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
        
        if status_code == 200:
            # La respuesta Lambda fue exitosa, ahora analizar el statusCode interno
            if payload.get('statusCode') in [200, 201]:
                # Extraer el body (que es un string JSON) y parsearlo
                body = json.loads(payload.get('body', '{}'))
                tenant_id = body.get('tenant_id')
                
                if tenant_id:
                    print(f"\n✅ Tenant creado exitosamente:")
                    print(f"   ID: {tenant_id}")
                    print(f"   Nombre: {tenant_name}")
                    print(f"   Admin: {admin_email}")
                    print(f"   Plan: {plan}")
                    
                    # Mostrar recursos creados
                    resources = body.get('resources_created', [])
                    if resources:
                        print("\nRecursos creados:")
                        for resource in resources:
                            print(f"   • {resource}")
                    
                    # Información sobre verificación por correo
                    print("\n📧 IMPORTANTE: Se ha enviado un correo de verificación a la dirección de administrador.")
                    print("   ⚠️  El usuario debe verificar su correo electrónico para activar su cuenta.")
                    print("   ℹ️  El enlace de verificación expirará en 3 días.")
                    print(f"   🔗 El enlace de verificación apuntará a: {VERIFICATION_URL}?token=XXX&tenant={tenant_id}")
                    
                    return tenant_id
                else:
                    print(f"\n❌ Error: No se encontró tenant_id en la respuesta")
                    print(f"Respuesta: {json.dumps(body, indent=2)}")
            else:
                error_msg = json.loads(payload.get('body', '{}')).get('error', 'Error desconocido')
                print(f"\n❌ Error: {error_msg}")
                print(f"StatusCode: {payload.get('statusCode')}")
                
                # Si es un error de correo no corporativo, mostrar información adicional
                if "corporativo" in error_msg.lower():
                    print("\n⚠️ Solo se permiten correos corporativos (no personales).")
                    print("   Los siguientes dominios no están permitidos:")
                    print("   - Gmail, Hotmail, Outlook, Yahoo, AOL")
                    print("   - iCloud, Protonmail, etc.")
                    print("   Por favor, utilice un correo electrónico corporativo.")
        else:
            print(f"\n❌ Error en la invocación Lambda: Status {status_code}")
            print(f"Respuesta: {payload_bytes.decode('utf-8')}")
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
    
    return None

def check_email_verification(tenant_id, email):
    """
    Comprueba el estado de verificación del correo electrónico
    """
    try:
        print(f"Usando tabla de usuarios: {USERS_TABLE}")
        
        # Configurar cliente DynamoDB
        dynamodb = boto3.resource('dynamodb', region_name=REGION)
        users_table = dynamodb.Table(USERS_TABLE)
        
        # Buscar el usuario por tenant_id y email
        response = users_table.scan(
            FilterExpression="tenant_id = :t AND email = :e",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":e": email
            }
        )
        
        users = response.get('Items', [])
        
        if not users:
            print(f"\n❓ No se encontró el usuario con email {email} en el tenant {tenant_id}")
            return None
        
        user = users[0]
        status = user.get('status', 'unknown')
        email_verified = user.get('email_verified', False)
        verification_expiry = user.get('verification_expiry')
        
        # Verificar si el token ha expirado
        is_expired = False
        if verification_expiry:
            try:
                expiry_date = datetime.fromisoformat(verification_expiry)
                is_expired = datetime.now() > expiry_date
            except:
                pass
                
        if status == 'active' and email_verified:
            print(f"\n✅ El correo {email} ha sido verificado correctamente")
            return True
        elif status == 'pending_verification':
            print(f"\n⏳ El correo {email} está pendiente de verificación")
            if is_expired:
                print("   ⚠️ El enlace de verificación ha expirado.")
            else:
                print("   Por favor, revise su bandeja de entrada y haga clic en el enlace de verificación")
            return False
        else:
            print(f"\n❓ Estado del usuario: {status}")
            print(f"   Email verificado: {'Sí' if email_verified else 'No'}")
            return None
            
    except Exception as e:
        print(f"\n❌ Error comprobando verificación: {str(e)}")
        return None

def fix_api_gateway_cors():
    """
    Configura correctamente CORS para API Gateway
    """
    print(f"Configurando CORS para API Gateway: {API_ID}")
    
    # Configurar cliente API Gateway
    api_gateway = boto3.client('apigateway', region_name=REGION)
    
    # Obtener recursos de la API
    resources = api_gateway.get_resources(restApiId=API_ID)
    
    # Encontrar el recurso /tenants/verify-email
    verify_email_resource_id = None
    for resource in resources['items']:
        if resource.get('path') == '/tenants/verify-email':
            verify_email_resource_id = resource['id']
            break
    
    if not verify_email_resource_id:
        print("❌ No se encontró el recurso /tenants/verify-email")
        return False
    
    print(f"Configurando CORS para el recurso: {verify_email_resource_id}")
    
    # Configurar CORS para el método GET
    try:
        # Obtener el método antes de actualizarlo
        method = api_gateway.get_method(
            restApiId=API_ID,
            resourceId=verify_email_resource_id,
            httpMethod='GET'
        )
        
        # Actualizar integración para habilitar CORS
        api_gateway.update_integration_response(
            restApiId=API_ID,
            resourceId=verify_email_resource_id,
            httpMethod='GET',
            statusCode='200',
            selectionPattern='',
            patchOperations=[
                {
                    'op': 'add',
                    'path': '/responseParameters/method.response.header.Access-Control-Allow-Origin',
                    'value': "'*'"
                }
            ]
        )
        
        # También configurar para redirección 302
        api_gateway.update_integration_response(
            restApiId=API_ID,
            resourceId=verify_email_resource_id,
            httpMethod='GET',
            statusCode='302',
            selectionPattern='',
            patchOperations=[
                {
                    'op': 'add',
                    'path': '/responseParameters/method.response.header.Access-Control-Allow-Origin',
                    'value': "'*'"
                }
            ]
        )
        
        print("✅ CORS configurado correctamente para el método GET")
        
        # Crear OPTIONS method para preflight CORS requests
        try:
            # Verificar si ya existe OPTIONS
            api_gateway.get_method(
                restApiId=API_ID, 
                resourceId=verify_email_resource_id,
                httpMethod='OPTIONS'
            )
            print("El método OPTIONS ya existe, actualizando...")
        except:
            # No existe, crearlo
            api_gateway.put_method(
                restApiId=API_ID,
                resourceId=verify_email_resource_id,
                httpMethod='OPTIONS',
                authorizationType='NONE'
            )
            
            # Crear respuesta del método
            api_gateway.put_method_response(
                restApiId=API_ID,
                resourceId=verify_email_resource_id,
                httpMethod='OPTIONS',
                statusCode='200',
                responseParameters={
                    'method.response.header.Access-Control-Allow-Headers': True,
                    'method.response.header.Access-Control-Allow-Methods': True,
                    'method.response.header.Access-Control-Allow-Origin': True
                }
            )
            
            # Crear integración MOCK para OPTIONS
            api_gateway.put_integration(
                restApiId=API_ID,
                resourceId=verify_email_resource_id,
                httpMethod='OPTIONS',
                type='MOCK',
                integrationHttpMethod='OPTIONS',
                requestTemplates={
                    'application/json': '{"statusCode": 200}'
                }
            )
            
            # Configurar respuesta de integración
            api_gateway.put_integration_response(
                restApiId=API_ID,
                resourceId=verify_email_resource_id,
                httpMethod='OPTIONS',
                statusCode='200',
                responseParameters={
                    'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,Origin'",
                    'method.response.header.Access-Control-Allow-Methods': "'GET,OPTIONS'",
                    'method.response.header.Access-Control-Allow-Origin': "'*'"
                },
                responseTemplates={
                    'application/json': ''
                }
            )
            
            print("✅ Método OPTIONS creado para preflight CORS")
        
        # Crear despliegue para aplicar cambios
        api_gateway.create_deployment(
            restApiId=API_ID,
            stageName=STAGE,
            description='Actualización de CORS por script de corrección'
        )
        
        print(f"✅ Cambios desplegados en el stage: {STAGE}")
        print(f"🔗 Endpoint actualizado: https://{API_ID}.execute-api.{REGION}.amazonaws.com/{STAGE}/tenants/verify-email")
        
        return True
    except Exception as e:
        print(f"❌ Error configurando CORS: {str(e)}")
        return False

def main():
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Crear un tenant llamando directamente a Lambda.')
    parser.add_argument('--name', required=False, help='Nombre del tenant')
    parser.add_argument('--email', required=False, help='Email del administrador')
    parser.add_argument('--plan', default='free', choices=['free', 'basic', 'premium', 'enterprise'], 
                       help='Plan de suscripción (default: free)')
    parser.add_argument('--check', action='store_true', help='Comprobar estado de verificación para un tenant existente')
    parser.add_argument('--fix-cors', action='store_true', help='Configurar CORS para API Gateway')
    parser.add_argument('--stage', help='Etapa (dev, test, prod)')
    parser.add_argument('--region', help='Región AWS')
    
    args = parser.parse_args()
    
    # Actualizar variables globales si se proporcionan
    global STAGE, REGION, FUNCTION_NAME, USERS_TABLE, TENANTS_TABLE
    if args.stage:
        STAGE = args.stage
        FUNCTION_NAME = f"{SERVICE_NAME}-{STAGE}-tenantOnboarding"
        USERS_TABLE = f"{SERVICE_NAME}-users-{STAGE}"
        TENANTS_TABLE = f"{SERVICE_NAME}-tenants-{STAGE}"
    
    if args.region:
        REGION = args.region
    
    print(f"Usando entorno: {STAGE}, región: {REGION}")
    
    if args.check:
        # Comprobar verificación de correo
        print(f"Comprobando estado de verificación para email {args.email}...")
        check_email_verification(args.name, args.email)
    elif args.fix_cors:
        # Configurar CORS para API Gateway
        fix_api_gateway_cors()
    else:
        # Crear tenant
        if not args.name or not args.email:
            parser.error("Los argumentos --name y --email son obligatorios para crear un tenant")
            
        tenant_id = create_tenant_via_lambda(args.name, args.email, args.plan)
        
        if tenant_id:
            print("\n¡Proceso de creación completado exitosamente!")
            print("\n⚠️ Recuerde que el usuario necesita verificar su correo electrónico.")
            print(f"   Puede comprobar el estado con: python scripts/api_gateway_fix.py --check --name {tenant_id} --email {args.email}")
            sys.exit(0)
        else:
            print("\nHubo un problema durante el proceso.")
            sys.exit(1)

if __name__ == "__main__":
    main() 