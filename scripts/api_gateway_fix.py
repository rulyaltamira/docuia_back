import boto3
import json
import argparse
import sys

def create_tenant_via_lambda(tenant_name, admin_email, plan="free"):
    """
    Crea un tenant invocando directamente la función Lambda
    """
    print(f"Creando tenant {tenant_name} con administrador {admin_email} (plan: {plan})")
    
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
    lambda_client = boto3.client('lambda', region_name='eu-west-1')
    
    # Invocar Lambda
    try:
        response = lambda_client.invoke(
            FunctionName='docpilot-newsystem-v2-dev-tenantOnboarding',
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
                    
                    return tenant_id
                else:
                    print(f"\n❌ Error: No se encontró tenant_id en la respuesta")
                    print(f"Respuesta: {json.dumps(body, indent=2)}")
            else:
                error_msg = json.loads(payload.get('body', '{}')).get('error', 'Error desconocido')
                print(f"\n❌ Error: {error_msg}")
                print(f"StatusCode: {payload.get('statusCode')}")
        else:
            print(f"\n❌ Error en la invocación Lambda: Status {status_code}")
            print(f"Respuesta: {payload_bytes.decode('utf-8')}")
            
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
    
    return None

def main():
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Crear un tenant llamando directamente a Lambda.')
    parser.add_argument('--name', required=True, help='Nombre del tenant')
    parser.add_argument('--email', required=True, help='Email del administrador')
    parser.add_argument('--plan', default='free', choices=['free', 'basic', 'premium', 'enterprise'], 
                       help='Plan de suscripción (default: free)')
    
    args = parser.parse_args()
    
    # Crear tenant
    tenant_id = create_tenant_via_lambda(args.name, args.email, args.plan)
    
    if tenant_id:
        print("\n¡Proceso completado exitosamente!")
        sys.exit(0)
    else:
        print("\nHubo un problema durante el proceso.")
        sys.exit(1)

if __name__ == "__main__":
    main() 