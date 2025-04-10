# docpilot-backend/scripts/setup_api_routes.py
# Script para configurar las rutas de API Gateway y conectarlas a las funciones Lambda

import json
import os
import sys
import subprocess
import argparse
import time

def run_command(command):
    """Ejecuta un comando y captura su salida"""
    print(f"Ejecutando: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        print(f"Error ejecutando comando: {command}")
        print(f"Error: {stderr.decode('utf-8')}")
        sys.exit(1)
    
    return stdout.decode('utf-8')

def load_config():
    """Carga la configuración del proyecto"""
    config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except:
        print(f"Error: No se pudo cargar la configuración desde {config_file}")
        sys.exit(1)

def create_resource(api_id, parent_id, path_part):
    """Crea un recurso en API Gateway"""
    try:
        output = run_command(f"""
            aws apigateway create-resource --rest-api-id {api_id} --parent-id {parent_id} --path-part "{path_part}"
        """)
        
        resource_data = json.loads(output)
        return resource_data["id"]
    except Exception as e:
        print(f"Error creando recurso {path_part}: {str(e)}")
        return None

def get_resource_id(api_id, path):
    """Obtiene el ID de un recurso por su path"""
    try:
        output = run_command(f"""
            aws apigateway get-resources --rest-api-id {api_id}
        """)
        
        resources_data = json.loads(output)
        
        for resource in resources_data["items"]:
            if resource["path"] == path:
                return resource["id"]
        
        return None
    except Exception as e:
        print(f"Error obteniendo recurso para path {path}: {str(e)}")
        return None

def setup_method(api_id, resource_id, http_method, function_name, region, account_id, authorizer_id=None):
    """Configura un método HTTP y lo integra con una función Lambda"""
    try:
        # Crear método
        auth_type = "NONE"
        authorizer_part = ""
        
        if authorizer_id:
            auth_type = "COGNITO_USER_POOLS"
            authorizer_part = f"--authorizer-id {authorizer_id}"
        
        run_command(f"""
            aws apigateway put-method --rest-api-id {api_id} --resource-id {resource_id} --http-method {http_method} --authorization-type {auth_type} {authorizer_part}
        """)
        
        # Crear integración con Lambda
        run_command(f"""
            aws apigateway put-integration --rest-api-id {api_id} --resource-id {resource_id} --http-method {http_method} --type AWS_PROXY --integration-http-method POST --uri arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/arn:aws:lambda:{region}:{account_id}:function:{function_name}/invocations
        """)
        
        # Configurar respuesta del método para CORS
        run_command(f"""
            aws apigateway put-method-response --rest-api-id {api_id} --resource-id {resource_id} --http-method {http_method} --status-code 200 --response-models '{{"application/json": "Empty"}}' --response-parameters '{{"method.response.header.Access-Control-Allow-Origin": true}}'
        """)
        
        # Dar permiso a API Gateway para invocar la función Lambda
        run_command(f"""
            aws lambda add-permission --function-name {function_name} --statement-id apigateway-{http_method}-{resource_id} --action lambda:InvokeFunction --principal apigateway.amazonaws.com --source-arn "arn:aws:execute-api:{region}:{account_id}:{api_id}/*/{http_method}/*"
        """)
        
        print(f"Método {http_method} configurado correctamente para recurso {resource_id}")
        return True
    except Exception as e:
        print(f"Error configurando método {http_method} para recurso {resource_id}: {str(e)}")
        return False

def setup_cors(api_id, resource_id):
    """Configura CORS para un recurso"""
    try:
        # Añadir método OPTIONS para CORS
        run_command(f"""
            aws apigateway put-method --rest-api-id {api_id} --resource-id {resource_id} --http-method OPTIONS --authorization-type NONE
        """)
        
        # Configurar integración para OPTIONS (mock)
        run_command(f"""
            aws apigateway put-integration --rest-api-id {api_id} --resource-id {resource_id} --http-method OPTIONS --type MOCK --integration-http-method OPTIONS --request-templates '{{"application/json":"{{\\\"statusCode\\\": 200}}"}}'
        """)
        
        # Configurar respuesta de integración
        run_command(f"""
            aws apigateway put-integration-response --rest-api-id {api_id} --resource-id {resource_id} --http-method OPTIONS --status-code 200 --response-parameters '{{"method.response.header.Access-Control-Allow-Origin":"'\\''*'\\''","method.response.header.Access-Control-Allow-Methods":"'\\''{http_method_list}'\\''"}}' --response-templates '{{"application/json":""}}'
        """)
        
        # Configurar respuesta de método
        run_command(f"""
            aws apigateway put-method-response --rest-api-id {api_id} --resource-id {resource_id} --http-method OPTIONS --status-code 200 --response-parameters '{{"method.response.header.Access-Control-Allow-Origin":true,"method.response.header.Access-Control-Allow-Methods":true,"method.response.header.Access-Control-Allow-Headers":true}}'
        """)
        
        print(f"CORS configurado correctamente para recurso {resource_id}")
        return True
    except Exception as e:
        print(f"Error configurando CORS para recurso {resource_id}: {str(e)}")
        return False

def deploy_api(api_id, stage_name):
    """Despliega la API a un stage"""
    try:
        run_command(f"""
            aws apigateway create-deployment --rest-api-id {api_id} --stage-name {stage_name}
        """)
        
        print(f"API desplegada correctamente al stage {stage_name}")
        return True
    except Exception as e:
        print(f"Error desplegando API: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Configurar rutas de API Gateway para DocPilot')
    parser.add_argument('--region', default='eu-west-1', help='Región de AWS')
    parser.add_argument('--account-id', required=True, help='ID de la cuenta de AWS')
    parser.add_argument('--stage', default='v1', help='Nombre del stage de despliegue')
    
    args = parser.parse_args()
    
    # Cargar configuración
    config = load_config()
    
    if 'api_gateway_id' not in config or 'api_gateway_root_id' not in config:
        print("Error: No se encontró información de API Gateway en el archivo de configuración")
        sys.exit(1)
    
    api_id = config['api_gateway_id']
    root_id = config['api_gateway_root_id']
    
    print(f"Configurando rutas para API Gateway {api_id}")
    
    # Configurar rutas para documentos
    print("\n=== Configurando rutas para documentos ===")
    
    # Recurso /documents
    documents_id = create_resource(api_id, root_id, "documents")
    if documents_id:
        print(f"Recurso /documents creado con ID: {documents_id}")
        
        # Configurar métodos
        setup_method(api_id, documents_id, "GET", "docpilot-document-manager", args.region, args.account_id)
        setup_cors(api_id, documents_id)
        
        # Recurso /documents/{id}
        documents_id_param = create_resource(api_id, documents_id, "{id}")
        if documents_id_param:
            print(f"Recurso /documents/{{id}} creado con ID: {documents_id_param}")
            
            # Configurar métodos
            setup_method(api_id, documents_id_param, "GET", "docpilot-document-manager", args.region, args.account_id)
            setup_method(api_id, documents_id_param, "DELETE", "docpilot-document-manager", args.region, args.account_id)
            setup_cors(api_id, documents_id_param)
            
            # Recurso /documents/{id}/view
            documents_view_id = create_resource(api_id, documents_id_param, "view")
            if documents_view_id:
                print(f"Recurso /documents/{{id}}/view creado con ID: {documents_view_id}")
                
                # Configurar métodos
                setup_method(api_id, documents_view_id, "GET", "docpilot-document-manager", args.region, args.account_id)
                setup_cors(api_id, documents_view_id)
            
            # Recurso /documents/{id}/summary
            documents_summary_id = create_resource(api_id, documents_id_param, "summary")
            if documents_summary_id:
                print(f"Recurso /documents/{{id}}/summary creado con ID: {documents_summary_id}")
                
                # Configurar métodos
                setup_method(api_id, documents_summary_id, "GET", "docpilot-document-manager", args.region, args.account_id)
                setup_cors(api_id, documents_summary_id)
    
    # Configurar rutas para generación de URL y confirmación de subida
    print("\n=== Configurando rutas para subida de documentos ===")
    
    # Recurso /generate-url
    generate_url_id = create_resource(api_id, root_id, "generate-url")
    if generate_url_id:
        print(f"Recurso /generate-url creado con ID: {generate_url_id}")
        
        # Configurar métodos
        setup_method(api_id, generate_url_id, "GET", "docpilot-generate-url", args.region, args.account_id)
        setup_cors(api_id, generate_url_id)
    
    # Recurso /confirm-upload
    confirm_upload_id = create_resource(api_id, root_id, "confirm-upload")
    if confirm_upload_id:
        print(f"Recurso /confirm-upload creado con ID: {confirm_upload_id}")
        
        # Configurar métodos
        setup_method(api_id, confirm_upload_id, "POST", "docpilot-confirm-upload", args.region, args.account_id)
        setup_cors(api_id, confirm_upload_id)
    
    # Configurar rutas para tenants
    print("\n=== Configurando rutas para tenants ===")
    
    # Recurso /tenants
    tenants_id = create_resource(api_id, root_id, "tenants")
    if tenants_id:
        print(f"Recurso /tenants creado con ID: {tenants_id}")
        
        # Configurar métodos
        setup_method(api_id, tenants_id, "GET", "docpilot-tenant-management", args.region, args.account_id)
        setup_method(api_id, tenants_id, "POST", "docpilot-tenant-management", args.region, args.account_id)
        setup_cors(api_id, tenants_id)
        
        # Recurso /tenants/{tenant_id}
        tenants_id_param = create_resource(api_id, tenants_id, "{tenant_id}")
        if tenants_id_param:
            print(f"Recurso /tenants/{{tenant_id}} creado con ID: {tenants_id_param}")
            
            # Configurar métodos
            setup_method(api_id, tenants_id_param, "GET", "docpilot-tenant-management", args.region, args.account_id)
            setup_method(api_id, tenants_id_param, "PUT", "docpilot-tenant-management", args.region, args.account_id)
            setup_method(api_id, tenants_id_param, "DELETE", "docpilot-tenant-management", args.region, args.account_id)
            setup_cors(api_id, tenants_id_param)
    
    # Configurar rutas para usuarios
    print("\n=== Configurando rutas para usuarios ===")
    
    # Recurso /users
    users_id = create_resource(api_id, root_id, "users")
    if users_id:
        print(f"Recurso /users creado con ID: {users_id}")
        
        # Configurar métodos
        setup_method(api_id, users_id, "GET", "docpilot-user-management", args.region, args.account_id)
        setup_method(api_id, users_id, "POST", "docpilot-user-management", args.region, args.account_id)
        setup_cors(api_id, users_id)
        
        # Recurso /users/{user_id}
        users_id_param = create_resource(api_id, users_id, "{user_id}")
        if users_id_param:
            print(f"Recurso /users/{{user_id}} creado con ID: {users_id_param}")
            
            # Configurar métodos
            setup_method(api_id, users_id_param, "GET", "docpilot-user-management", args.region, args.account_id)
            setup_method(api_id, users_id_param, "PUT", "docpilot-user-management", args.region, args.account_id)
            setup_method(api_id, users_id_param, "DELETE", "docpilot-user-management", args.region, args.account_id)
            setup_cors(api_id, users_id_param)
    
    # Configurar ruta para estadísticas
    print("\n=== Configurando ruta para estadísticas ===")
    
    # Recurso /stats
    stats_id = create_resource(api_id, root_id, "stats")
    if stats_id:
        print(f"Recurso /stats creado con ID: {stats_id}")
        
        # Configurar métodos
        setup_method(api_id, stats_id, "GET", "docpilot-document-manager", args.region, args.account_id)
        setup_cors(api_id, stats_id)
    
    # Desplegar la API
    print("\n=== Desplegando API ===")
    deploy_api(api_id, args.stage)
    
    # Mostrar URL de la API
    api_url = f"https://{api_id}.execute-api.{args.region}.amazonaws.com/{args.stage}"
    print(f"\nAPI desplegada en: {api_url}")
    
    # Guardar URL en el archivo de configuración
    config['api_url'] = api_url
    config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"URL de la API guardada en {config_file}")

if __name__ == "__main__":
    main()