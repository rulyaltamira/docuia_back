#!/usr/bin/env python3
# scripts/test_api_flow.py
# Script para simular flujo completo de APIs real entre frontend y backend

import requests
import json
import argparse
import time
import webbrowser
import sys
from urllib.parse import urlparse, parse_qs

# Configuración
API_URL = "https://04rx323x27.execute-api.eu-west-1.amazonaws.com/dev"
VERIFY_URL = "https://verify.docpilot.link"

# Colores para la salida
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"

def log_success(message):
    print(f"{GREEN}✅ {message}{RESET}")

def log_error(message):
    print(f"{RED}❌ {message}{RESET}")

def log_info(message):
    print(f"{BLUE}ℹ️ {message}{RESET}")

def log_warning(message):
    print(f"{YELLOW}⚠️ {message}{RESET}")

def log_step(step_num, description):
    print(f"\n{BOLD}{YELLOW}Paso {step_num}: {description}{RESET}\n")

def make_api_call(method, endpoint, data=None, headers=None, params=None, auth_token=None):
    """
    Realiza una llamada a la API y devuelve la respuesta
    """
    url = f"{API_URL}{endpoint}"
    if not headers:
        headers = {}
    
    headers["Content-Type"] = "application/json"
    
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    
    log_info(f"Llamando a: {method} {url}")
    if params:
        log_info(f"Parámetros: {json.dumps(params)}")
    if data:
        log_info(f"Datos: {json.dumps(data)}")
    
    response = None
    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, params=params)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data, params=params)
        elif method.upper() == "PUT":
            response = requests.put(url, headers=headers, json=data, params=params)
        elif method.upper() == "DELETE":
            response = requests.delete(url, headers=headers, params=params)
        else:
            log_error(f"Método HTTP no soportado: {method}")
            return None
        
        # Intentar parsear respuesta como JSON
        status_code = response.status_code
        try:
            response_json = response.json()
            log_info(f"Respuesta ({status_code}): {json.dumps(response_json, indent=2)}")
            return response_json, status_code
        except:
            log_info(f"Respuesta ({status_code}): {response.text[:100]}...")
            return response.text, status_code
            
    except Exception as e:
        log_error(f"Error en la llamada API: {str(e)}")
        return None, 500

def create_tenant(name, admin_email, plan="free"):
    """
    Crea un nuevo tenant a través de la API
    """
    log_step(1, f"Creando tenant: {name}")
    
    # Preparar datos
    data = {
        "name": name,
        "plan": plan,
        "admin_email": admin_email,
        "industry": "Technology",
        "company_size": "1-10",
        "country": "Spain"
    }
    
    # Llamar a API
    response_data, status_code = make_api_call("POST", "/tenants/onboard", data=data)
    
    if status_code not in [200, 201]:
        log_error(f"Error creando tenant: {status_code}")
        sys.exit(1)
    
    tenant_id = response_data.get("tenant_id")
    if not tenant_id:
        log_error("No se pudo obtener tenant_id de la respuesta")
        sys.exit(1)
    
    log_success(f"Tenant creado: {tenant_id}")
    return tenant_id, response_data

def get_user_token(tenant_id, email):
    """
    Esto simula lo que haría un frontend - en un caso real,
    el frontend recibiría el token de verificación por correo electrónico
    y el usuario haría clic en el enlace.
    
    Aquí, forzamos a obtener el token consultando DynamoDB directamente
    """
    log_step(2, f"Obteniendo token de verificación para {email}")
    
    # En un caso real, el usuario recibiría esto por correo
    # Pero para la prueba, consultamos directamente
    import boto3
    dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
    users_table = dynamodb.Table('docpilot-newsystem-v2-users-dev')
    
    # Buscar usuario
    response = users_table.scan(
        FilterExpression="tenant_id = :t AND email = :e",
        ExpressionAttributeValues={
            ":t": tenant_id,
            ":e": email
        }
    )
    
    users = response.get('Items', [])
    
    if not users:
        log_error(f"No se encontró usuario con email {email} en tenant {tenant_id}")
        sys.exit(1)
    
    user = users[0]
    verification_token = user.get('verification_token')
    user_id = user.get('user_id')
    
    if not verification_token:
        log_error("No se encontró token de verificación para el usuario")
        sys.exit(1)
    
    log_success(f"Token de verificación obtenido: {verification_token[:10]}...")
    log_info(f"ID de usuario: {user_id}")
    
    return verification_token, user_id

def verify_email(token, tenant_id):
    """
    Verifica el correo electrónico
    """
    log_step(3, f"Verificando email para tenant {tenant_id}")
    
    # En un caso real, el usuario haría clic en un enlace en su correo
    # Aquí simulamos haciendo una solicitud directa
    url = f"{API_URL}/tenants/verify-email?token={token}&tenant={tenant_id}"
    
    log_info(f"Verificando email con URL: {url}")
    
    try:
        # Hacer la solicitud directamente
        response = requests.get(url)
        status_code = response.status_code
        
        log_info(f"Status code: {status_code}")
        
        if status_code in [200, 302]:
            if status_code == 302:
                redirect_url = response.headers.get('Location')
                log_info(f"Redirección a: {redirect_url}")
            
            log_success("Verificación de email exitosa")
            
            # Esperar a que la verificación se procese
            log_info("Esperando 2 segundos para que se procesen los cambios...")
            time.sleep(2)
            
            # Abre el enlace en el navegador si el usuario lo desea
            if input("¿Desea abrir el enlace de verificación en el navegador? (s/n): ").lower() == 's':
                webbrowser.open(url)
                
            return True
        else:
            try:
                error_data = response.json()
                log_error(f"Error en verificación: {error_data.get('message', 'Error desconocido')}")
            except:
                log_error(f"Error en verificación: {response.text}")
            return False
            
    except Exception as e:
        log_error(f"Error verificando email: {str(e)}")
        return False

def check_my_permissions(user_id, tenant_id, auth_token):
    """
    Comprueba los permisos del usuario
    """
    log_step(4, f"Comprobando permisos para usuario {user_id}")
    
    # Headers
    headers = {
        "x-user-id": user_id,
        "x-tenant-id": tenant_id
    }
    
    # Llamar a API
    response_data, status_code = make_api_call("GET", "/my-permissions", headers=headers, auth_token=auth_token)
    
    if status_code != 200:
        log_error(f"Error obteniendo permisos: {status_code}")
        return None
    
    permissions = response_data.get("permissions", [])
    roles = response_data.get("roles", [])
    is_admin = response_data.get("is_admin", False)
    
    log_info(f"Roles asignados: {roles}")
    log_info(f"Permisos: {permissions}")
    log_info(f"¿Es administrador? {'Sí' if is_admin else 'No'}")
    
    if is_admin:
        log_success("El usuario tiene permisos de administrador")
    elif roles:
        log_success(f"El usuario tiene {len(roles)} roles asignados")
    else:
        log_warning("El usuario no tiene roles ni permisos asignados")
    
    return response_data

def test_flow(tenant_name, admin_email, plan="free", auth_token=None):
    """
    Ejecuta el flujo completo de prueba
    """
    print(f"{BOLD}{BLUE}=== INICIO DE PRUEBA DE FLUJO COMPLETO ==={RESET}")
    
    # 1. Crear tenant
    tenant_id, tenant_data = create_tenant(tenant_name, admin_email, plan)
    
    # 2. Obtener token de verificación
    token, user_id = get_user_token(tenant_id, admin_email)
    
    # 3. Verificar email
    verify_email(token, tenant_id)
    
    # 4. Verificar permisos
    # En un caso real, obtendríamos este token del proceso de login
    if not auth_token:
        # Solicitar token
        auth_token = input(f"\n{YELLOW}⚠️ Por favor, proporcione un token de autenticación válido para Cognito: {RESET}")
        
    if not auth_token:
        log_warning("No se proporcionó token de autenticación. Usando token simulado.")
        auth_token = "simulated-auth-token"
        
    permissions_data = check_my_permissions(user_id, tenant_id, auth_token)
    
    print(f"\n{BOLD}{GREEN}=== RESUMEN DE LA PRUEBA ==={RESET}")
    print(f"Tenant ID: {tenant_id}")
    print(f"User ID: {user_id}")
    print(f"¿Flujo completo exitoso? {GREEN if permissions_data else RED}{'SÍ' if permissions_data else 'NO'}{RESET}")
    
    # Si no se obtuvieron los permisos correctamente, sugerir verificación manual
    if not permissions_data or not permissions_data.get('is_admin'):
        print(f"\n{YELLOW}Para verificar manualmente los permisos, puedes usar curl o Postman:{RESET}")
        print(f"curl -H \"Authorization: Bearer YOUR_TOKEN\" -H \"x-tenant-id: {tenant_id}\" -H \"x-user-id: {user_id}\" \"{API_URL}/my-permissions\"")
    
    return tenant_id, user_id, permissions_data

def main():
    parser = argparse.ArgumentParser(description='Prueba el flujo completo de APIs como lo haría un frontend real')
    parser.add_argument('--name', default='Ereace-Test', help='Nombre del tenant')
    parser.add_argument('--email', default='ruly.altamirano@ereace.es', help='Email del administrador')
    parser.add_argument('--plan', default='free', choices=['free', 'basic', 'premium', 'enterprise'], 
                       help='Plan de suscripción (default: free)')
    parser.add_argument('--token', help='Token de autenticación de Cognito (opcional)')
    parser.add_argument('--verify-only', action='store_true', help='Solo verificar permisos existentes sin crear tenant')
    
    args = parser.parse_args()
    
    if args.verify_only:
        # Si solo queremos verificar permisos de un tenant existente
        tenant_id = args.name  # Usar el nombre como tenant_id en este caso
        if not tenant_id:
            parser.error("Se requiere --name (tenant_id) para verificar permisos")
            
        # Buscar usuario
        import boto3
        dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
        users_table = dynamodb.Table('docpilot-newsystem-v2-users-dev')
        
        # Buscar usuario
        response = users_table.scan(
            FilterExpression="tenant_id = :t AND email = :e",
            ExpressionAttributeValues={
                ":t": tenant_id,
                ":e": args.email
            }
        )
        
        users = response.get('Items', [])
        
        if not users:
            log_error(f"No se encontró usuario con email {args.email} en tenant {tenant_id}")
            sys.exit(1)
        
        user = users[0]
        user_id = user.get('user_id')
        
        log_step(4, f"Verificando permisos para usuario existente {user_id}")
        
        # Solicitar token si no se proporcionó
        auth_token = args.token
        if not auth_token:
            auth_token = input(f"{YELLOW}⚠️ Por favor, proporcione un token de autenticación válido para Cognito: {RESET}")
            
        permissions_data = check_my_permissions(user_id, tenant_id, auth_token)
        
        print(f"\n{BOLD}{GREEN}=== RESUMEN DE LA VERIFICACIÓN ==={RESET}")
        print(f"Tenant ID: {tenant_id}")
        print(f"User ID: {user_id}")
        print(f"¿Verificación exitosa? {GREEN if permissions_data else RED}{'SÍ' if permissions_data else 'NO'}{RESET}")
        
    else:
        # Ejecutar flujo de prueba completo
        test_flow(args.name, args.email, args.plan, args.token)

if __name__ == "__main__":
    main() 