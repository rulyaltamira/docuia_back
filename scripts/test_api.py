# docpilot-backend/scripts/test_api.py
# Script para probar la API de DocPilot

import requests
import json
import os
import argparse
import uuid
import time

def load_config():
    """Carga la configuración del proyecto"""
    config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except:
        print(f"Error: No se pudo cargar la configuración desde {config_file}")
        return {}

def test_create_tenant(api_url):
    """Prueba la creación de un tenant"""
    print("\n=== Prueba: Crear tenant ===")
    
    tenant_name = f"Test Tenant {uuid.uuid4().hex[:8]}"
    
    data = {
        "name": tenant_name,
        "plan": "free",
        "settings": {
            "email_notifications": True
        }
    }
    
    url = f"{api_url}/tenants"
    
    try:
        response = requests.post(url, json=data)
        
        if response.status_code == 201:
            print(f"✅ Tenant creado correctamente: {tenant_name}")
            tenant_data = response.json()
            return tenant_data
        else:
            print(f"❌ Error creando tenant: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"❌ Error en la solicitud: {str(e)}")
        return None

def test_create_user(api_url, tenant_id):
    """Prueba la creación de un usuario"""
    print("\n=== Prueba: Crear usuario ===")
    
    email = f"test.user.{uuid.uuid4().hex[:8]}@example.com"
    
    data = {
        "email": email,
        "tenant_id": tenant_id,
        "role": "user"
    }
    
    url = f"{api_url}/users"
    
    try:
        response = requests.post(url, json=data)
        
        if response.status_code == 201:
            print(f"✅ Usuario creado correctamente: {email}")
            user_data = response.json()
            return user_data
        else:
            print(f"❌ Error creando usuario: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"❌ Error en la solicitud: {str(e)}")
        return None

def test_generate_url(api_url, tenant_id):
    """Prueba la generación de URL para subir un documento"""
    print("\n=== Prueba: Generar URL para subir documento ===")
    
    params = {
        "filename": f"test_document_{uuid.uuid4().hex[:8]}.pdf",
        "contentType": "application/pdf",
        "description": "Documento de prueba",
        "tenant_id": tenant_id
    }
    
    url = f"{api_url}/generate-url"
    
    try:
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            print(f"✅ URL generada correctamente")
            url_data = response.json()
            return url_data
        else:
            print(f"❌ Error generando URL: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"❌ Error en la solicitud: {str(e)}")
        return None

def test_list_documents(api_url, tenant_id):
    """Prueba el listado de documentos"""
    print("\n=== Prueba: Listar documentos ===")
    
    params = {
        "tenant_id": tenant_id
    }
    
    url = f"{api_url}/documents"
    
    try:
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            print(f"✅ Documentos listados correctamente")
            documents_data = response.json()
            return documents_data
        else:
            print(f"❌ Error listando documentos: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"❌ Error en la solicitud: {str(e)}")
        return None

def test_get_stats(api_url, tenant_id):
    """Prueba la obtención de estadísticas"""
    print("\n=== Prueba: Obtener estadísticas ===")
    
    params = {
        "tenant_id": tenant_id
    }
    
    url = f"{api_url}/stats"
    
    try:
        response = requests.get(url, params=params)
        
        if response.status_code == 200:
            print(f"✅ Estadísticas obtenidas correctamente")
            stats_data = response.json()
            return stats_data
        else:
            print(f"❌ Error obteniendo estadísticas: {response.status_code}")
            print(response.text)
            return None
    except Exception as e:
        print(f"❌ Error en la solicitud: {str(e)}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Prueba la API de DocPilot')
    parser.add_argument('--api-url', help='URL base de la API')
    parser.add_argument('--tenant-id', help='ID del tenant existente para pruebas')
    
    args = parser.parse_args()
    
    # Cargar configuración
    config = load_config()
    
    # Obtener URL de la API
    api_url = args.api_url or config.get('api_url')
    
    if not api_url:
        print("Error: No se especificó URL de la API y no se pudo cargar de config.json")
        return
    
    print(f"Probando API en: {api_url}")
    
    # Crear tenant si no se especificó uno existente
    tenant_id = args.tenant_id
    tenant_data = None
    
    if not tenant_id:
        tenant_data = test_create_tenant(api_url)
        if tenant_data:
            tenant_id = tenant_data.get("tenant_id")
    
    if not tenant_id:
        print("Error: No se pudo obtener ID de tenant para las pruebas")
        return
    
    # Crear usuario
    user_data = test_create_user(api_url, tenant_id)
    
    # Generar URL para subir documento
    url_data = test_generate_url(api_url, tenant_id)
    
    # Esperar unos segundos
    print("Esperando 2 segundos...")
    time.sleep(2)
    
    # Listar documentos
    documents_data = test_list_documents(api_url, tenant_id)
    
    # Obtener estadísticas
    stats_data = test_get_stats(api_url, tenant_id)
    
    print("\n=== Resumen de pruebas ===")
    
    if tenant_data or tenant_id:
        print(f"✅ Tenant: {tenant_id}")
    else:
        print("❌ No se pudo crear/usar tenant")
    
    if user_data:
        print(f"✅ Usuario: {user_data.get('email')}")
    else:
        print("❌ No se pudo crear usuario")
    
    if url_data:
        print(f"✅ URL generada para documento: {url_data.get('file_id')}")
    else:
        print("❌ No se pudo generar URL")
    
    if documents_data:
        print(f"✅ Documentos listados: {len(documents_data.get('documents', []))}")
    else:
        print("❌ No se pudieron listar documentos")
    
    if stats_data:
        print(f"✅ Estadísticas obtenidas")
    else:
        print("❌ No se pudieron obtener estadísticas")

if __name__ == "__main__":
    main()