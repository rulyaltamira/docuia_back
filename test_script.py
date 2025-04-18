import requests
import json
import time
import argparse

API_BASE_URL = "https://9qobjsxd0g.execute-api.eu-west-1.amazonaws.com/dev"

def main():
    parser = argparse.ArgumentParser(description='Prueba la API de DocPilot')
    parser.add_argument('--tenant-id', required=True, help='ID del tenant a usar')
    args = parser.parse_args()
    
    tenant_id = args.tenant_id
    print(f"Usando tenant_id: {tenant_id}")
    
    # Probar generación de URL para upload
    test_generate_url(tenant_id)
    
    # Listar documentos
    test_list_documents(tenant_id)
    
    # Obtener estadísticas
    test_get_stats(tenant_id)

def test_generate_url(tenant_id):
    print("\n--> Generando URL para subida...")
    url = f"{API_BASE_URL}/generate-url"
    params = {
        "filename": "test.pdf",
        "contentType": "application/pdf",
        "tenant_id": tenant_id,
        "description": "Prueba simple"
    }
    
    response = requests.get(url, params=params)
    print(f"Status Code: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def test_list_documents(tenant_id):
    print("\n--> Listando documentos...")
    url = f"{API_BASE_URL}/documents"
    params = {
        "tenant_id": tenant_id
    }
    
    response = requests.get(url, params=params)
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        documents = data.get("documents", [])
        print(f"Documentos encontrados: {len(documents)}")
        
        if documents:
            print("\nPrimer documento:")
            print(json.dumps(documents[0], indent=2))

def test_get_stats(tenant_id):
    print("\n--> Obteniendo estadísticas...")
    url = f"{API_BASE_URL}/stats"
    params = {
        "tenant_id": tenant_id
    }
    
    response = requests.get(url, params=params)
    print(f"Status Code: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

if __name__ == "__main__":
    main()