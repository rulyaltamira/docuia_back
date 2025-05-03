# docpilot-backend/scripts/test_user.py
# Script to create a new tenant with admin user in DocPilot

import json
import requests
import urllib3
import time
import argparse
import sys

def create_tenant(tenant_name, admin_email, plan="free"):
    """Create a new tenant with admin user"""
    base_url = "https://j6i9gzg4se.execute-api.eu-west-1.amazonaws.com/dev"
    
    # Data for tenant creation
    data = {
        "name": tenant_name,
        "plan": plan,
        "admin_email": admin_email,
        "industry": "Technology",
        "company_size": "1-10",
        "country": "Spain"
    }
    
    # Escribir logs a un archivo
    with open("tenant_creation_log.txt", "w") as f:
        f.write(f"Creating tenant {tenant_name} with admin {admin_email}...\n")
        f.write(f"Datos a enviar: {json.dumps(data, indent=2)}\n")
        
        # Step 1: Create tenant using urllib3 directly
        try:
            http = urllib3.PoolManager()
            url = f"{base_url}/tenants/onboard"
            f.write(f"URL: {url}\n")
            print(f"Sending request to: {url}")
            
            encoded_data = json.dumps(data).encode('utf-8')
            response = http.request(
                'POST',
                url,
                body=encoded_data,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            )
            
            status = response.status
            response_data = response.data.decode('utf-8')
            
            f.write(f"Status Code: {status}\n")
            f.write(f"Response Text: {response_data}\n")
            f.write(f"Request Headers: {response.request.headers}\n")
            
            # Verificar si hay respuesta antes de continuar
            try:
                if 200 <= status < 300:
                    tenant_data = json.loads(response_data)
                    f.write(f"Respuesta JSON: {json.dumps(tenant_data, indent=2)}\n")
                    tenant_id = tenant_data.get("tenant_id")
                else:
                    f.write(f"Error: Status code {status}\n")
                    print(f"Error: Status code {status}")
                    return None
            except Exception as e:
                f.write(f"Error procesando respuesta: {str(e)}\n")
                print(f"Error procesando respuesta: {str(e)}")
                return None

            if not tenant_id:
                print(f"Error: No tenant_id returned")
                return None
            
            print(f"Tenant created successfully: {tenant_id}")
            
            # Wait for admin creation
            time.sleep(2)
            
            return {
                'tenant_id': tenant_id,
                'admin_email': admin_email
            }
        except Exception as e:
            print(f"Error creating tenant: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Create a new DocPilot tenant.')
    parser.add_argument('--name', required=True, help='Tenant name')
    parser.add_argument('--email', required=True, help='Admin email')
    parser.add_argument('--plan', default='free', choices=['free', 'basic', 'premium', 'enterprise'], help='Subscription plan')
    
    args = parser.parse_args()
    
    result = create_tenant(args.name, args.email, args.plan)
    if result:
        print(f"Tenant created: {result['tenant_id']}")
    else:
        print("Tenant creation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main() 