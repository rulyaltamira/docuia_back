# docpilot-backend/scripts/create_tenant.py
# Script to create a new tenant with admin user in DocPilot

import json
import requests
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
        
        # Step 1: Create tenant
        try:
            # Enfoque básico que debería funcionar con API Gateway
            url = f"{base_url}/tenants/onboard"
            f.write(f"URL: {url}\n")
            print(f"Sending request to: {url}")
            
            # Usar requests.post con json parameter (en lugar de data)
            # Esto asegura que se serialice correctamente y se establezcan los headers adecuados
            response = requests.post(
                url, 
                json=data,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            )
            
            f.write(f"Status Code: {response.status_code}\n")
            f.write(f"Response Text: {response.text}\n")
            f.write(f"Request Headers: {response.request.headers}\n")
            f.write(f"Request Body: {response.request.body}\n")
            
            # Verificar si hay respuesta antes de continuar
            try:
                response.raise_for_status()
                response_json = response.json()
                f.write(f"Respuesta JSON: {json.dumps(response_json, indent=2)}\n")
                tenant_data = response_json
                tenant_id = tenant_data.get("tenant_id")
            except Exception as e:
                f.write(f"Error procesando respuesta: {str(e)}\n")
                print(f"Error procesando respuesta: {str(e)}")
                return None
            
            if not tenant_id:
                print("Error: No tenant ID returned")
                sys.exit(1)
            
            print(f"✅ Tenant created successfully with ID: {tenant_id}")
            
            # Step 2: Check onboarding status
            max_attempts = 5
            attempts = 0
            completed = False
            
            print("\nChecking onboarding status...")
            while not completed and attempts < max_attempts:
                attempts += 1
                status_response = requests.get(
                    f"{base_url}/tenants/onboard/status?tenant_id={tenant_id}"
                )
                status_data = status_response.json()
                
                completion = status_data.get("onboarding", {}).get("completion_percentage", 0)
                current_step = status_data.get("onboarding", {}).get("current_step", "unknown")
                
                print(f"Progress: {completion}% - Current step: {current_step}")
                
                if completion == 100:
                    completed = True
                    print("✅ Onboarding process completed")
                else:
                    print("Waiting 3 seconds to check again...")
                    time.sleep(3)
            
            # Step 3: Verify admin user was created
            print("\nVerifying admin user...")
            users_response = requests.get(
                f"{base_url}/users?tenant_id={tenant_id}"
            )
            users_data = users_response.json()
            
            admin_found = False
            for user in users_data.get("users", []):
                if user.get("email") == admin_email:
                    admin_found = True
                    print(f"✅ Admin user created successfully")
                    print(f"Email: {user.get('email')}")
                    print(f"Role: {user.get('role')}")
                    print(f"User ID: {user.get('user_id')}")
                    break
            
            if not admin_found:
                print("\nAdmin user not found. Creating manually...")
                admin_data = {
                    "tenant_id": tenant_id,
                    "email": admin_email
                }
                
                admin_response = requests.post(
                    f"{base_url}/tenants/onboard/admin", 
                    json=admin_data,
                    headers={"Content-Type": "application/json"}
                )
                
                if admin_response.status_code == 200:
                    print("✅ Admin user created manually")
                    admin_data = admin_response.json()
                    print(f"User ID: {admin_data.get('user_id')}")
                else:
                    print(f"❌ Error creating admin: {admin_response.text}")
            
            # Print final instructions
            print("\n========== LOGIN INSTRUCTIONS ==========")
            print(f"1. Check email {admin_email} for temporary password")
            print("2. Visit: https://app.docpilot.com to login")
            print("3. Use your email and the temporary password")
            print("4. You'll be asked to change your password on first login")
            print("========================================")
            
            return tenant_id
        
        except requests.exceptions.RequestException as e:
            print(f"❌ Error: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response: {e.response.text}")
            return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a new tenant with admin user')
    parser.add_argument('--name', required=True, help='Tenant name')
    parser.add_argument('--email', required=True, help='Admin email')
    parser.add_argument('--plan', default='free', choices=['free', 'basic', 'premium', 'enterprise'],
                       help='Subscription plan (default: free)')
    
    args = parser.parse_args()
    create_tenant(args.name, args.email, args.plan)