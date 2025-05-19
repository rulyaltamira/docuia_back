import requests
import json
import os
import argparse

# --- Configuración ---
API_BASE_URL = os.environ.get("API_BASE_URL", "https://v8h46pq99j.execute-api.eu-west-1.amazonaws.com/dev")
# ADMIN_AUTH_TOKEN ya no es necesario para este flujo.

# --- Funciones de Ayuda ---
def print_response(response):
    """Imprime la respuesta de la API de forma legible."""
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response JSON: {json.dumps(response.json(), indent=2, ensure_ascii=False)}")
    except json.JSONDecodeError:
        print(f"Response Text: {response.text}")
    print("---")

def onboard_new_tenant_and_user(api_base_url, new_user_email, tenant_name, plan_id, onboarding_details=None):
    """
    Llama al endpoint de onboarding para crear un nuevo tenant y su primer usuario.
    Se asume que esta acción desencadena un email de verificación.
    """
    url = f"{api_base_url}/tenants/onboard" 
    
    # Payload base, puedes necesitar ajustar estos campos según tu API
    payload = {
        "name": tenant_name,
        "plan": plan_id, # Asumiendo que el nombre del tenant se pasa como 'company_name'
        "admin_email": new_user_email
        # Podrías necesitar un nombre de usuario explícito si es diferente del email
        # "user_name": new_user_email.split('@')[0] 
    }
    if onboarding_details: # Permite añadir más detalles específicos del onboarding
        payload.update(onboarding_details)

    print(f"Intentando onboarding para el usuario: {new_user_email} en un nuevo tenant: {tenant_name} con plan: {plan_id}...")
    print(f"POST {url}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    print("Headers: No se envía token de autorización para este endpoint público.")

    try:
        response = requests.post(url, json=payload) # No se pasan headers de autenticación
        print_response(response)
        if response.status_code // 100 == 2: # 2xx status codes
            print(f"Solicitud de onboarding para {new_user_email} y tenant {tenant_name} enviada.")
            print(f"Por favor, revisa la bandeja de entrada de {new_user_email} para el correo de verificación.")
            print("Deberás extraer el CÓDIGO DE CONFIRMACIÓN y el USER_ID (si es diferente del email o de lo que devuelva esta API) del enlace/correo.")
            
            # La respuesta del onboarding podría contener el user_id o un token de proceso
            # Esta parte es especulativa y depende de cómo tu API /tenants/onboard responda.
            try:
                response_data = response.json()
                user_id_from_response = response_data.get("user_id")
                if not user_id_from_response:
                    user_id_from_response = response_data.get("sub")
                if not user_id_from_response:
                    # Si el onboarding no devuelve un user_id directamente, 
                    # el user_id para la verificación podría ser el email mismo,
                    # o necesitarse de otra fuente (ej. el email de verificación)
                    print("ADVERTENCIA: El user_id no se encontró en la respuesta de onboarding. Se usará el email para la verificación, lo cual podría no ser correcto.")
                    return new_user_email 
                return user_id_from_response
            except Exception as e:
                print(f"Nota: No se pudo extraer user_id de la respuesta de onboarding (Error: {e}). Se usará el email como user_id para la verificación, ajústalo si es necesario.")
                return new_user_email
        else:
            print("Error en la solicitud de onboarding.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error en la solicitud de onboarding: {e}")
        return None

def verify_user_email(api_base_url, user_id_to_verify, confirmation_code):
    """
    Llama al endpoint para verificar el email de un usuario usando el código de confirmación.
    """
    url = f"{api_base_url}/tenants/verify-email"
    params = {
        "user_id": user_id_to_verify, 
        "token": confirmation_code    
    }
    
    print(f"Intentando verificar email para user_id: {user_id_to_verify} con el código: {confirmation_code}...")
    print(f"GET {url}")
    print(f"Query Params: {params}")

    try:
        response = requests.get(url, params=params)
        print_response(response)
        if response.status_code == 200:
            print(f"Email para {user_id_to_verify} verificado exitosamente.")
        else:
            print(f"Error al verificar el email para {user_id_to_verify}.")
    except requests.exceptions.RequestException as e:
        print(f"Error en la solicitud de verificación de email: {e}")

# --- Flujo Principal de Simulación ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulación de Alta de Nuevo Tenant y Usuario Admin.")
    parser.add_argument("--email", required=True, help="Email del primer usuario/admin para el nuevo tenant.")
    parser.add_argument("--name", required=True, help="Nombre deseado para el nuevo tenant/empresa.")
    parser.add_argument("--plan", required=True, help="ID del plan para el nuevo tenant (ej: free, premium).")
    
    args = parser.parse_args()

    NEW_USER_EMAIL = args.email
    TENANT_NAME = args.name
    PLAN_ID = args.plan

    print("--- Simulación de Alta de Nuevo Tenant y Usuario Admin ---")
    print(f"Email del primer usuario: {NEW_USER_EMAIL}")
    print(f"Nombre del nuevo Tenant/Empresa: {TENANT_NAME}")
    print(f"Plan seleccionado: {PLAN_ID}")

    # Aquí podrías añadir campos adicionales para el payload de /tenants/onboard si son necesarios
    # y no se pasan por argumentos. Por ejemplo:
    # onboarding_extra_details = {"user_full_name": "Ruly Altamirano"}
    onboarding_extra_details = {} 

    if not all([NEW_USER_EMAIL, TENANT_NAME, PLAN_ID]):
        # Esta comprobación es redundante si los args son `required=True`
        print("Faltan datos (email, nombre de tenant, plan). Saliendo.")
    else:
        print(f"Paso 1: Solicitud de Onboarding para Nuevo Tenant y Usuario ({NEW_USER_EMAIL} en {TENANT_NAME})")
        # user_id_for_verification es el ID que se usará en el endpoint de verificación.
        # Podría ser el email, un ID de Cognito (sub), o un ID específico de tu sistema.
        # La función onboard_new_tenant_and_user intenta obtenerlo de la respuesta.
        user_id_for_verification = onboard_new_tenant_and_user(API_BASE_URL, NEW_USER_EMAIL, TENANT_NAME, PLAN_ID, onboarding_extra_details)

        if user_id_for_verification:
            print(f"USER_ID para la verificación (puede ser el email o un ID de la respuesta): {user_id_for_verification}")
            confirmation_code = input("Introduce el CÓDIGO DE CONFIRMACIÓN obtenido del email de verificación: ")
            
            if confirmation_code:
                print("Paso 2: Verificación del Email")
                verify_user_email(API_BASE_URL, user_id_for_verification, confirmation_code)
            else:
                print("No se introdujo código de confirmación. Finalizando simulación.")
        else:
            print("La solicitud de onboarding falló o no se pudo determinar el ID del usuario para la verificación. Finalizando simulación.")
            
    print("--- Simulación Finalizada ---") 