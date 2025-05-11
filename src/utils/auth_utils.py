"""
Utilidades para autenticación y autorización

Para que la extracción del tenant_id funcione correctamente, se deben cumplir
los siguientes requisitos:

1. En Cognito User Pool:
   - El atributo personalizado "custom:tenant_id" debe estar configurado
   - El atributo debe incluirse en los tokens ID y Access
   - El atributo debe estar marcado como "readable" para la app client

2. En el proceso de creación de usuario:
   - El atributo "custom:tenant_id" debe asignarse al crear usuarios
   - Verificar que las funciones como admin_create_user incluyan este atributo

3. En el frontend:
   - Configurar la librería Amplify para propagar el token en Authorization header
   - No es necesario enviar tenant_id como parámetro si se obtiene del token
"""

from src.utils.response_helpers import create_error_response

def extract_tenant_id(event):
    """
    Extrae el tenant_id de un evento de API Gateway.
    Busca en el siguiente orden:
    1. Token JWT (claims cognito)
    2. Query parameters
    3. Headers personalizados
    
    Args:
        event (dict): Evento de API Gateway
        
    Returns:
        str: tenant_id o None si no se encuentra
    """
    # Intentar obtener del token JWT (authorizer claims)
    claims = event.get("requestContext", {}).get("authorizer", {}).get("claims", {})
    tenant_id = claims.get("custom:tenant_id")

    # Si no está en el token, buscar en query parameters
    if not tenant_id:
        tenant_id = (event.get("queryStringParameters") or {}).get("tenant_id")

    # Si tampoco está en query params, buscar en headers
    if not tenant_id:
        tenant_id = (event.get("headers") or {}).get("x-tenant-id")
        
    return tenant_id 

def get_tenant_id_or_error(event, decimal_encoder_cls=None):
    """
    Extrae el tenant_id usando extract_tenant_id y devuelve un error HTTP si no se encuentra.

    Args:
        event (dict): Evento de API Gateway.
        decimal_encoder_cls: Clase para serializar Decimales a JSON (opcional para el error).

    Returns:
        tuple: (tenant_id, None) si es exitoso.
               (None, error_response_dict) si tenant_id no se encuentra.
    """
    tenant_id = extract_tenant_id(event)
    if not tenant_id:
        # No es necesario pasar el logger aquí si create_error_response no lo usa directamente.
        # El logging de "No se pudo determinar tenant_id" debería hacerse en el handler si se desea antes de llamar a esta función,
        # o esta función podría tomar un logger como parámetro.
        return None, create_error_response(
            status_code=400, 
            message='No se pudo determinar el tenant_id. Asegúrese de incluirlo en el token, query params o header x-tenant-id.',
            error_code="TENANT_ID_MISSING",
            decimal_encoder_cls=decimal_encoder_cls
        )
    return tenant_id, None 