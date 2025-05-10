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