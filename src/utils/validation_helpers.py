"""
Utilidades para validación de datos de entrada.
"""
import logging
# Asumimos que create_error_response está en response_helpers y se importará donde se use validate_required_fields
# from .response_helpers import create_error_response 

logger = logging.getLogger()

def validate_required_fields(data_dict, required_fields, decimal_encoder_cls=None):
    """
    Valida que todos los campos requeridos estén presentes en el diccionario de datos.

    Args:
        data_dict (dict): Diccionario con los datos a validar.
        required_fields (list): Lista de strings con los nombres de los campos requeridos.
        decimal_encoder_cls: Clase codificadora JSON para el error (opcional).

    Returns:
        dict: None si todos los campos están presentes.
              Una respuesta de error HTTP (diccionario) si faltan campos.
    """
    if not isinstance(data_dict, dict):
        logger.error("validate_required_fields recibió data_dict que no es un diccionario.")
        # Necesitaríamos importar create_error_response aquí para usarlo, o manejar el error de otra forma.
        # Por ahora, devolvemos un mensaje simple, asumiendo que el llamador lo convertirá en respuesta HTTP.
        return {"error_message": "Datos de entrada inválidos para validación."}
        
    missing_fields = [field for field in required_fields if not data_dict.get(field)]
    
    if missing_fields:
        msg = f"Faltan campos obligatorios: {', '.join(missing_fields)}"
        logger.error(msg)
        # Para usar create_error_response aquí, necesitaría ser importado.
        # Devolveremos un diccionario simple que el llamador puede usar para construir la respuesta.
        return {"error_message": msg, "error_code": "MISSING_FIELDS", "status_code": 400}
        # Idealmente: return create_error_response(400, msg, error_code="MISSING_FIELDS", decimal_encoder_cls=decimal_encoder_cls)
    
    return None # Sin errores

def validate_plan_or_error(plan_name, available_plans, decimal_encoder_cls=None):
    """
    Valida que un plan exista en la lista de planes disponibles.

    Args:
        plan_name (str): Nombre del plan a validar.
        available_plans (dict): Diccionario de planes disponibles (ej. TENANT_PLANS).
        decimal_encoder_cls: Clase codificadora JSON para el error (opcional).

    Returns:
        dict: None si el plan es válido.
              Una respuesta de error HTTP (diccionario) si el plan no es válido.
    """
    if plan_name not in available_plans:
        msg = f'Plan no válido. Opciones disponibles: {", ".join(available_plans.keys())}'
        logger.error(f"Plan no válido: {plan_name}")
        # Devolveremos un diccionario simple que el llamador puede usar para construir la respuesta.
        return {"error_message": msg, "error_code": "INVALID_PLAN", "status_code": 400}
        # Idealmente: return create_error_response(400, msg, error_code="INVALID_PLAN", decimal_encoder_cls=decimal_encoder_cls)

    return None # Sin errores 