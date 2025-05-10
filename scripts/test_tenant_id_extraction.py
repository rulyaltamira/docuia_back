#!/usr/bin/env python3
# scripts/test_tenant_id_extraction.py
# Script para probar la extracción de tenant_id en diferentes escenarios

import sys
import os
import json
from colorama import init, Fore, Style

# Para importar módulos desde src, agrega el directorio raíz al path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.auth_utils import extract_tenant_id

# Inicializar colorama para colores en la terminal
init()

def success(message):
    """Muestra un mensaje de éxito en verde"""
    print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def warning(message):
    """Muestra un mensaje de advertencia en amarillo"""
    print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

def error(message):
    """Muestra un mensaje de error en rojo"""
    print(f"{Fore.RED}{message}{Style.RESET_ALL}")

def info(message):
    """Muestra un mensaje informativo en azul"""
    print(f"{Fore.CYAN}{message}{Style.RESET_ALL}")

def create_test_event(tenant_id=None, include_in_token=False, include_in_query=False, include_in_header=False):
    """
    Crea un evento de prueba con tenant_id en diferentes lugares
    
    Args:
        tenant_id (str): ID del tenant a incluir
        include_in_token (bool): Incluir tenant_id en el token
        include_in_query (bool): Incluir tenant_id en query parameters
        include_in_header (bool): Incluir tenant_id en headers
        
    Returns:
        dict: Evento de prueba en formato API Gateway
    """
    event = {
        "requestContext": {
            "authorizer": {
                "claims": {}
            }
        },
        "queryStringParameters": {},
        "headers": {}
    }
    
    if tenant_id:
        if include_in_token:
            event["requestContext"]["authorizer"]["claims"]["custom:tenant_id"] = tenant_id
        
        if include_in_query:
            event["queryStringParameters"]["tenant_id"] = tenant_id
        
        if include_in_header:
            event["headers"]["x-tenant-id"] = tenant_id
    
    return event

def test_extract_tenant_id():
    """Realiza pruebas de extracción de tenant_id en diferentes escenarios"""
    tenant_id = "test-tenant-123"
    
    # Lista de escenarios de prueba
    scenarios = [
        {
            "name": "Token JWT",
            "event": create_test_event(tenant_id, include_in_token=True),
            "expected": tenant_id
        },
        {
            "name": "Query Parameters",
            "event": create_test_event(tenant_id, include_in_query=True),
            "expected": tenant_id
        },
        {
            "name": "Headers",
            "event": create_test_event(tenant_id, include_in_header=True),
            "expected": tenant_id
        },
        {
            "name": "Token JWT (prioritario)",
            "event": create_test_event(
                tenant_id, 
                include_in_token=True, 
                include_in_query=True, 
                include_in_header=True
            ),
            "expected": tenant_id
        },
        {
            "name": "Query sobre Header",
            "event": create_test_event(
                tenant_id,
                include_in_query=True,
                include_in_header=True
            ),
            "expected": tenant_id
        },
        {
            "name": "Sin tenant_id",
            "event": create_test_event(),
            "expected": None
        }
    ]
    
    # Ejecutar pruebas
    info("\n=== Pruebas de extracción de tenant_id ===\n")
    
    for i, scenario in enumerate(scenarios, 1):
        print(f"Prueba {i}: {scenario['name']}")
        print(f"Evento: {json.dumps(scenario['event'], indent=2)}")
        
        result = extract_tenant_id(scenario['event'])
        expected = scenario['expected']
        
        print(f"Resultado: {result}")
        print(f"Esperado: {expected}")
        
        if result == expected:
            success("✅ ÉXITO: tenant_id extraído correctamente")
        else:
            error("❌ ERROR: tenant_id no extraído correctamente")
        
        print("\n" + "-" * 50 + "\n")
    
    info("Pruebas completadas.")

if __name__ == "__main__":
    test_extract_tenant_id() 