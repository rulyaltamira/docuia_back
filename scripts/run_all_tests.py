# docpilot-backend/run_all_tests.py
"""
Script para ejecutar todas las pruebas de integración.

Uso: python run_all_tests.py --tenant_id TENANT_ID [--api_url API_URL]
"""

import argparse
import subprocess
import logging
import sys
import os
import time
from datetime import datetime

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(f"all_tests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

# Colores para la terminal
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log_section(message):
    logger.info(f"\n{Colors.HEADER}{Colors.BOLD}=== {message} ==={Colors.ENDC}")

def run_test_script(script_name, tenant_id, api_url):
    """Ejecuta un script de prueba y devuelve el resultado"""
    log_section(f"EJECUTANDO {script_name.upper()}")
    
    try:
        # Ejecutar script de prueba
        command = [sys.executable, script_name, "--tenant_id", tenant_id, "--api_url", api_url]
        logger.info(f"Ejecutando: {' '.join(command)}")
        
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Mostrar la salida
        for line in result.stdout.splitlines():
            logger.info(line)
        
        # Mostrar errores si los hay
        if result.stderr:
            for line in result.stderr.splitlines():
                logger.error(line)
        
        success = result.returncode == 0
        
        if success:
            logger.info(f"{Colors.OKGREEN}✓ {script_name} completado exitosamente.{Colors.ENDC}")
        else:
            logger.error(f"{Colors.FAIL}✗ {script_name} falló con código {result.returncode}.{Colors.ENDC}")
        
        return success
        
    except Exception as e:
        logger.error(f"Error ejecutando {script_name}: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Ejecuta todas las pruebas de integración')
    parser.add_argument('--tenant_id', required=True, help='ID del tenant para las pruebas')
    parser.add_argument('--api_url', default='https://49b3724c7h.execute-api.eu-west-1.amazonaws.com/dev', 
                        help='URL base de la API')
    
    args = parser.parse_args()
    
    log_section("INICIANDO PRUEBAS DE INTEGRACIÓN COMPLETAS")
    
    # Verificar que los scripts existen
    tests = [
        "test_special_chars.py",
        "test_duplicates.py"
    ]
    
    for test in tests:
        if not os.path.exists(test):
            logger.error(f"Error: El script {test} no existe en el directorio actual.")
            return
    
    # Ejecutar cada script de prueba
    results = {}
    
    for test in tests:
        results[test] = run_test_script(test, args.tenant_id, args.api_url)
        # Esperar un poco entre pruebas para evitar problemas de concurrencia
        time.sleep(5)
    
    # Mostrar resumen final
    log_section("RESUMEN FINAL DE PRUEBAS")
    
    all_passed = True
    for test, success in results.items():
        if success:
            logger.info(f"{Colors.OKGREEN}✓ {test}: ÉXITO{Colors.ENDC}")
        else:
            logger.error(f"{Colors.FAIL}✗ {test}: FALLO{Colors.ENDC}")
            all_passed = False
    
    if all_passed:
        logger.info(f"\n{Colors.OKGREEN}¡TODAS LAS PRUEBAS HAN SIDO EXITOSAS!{Colors.ENDC}")
    else:
        logger.error(f"\n{Colors.FAIL}ALGUNAS PRUEBAS HAN FALLADO. Revisa los logs para más detalles.{Colors.ENDC}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())