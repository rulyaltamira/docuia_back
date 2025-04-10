# docpilot-backend/scripts/deploy_lambda.py
# Script para empaquetar y desplegar funciones Lambda

import os
import sys
import subprocess
import argparse
import json
import shutil
import tempfile

def run_command(command):
    """Ejecuta un comando y captura su salida"""
    print(f"Ejecutando: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode != 0:
        print(f"Error ejecutando comando: {command}")
        print(f"Error: {stderr.decode('utf-8')}")
        sys.exit(1)
    
    return stdout.decode('utf-8')

def create_deployment_package(function_dir, include_utils=True):
    """Crea un paquete de despliegue para la función Lambda"""
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Copiar archivos de la función
        function_files = [f for f in os.listdir(function_dir) if f.endswith('.py')]
        for file in function_files:
            shutil.copy(os.path.join(function_dir, file), temp_dir)
        
        # Instalar dependencias si existe requirements.txt
        req_file = os.path.join(function_dir, 'requirements.txt')
        if os.path.exists(req_file):
            cmd = f"pip install -r {req_file} --target {temp_dir} --upgrade"
            run_command(cmd)
        
        # Incluir utilidades compartidas si se solicita
        if include_utils:
            utils_dir = os.path.join(os.path.dirname(os.path.dirname(function_dir)), 'utils')
            if os.path.exists(utils_dir):
                utils_target_dir = os.path.join(temp_dir, 'utils')
                os.makedirs(utils_target_dir, exist_ok=True)
                
                for file in os.listdir(utils_dir):
                    if file.endswith('.py'):
                        shutil.copy(os.path.join(utils_dir, file), utils_target_dir)
        
        # Crear archivo ZIP
        zip_file = os.path.join(os.path.dirname(function_dir), f"{os.path.basename(function_dir)}.zip")
        
        # Eliminar ZIP existente si lo hay
        if os.path.exists(zip_file):
            os.remove(zip_file)
        
        # Crear nuevo ZIP
        current_dir = os.getcwd()
        os.chdir(temp_dir)
        run_command(f"zip -r {zip_file} .")
        os.chdir(current_dir)
        
        return zip_file
    
    finally:
        # Limpiar directorio temporal
        shutil.rmtree(temp_dir)

def deploy_lambda(function_name, zip_file, role_arn, handler='lambda_function.lambda_handler', runtime='python3.9', 
                 timeout=30, memory_size=256, environment=None, update_only=False):
    """Despliega o actualiza una función Lambda"""
    # Verificar si la función ya existe
    try:
        run_command(f"aws lambda get-function --function-name {function_name}")
        function_exists = True
    except:
        function_exists = False
    
    # Preparar variable de entorno
    env_vars = ""
    if environment:
        env_vars = f"--environment Variables='{json.dumps(environment)}'"
    
    if function_exists and update_only:
        # Actualizar código de la función
        cmd = f"aws lambda update-function-code --function-name {function_name} --zip-file fileb://{zip_file}"
        run_command(cmd)
        
        # Actualizar configuración
        cmd = f"aws lambda update-function-configuration --function-name {function_name} --handler {handler} --runtime {runtime} --timeout {timeout} --memory-size {memory_size} {env_vars}"
        run_command(cmd)
        
        print(f"Función Lambda '{function_name}' actualizada correctamente")
    elif not function_exists:
        # Crear nueva función
        cmd = f"aws lambda create-function --function-name {function_name} --zip-file fileb://{zip_file} --handler {handler} --runtime {runtime} --role {role_arn} --timeout {timeout} --memory-size {memory_size} {env_vars}"
        run_command(cmd)
        
        print(f"Función Lambda '{function_name}' creada correctamente")
    else:
        print(f"La función '{function_name}' ya existe y no se solicitó actualización")

def main():
    parser = argparse.ArgumentParser(description='Desplegar funciones Lambda para DocPilot')
    parser.add_argument('--function', help='Nombre de la carpeta de la función a desplegar (sin ruta)')
    parser.add_argument('--all', action='store_true', help='Desplegar todas las funciones')
    parser.add_argument('--role', default=None, help='ARN del rol IAM para las funciones')
    parser.add_argument('--update', action='store_true', help='Actualizar funciones existentes')
    
    args = parser.parse_args()
    
    # Ruta base del proyecto
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    lambda_dir = os.path.join(base_dir, 'lambda')
    
    # Obtener ARN del rol IAM
    if not args.role:
        try:
            with open(os.path.join(base_dir, 'config.json'), 'r') as f:
                config = json.load(f)
                role_arn = config.get('lambda_role_arn')
        except:
            print("Error: No se especificó un rol IAM y no se pudo leer de config.json")
            sys.exit(1)
    else:
        role_arn = args.role
    
    # Valores por defecto para cada función
    defaults = {
        'email_handler': {
            'function_name': 'docpilot-email-handler',
            'memory_size': 256,
            'timeout': 30,
            'environment': {
                'CONTRACTS_TABLE': 'DocpilotContracts',
                'MAIN_BUCKET': 'docpilot-contracts-storage',
                'SES_BUCKET': 'docpilot-ses-emails'
            }
        },
        'generate_url': {
            'function_name': 'docpilot-generate-url',
            'memory_size': 128,
            'timeout': 10,
            'environment': {
                'CONTRACTS_TABLE': 'DocpilotContracts',
                'MAIN_BUCKET': 'docpilot-contracts-storage'
            }
        },
        'confirm_upload': {
            'function_name': 'docpilot-confirm-upload',
            'memory_size': 128,
            'timeout': 10,
            'environment': {
                'CONTRACTS_TABLE': 'DocpilotContracts',
                'MAIN_BUCKET': 'docpilot-contracts-storage'
            }
        },
        'document_processor': {
            'function_name': 'docpilot-document-processor',
            'memory_size': 1024,
            'timeout': 180,
            'environment': {
                'CONTRACTS_TABLE': 'DocpilotContracts',
                'BEDROCK_MODEL_ID': 'anthropic.claude-3-sonnet-20240229-v1:0'
            }
        },
        'tenant_management': {
            'function_name': 'docpilot-tenant-management',
            'memory_size': 256,
            'timeout': 30,
            'environment': {
                'TENANTS_TABLE': 'DocpilotTenants',
                'MAIN_BUCKET': 'docpilot-contracts-storage'
            }
        },
        'user_management': {
            'function_name': 'docpilot-user-management',
            'memory_size': 256,
            'timeout': 30,
            'environment': {
                'USERS_TABLE': 'DocpilotUsers',
                'TENANTS_TABLE': 'DocpilotTenants',
                'USER_POOL_ID': 'eu-west-1'
            }
        },
        'audit_logger': {
            'function_name': 'docpilot-audit-logger',
            'memory_size': 256,
            'timeout': 30,
            'environment': {
                'AUDIT_BUCKET': 'docpilot-audit-logs'
            }
        },
        'document_manager': {
            'function_name': 'docpilot-document-manager',
            'memory_size': 256,
            'timeout': 30,
            'environment': {
                'CONTRACTS_TABLE': 'DocpilotContracts',
                'MAIN_BUCKET': 'docpilot-contracts-storage'
            }
        }
    }
    
    if args.all:
        # Desplegar todas las funciones
        functions = os.listdir(lambda_dir)
        functions = [f for f in functions if os.path.isdir(os.path.join(lambda_dir, f))]
    elif args.function:
        # Desplegar una función específica
        if not os.path.isdir(os.path.join(lambda_dir, args.function)):
            print(f"Error: La función '{args.function}' no existe")
            sys.exit(1)
        functions = [args.function]
    else:
        print("Error: Debe especificar --function o --all")
        sys.exit(1)
    
    for function in functions:
        function_dir = os.path.join(lambda_dir, function)
        
        print(f"\nProcesando función: {function}")
        
        # Obtener configuración para esta función
        config = defaults.get(function, {
            'function_name': f"docpilot-{function.replace('_', '-')}",
            'memory_size': 256,
            'timeout': 30,
            'environment': {}
        })
        
        try:
            # Crear paquete de despliegue
            zip_file = create_deployment_package(function_dir)
            
            # Desplegar función
            deploy_lambda(
                function_name=config['function_name'],
                zip_file=zip_file,
                role_arn=role_arn,
                timeout=config['timeout'],
                memory_size=config['memory_size'],
                environment=config['environment'],
                update_only=args.update
            )
            
            print(f"Función '{function}' desplegada correctamente como '{config['function_name']}'")
            
        except Exception as e:
            print(f"Error desplegando función '{function}': {str(e)}")
            continue

if __name__ == "__main__":
    main()