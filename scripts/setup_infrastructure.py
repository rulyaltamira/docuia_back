# docpilot-backend/scripts/setup_infrastructure.py
# Script para crear la infraestructura base en AWS (tablas DynamoDB, buckets S3, etc.)

import subprocess
import argparse
import json
import os
import sys
import time

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

def create_dynamodb_tables():
    """Crea las tablas DynamoDB necesarias"""
    print("\n=== Creando tablas DynamoDB ===")
    
    # Tabla de contratos
    try:
        print("Creando tabla DocpilotContracts...")
        run_command("""
            aws dynamodb create-table \
                --table-name DocpilotContracts \
                --attribute-definitions \
                    AttributeName=id,AttributeType=S \
                --key-schema \
                    AttributeName=id,KeyType=HASH \
                --billing-mode PAY_PER_REQUEST
        """)
    except Exception as e:
        print(f"Error o tabla ya existe: {str(e)}")
    
    # Tabla de tenants
    try:
        print("Creando tabla DocpilotTenants...")
        run_command("""
            aws dynamodb create-table \
                --table-name DocpilotTenants \
                --attribute-definitions \
                    AttributeName=tenant_id,AttributeType=S \
                --key-schema \
                    AttributeName=tenant_id,KeyType=HASH \
                --billing-mode PAY_PER_REQUEST
        """)
    except Exception as e:
        print(f"Error o tabla ya existe: {str(e)}")
    
    # Tabla de usuarios
    try:
        print("Creando tabla DocpilotUsers...")
        run_command("""
            aws dynamodb create-table \
                --table-name DocpilotUsers \
                --attribute-definitions \
                    AttributeName=user_id,AttributeType=S \
                --key-schema \
                    AttributeName=user_id,KeyType=HASH \
                --billing-mode PAY_PER_REQUEST
        """)
    except Exception as e:
        print(f"Error o tabla ya existe: {str(e)}")
    
    print("Tablas DynamoDB creadas correctamente")

def create_s3_buckets(region, account_id):
    """Crea los buckets S3 necesarios"""
    print("\n=== Creando buckets S3 ===")
    
    # Bucket principal
    try:
        print("Creando bucket principal docpilot-contracts-storage...")
        run_command(f"""
            aws s3api create-bucket --bucket docpilot-contracts-storage --region {region} \
                --create-bucket-configuration LocationConstraint={region}
        """)
        
        # Configurar CORS
        cors_config = {
            "CORSRules": [
                {
                    "AllowedHeaders": ["*"],
                    "AllowedMethods": ["PUT", "POST", "GET", "HEAD"],
                    "AllowedOrigins": ["*"],
                    "ExposeHeaders": ["ETag"],
                    "MaxAgeSeconds": 3000
                }
            ]
        }
        
        with open("cors-config.json", "w") as f:
            json.dump(cors_config, f)
        
        run_command("""
            aws s3api put-bucket-cors --bucket docpilot-contracts-storage --cors-configuration file://cors-config.json
        """)
        
        os.remove("cors-config.json")
    except Exception as e:
        print(f"Error o bucket ya existe: {str(e)}")
    
    # Bucket para emails SES
    try:
        print("Creando bucket para emails SES docpilot-ses-emails...")
        run_command(f"""
            aws s3api create-bucket --bucket docpilot-ses-emails --region {region} \
                --create-bucket-configuration LocationConstraint={region}
        """)
    except Exception as e:
        print(f"Error o bucket ya existe: {str(e)}")
    
    # Bucket para logs de auditoría
    try:
        print("Creando bucket para logs de auditoría docpilot-audit-logs...")
        run_command(f"""
            aws s3api create-bucket --bucket docpilot-audit-logs --region {region} \
                --create-bucket-configuration LocationConstraint={region}
        """)
        
        # Configurar política de ciclo de vida
        lifecycle_config = {
            "Rules": [
                {
                    "ID": "RetainAuditLogs",
                    "Status": "Enabled",
                    "Filter": {
                        "Prefix": "audit-logs/"
                    },
                    "Transitions": [
                        {
                            "Days": 90,
                            "StorageClass": "GLACIER"
                        }
                    ],
                    "Expiration": {
                        "Days": 365
                    }
                }
            ]
        }
        
        with open("lifecycle-config.json", "w") as f:
            json.dump(lifecycle_config, f)
        
        run_command("""
            aws s3api put-bucket-lifecycle-configuration --bucket docpilot-audit-logs --lifecycle-configuration file://lifecycle-config.json
        """)
        
        os.remove("lifecycle-config.json")
    except Exception as e:
        print(f"Error o bucket ya existe: {str(e)}")
    
    print("Buckets S3 creados correctamente")

def create_cognito_userpool(region):
    """Crea un User Pool de Cognito"""
    print("\n=== Creando User Pool de Cognito ===")
    
    try:
        print("Creando User Pool DocpilotUserPool...")
        output = run_command("""
            aws cognito-idp create-user-pool \
                --pool-name DocpilotUserPool \
                --auto-verified-attributes email \
                --schema '[{"Name":"email","Required":true},{"Name":"custom:tenant_id","Required":false},{"Name":"custom:role","Required":false}]'
        """)
        
        user_pool_data = json.loads(output)
        user_pool_id = user_pool_data["UserPool"]["Id"]
        
        print(f"User Pool creado con ID: {user_pool_id}")
        
        # Crear cliente de aplicación
        print("Creando cliente de aplicación DocpilotWebApp...")
        output = run_command(f"""
            aws cognito-idp create-user-pool-client \
                --user-pool-id {user_pool_id} \
                --client-name DocpilotWebApp \
                --generate-secret \
                --explicit-auth-flows ADMIN_NO_SRP_AUTH USER_PASSWORD_AUTH
        """)
        
        client_data = json.loads(output)
        client_id = client_data["UserPoolClient"]["ClientId"]
        client_secret = client_data["UserPoolClient"]["ClientSecret"]
        
        print(f"Cliente de aplicación creado con ID: {client_id}")
        
        # Guardar información en config.json
        config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except:
            config = {}
        
        config['cognito_user_pool_id'] = user_pool_id
        config['cognito_client_id'] = client_id
        config['cognito_client_secret'] = client_secret
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"Información de Cognito guardada en {config_file}")
        
    except Exception as e:
        print(f"Error o User Pool ya existe: {str(e)}")
    
    print("User Pool de Cognito creado correctamente")

def create_iam_role(region, account_id):
    """Crea un rol IAM para las funciones Lambda"""
    print("\n=== Creando rol IAM para funciones Lambda ===")
    
    try:
        # Política de confianza
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        with open("trust-policy.json", "w") as f:
            json.dump(trust_policy, f)
        
        # Crear rol
        print("Creando rol DocpilotLambdaRole...")
        output = run_command("""
            aws iam create-role --role-name DocpilotLambdaRole --assume-role-policy-document file://trust-policy.json
        """)
        
        role_data = json.loads(output)
        role_arn = role_data["Role"]["Arn"]
        
        print(f"Rol creado con ARN: {role_arn}")
        
        # Política de permisos
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:ListBucket",
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:Query",
                        "dynamodb:Scan",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "ses:*",
                        "bedrock:InvokeModel"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        with open("lambda-policy.json", "w") as f:
            json.dump(lambda_policy, f)
        
        # Crear política
        print("Creando política DocpilotLambdaPolicy...")
        output = run_command("""
            aws iam create-policy --policy-name DocpilotLambdaPolicy --policy-document file://lambda-policy.json
        """)
        
        policy_data = json.loads(output)
        policy_arn = policy_data["Policy"]["Arn"]
        
        print(f"Política creada con ARN: {policy_arn}")
        
        # Adjuntar política al rol
        print("Adjuntando política al rol...")
        run_command(f"""
            aws iam attach-role-policy --role-name DocpilotLambdaRole --policy-arn {policy_arn}
        """)
        
        # Adjuntar política AWSLambdaBasicExecutionRole
        print("Adjuntando política AWSLambdaBasicExecutionRole...")
        run_command("""
            aws iam attach-role-policy --role-name DocpilotLambdaRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        """)
        
        # Limpiar archivos temporales
        os.remove("trust-policy.json")
        os.remove("lambda-policy.json")
        
        # Guardar ARN del rol en config.json
        config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except:
            config = {}
        
        config['lambda_role_arn'] = role_arn
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"ARN del rol guardado en {config_file}")
        
        # Esperar a que el rol se propague (IAM tiene consistencia eventual)
        print("Esperando 10 segundos para que el rol se propague...")
        time.sleep(10)
        
    except Exception as e:
        print(f"Error o rol ya existe: {str(e)}")
    
    print("Rol IAM creado correctamente")

def create_api_gateway(region, account_id):
    """Crea una API Gateway para las funciones Lambda"""
    print("\n=== Creando API Gateway ===")
    
    try:
        # Crear API
        print("Creando API Gateway DocpilotAPI...")
        output = run_command("""
            aws apigateway create-rest-api --name DocpilotAPI --description "API para DocPilot document management"
        """)
        
        api_data = json.loads(output)
        api_id = api_data["id"]
        
        print(f"API Gateway creada con ID: {api_id}")
        
        # Obtener ID del recurso raíz
        output = run_command(f"""
            aws apigateway get-resources --rest-api-id {api_id}
        """)
        
        resources_data = json.loads(output)
        root_id = None
        
        for resource in resources_data["items"]:
            if resource["path"] == "/":
                root_id = resource["id"]
                break
        
        if not root_id:
            raise Exception("No se pudo obtener el ID del recurso raíz")
        
        print(f"ID del recurso raíz: {root_id}")
        
        # Guardar ID de la API en config.json
        config_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config.json')
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except:
            config = {}
        
        config['api_gateway_id'] = api_id
        config['api_gateway_root_id'] = root_id
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"ID de API Gateway guardado en {config_file}")
        
    except Exception as e:
        print(f"Error o API Gateway ya existe: {str(e)}")
    
    print("API Gateway creada correctamente")

def main():
    parser = argparse.ArgumentParser(description='Configurar infraestructura AWS para DocPilot')
    parser.add_argument('--region', default='eu-west-1', help='Región de AWS')
    parser.add_argument('--account-id', required=True, help='ID de la cuenta de AWS')
    parser.add_argument('--tables', action='store_true', help='Crear tablas DynamoDB')
    parser.add_argument('--buckets', action='store_true', help='Crear buckets S3')
    parser.add_argument('--cognito', action='store_true', help='Crear User Pool de Cognito')
    parser.add_argument('--role', action='store_true', help='Crear rol IAM para Lambda')
    parser.add_argument('--api', action='store_true', help='Crear API Gateway')
    parser.add_argument('--all', action='store_true', help='Crear toda la infraestructura')
    
    args = parser.parse_args()
    
    # Si no se especifica ninguna opción, mostrar ayuda
    if not any([args.tables, args.buckets, args.cognito, args.role, args.api, args.all]):
        parser.print_help()
        sys.exit(1)
    
    # Crear la infraestructura según las opciones
    if args.all or args.tables:
        create_dynamodb_tables()
    
    if args.all or args.buckets:
        create_s3_buckets(args.region, args.account_id)
    
    if args.all or args.cognito:
        create_cognito_userpool(args.region)
    
    if args.all or args.role:
        create_iam_role(args.region, args.account_id)
    
    if args.all or args.api:
        create_api_gateway(args.region, args.account_id)
    
    print("\n=== Infraestructura configurada correctamente ===")

if __name__ == "__main__":
    main()