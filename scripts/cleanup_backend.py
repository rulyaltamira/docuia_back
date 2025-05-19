import boto3
import os

# Configura aquí tus datos de AWS
COGNITO_USER_POOL_ID = 'eu-west-1_SvSDg4lnh'  # ID proporcionado

# Nombres de las tablas DynamoDB según serverless.yml
DYNAMODB_TABLES = [
    'docpilot-newsystem-v3-contracts-dev',
    'docpilot-newsystem-v3-tenants-dev',
    'docpilot-newsystem-v3-users-dev',
    'docpilot-newsystem-v3-alerts-dev',
    'docpilot-newsystem-v3-alert-rules-dev',
    'docpilot-newsystem-v3-alert-preferences-dev',
    'docpilot-newsystem-v3-roles-dev',
    'docpilot-newsystem-v3-permissions-dev',
    'docpilot-newsystem-v3-user-roles-dev',
    'docpilot-newsystem-v3-role-permissions-dev',
    'docpilot-newsystem-v3-statistics-dev',
]

# Inicializa clientes
cognito = boto3.client('cognito-idp')
dynamodb = boto3.resource('dynamodb')

def limpiar_cognito():
    print('Limpiando usuarios de Cognito...')
    paginator = cognito.get_paginator('list_users')
    for page in paginator.paginate(UserPoolId=COGNITO_USER_POOL_ID):
        for user in page['Users']:
            print(f"Eliminando usuario: {user['Username']}")
            cognito.admin_delete_user(UserPoolId=COGNITO_USER_POOL_ID, Username=user['Username'])

def limpiar_dynamodb():
    print('Limpiando registros de DynamoDB...')
    for table_name in DYNAMODB_TABLES:
        table = dynamodb.Table(table_name)
        print(f"Limpiando tabla: {table_name}")
        scan = table.scan()
        for item in scan.get('Items', []):
            # Obtiene la clave primaria
            key_schema = table.key_schema
            key = {k['AttributeName']: item[k['AttributeName']] for k in key_schema}
            print(f"Eliminando item con clave: {key}")
            table.delete_item(Key=key)

def main():
    limpiar_cognito()
    limpiar_dynamodb()
    print('Limpieza completada.')

if __name__ == '__main__':
    main() 