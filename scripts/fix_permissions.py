#!/usr/bin/env python3
# scripts/fix_permissions.py
# Script para asignar rol de administrador a un usuario y agregar permisos

import boto3
import argparse
import uuid
import json
from datetime import datetime

# Configuración
REGION = 'eu-west-1'
STAGE = 'dev'
SERVICE_NAME = 'docpilot-newsystem-v2'

# Tablas
ROLES_TABLE = f"{SERVICE_NAME}-roles-{STAGE}"
USER_ROLES_TABLE = f"{SERVICE_NAME}-user-roles-{STAGE}"
ROLE_PERMISSIONS_TABLE = f"{SERVICE_NAME}-role-permissions-{STAGE}"
USERS_TABLE = f"{SERVICE_NAME}-users-{STAGE}"

# Cliente DynamoDB
dynamodb = boto3.resource('dynamodb', region_name=REGION)

# Tablas
roles_table = dynamodb.Table(ROLES_TABLE)
user_roles_table = dynamodb.Table(USER_ROLES_TABLE)
role_permissions_table = dynamodb.Table(ROLE_PERMISSIONS_TABLE)
users_table = dynamodb.Table(USERS_TABLE)

def assign_role_to_user(user_id, role_id, tenant_id):
    """
    Asigna un rol a un usuario
    """
    print(f"Asignando rol {role_id} al usuario {user_id} del tenant {tenant_id}...")
    
    # Verificar si ya existe la asignación
    response = user_roles_table.scan(
        FilterExpression="user_id = :u AND role_id = :r AND tenant_id = :t",
        ExpressionAttributeValues={
            ":u": user_id,
            ":r": role_id,
            ":t": tenant_id
        }
    )
    
    if response.get('Items'):
        print(f"El usuario ya tiene el rol asignado: {response['Items'][0]['id']}")
        return response['Items'][0]['id']
    
    # Crear nueva asignación
    assignment_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    
    user_roles_table.put_item(Item={
        'id': assignment_id,
        'user_id': user_id,
        'role_id': role_id,
        'tenant_id': tenant_id,
        'created_at': timestamp
    })
    
    print(f"Rol asignado correctamente. ID de asignación: {assignment_id}")
    return assignment_id

def add_permissions_to_role(role_id, tenant_id):
    """
    Agrega permisos al rol de administrador
    """
    print(f"Agregando permisos al rol {role_id} del tenant {tenant_id}...")
    
    # Verificar si ya tiene permisos
    response = role_permissions_table.scan(
        FilterExpression="role_id = :r AND tenant_id = :t",
        ExpressionAttributeValues={
            ":r": role_id,
            ":t": tenant_id
        }
    )
    
    if response.get('Items'):
        print(f"El rol ya tiene {len(response['Items'])} permisos asignados")
        return len(response['Items'])
    
    # Lista de permisos del administrador
    permissions = [
        'document:read', 'document:create', 'document:update', 'document:delete', 'document:download',
        'user:read', 'user:create', 'user:update', 'user:delete',
        'role:read', 'role:create', 'role:update', 'role:delete', 'role:assign',
        'tenant:read', 'tenant:update', 'tenant:configure',
        'alert:read', 'alert:manage', 'alert:rule',
        'stats:view', 'stats:advanced', 'stats:export',
        'audit:view', 'audit:export',
        'email:configure',
        'admin:full'
    ]
    
    # Agregar permisos
    timestamp = datetime.now().isoformat()
    count = 0
    
    for permission in permissions:
        permission_id = str(uuid.uuid4())
        
        role_permissions_table.put_item(Item={
            'id': permission_id,
            'role_id': role_id,
            'permission': permission,
            'tenant_id': tenant_id,
            'created_at': timestamp
        })
        
        count += 1
    
    print(f"Se agregaron {count} permisos al rol")
    return count

def find_admin_role(tenant_id):
    """
    Busca el rol de administrador para un tenant
    """
    print(f"Buscando rol de administrador para tenant {tenant_id}...")
    
    response = roles_table.scan(
        FilterExpression="tenant_id = :t AND role_name = :r",
        ExpressionAttributeValues={
            ":t": tenant_id,
            ":r": "admin"
        }
    )
    
    if not response.get('Items'):
        print(f"No se encontró rol de administrador para tenant {tenant_id}")
        return None
    
    role = response['Items'][0]
    print(f"Rol encontrado: {role['role_id']} ({role['role_name']})")
    return role['role_id']

def find_user(tenant_id, email=None, user_id=None):
    """
    Busca un usuario por email o ID
    """
    if email:
        print(f"Buscando usuario con email {email} en tenant {tenant_id}...")
        filter_expr = "tenant_id = :t AND email = :e"
        expr_values = {
            ":t": tenant_id,
            ":e": email
        }
    elif user_id:
        print(f"Buscando usuario con ID {user_id} en tenant {tenant_id}...")
        filter_expr = "tenant_id = :t AND user_id = :u"
        expr_values = {
            ":t": tenant_id,
            ":u": user_id
        }
    else:
        print("Se requiere email o user_id para buscar usuario")
        return None
    
    response = users_table.scan(
        FilterExpression=filter_expr,
        ExpressionAttributeValues=expr_values
    )
    
    if not response.get('Items'):
        print(f"No se encontró usuario en tenant {tenant_id}")
        return None
    
    user = response['Items'][0]
    print(f"Usuario encontrado: {user['user_id']} ({user['email']})")
    return user['user_id']

def fix_permissions(tenant_id, email=None, user_id=None):
    """
    Arregla los permisos para un usuario y tenant
    """
    print(f"\n==== Arreglando permisos para tenant: {tenant_id} ====\n")
    
    # 1. Encontrar usuario
    user_id = find_user(tenant_id, email, user_id)
    if not user_id:
        return False
    
    # 2. Encontrar rol de administrador
    role_id = find_admin_role(tenant_id)
    if not role_id:
        return False
    
    # 3. Asignar rol al usuario
    assignment_id = assign_role_to_user(user_id, role_id, tenant_id)
    
    # 4. Agregar permisos al rol
    perm_count = add_permissions_to_role(role_id, tenant_id)
    
    print(f"\n==== Resumen ====")
    print(f"Usuario: {user_id}")
    print(f"Rol: {role_id}")
    print(f"Asignación: {assignment_id}")
    print(f"Permisos: {perm_count}")
    print(f"==== Finalizado ====\n")
    
    return True

def main():
    parser = argparse.ArgumentParser(description='Arregla los permisos para un usuario y tenant')
    parser.add_argument('--tenant', required=True, help='ID del tenant')
    parser.add_argument('--email', help='Email del usuario')
    parser.add_argument('--user-id', help='ID del usuario')
    
    args = parser.parse_args()
    
    if not args.email and not args.user_id:
        parser.error("Se requiere --email o --user-id")
    
    fix_permissions(args.tenant, args.email, args.user_id)

if __name__ == "__main__":
    main() 