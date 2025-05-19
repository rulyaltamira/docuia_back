# docpilot-backend/utils/dynamodb_helper.py
# Utilidades para interactuar con DynamoDB

import boto3
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_table(table_name):
    """Obtiene una referencia a una tabla de DynamoDB"""
    dynamodb = boto3.resource('dynamodb')
    return dynamodb.Table(table_name)

def put_item(table_name, item):
    """Inserta un ítem en una tabla de DynamoDB"""
    table = get_table(table_name)
    try:
        response = table.put_item(Item=item)
        return response
    except ClientError as e:
        logger.error(f"Error al insertar ítem en {table_name}: {e}")
        raise

def get_item(table_name, key):
    """Obtiene un ítem de una tabla de DynamoDB por su clave"""
    table = get_table(table_name)
    try:
        response = table.get_item(Key=key)
        return response.get('Item')
    except ClientError as e:
        logger.error(f"Error al obtener ítem de {table_name}: {e}")
        raise

def update_item(table_name, key, update_expression, expression_attribute_values, expression_attribute_names=None):
    """Actualiza un ítem en una tabla de DynamoDB"""
    table = get_table(table_name)
    
    update_params = {
        'Key': key,
        'UpdateExpression': update_expression,
        'ExpressionAttributeValues': expression_attribute_values,
        'ReturnValues': 'UPDATED_NEW'
    }
    
    if expression_attribute_names:
        update_params['ExpressionAttributeNames'] = expression_attribute_names
    
    try:
        response = table.update_item(**update_params)
        return response
    except ClientError as e:
        logger.error(f"Error al actualizar ítem en {table_name}: {e}")
        raise

def query_items(table_name, key_condition_expression, expression_attribute_values, index_name=None):
    """Consulta ítems en una tabla de DynamoDB"""
    table = get_table(table_name)
    
    query_params = {
        'KeyConditionExpression': key_condition_expression,
        'ExpressionAttributeValues': expression_attribute_values
    }
    
    if index_name:
        query_params['IndexName'] = index_name
    
    try:
        response = table.query(**query_params)
        return response.get('Items', [])
    except ClientError as e:
        logger.error(f"Error al consultar ítems en {table_name}: {e}")
        raise

def scan_items(table_name, filter_expression=None, expression_attribute_values=None):
    """Escanea ítems en una tabla de DynamoDB"""
    table = get_table(table_name)
    
    scan_params = {}
    
    if filter_expression:
        scan_params['FilterExpression'] = filter_expression
    
    if expression_attribute_values:
        scan_params['ExpressionAttributeValues'] = expression_attribute_values
    
    try:
        response = table.scan(**scan_params)
        return response.get('Items', [])
    except ClientError as e:
        logger.error(f"Error al escanear ítems en {table_name}: {e}")
        raise