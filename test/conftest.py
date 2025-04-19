# tests/conftest.py
# Configuración global para pytest

import os
import pytest
import boto3
import json
from moto import mock_dynamodb, mock_s3, mock_ses

@pytest.fixture(scope="function")
def aws_credentials():
    """Proporciona credenciales de AWS mock."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "eu-west-1"

@pytest.fixture(scope="function")
def dynamodb(aws_credentials):
    """Proporciona una instancia de DynamoDB mock."""
    with mock_dynamodb():
        yield boto3.resource('dynamodb')

@pytest.fixture(scope="function")
def s3(aws_credentials):
    """Proporciona una instancia de S3 mock."""
    with mock_s3():
        yield boto3.client('s3')

@pytest.fixture(scope="function")
def contracts_table(dynamodb):
    """Crea una tabla Contracts mock para pruebas."""
    table = dynamodb.create_table(
        TableName='docpilot-newsystem-contracts-dev',
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}
        ],
        BillingMode='PAY_PER_REQUEST'
    )
    yield table

# Fixtures similares para otras tablas...

@pytest.fixture(scope="function")
def api_url():
    """URL base de la API para pruebas."""
    return "https://49b3724c7h.execute-api.eu-west-1.amazonaws.com/dev"

@pytest.fixture(scope="function")
def test_tenant():
    """Datos de tenant para pruebas."""
    return {
        "tenant_id": "test-tenant",
        "name": "Test Tenant",
        "plan": "basic",
        "status": "active"
    }

@pytest.fixture(scope="function")
def test_user():
    """Datos de usuario para pruebas."""
    return {
        "user_id": "test-user",
        "email": "test@example.com",
        "tenant_id": "test-tenant",
        "role": "admin",
        "status": "active"
    }

@pytest.fixture(scope="function")
def auth_token():
    """Token de autenticación para pruebas."""
    # En un entorno real, esto generaría o obtendría un token válido
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJ0ZW5hbnRfaWQiOiJ0ZXN0LXRlbmFudCIsInJvbGUiOiJhZG1pbiJ9.signature"