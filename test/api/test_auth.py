# tests/api/test_documents_api.py
# Pruebas para API de documentos

import pytest
import requests
import os
import json
from dotenv import load_dotenv

load_dotenv(".env.test")

API_URL = os.getenv("API_URL")
TEST_TENANT_ID = "test-tenant"

@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Obtiene headers de autenticación para las pruebas."""
    return {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

def test_list_documents(auth_headers):
    """Prueba listado de documentos."""
    response = requests.get(
        f"{API_URL}/documents",
        params={"tenant_id": TEST_TENANT_ID},
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "documents" in data
    assert isinstance(data["documents"], list)

def test_get_nonexistent_document(auth_headers):
    """Prueba obtener un documento inexistente."""
    response = requests.get(
        f"{API_URL}/documents/non-existent-id",
        params={"tenant_id": TEST_TENANT_ID},
        headers=auth_headers
    )
    
    assert response.status_code == 404

def test_filter_documents_by_status(auth_headers):
    """Prueba filtrar documentos por estado."""
    response = requests.get(
        f"{API_URL}/documents",
        params={
            "tenant_id": TEST_TENANT_ID,
            "status": "processed"
        },
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Verificar que todos los documentos tienen el estado solicitado
    for doc in data["documents"]:
        assert doc["status"] == "processed"

def test_pagination(auth_headers):
    """Prueba paginación de documentos."""
    # Primera página
    response1 = requests.get(
        f"{API_URL}/documents",
        params={
            "tenant_id": TEST_TENANT_ID,
            "page": 1,
            "limit": 5
        },
        headers=auth_headers
    )
    
    assert response1.status_code == 200
    data1 = response1.json()
    assert len(data1["documents"]) <= 5
    
    # Segunda página
    response2 = requests.get(
        f"{API_URL}/documents",
        params={
            "tenant_id": TEST_TENANT_ID,
            "page": 2,
            "limit": 5
        },
        headers=auth_headers
    )
    
    assert response2.status_code == 200
    data2 = response2.json()
    
    # Verificar que las páginas son diferentes
    if data1["documents"] and data2["documents"]:
        assert data1["documents"][0]["id"] != data2["documents"][0]["id"]