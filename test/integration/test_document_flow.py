# tests/integration/test_document_flow.py
# Pruebas de integración para el flujo de documentos

import pytest
import boto3
import requests
import os
import json
import time
import base64
import uuid
from dotenv import load_dotenv

load_dotenv(".env.test")

API_URL = os.getenv("API_URL")
TEST_TENANT_ID = "test-tenant"

@pytest.fixture(scope="module")
def auth_headers():
    """Obtiene headers de autenticación para las pruebas."""
    # En un ambiente real, obtendríamos el token vía Cognito
    return {
        "Authorization": "Bearer test-token",
        "Content-Type": "application/json"
    }

@pytest.fixture(scope="module")
def test_pdf_content():
    """Carga un PDF de prueba."""
    with open("tests/fixtures/test_document.pdf", "rb") as f:
        return f.read()

def test_document_upload_process_flow(auth_headers, test_pdf_content):
    """
    Prueba el flujo completo de un documento:
    1. Generar URL para subida
    2. Subir archivo a S3
    3. Confirmar subida
    4. Verificar procesamiento
    5. Obtener resumen procesado
    """
    # 1. Generar URL para subida
    generate_url_response = requests.get(
        f"{API_URL}/generate-url",
        params={
            "tenant_id": TEST_TENANT_ID,
            "filename": "test_document.pdf",
            "contentType": "application/pdf",
            "fileSize": len(test_pdf_content)
        },
        headers=auth_headers
    )
    
    assert generate_url_response.status_code == 200
    url_data = generate_url_response.json()
    assert "upload_url" in url_data
    assert "file_id" in url_data
    
    file_id = url_data["file_id"]
    upload_url = url_data["upload_url"]
    
    # 2. Subir archivo a S3 (directamente a la URL prefirmada)
    upload_response = requests.put(
        upload_url,
        data=test_pdf_content,
        headers={"Content-Type": "application/pdf"}
    )
    
    assert upload_response.status_code == 200
    
    # 3. Confirmar subida
    confirm_response = requests.post(
        f"{API_URL}/confirm-upload",
        json={"file_id": file_id},
        headers=auth_headers
    )
    
    assert confirm_response.status_code == 200
    confirm_data = confirm_response.json()
    assert confirm_data["file_id"] == file_id
    
    # 4. Esperar y verificar procesamiento (puede tardar)
    processed = False
    max_retries = 10
    retry_count = 0
    
    while not processed and retry_count < max_retries:
        document_response = requests.get(
            f"{API_URL}/documents/{file_id}",
            params={"tenant_id": TEST_TENANT_ID},
            headers=auth_headers
        )
        
        assert document_response.status_code == 200
        document_data = document_response.json()
        
        if document_data["document"]["status"] == "processed":
            processed = True
        elif document_data["document"]["status"] == "error":
            pytest.fail(f"Error procesando documento: {document_data['document'].get('processing_error', 'Unknown error')}")
        else:
            # Esperar antes de reintentar
            retry_count += 1
            time.sleep(5)
    
    assert processed, "El documento no se procesó en el tiempo esperado"
    
    # 5. Obtener resumen procesado
    summary_response = requests.get(
        f"{API_URL}/documents/{file_id}/summary",
        params={"tenant_id": TEST_TENANT_ID},
        headers=auth_headers
    )
    
    assert summary_response.status_code == 200
    summary_data = summary_response.json()
    
    # Verificar que el resumen contiene los campos esperados
    assert "resumen" in summary_data
    assert "partes" in summary_data
    assert "fechas_clave" in summary_data
    assert "obligaciones" in summary_data
    assert "clausulas_importantes" in summary_data
    
    # 6. Limpiar: Eliminar documento
    delete_response = requests.delete(
        f"{API_URL}/documents/{file_id}",
        params={"tenant_id": TEST_TENANT_ID},
        headers=auth_headers
    )
    
    assert delete_response.status_code == 200