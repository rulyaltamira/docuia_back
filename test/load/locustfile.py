# tests/load/locustfile.py
# Pruebas de carga con Locust

import json
import random
from locust import HttpUser, task, between

class DocPilotUser(HttpUser):
    wait_time = between(1, 5)  # Tiempo entre tareas
    
    # Simulación de token JWT
    auth_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsb2N1c3QtdGVzdC11c2VyIiwidGVuYW50X2lkIjoidGVzdC10ZW5hbnQifQ.signature"
    
    def on_start(self):
        """Inicialización al comenzar un usuario."""
        self.tenant_id = "test-tenant"
        self.user_id = "locust-test-user"
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
    
    @task(10)
    def list_documents(self):
        """Listar documentos (tarea frecuente)."""
        self.client.get(
            "/documents",
            params={"tenant_id": self.tenant_id},
            headers=self.headers,
            name="/documents - Listar"
        )
    
    @task(5)
    def get_document(self):
        """Obtener un documento específico."""
        # En una prueba real, obtendríamos IDs válidos de una lista previa
        doc_ids = ["test-doc-1", "test-doc-2", "test-doc-3", "test-doc-4", "test-doc-5"]
        doc_id = random.choice(doc_ids)
        
        self.client.get(
            f"/documents/{doc_id}",
            params={"tenant_id": self.tenant_id},
            headers=self.headers,
            name="/documents/{id} - Obtener"
        )
    
    @task(3)
    def get_document_summary(self):
        """Obtener resumen de un documento."""
        doc_ids = ["test-doc-1", "test-doc-2", "test-doc-3"]
        doc_id = random.choice(doc_ids)
        
        self.client.get(
            f"/documents/{doc_id}/summary",
            params={"tenant_id": self.tenant_id},
            headers=self.headers,
            name="/documents/{id}/summary - Obtener"
        )
    
    @task(2)
    def get_stats_summary(self):
        """Obtener resumen de estadísticas."""
        self.client.get(
            "/stats/summary",
            params={"tenant_id": self.tenant_id},
            headers=self.headers,
            name="/stats/summary - Obtener"
        )
    
    @task(1)
    def check_alerts(self):
        """Verificar alertas."""
        self.client.get(
            "/alerts",
            params={
                "tenant_id": self.tenant_id,
                "status": "new",
                "limit": 10
            },
            headers=self.headers,
            name="/alerts - Listar"
        )