import requests
import json
import logging

# Configurar logging
logging.basicConfig(level=logging.DEBUG)

# URL del endpoint
base_url = "https://j6i9gzg4se.execute-api.eu-west-1.amazonaws.com/dev"
endpoint = f"{base_url}/tenants/onboard"

# Datos para crear el tenant
data = {
    "name": "Ereace",
    "plan": "free",
    "admin_email": "ruly.altamirano@gmail.com",
    "industry": "Technology",
    "company_size": "1-10",
    "country": "Spain"
}

print(f"Enviando datos a {endpoint}")
print(f"Datos: {json.dumps(data, indent=2)}")

# Intentar con Content-Type explícito y sin permitir redirects
response = requests.post(
    endpoint,
    json=data,  # Esto automáticamente serializa a JSON y establece Content-Type
    headers={
        "Accept": "application/json",
        "Content-Type": "application/json"
    },
    allow_redirects=False
)

print(f"Status Code: {response.status_code}")
print(f"Headers enviados: {response.request.headers}")
print(f"Body enviado: {response.request.body}")
print(f"Response Headers: {response.headers}")
print(f"Response: {response.text}")

# Guardar información en un archivo
with open("api_test_log.txt", "w") as f:
    f.write(f"URL: {endpoint}\n")
    f.write(f"Status Code: {response.status_code}\n")
    f.write(f"Request Headers: {response.request.headers}\n")
    f.write(f"Request Body: {response.request.body}\n")
    f.write(f"Response Headers: {response.headers}\n")
    f.write(f"Response: {response.text}\n")

print("Log guardado en api_test_log.txt") 