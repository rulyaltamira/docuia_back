
# ===============================
# DocPilot API Test Script (.ps1) - Verbose
# ===============================

# --- Configuración de usuario ---
$cognitoParams = @{
    ClientId = "3upv43kntm61e0dt3hg5el2k1g"
    Username = "brady.altamirano@gmail.com"
    Password = "Bradlyemes29#"
    AuthFlow = "USER_PASSWORD_AUTH"
}

# --- Autenticación en Cognito ---
$authBody = @{
    AuthParameters = @{
        USERNAME = $cognitoParams.Username
        PASSWORD = $cognitoParams.Password
    }
    AuthFlow = $cognitoParams.AuthFlow
    ClientId = $cognitoParams.ClientId
} | ConvertTo-Json -Depth 3

try {
    $authResponse = Invoke-RestMethod -Uri "https://cognito-idp.eu-west-1.amazonaws.com/" -Method POST -Headers @{
        "X-Amz-Target" = "AWSCognitoIdentityProviderService.InitiateAuth"
        "Content-Type" = "application/x-amz-json-1.1"
    } -Body $authBody
} catch {
    Write-Host "ERROR: Falló la autenticación con Cognito: $($_.Exception.Message)"
    exit 1
}

# --- Obtener AccessToken ---
$token = $authResponse.AuthenticationResult.AccessToken

# --- Headers con token ---
$headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
}

# --- Variables de entorno ---
$baseUrl = "https://49b3724c7h.execute-api.eu-west-1.amazonaws.com/dev"
$tenantId = "default"

# --- Función para probar endpoints con contenido ---
function Test-GetEndpoint {
    param (
        [string]$path,
        [string]$description,
        [string]$extractField
    )
    $url = "$baseUrl$path"
    Write-Host ""
    Write-Host "Probando: $description"
    Write-Host "URL: $url"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
        if ($extractField -and $response.$extractField) {
            $count = $response.$extractField.Count
            Write-Host "OK: $description ($count elementos)"
        } elseif ($response.Count -gt 0) {
            Write-Host "OK: $description ($($response.Count) elementos)"
        } else {
            Write-Host "OK: $description (sin datos)"
        }
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $body = $reader.ReadToEnd()
        Write-Host "ERROR $statusCode - $description"
        Write-Host "Detalles: $body"
    }
}

# --- Inicio del test ---
Write-Host ""
Write-Host "Verificando endpoints de DocPilot (con detalle y URL)..."
Write-Host "======================================"

Test-GetEndpoint "/alerts/summary?tenant_id=$tenantId" "Resumen de alertas" ""
Test-GetEndpoint "/documents?tenant_id=$tenantId" "Lista de documentos" "documents"
Test-GetEndpoint "/stats/summary?tenant_id=$tenantId" "Resumen de estadísticas" ""
Test-GetEndpoint "/tenants" "Listado de tenants" ""
Test-GetEndpoint "/alerts/rules" "Reglas de alertas" ""
